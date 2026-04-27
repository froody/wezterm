//! Client-side handler for SSH agent forwarding over the wezterm
//! protocol. The server opens a channel via `OpenAgentChannel`; this
//! module proxies bytes between that channel and the local
//! `$SSH_AUTH_SOCK`.

use crate::client::ReaderMessage;
use codec::{AgentChannelData, CloseAgentChannel, Pdu};
use parking_lot::{Mutex, RwLock};
use smol::block_on;
use smol::channel::Sender;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::Arc;

struct ChannelEntry {
    /// Cloned write half of the local agent socket. Locked per-write.
    local_write: Mutex<UnixStream>,
}

#[derive(Clone)]
pub(crate) struct ClientAgentState {
    inner: Arc<Inner>,
}

struct Inner {
    channels: RwLock<HashMap<u64, Arc<ChannelEntry>>>,
    sender: Sender<ReaderMessage>,
}

impl ClientAgentState {
    pub(crate) fn new(sender: Sender<ReaderMessage>) -> Self {
        Self {
            inner: Arc::new(Inner {
                channels: RwLock::new(HashMap::new()),
                sender,
            }),
        }
    }

    /// If `pdu` is an agent channel PDU, dispatch it and return None.
    /// Otherwise return Some(pdu) so the caller can fall through to
    /// pane-oriented unilateral handling.
    pub(crate) fn try_dispatch(&self, pdu: Pdu) -> Option<Pdu> {
        match pdu {
            Pdu::OpenAgentChannel(open) => {
                self.open(open.channel_id);
                None
            }
            Pdu::AgentChannelData(data) => {
                self.handle_data(data.channel_id, data.data);
                None
            }
            Pdu::CloseAgentChannel(close) => {
                self.handle_close(close.channel_id);
                None
            }
            other => Some(other),
        }
    }

    fn open(&self, channel_id: u64) {
        let path = match resolve_local_agent_path() {
            Some(p) => p,
            None => {
                self.send_close(channel_id);
                return;
            }
        };
        let stream = match UnixStream::connect(&path) {
            Ok(s) => s,
            Err(err) => {
                log::warn!(
                    "failed to connect to local SSH agent at {path}: {err:#}; rejecting agent channel {channel_id}"
                );
                self.send_close(channel_id);
                return;
            }
        };
        let read_half = match stream.try_clone() {
            Ok(s) => s,
            Err(err) => {
                log::warn!("agent try_clone failed: {err:#}");
                self.send_close(channel_id);
                return;
            }
        };

        let entry = Arc::new(ChannelEntry {
            local_write: Mutex::new(stream),
        });
        self.inner.channels.write().insert(channel_id, entry);

        let inner = self.inner.clone();
        std::thread::spawn(move || {
            pump_local_to_server(channel_id, read_half, &inner);
            // Reader thread exiting means the local socket is gone:
            // remove the entry and tell the remote we're done.
            inner.channels.write().remove(&channel_id);
            send_unsolicited(
                &inner.sender,
                Pdu::CloseAgentChannel(CloseAgentChannel { channel_id }),
            );
        });
    }

    fn handle_data(&self, channel_id: u64, data: Vec<u8>) {
        let entry = self.inner.channels.read().get(&channel_id).cloned();
        let Some(entry) = entry else { return };
        let mut sock = entry.local_write.lock();
        if data.is_empty() {
            // Half-close from the server side.
            sock.shutdown(std::net::Shutdown::Write).ok();
            return;
        }
        if let Err(err) = sock.write_all(&data) {
            log::debug!("agent channel {channel_id} local write failed: {err:#}");
            drop(sock);
            self.handle_close(channel_id);
            self.send_close(channel_id);
        }
    }

    fn handle_close(&self, channel_id: u64) {
        let entry = self.inner.channels.write().remove(&channel_id);
        if let Some(entry) = entry {
            entry
                .local_write
                .lock()
                .shutdown(std::net::Shutdown::Both)
                .ok();
        }
    }

    fn send_close(&self, channel_id: u64) {
        send_unsolicited(
            &self.inner.sender,
            Pdu::CloseAgentChannel(CloseAgentChannel { channel_id }),
        );
    }
}

fn resolve_local_agent_path() -> Option<String> {
    std::env::var("SSH_AUTH_SOCK").ok().filter(|p| !p.is_empty())
}

fn pump_local_to_server(channel_id: u64, mut sock: UnixStream, inner: &Inner) {
    let mut buf = [0u8; 16 * 1024];
    loop {
        match sock.read(&mut buf) {
            Ok(0) => {
                // Local agent closed: signal half-close to remote.
                send_unsolicited(
                    &inner.sender,
                    Pdu::AgentChannelData(AgentChannelData {
                        channel_id,
                        data: Vec::new(),
                    }),
                );
                return;
            }
            Ok(n) => {
                let data = buf[..n].to_vec();
                if !send_unsolicited(
                    &inner.sender,
                    Pdu::AgentChannelData(AgentChannelData { channel_id, data }),
                ) {
                    return;
                }
            }
            Err(err) => {
                log::debug!("agent channel {channel_id} local read failed: {err:#}");
                return;
            }
        }
    }
}

fn send_unsolicited(sender: &Sender<ReaderMessage>, pdu: Pdu) -> bool {
    block_on(sender.send(ReaderMessage::SendPduUnsolicited { pdu })).is_ok()
}
