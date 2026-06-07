use crate::{ClientId, Mux};
use chrono::{DateTime, Duration, Utc};
use parking_lot::{Mutex, RwLock};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// AgentProxy listens on a unix socket in the wezterm runtime
/// directory (`agent.PID`). When a process on the server side
/// connects to it, AgentProxy picks the most recently active
/// agent-capable client and bridges the connection's traffic to
/// that client over the wezterm protocol via OpenAgentChannel /
/// AgentChannelData / CloseAgentChannel PDUs. The client at the
/// far end of the wezterm connection then proxies the bytes to
/// its local SSH agent socket.
///
/// As a further complication, when a wezterm proxy client is
/// present, both the proxy and the mux instance inside a gui
/// tend to be updated together, with the gui often being
/// touched last.
///
/// To deal with that we weight proxy clients higher so that we
/// can avoid thrashing between gui and proxy.

/// Abstract message produced by AgentProxy and consumed by the
/// per-session transport in the mux server. Lives in `mux` so the
/// AgentProxy can be transport-agnostic; mux-server-impl translates
/// these into wire PDUs.
pub enum AgentMessage {
    Open { channel_id: u64 },
    Data { channel_id: u64, data: Vec<u8> },
    Close { channel_id: u64 },
}

pub type AgentSender = Arc<dyn Fn(AgentMessage) + Send + Sync>;

struct ChannelEntry {
    /// Used to write data inbound from the remote client back into
    /// the local connection.
    write_half: Mutex<UnixStream>,
    client_id: Arc<ClientId>,
}

pub struct AgentProxy {
    sock_path: PathBuf,
    senders: RwLock<HashMap<ClientId, AgentSender>>,
    channels: RwLock<HashMap<u64, ChannelEntry>>,
    next_channel_id: AtomicU64,
}

impl Drop for AgentProxy {
    fn drop(&mut self) {
        std::fs::remove_file(&self.sock_path).ok();
    }
}

impl AgentProxy {
    pub fn new() -> Self {
        let pid = unsafe { libc::getpid() };
        let sock_path = config::RUNTIME_DIR.join(format!("agent.{pid}"));

        // Remove any stale socket left from a previous run with the
        // same pid (rare but possible after a crash).
        std::fs::remove_file(&sock_path).ok();

        let proxy = Self {
            sock_path: sock_path.clone(),
            senders: RwLock::new(HashMap::new()),
            channels: RwLock::new(HashMap::new()),
            next_channel_id: AtomicU64::new(1),
        };

        match UnixListener::bind(&sock_path) {
            Ok(listener) => {
                std::thread::spawn(move || Self::accept_loop(listener));
            }
            Err(err) => {
                log::error!(
                    "failed to bind agent socket at {}: {err:#}",
                    sock_path.display()
                );
            }
        }

        proxy
    }

    pub fn default_ssh_auth_sock() -> Option<String> {
        match &config::configuration().default_ssh_auth_sock {
            Some(value) => Some(value.to_string()),
            None => std::env::var("SSH_AUTH_SOCK").ok(),
        }
    }

    pub fn path(&self) -> &Path {
        &self.sock_path
    }

    /// `update_target` exists for compatibility with the previous
    /// symlink-based design which was driven by client input events.
    /// In the channel-based design we pick the target lazily at the
    /// moment a connection is accepted, so this is a no-op.
    pub fn update_target(&self) {}

    /// Register a transport sink for a client that has indicated
    /// it can forward an agent (ssh_agent_forward = true).
    pub fn register_client(&self, client_id: ClientId, sender: AgentSender) {
        self.senders.write().insert(client_id, sender);
    }

    pub fn unregister_client(&self, client_id: &ClientId) {
        self.senders.write().remove(client_id);
        // Drop any channels that were routed to this client; the
        // accompanying UnixStream close will signal EOF to the local
        // process that connected to the agent socket.
        let mut channels = self.channels.write();
        channels.retain(|_, entry| entry.client_id.as_ref() != client_id);
    }

    /// Inbound from a remote client: write `data` to the local
    /// connection associated with `channel_id`. Empty `data` is EOF.
    pub fn handle_inbound_data(&self, channel_id: u64, data: &[u8]) {
        let channels = self.channels.read();
        let Some(entry) = channels.get(&channel_id) else {
            return;
        };
        let mut stream = entry.write_half.lock();
        if data.is_empty() {
            // Half-close: shut down the write side so the local
            // process sees EOF. The reader thread on this side will
            // wrap up when its read returns 0.
            stream.shutdown(std::net::Shutdown::Write).ok();
            return;
        }
        if let Err(err) = stream.write_all(data) {
            log::debug!("agent channel {channel_id} write failed: {err:#}");
            drop(stream);
            drop(channels);
            self.close_channel(channel_id, true);
        }
    }

    /// Inbound from a remote client: close the channel.
    pub fn handle_inbound_close(&self, channel_id: u64) {
        self.close_channel(channel_id, false);
    }

    fn close_channel(&self, channel_id: u64, notify_remote: bool) {
        let entry = self.channels.write().remove(&channel_id);
        if let Some(entry) = entry {
            // Tear down both halves of the unix socket so the local
            // process sees EOF *and* the read pump thread exits.
            entry.write_half.lock().shutdown(std::net::Shutdown::Both).ok();
            if notify_remote {
                let senders = self.senders.read();
                if let Some(sender) = senders.get(entry.client_id.as_ref()) {
                    sender(AgentMessage::Close { channel_id });
                }
            }
        }
    }

    fn pick_target_client(&self) -> Option<Arc<ClientId>> {
        let mut clients = Mux::get().iter_clients();
        log::info!("pick_target_client: all clients in mux: {:#?}", clients);
        clients.retain(|info| info.client_id.ssh_agent_forward);
        log::info!("pick_target_client: clients after forward filter: {:#?}", clients);

        clients.sort_by(|a, b| {
            // Biggest last_input wins. Bias proxies upward so that
            // gui-via-proxy setups don't flap; matches the pairing in
            // wezterm-mux-server-impl/src/sessionhandler.rs.
            const PROXY_MARKER: &str = "via proxy pid";
            let a_proxy = a.client_id.hostname.contains(PROXY_MARKER);
            let b_proxy = b.client_id.hostname.contains(PROXY_MARKER);

            fn adjust(time: DateTime<Utc>, is_proxy: bool) -> DateTime<Utc> {
                if is_proxy {
                    time + Duration::milliseconds(100)
                } else {
                    time
                }
            }

            adjust(b.last_input, b_proxy).cmp(&adjust(a.last_input, a_proxy))
        });

        let picked = clients.into_iter().map(|info| info.client_id).next();
        log::info!("pick_target_client: picked: {:#?}", picked);
        picked
    }

    fn accept_loop(listener: UnixListener) {
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    if let Some(mux) = Mux::try_get() {
                        if let Some(agent) = &mux.agent {
                            agent.handle_accepted(stream);
                        }
                    }
                }
                Err(err) => {
                    log::warn!("agent socket accept failed: {err:#}");
                    // Brief pause so we don't spin on a persistent
                    // error (e.g. EMFILE).
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
            }
        }
    }

    fn handle_accepted(&self, stream: UnixStream) {
        log::info!("handle_accepted: new connection to agent socket!");
        let senders_keys: Vec<_> = self.senders.read().keys().cloned().collect();
        log::info!("handle_accepted: registered senders: {:#?}", senders_keys);
        let Some(target) = self.pick_target_client() else {
            log::warn!("agent: no forward-capable client available; dropping connection");
            return;
        };

        let sender = match self.senders.read().get(target.as_ref()).cloned() {
            Some(s) => s,
            None => {
                log::warn!("agent: picked client {:#?} but its sender already went away; dropping connection", target);
                // Client was registered by client_id but its sender
                // already went away; drop the connection.
                return;
            }
        };
        log::info!("handle_accepted: successfully picked sender for {:#?}", target);

        let read_half = match stream.try_clone() {
            Ok(s) => s,
            Err(err) => {
                log::warn!("agent: try_clone failed: {err:#}");
                return;
            }
        };

        let channel_id = self.next_channel_id.fetch_add(1, Ordering::Relaxed);
        self.channels.write().insert(
            channel_id,
            ChannelEntry {
                write_half: Mutex::new(stream),
                client_id: target.clone(),
            },
        );

        sender(AgentMessage::Open { channel_id });

        let sender_for_thread = sender.clone();
        std::thread::spawn(move || {
            Self::pump_local_to_remote(channel_id, read_half, sender_for_thread);
            if let Some(mux) = Mux::try_get() {
                if let Some(agent) = &mux.agent {
                    agent.close_channel(channel_id, true);
                }
            }
        });
    }

    fn pump_local_to_remote(channel_id: u64, mut stream: UnixStream, sender: AgentSender) {
        let mut buf = [0u8; 16 * 1024];
        loop {
            match stream.read(&mut buf) {
                Ok(0) => {
                    // Local side closed; let the remote know so it can
                    // half-close its agent connection.
                    sender(AgentMessage::Data {
                        channel_id,
                        data: Vec::new(),
                    });
                    return;
                }
                Ok(n) => {
                    sender(AgentMessage::Data {
                        channel_id,
                        data: buf[..n].to_vec(),
                    });
                }
                Err(err) => {
                    log::debug!("agent channel {channel_id} read failed: {err:#}");
                    return;
                }
            }
        }
    }
}

