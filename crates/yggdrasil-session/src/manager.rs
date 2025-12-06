//! Session manager for handling multiple sessions.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use parking_lot::RwLock;
use yggdrasil_crypto::box_crypto::{self, BoxPriv};
use yggdrasil_types::{PublicKey, SecretKey};

use crate::{SESSION_TIMEOUT, SessionBuffer, SessionInfo, SessionInit};

/// Snapshot of an active session for introspection.
#[derive(Debug, Clone)]
pub struct SessionStats {
    pub peer: PublicKey,
    pub since: Instant,
    pub last_activity: Instant,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

/// Manages all active sessions.
pub struct SessionManager {
    /// Our ed25519 secret key.
    secret_ed: SecretKey,
    /// Our box secret key (derived from ed25519).
    secret_box: BoxPriv,
    /// Active sessions by remote public key.
    sessions: RwLock<HashMap<PublicKey, Arc<RwLock<SessionInfo>>>>,
    /// Pending session buffers.
    buffers: RwLock<HashMap<PublicKey, SessionBuffer>>,
}

impl SessionManager {
    /// Create a new session manager.
    pub fn new(secret_ed: SecretKey) -> Self {
        let secret_box = yggdrasil_crypto::conversion::ed_to_curve25519_secret(&secret_ed);
        Self {
            secret_ed,
            secret_box,
            sessions: RwLock::new(HashMap::new()),
            buffers: RwLock::new(HashMap::new()),
        }
    }

    /// Get or create a session for a peer.
    pub fn get_session(&self, peer: &PublicKey) -> Option<Arc<RwLock<SessionInfo>>> {
        self.sessions.read().get(peer).cloned()
    }

    /// Create a new session for a peer.
    #[allow(dead_code)]
    fn new_session(
        &self,
        ed: PublicKey,
        recv: yggdrasil_crypto::box_crypto::BoxPub,
        send: yggdrasil_crypto::box_crypto::BoxPub,
        seq: u64,
    ) -> Arc<RwLock<SessionInfo>> {
        let info = SessionInfo::new(ed, recv, send, seq);
        let session = Arc::new(RwLock::new(info));
        self.sessions.write().insert(ed, session.clone());
        session
    }

    /// Get or create a session from an init message.
    pub fn session_for_init(
        &self,
        pub_key: &PublicKey,
        init: &SessionInit,
    ) -> (Arc<RwLock<SessionInfo>>, Option<SessionBuffer>) {
        let mut sessions = self.sessions.write();

        if let Some(existing) = sessions.get(pub_key) {
            return (existing.clone(), None);
        }

        // Create new session
        let info = SessionInfo::new(*pub_key, init.current, init.next, init.seq);
        let session = Arc::new(RwLock::new(info));
        sessions.insert(*pub_key, session.clone());

        // Check for pending buffer
        let buf = self.buffers.write().remove(pub_key);
        if let Some(buf) = buf {
            let mut sess = session.write();
            sess.send_pub = buf.init.current;
            sess.send_priv = buf.current_priv.clone();
            sess.next_pub = buf.init.next;
            sess.next_priv = buf.next_priv.clone();
            sess.fix_shared(0, 0);
            return (session.clone(), Some(buf));
        }

        (session, None)
    }

    /// Handle incoming session data.
    pub fn handle_data(&self, from: &PublicKey, data: &[u8]) -> HandleResult {
        if data.is_empty() {
            return HandleResult::Ignored;
        }

        match data[0] {
            0 => HandleResult::Ignored, // Dummy
            1 => {
                // Init
                if let Some(init) = SessionInit::decrypt(&self.secret_box, from, data) {
                    self.handle_init(from, &init)
                } else {
                    HandleResult::Error
                }
            }
            2 => {
                // Ack
                if let Some(ack) = crate::SessionAck::decrypt(&self.secret_box, from, data) {
                    self.handle_ack(from, &ack)
                } else {
                    HandleResult::Error
                }
            }
            3 => {
                // Traffic
                self.handle_traffic(from, data)
            }
            _ => HandleResult::Ignored,
        }
    }

    fn handle_init(&self, pub_key: &PublicKey, init: &SessionInit) -> HandleResult {
        let (session, buf) = self.session_for_init(pub_key, init);
        {
            let mut info = session.write();
            if !info.handle_init(init) {
                return HandleResult::Ignored;
            }
        }

        // Need to send ack
        let ack = session.read().create_ack();
        HandleResult::SendAck {
            dest: *pub_key,
            ack,
            buffered_data: buf.and_then(|b| b.data),
        }
    }

    fn handle_ack(&self, pub_key: &PublicKey, ack: &crate::SessionAck) -> HandleResult {
        let is_old = self.sessions.read().contains_key(pub_key);
        let (session, buf) = self.session_for_init(pub_key, &ack.inner);

        {
            let mut info = session.write();
            if is_old {
                if !info.handle_ack(ack) {
                    return HandleResult::Ignored;
                }
            } else {
                if !info.handle_init(&ack.inner) {
                    return HandleResult::Ignored;
                }
            }
        }

        if let Some(buf) = buf {
            if let Some(data) = buf.data {
                return HandleResult::SendBuffered {
                    dest: *pub_key,
                    data,
                };
            }
        }

        HandleResult::Ignored
    }

    fn handle_traffic(&self, pub_key: &PublicKey, msg: &[u8]) -> HandleResult {
        if let Some(session) = self.sessions.read().get(pub_key) {
            let mut info = session.write();
            match info.decrypt_traffic(msg) {
                Ok(payload) => HandleResult::Received { payload },
                Err(crate::info::DecryptError::KeyMismatch) => {
                    // Send init to resync
                    let init = info.create_init();
                    HandleResult::SendInit {
                        dest: *pub_key,
                        init,
                    }
                }
                Err(_) => HandleResult::Error,
            }
        } else {
            // No session - send ephemeral init
            let (current_pub, _) = box_crypto::generate_keypair();
            let (next_pub, _) = box_crypto::generate_keypair();
            let init = SessionInit::new(&current_pub, &next_pub, 0);
            HandleResult::SendInit {
                dest: *pub_key,
                init,
            }
        }
    }

    /// Encrypt and send data to a peer.
    pub fn write_to(&self, to_key: PublicKey, msg: Vec<u8>) -> WriteResult {
        if let Some(session) = self.sessions.read().get(&to_key) {
            let mut info = session.write();
            let encrypted = info.encrypt_traffic(&msg);
            WriteResult::Send { data: encrypted }
        } else {
            // Buffer and init
            self.buffer_and_init(to_key, msg)
        }
    }

    fn buffer_and_init(&self, to_key: PublicKey, msg: Vec<u8>) -> WriteResult {
        let mut buffers = self.buffers.write();

        let buf = buffers.entry(to_key).or_insert_with(|| {
            let (current_pub, current_priv) = box_crypto::generate_keypair();
            let (next_pub, next_priv) = box_crypto::generate_keypair();
            SessionBuffer::new(current_pub, current_priv, next_pub, next_priv)
        });

        buf.data = Some(msg);
        let init = buf.init.clone();

        WriteResult::NeedInit { dest: to_key, init }
    }

    /// Encrypt a session init message.

    /// Return a snapshot of all active sessions for observability.
    pub fn list_sessions(&self) -> Vec<SessionStats> {
        let sessions = self.sessions.read();
        sessions
            .iter()
            .map(|(peer, info)| {
                let info = info.read();
                SessionStats {
                    peer: *peer,
                    since: info.since,
                    last_activity: info.last_activity,
                    rx_bytes: info.rx,
                    tx_bytes: info.tx,
                }
            })
            .collect()
    }
    pub fn encrypt_init(&self, dest: &PublicKey, init: &SessionInit) -> Option<Vec<u8>> {
        init.encrypt(&self.secret_ed, dest).ok()
    }

    /// Encrypt a session ack message.
    pub fn encrypt_ack(&self, dest: &PublicKey, ack: &crate::SessionAck) -> Option<Vec<u8>> {
        ack.encrypt(&self.secret_ed, dest).ok()
    }

    /// Clean up expired sessions and buffers.
    pub fn cleanup(&self) {
        // Clean expired sessions
        self.sessions
            .write()
            .retain(|_, session| session.read().last_activity.elapsed() < SESSION_TIMEOUT);

        // Clean expired buffers
        self.buffers
            .write()
            .retain(|_, buf| !buf.is_expired(SESSION_TIMEOUT));
    }
}

/// Result of handling incoming session data.
#[derive(Debug)]
pub enum HandleResult {
    /// Data was ignored (e.g., dummy packet).
    Ignored,
    /// Error processing data.
    Error,
    /// Received decrypted payload.
    Received { payload: Vec<u8> },
    /// Need to send an init message.
    SendInit { dest: PublicKey, init: SessionInit },
    /// Need to send an ack message.
    SendAck {
        dest: PublicKey,
        ack: crate::SessionAck,
        buffered_data: Option<Vec<u8>>,
    },
    /// Need to send buffered data.
    SendBuffered { dest: PublicKey, data: Vec<u8> },
}

/// Result of a write operation.
#[derive(Debug)]
pub enum WriteResult {
    /// Data is ready to send.
    Send { data: Vec<u8> },
    /// Need to send init first, data is buffered.
    NeedInit { dest: PublicKey, init: SessionInit },
}
