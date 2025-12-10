//! Session manager for handling multiple sessions.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use parking_lot::RwLock;
use yggdrasil_crypto::box_crypto::{self, BoxPriv};
use yggdrasil_types::{PublicKey, SecretKey, WireError};

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

        let packet_type = data[0];
        tracing::debug!(
            from = %hex::encode(&from.as_bytes()[..8]),
            packet_type = packet_type,
            data_len = data.len(),
            packet_name = match packet_type {
                0 => "Dummy",
                1 => "Init",
                2 => "Ack",
                3 => "Traffic",
                _ => "Unknown"
            },
            "Session: Received packet"
        );

        match data[0] {
            0 => HandleResult::Ignored, // Dummy
            1 => {
                // Init
                if let Some(init) = SessionInit::decrypt(&self.secret_box, from, data) {
                    tracing::debug!(
                        from = %hex::encode(&from.as_bytes()[..8]),
                        "Session: Init decrypted successfully"
                    );
                    self.handle_init(from, &init)
                } else {
                    tracing::warn!(
                        from = %hex::encode(&from.as_bytes()[..8]),
                        "Session: Failed to decrypt Init packet"
                    );
                    HandleResult::Error
                }
            }
            2 => {
                // Ack
                if let Some(ack) = crate::SessionAck::decrypt(&self.secret_box, from, data) {
                    tracing::debug!(
                        from = %hex::encode(&from.as_bytes()[..8]),
                        "Session: Ack decrypted successfully"
                    );
                    self.handle_ack(from, &ack)
                } else {
                    tracing::warn!(
                        from = %hex::encode(&from.as_bytes()[..8]),
                        "Session: Failed to decrypt Ack packet"
                    );
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
        tracing::debug!(
            from = %hex::encode(&pub_key.as_bytes()[..8]),
            seq = init.seq,
            key_seq = init.key_seq,
            "Session: Processing Init message"
        );
        let (session, buf) = self.session_for_init(pub_key, init);
        {
            let mut info = session.write();
            let current_seq = info.seq;
            if !info.handle_init(init) {
                tracing::debug!(
                    from = %hex::encode(&pub_key.as_bytes()[..8]),
                    init_seq = init.seq,
                    current_seq = current_seq,
                    "Session: Init ignored (duplicate or out-of-order)"
                );
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
            let current_seq = info.seq;
            if is_old {
                if !info.handle_ack(ack) {
                    tracing::debug!(
                        from = %hex::encode(&pub_key.as_bytes()[..8]),
                        ack_seq = ack.inner.seq,
                        current_seq = current_seq,
                        is_old = is_old,
                        "Session: Ack ignored (duplicate or out-of-order)"
                    );
                    return HandleResult::Ignored;
                }
            } else {
                if !info.handle_init(&ack.inner) {
                    tracing::debug!(
                        from = %hex::encode(&pub_key.as_bytes()[..8]),
                        init_seq = ack.inner.seq,
                        current_seq = current_seq,
                        is_old = is_old,
                        "Session: Ack-init ignored (duplicate or out-of-order)"
                    );
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
            let info_read = session.read();
            tracing::debug!(
                from = %hex::encode(&pub_key.as_bytes()[..8]),
                recv_shared = %hex::encode(info_read.recv_shared.as_bytes()),
                recv_nonce = info_read.recv_nonce,
                next_recv_shared = %hex::encode(info_read.next_recv_shared.as_bytes()),
                next_recv_nonce = info_read.next_recv_nonce,
                msg_len = msg.len(),
                "Session: Found existing session, attempting to decrypt traffic"
            );
            drop(info_read);
            let mut info = session.write();
            match info.decrypt_traffic(msg) {
                Ok(payload) => {
                    tracing::debug!(
                        from = %hex::encode(&pub_key.as_bytes()[..8]),
                        payload_len = payload.len(),
                        "Session: Traffic decrypted successfully"
                    );
                    HandleResult::Received { payload }
                }
                Err(crate::info::DecryptError::KeyMismatch) => {
                    tracing::warn!(
                        from = %hex::encode(&pub_key.as_bytes()[..8]),
                        "Session: Key mismatch, sending Init to resync"
                    );
                    // Send init to resync
                    let init = info.create_init();
                    HandleResult::SendInit {
                        dest: *pub_key,
                        init,
                    }
                }
                Err(e) => {
                    tracing::error!(
                        from = %hex::encode(&pub_key.as_bytes()[..8]),
                        error = ?e,
                        "Session: Failed to decrypt traffic"
                    );
                    HandleResult::Error
                }
            }
        } else {
            tracing::warn!(
                from = %hex::encode(&pub_key.as_bytes()[..8]),
                "Session: No session found for traffic, sending ephemeral Init"
            );
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
            let info = session.read();
            tracing::debug!(
                dest = %hex::encode(&to_key.as_bytes()[..8]),
                msg_len = msg.len(),
                send_shared = %hex::encode(info.send_shared.as_bytes()),
                send_nonce = info.send_nonce,
                "Session: Encrypting traffic with existing session"
            );
            drop(info);
            let mut info = session.write();
            let encrypted = info.encrypt_traffic(&msg);
            tracing::debug!(
                dest = %hex::encode(&to_key.as_bytes()[..8]),
                encrypted_len = encrypted.len(),
                "Session: Traffic encrypted successfully"
            );
            WriteResult::Send { data: encrypted }
        } else {
            tracing::debug!(
                dest = %hex::encode(&to_key.as_bytes()[..8]),
                msg_len = msg.len(),
                "Session: No session exists, buffering and sending Init"
            );
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

        // Refresh the init sequence so peers that already tracked a previous
        // init (e.g., if an ack was lost) will accept and respond instead of
        // treating it as stale.
        let current = buf.init.current;
        let next = buf.init.next;
        let key_seq = buf.init.key_seq;
        buf.init = SessionInit::new(&current, &next, key_seq);

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

    pub fn encrypt_init(&self, dest: &PublicKey, init: &SessionInit) -> Result<Vec<u8>, WireError> {
        init.encrypt(&self.secret_ed, dest)
    }

    /// Encrypt a session ack message.
    pub fn encrypt_ack(
        &self,
        dest: &PublicKey,
        ack: &crate::SessionAck,
    ) -> Result<Vec<u8>, WireError> {
        ack.encrypt(&self.secret_ed, dest)
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
