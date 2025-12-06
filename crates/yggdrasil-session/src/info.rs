//! Session information and state management.

use std::time::Instant;

use yggdrasil_crypto::box_crypto::{self, BoxPriv, BoxPub, BoxShared};
use yggdrasil_types::PublicKey;

use crate::{
    SESSION_TRAFFIC_OVERHEAD, SESSION_TRAFFIC_OVERHEAD_MIN, SessionAck, SessionInit, SessionType,
};

/// Information about an active session.
#[derive(Debug)]
pub struct SessionInfo {
    /// Remote ed25519 public key.
    pub ed: PublicKey,
    /// Remote sequence number.
    pub seq: u64,
    /// Remote key sequence (for rotation).
    pub remote_key_seq: u64,
    /// Current remote box key.
    pub current: BoxPub,
    /// Next remote box key.
    pub next: BoxPub,
    /// Local key sequence.
    pub local_key_seq: u64,
    /// Receive private key.
    pub recv_priv: BoxPriv,
    /// Receive public key.
    pub recv_pub: BoxPub,
    /// Precomputed receive shared secret.
    pub recv_shared: BoxShared,
    /// Receive nonce.
    pub recv_nonce: u64,
    /// Send private key (becomes recv on ratchet).
    pub send_priv: BoxPriv,
    /// Send public key.
    pub send_pub: BoxPub,
    /// Precomputed send shared secret.
    pub send_shared: BoxShared,
    /// Send nonce.
    pub send_nonce: u64,
    /// Next private key (becomes send on ratchet).
    pub next_priv: BoxPriv,
    /// Next public key.
    pub next_pub: BoxPub,
    /// Session creation time.
    pub since: Instant,
    /// Last key rotation time.
    pub rotated: Option<Instant>,
    /// Bytes received.
    pub rx: u64,
    /// Bytes transmitted.
    pub tx: u64,
    /// Next send shared secret.
    pub next_send_shared: BoxShared,
    /// Next send nonce.
    pub next_send_nonce: u64,
    /// Next receive shared secret.
    pub next_recv_shared: BoxShared,
    /// Next receive nonce.
    pub next_recv_nonce: u64,
    /// Last activity time (for timeout).
    pub last_activity: Instant,
}

impl SessionInfo {
    /// Create a new session.
    pub fn new(ed: PublicKey, current: BoxPub, next: BoxPub, seq: u64) -> Self {
        let (recv_pub, recv_priv) = box_crypto::generate_keypair();
        let (send_pub, send_priv) = box_crypto::generate_keypair();
        let (next_pub, next_priv) = box_crypto::generate_keypair();

        let mut info = Self {
            ed,
            seq: seq.wrapping_sub(1), // So first update works
            remote_key_seq: 0,
            current,
            next,
            local_key_seq: 0,
            recv_priv,
            recv_pub,
            recv_shared: BoxShared::default(),
            recv_nonce: 0,
            send_priv,
            send_pub,
            send_shared: BoxShared::default(),
            send_nonce: 0,
            next_priv,
            next_pub,
            since: Instant::now(),
            rotated: None,
            rx: 0,
            tx: 0,
            next_send_shared: BoxShared::default(),
            next_send_nonce: 0,
            next_recv_shared: BoxShared::default(),
            next_recv_nonce: 0,
            last_activity: Instant::now(),
        };
        info.fix_shared(0, 0);
        info
    }

    /// Fix/update shared secrets after key changes.
    pub fn fix_shared(&mut self, recv_nonce: u64, send_nonce: u64) {
        self.recv_shared = box_crypto::precompute(&self.current, &self.recv_priv);
        self.send_shared = box_crypto::precompute(&self.current, &self.send_priv);
        self.next_send_shared = box_crypto::precompute(&self.next, &self.send_priv);
        self.next_recv_shared = box_crypto::precompute(&self.next, &self.recv_priv);
        self.next_send_nonce = 0;
        self.next_recv_nonce = 0;
        self.recv_nonce = recv_nonce;
        self.send_nonce = send_nonce;
    }

    /// Reset the activity timer.
    pub fn reset_timer(&mut self) {
        self.last_activity = Instant::now();
    }

    /// Handle a session init message.
    pub fn handle_init(&mut self, init: &SessionInit) -> bool {
        if init.seq <= self.seq {
            return false;
        }
        self.handle_update(init);
        true
    }

    /// Handle a session ack message.
    pub fn handle_ack(&mut self, ack: &SessionAck) -> bool {
        if ack.inner.seq <= self.seq {
            return false;
        }
        self.handle_update(&ack.inner);
        true
    }

    /// Handle a session update (from init or ack).
    fn handle_update(&mut self, init: &SessionInit) {
        self.current = init.current;
        self.next = init.next;
        self.seq = init.seq;
        self.remote_key_seq = init.key_seq;

        // Advance our keys (this counts as a response)
        self.recv_pub = self.send_pub;
        self.recv_priv = self.send_priv.clone();
        self.send_pub = self.next_pub;
        self.send_priv = self.next_priv.clone();
        let (next_pub, next_priv) = box_crypto::generate_keypair();
        self.next_pub = next_pub;
        self.next_priv = next_priv;
        self.local_key_seq += 1;

        // Don't roll back send_nonce
        self.fix_shared(0, self.send_nonce);
        self.reset_timer();
    }

    /// Encrypt and format a traffic message for sending.
    pub fn encrypt_traffic(&mut self, msg: &[u8]) -> Vec<u8> {
        self.send_nonce += 1;

        // Check for nonce overflow - rotate keys if needed
        if self.send_nonce == 0 {
            self.recv_pub = self.send_pub;
            self.recv_priv = self.send_priv.clone();
            self.send_pub = self.next_pub;
            self.send_priv = self.next_priv.clone();
            let (next_pub, next_priv) = box_crypto::generate_keypair();
            self.next_pub = next_pub;
            self.next_priv = next_priv;
            self.local_key_seq += 1;
            self.fix_shared(0, 0);
        }

        let mut bs = Vec::with_capacity(SESSION_TRAFFIC_OVERHEAD + msg.len());
        bs.push(SessionType::Traffic as u8);

        // Encode varints
        encode_uvarint(&mut bs, self.local_key_seq);
        encode_uvarint(&mut bs, self.remote_key_seq);
        encode_uvarint(&mut bs, self.send_nonce);

        // Build inner payload: next_pub + msg
        let mut inner = Vec::with_capacity(32 + msg.len());
        inner.extend_from_slice(self.next_pub.as_bytes());
        inner.extend_from_slice(msg);

        // Encrypt
        let encrypted =
            box_crypto::seal_after_precomputation(&inner, self.send_nonce, &self.send_shared);
        bs.extend_from_slice(&encrypted);

        self.tx += msg.len() as u64;
        self.reset_timer();

        bs
    }

    /// Decrypt a traffic message. Returns the decrypted payload and whether an init should be sent.
    pub fn decrypt_traffic(&mut self, msg: &[u8]) -> Result<Vec<u8>, DecryptError> {
        if msg.len() < SESSION_TRAFFIC_OVERHEAD_MIN {
            return Err(DecryptError::TooShort);
        }
        if msg[0] != SessionType::Traffic as u8 {
            return Err(DecryptError::WrongType);
        }

        let mut offset = 1;

        let (remote_key_seq, len) = decode_uvarint(&msg[offset..])?;
        offset += len;

        let (local_key_seq, len) = decode_uvarint(&msg[offset..])?;
        offset += len;

        let (nonce, len) = decode_uvarint(&msg[offset..])?;
        offset += len;

        let encrypted = &msg[offset..];

        let from_current = remote_key_seq == self.remote_key_seq;
        let from_next = remote_key_seq == self.remote_key_seq + 1;
        let to_recv = local_key_seq + 1 == self.local_key_seq;
        let to_send = local_key_seq == self.local_key_seq;

        let (shared_key, should_rotate) = match (from_current, from_next, to_recv, to_send) {
            (true, _, true, _) => {
                // Normal case: from current to recv
                if self.recv_nonce >= nonce {
                    return Err(DecryptError::NonceReplay);
                }
                (&self.recv_shared, RotateAction::UpdateRecvNonce(nonce))
            }
            (_, true, _, true) => {
                // Remote ratcheted forward: from next to send
                if self.next_send_nonce >= nonce {
                    return Err(DecryptError::NonceReplay);
                }
                (
                    &self.next_send_shared,
                    RotateAction::RotateFromNextToSend(nonce),
                )
            }
            (_, true, true, _) => {
                // Remote ratcheted forward early: from next to recv
                if self.next_recv_nonce >= nonce {
                    return Err(DecryptError::NonceReplay);
                }
                (
                    &self.next_recv_shared,
                    RotateAction::RotateFromNextToRecv(nonce),
                )
            }
            _ => {
                // Can't make sense of their message
                return Err(DecryptError::KeyMismatch);
            }
        };

        let decrypted = box_crypto::open_after_precomputation(encrypted, nonce, shared_key)
            .ok_or(DecryptError::DecryptionFailed)?;

        if decrypted.len() < 32 {
            return Err(DecryptError::PayloadTooShort);
        }

        let inner_key = BoxPub::from_slice(&decrypted[..32]).ok_or(DecryptError::InvalidKey)?;
        let payload = decrypted[32..].to_vec();

        // Apply rotation action
        match should_rotate {
            RotateAction::UpdateRecvNonce(n) => {
                self.recv_nonce = n;
            }
            RotateAction::RotateFromNextToSend(n) => {
                self.next_send_nonce = n;
                if self.should_rotate() {
                    self.rotate_keys(inner_key, n);
                }
            }
            RotateAction::RotateFromNextToRecv(n) => {
                self.next_recv_nonce = n;
                if self.should_rotate() {
                    self.rotate_keys(inner_key, n);
                }
            }
        }

        self.rx += payload.len() as u64;
        self.reset_timer();

        Ok(payload)
    }

    fn should_rotate(&self) -> bool {
        match self.rotated {
            None => true,
            Some(t) => t.elapsed() > std::time::Duration::from_secs(60),
        }
    }

    fn rotate_keys(&mut self, inner_key: BoxPub, nonce: u64) {
        // Rotate their keys
        self.current = self.next;
        self.next = inner_key;
        self.remote_key_seq += 1;

        // Rotate our own keys
        self.recv_pub = self.send_pub;
        self.recv_priv = self.send_priv.clone();
        self.send_pub = self.next_pub;
        self.send_priv = self.next_priv.clone();
        self.local_key_seq += 1;

        // Generate new next keys
        let (next_pub, next_priv) = box_crypto::generate_keypair();
        self.next_pub = next_pub;
        self.next_priv = next_priv;

        // Update nonces
        self.fix_shared(nonce, 0);
        self.rotated = Some(Instant::now());
    }

    /// Create a session init for this session.
    pub fn create_init(&self) -> SessionInit {
        SessionInit::new(&self.send_pub, &self.next_pub, self.local_key_seq)
    }

    /// Create a session ack for this session.
    pub fn create_ack(&self) -> SessionAck {
        SessionAck::new(self.create_init())
    }
}

#[derive(Debug)]
enum RotateAction {
    UpdateRecvNonce(u64),
    RotateFromNextToSend(u64),
    RotateFromNextToRecv(u64),
}

/// Errors that can occur during traffic decryption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecryptError {
    /// Message too short.
    TooShort,
    /// Wrong message type.
    WrongType,
    /// Nonce replay detected.
    NonceReplay,
    /// Key sequence mismatch.
    KeyMismatch,
    /// Decryption failed.
    DecryptionFailed,
    /// Payload too short.
    PayloadTooShort,
    /// Invalid inner key.
    InvalidKey,
    /// Varint decode error.
    VarintError,
}

fn encode_uvarint(buf: &mut Vec<u8>, mut value: u64) {
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        buf.push(byte);
        if value == 0 {
            break;
        }
    }
}

fn decode_uvarint(buf: &[u8]) -> Result<(u64, usize), DecryptError> {
    let mut value: u64 = 0;
    let mut shift = 0;
    for (i, &byte) in buf.iter().enumerate() {
        if shift >= 64 {
            return Err(DecryptError::VarintError);
        }
        value |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            return Ok((value, i + 1));
        }
        shift += 7;
    }
    Err(DecryptError::VarintError)
}
