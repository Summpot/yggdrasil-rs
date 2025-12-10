//! Peer connection handler.
//!
//! Manages the lifecycle of a single peer connection, including:
//! - Reading and writing framed packets
//! - Dispatching packets to appropriate handlers
//! - Sending keep-alive packets
//! - Handling router protocol exchanges

use std::sync::{Arc, atomic::Ordering};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, BufReader, BufWriter};
use tokio::sync::mpsc;
use tokio::time::{Instant, interval};
use tracing::{debug, trace, warn};
use yggdrasil_types::{PeerPort, PrivateKey, PublicKey};
use yggdrasil_wire::{
    FramedPacket, PathBroken, PathLookup, PathNotify, RouterAnnounce, RouterSigReq, RouterSigRes,
    Traffic, WireDecode, WireEncode, WirePacketType, flush_writer, read_frame,
    write_frame_with_payload,
};

use crate::LinkError;
use crate::links::LinkMetrics;

/// Peer connection state.
pub struct PeerHandler<S> {
    /// The underlying TLS stream.
    stream: S,
    /// Our private key.
    private_key: PrivateKey,
    /// Our public key.
    public_key: PublicKey,
    /// Remote peer's public key.
    remote_key: PublicKey,
    /// Assigned peer port for this connection.
    peer_port: PeerPort,
    /// Channel to send outgoing packets.
    outgoing_rx: mpsc::Receiver<OutgoingPacket>,
    /// Channel to receive events.
    event_tx: mpsc::UnboundedSender<PeerEvent>,
    /// Keep-alive interval.
    keep_alive_interval: Duration,
    /// Optional metrics collector for this connection.
    metrics: Option<Arc<LinkMetrics>>,
}

/// Outgoing packet to send to a peer.
#[derive(Debug)]
pub struct OutgoingPacket {
    /// The packet type.
    pub packet_type: WirePacketType,
    /// The encoded payload.
    pub payload: Vec<u8>,
}

/// Event from a peer connection.
#[derive(Debug)]
pub enum PeerEvent {
    /// Received a signature request.
    SigRequest { from: PublicKey, req: RouterSigReq },
    /// Received a signature response.
    SigResponse {
        from: PublicKey,
        res: RouterSigRes,
        rtt: Duration,
    },
    /// Received a router announcement.
    Announce {
        from: PublicKey,
        announce: RouterAnnounce,
    },
    /// Received a bloom filter update.
    BloomFilter { from: PublicKey, data: Vec<u8> },
    /// Received a path lookup request.
    PathLookup { from: PublicKey, lookup: PathLookup },
    /// Received a path notification.
    PathNotify { from: PublicKey, notify: PathNotify },
    /// Received a path broken notification.
    PathBroken { from: PublicKey, broken: PathBroken },
    /// Received traffic.
    Traffic { from: PublicKey, traffic: Traffic },
    /// Peer disconnected.
    Disconnected {
        key: PublicKey,
        peer_port: PeerPort,
        error: Option<String>,
    },
}

/// Create peer handler channels.
pub fn create_peer_channels() -> (
    mpsc::Sender<OutgoingPacket>,
    mpsc::Receiver<OutgoingPacket>,
    mpsc::UnboundedSender<PeerEvent>,
    mpsc::UnboundedReceiver<PeerEvent>,
) {
    const OUTGOING_CHANNEL_CAPACITY: usize = 512;
    let (outgoing_tx, outgoing_rx) = mpsc::channel(OUTGOING_CHANNEL_CAPACITY);
    let (event_tx, event_rx) = mpsc::unbounded_channel();
    (outgoing_tx, outgoing_rx, event_tx, event_rx)
}

impl<S> PeerHandler<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    /// Create a new peer handler.
    pub fn new(
        stream: S,
        private_key: PrivateKey,
        remote_key: PublicKey,
        peer_port: PeerPort,
        outgoing_rx: mpsc::Receiver<OutgoingPacket>,
        event_tx: mpsc::UnboundedSender<PeerEvent>,
    ) -> Self {
        let public_key = private_key.public_key();
        Self {
            stream,
            private_key,
            public_key,
            remote_key,
            peer_port,
            outgoing_rx,
            event_tx,
            keep_alive_interval: Duration::from_secs(2),
            metrics: None,
        }
    }

    /// Attach a metrics collector for byte counters and liveness tracking.
    pub fn with_metrics(mut self, metrics: Arc<LinkMetrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Run the peer handler loop.
    pub async fn run(self) -> Result<(), LinkError> {
        let (reader, writer) = tokio::io::split(self.stream);
        let mut reader = BufReader::new(reader);
        let mut writer = BufWriter::new(writer);

        let remote_key = self.remote_key.clone();
        let event_tx = self.event_tx.clone();
        let mut outgoing_rx = self.outgoing_rx;
        let private_key = self.private_key;
        let public_key = self.public_key;
        let peer_port = self.peer_port;

        // Timestamp for RTT calculation
        let mut last_sig_req_time: Option<Instant> = None;

        // Keep-alive timer
        let mut keep_alive = interval(self.keep_alive_interval);
        keep_alive.reset(); // Reset to avoid immediate tick

        loop {
            tokio::select! {
                // Read incoming packets
                result = read_frame(&mut reader) => {
                    match result {
                        Ok(packet) => {
                            debug!(
                                remote = %hex::encode(&remote_key.as_bytes()[..8]),
                                packet_type = ?packet.packet_type,
                                payload_len = packet.payload.len(),
                                "Received packet from peer"
                            );

                            if let Some(metrics) = &self.metrics {
                                metrics.rx.fetch_add(packet.payload.len() as u64, Ordering::Relaxed);
                            }

                            if let Err(e) = handle_packet(
                                &packet,
                                &remote_key,
                                &private_key,
                                &public_key,
                                peer_port,
                                &event_tx,
                                &mut writer,
                                &mut last_sig_req_time,
                            ).await {
                                debug!(
                                    remote = %hex::encode(&remote_key.as_bytes()[..8]),
                                    error = %e,
                                    "Failed to handle packet"
                                );
                            }
                        }
                        Err(e) => {
                            debug!(
                                remote = %hex::encode(&remote_key.as_bytes()[..8]),
                                error = ?e,
                                "Failed to read frame, connection closing"
                            );
                            let _ = event_tx.send(PeerEvent::Disconnected {
                                key: remote_key,
                                peer_port,
                                error: Some(format!("{:?}", e)),
                            });
                            break;
                        }
                    }
                }

                // Send outgoing packets
                Some(packet) = outgoing_rx.recv() => {
                    debug!(
                        remote = %hex::encode(&remote_key.as_bytes()[..8]),
                        packet_type = ?packet.packet_type,
                        payload_len = packet.payload.len(),
                        "Received outgoing packet from channel, writing to peer"
                    );

                    if let Some(metrics) = &self.metrics {
                        metrics.tx.fetch_add(packet.payload.len() as u64, Ordering::Relaxed);
                    }

                    if packet.packet_type == WirePacketType::ProtoSigReq {
                        last_sig_req_time = Some(Instant::now());
                    }

                    if let Err(e) = write_frame_with_payload(&mut writer, packet.packet_type, &packet.payload).await {
                        debug!(
                            remote = %hex::encode(&remote_key.as_bytes()[..8]),
                            error = ?e,
                            packet_type = ?packet.packet_type,
                            "Failed to write frame"
                        );
                        let _ = event_tx.send(PeerEvent::Disconnected {
                            key: remote_key,
                            peer_port,
                            error: Some(format!("{:?}", e)),
                        });
                        break;
                    }
                    
                    if let Err(e) = flush_writer(&mut writer).await {
                        debug!(
                            remote = %hex::encode(&remote_key.as_bytes()[..8]),
                            error = ?e,
                            packet_type = ?packet.packet_type,
                            "Failed to flush writer - disconnecting peer"
                        );
                        let _ = event_tx.send(PeerEvent::Disconnected {
                            key: remote_key,
                                peer_port,
                            error: Some(format!("flush error: {:?}", e)),
                        });
                        break;
                    }
                    
                    debug!(
                        remote = %hex::encode(&remote_key.as_bytes()[..8]),
                        packet_type = ?packet.packet_type,
                        "Packet written and flushed successfully"
                    );
                }

                // Send keep-alive periodically
                _ = keep_alive.tick() => {
                    trace!("Sending keep-alive");
                    if let Err(e) = write_frame_with_payload(&mut writer, WirePacketType::KeepAlive, &[]).await {
                        debug!(error = ?e, "Failed to send keep-alive");
                        break;
                    }
                    if let Err(e) = flush_writer(&mut writer).await {
                        debug!(error = ?e, "Failed to flush writer");
                    }
                }
            }
        }

        Ok(())
    }
}

/// Handle a received packet.
async fn handle_packet<W: AsyncWrite + Unpin>(
    packet: &FramedPacket,
    remote_key: &PublicKey,
    private_key: &PrivateKey,
    public_key: &PublicKey,
    peer_port: PeerPort,
    event_tx: &mpsc::UnboundedSender<PeerEvent>,
    writer: &mut W,
    last_sig_req_time: &mut Option<Instant>,
) -> Result<(), LinkError> {
    match packet.packet_type {
        WirePacketType::Dummy => {
            // Ignore dummy packets
        }

        WirePacketType::KeepAlive => {
            trace!("Received keep-alive");
        }

        WirePacketType::ProtoSigReq => {
            // Decode the signature request
            let mut data = packet.payload.as_slice();
            let req = RouterSigReq::wire_decode(&mut data).map_err(|e| {
                LinkError::Protocol(format!("Failed to decode sig request: {:?}", e))
            })?;

            trace!(
                seq = req.seq,
                nonce = req.nonce,
                "Received signature request"
            );

            // Create a signature response
            let mut res = RouterSigRes {
                req: req.clone(),
                port: peer_port,
                psig: yggdrasil_types::Signature::default(),
            };

            // Sign the response
            let msg = res.bytes_for_sig(remote_key, public_key);
            res.psig = private_key.sign(&msg);

            // Encode and send the response
            let mut payload = Vec::new();
            res.wire_encode(&mut payload).map_err(|e| {
                LinkError::Protocol(format!("Failed to encode sig response: {:?}", e))
            })?;

            trace!(port = peer_port, "Sending signature response");
            write_frame_with_payload(writer, WirePacketType::ProtoSigRes, &payload)
                .await
                .map_err(|e| {
                    LinkError::Protocol(format!("Failed to send sig response: {:?}", e))
                })?;
            flush_writer(writer)
                .await
                .map_err(|e| LinkError::Protocol(format!("Failed to flush: {:?}", e)))?;

            // Send event
            let _ = event_tx.send(PeerEvent::SigRequest {
                from: *remote_key,
                req,
            });
        }

        WirePacketType::ProtoSigRes => {
            // Decode the signature response
            let mut data = packet.payload.as_slice();
            let res = RouterSigRes::wire_decode(&mut data).map_err(|e| {
                LinkError::Protocol(format!("Failed to decode sig response: {:?}", e))
            })?;

            trace!(
                seq = res.req.seq,
                port = res.port,
                "Received signature response"
            );

            // Calculate RTT
            let rtt = last_sig_req_time
                .take()
                .map(|t| t.elapsed())
                .unwrap_or(Duration::ZERO);

            // Send event
            let _ = event_tx.send(PeerEvent::SigResponse {
                from: *remote_key,
                res,
                rtt,
            });
        }

        WirePacketType::ProtoAnnounce => {
            // Decode the router announcement
            let mut data = packet.payload.as_slice();
            let announce = RouterAnnounce::wire_decode(&mut data)
                .map_err(|e| LinkError::Protocol(format!("Failed to decode announce: {:?}", e)))?;

            trace!(
                key = %hex::encode(&announce.key.as_bytes()[..8]),
                parent = %hex::encode(&announce.parent.as_bytes()[..8]),
                "Received router announcement"
            );

            // Verify the announcement
            if !announce.check() {
                warn!("Invalid router announcement, ignoring");
                return Ok(());
            }

            // Send event
            let _ = event_tx.send(PeerEvent::Announce {
                from: *remote_key,
                announce,
            });
        }

        WirePacketType::ProtoBloomFilter => {
            // Bloom filter updates - forward to router
            trace!(
                "Received bloom filter update, payload_len={}",
                packet.payload.len()
            );

            // Forward the raw data to the router for processing
            let _ = event_tx.send(PeerEvent::BloomFilter {
                from: *remote_key,
                data: packet.payload.clone(),
            });
        }

        WirePacketType::ProtoPathLookup => {
            // Decode the path lookup
            let mut data = packet.payload.as_slice();
            let lookup = PathLookup::wire_decode(&mut data).map_err(|e| {
                LinkError::Protocol(format!("Failed to decode path lookup: {:?}", e))
            })?;

            trace!(
                source = %hex::encode(&lookup.source.as_bytes()[..8]),
                dest = %hex::encode(&lookup.dest.as_bytes()[..8]),
                from_len = lookup.from.len(),
                "Received path lookup"
            );

            // Forward to router for processing
            let _ = event_tx.send(PeerEvent::PathLookup {
                from: *remote_key,
                lookup,
            });
        }

        WirePacketType::ProtoPathNotify => {
            // Decode the path notification
            let mut data = packet.payload.as_slice();
            let notify = PathNotify::wire_decode(&mut data).map_err(|e| {
                LinkError::Protocol(format!("Failed to decode path notify: {:?}", e))
            })?;

            trace!(
                source = %hex::encode(&notify.source.as_bytes()[..8]),
                dest = %hex::encode(&notify.dest.as_bytes()[..8]),
                path_len = notify.path.len(),
                "Received path notify"
            );

            // Verify the notification
            if !notify.check() {
                warn!("Invalid path notify signature, ignoring");
                return Ok(());
            }

            // Forward to router for processing
            let _ = event_tx.send(PeerEvent::PathNotify {
                from: *remote_key,
                notify,
            });
        }

        WirePacketType::ProtoPathBroken => {
            // Decode the path broken notification
            let mut data = packet.payload.as_slice();
            let broken = PathBroken::wire_decode(&mut data).map_err(|e| {
                LinkError::Protocol(format!("Failed to decode path broken: {:?}", e))
            })?;

            trace!(
                source = %hex::encode(&broken.source.as_bytes()[..8]),
                dest = %hex::encode(&broken.dest.as_bytes()[..8]),
                path_len = broken.path.len(),
                "Received path broken"
            );

            // Forward to router for processing
            let _ = event_tx.send(PeerEvent::PathBroken {
                from: *remote_key,
                broken,
            });
        }

        WirePacketType::Traffic => {
            // Decode traffic packet
            let mut data = packet.payload.as_slice();
            let traffic = Traffic::wire_decode(&mut data)
                .map_err(|e| LinkError::Protocol(format!("Failed to decode traffic: {:?}", e)))?;

            debug!(
                remote = %hex::encode(remote_key.as_bytes()[..8].as_ref()),
                source = %hex::encode(&traffic.source.as_bytes()[..8]),
                dest = %hex::encode(&traffic.dest.as_bytes()[..8]),
                payload_len = traffic.payload.len(),
                "Received traffic packet from peer"
            );

            // Send event
            let _ = event_tx.send(PeerEvent::Traffic {
                from: *remote_key,
                traffic,
            });
        }
    }

    Ok(())
}
