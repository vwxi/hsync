//! there is only one relay per pair of clients

use std::{any::Any, collections::HashMap, net::SocketAddr, sync::Arc};

use quinn::{Connection, RecvStream, SendStream};
use tokio::sync::mpsc::{Receiver, Sender, channel};
use tokio_util::sync::CancellationToken;

use crate::server::{Server, protocol};

pub(crate) const RELAY_BUFSZ: usize = 32;

pub(crate) struct Relay {
    pub(crate) source_send: Sender<protocol::Packet>,
    pub(crate) recipient_send: Sender<protocol::Packet>,
    token: CancellationToken,
}

impl Server {
    pub(crate) async fn handle_incoming_relay(
        self: Arc<Self>,
        addr: SocketAddr,
        token: CancellationToken,
        mut bidi: (SendStream, RecvStream),
        mut chan: (
            Sender<protocol::Packet>,
            Receiver<protocol::Packet>,
        ),
    ) {
        let kill_token = CancellationToken::new();
        let mut recipient_addr: Option<SocketAddr> = None;

        loop {
            tokio::select! {
                _ = token.cancelled() => {
                    tracing::debug!("relay: relay for {} <-> {:?} closed externally", addr, recipient_addr);
                    break;
                }

                _ = kill_token.cancelled() => {
                    tracing::debug!("relay: relay for {} <-> {:?} closed internally", addr, recipient_addr);
                    break;
                }
                
                // outbound messages
                Some(p) = chan.1.recv() => {
                    if let Err(e) = Self::write_packet(&mut bidi.0, &p).await {
                        tracing::error!("aux packet out: {}", e.to_string());

                        kill_token.cancel();
                    }
                }

                // inbound messages
                p = Self::read_packet(&mut bidi.1) => {
                    match p {
                        Ok(Some(pkt)) => {
                            if let Err(e) = self.relay_packet(addr, pkt, &chan.0, &mut recipient_addr).await {
                                tracing::error!("aux packet handler: {}", e.to_string());
                                kill_token.cancel();
                            }
                        }

                        _ => {
                            tracing::debug!("ending client event thread");

                            kill_token.cancel();
                        }
                    }
                }
            }
        }
    }

    async fn open_relay(
        &self,
        addr: SocketAddr,
        open: protocol::RelayOpen,
        source_send: &Sender<protocol::Packet>,
        recipient_addr: &mut Option<SocketAddr>,
    ) -> anyhow::Result<()> {
        let db = self.db_pool.get()?;

        let relay_addr: SocketAddr = db
            .query_row(
                "SELECT addr FROM users WHERE id = ?1 LIMIT 1",
                [open.id as i64],
                |r| r.get::<_, String>(0),
            )?
            .parse()?;

        let source_id = db.query_row(
            "SELECT id FROM users WHERE addr = ?1 LIMIT 1",
            [addr.to_string()],
            |r| r.get::<_, i64>(0),
        )? as u64;

        let mut relays_lock = self.relays.write().await;

        // check if relay a->b exists
        if relays_lock
            .get(&addr)
            .map(|a| a.get(&relay_addr))
            .flatten()
            .is_none()
        {
            // create a channel for source->recipient
            let mut r_chan = channel::<protocol::Packet>(RELAY_BUFSZ);

            let kill_token = CancellationToken::new();

            // open a new stream on the recipients end
            let (mut r_send, mut r_recv) = {
                let streams_lock = self.streams.read().await;
                streams_lock
                    .get(&relay_addr)
                    .ok_or(anyhow::anyhow!("relay addr not found"))?
                    .1
                    .open_bi()
                    .await?
            };

            // notify recipient of who is opening this relay
            Self::write_packet(
                &mut r_send,
                &protocol::Packet {
                    code: protocol::Return::NoneUnspecified as i32,
                    message: Some(protocol::packet::Message::RelayOpen(protocol::RelayOpen {
                        id: source_id,
                    })),
                },
            )
            .await?;

            *recipient_addr = Some(relay_addr);
            
            // create recipient->source listener
            let source_send_ = source_send.clone();
            let kill_token_ = kill_token.clone();
            tokio::task::spawn(async move {
                loop {
                    tokio::select! {
                        _ = kill_token_.cancelled() => {
                            tracing::debug!("relay: single-way relay {} -> {} closed internally", relay_addr, addr);
                            return;
                        }

                        Ok(Some(r_pkt)) = Self::read_packet(&mut r_recv) => {
                            match r_pkt.message {
                                // ignore this type of message
                                Some(protocol::packet::Message::RelayOpen(_)) => {}

                                Some(protocol::packet::Message::RelayClose(_)) => {
                                    tracing::debug!("relay {} -> {}: relay close", relay_addr, addr);
                                    kill_token_.cancel();
                                    return;
                                }

                                _ => if let Err(e) = source_send_.send(r_pkt).await {
                                    tracing::error!("relay {} -> {} write: {}", relay_addr, addr, e.to_string());
                                    kill_token_.cancel();
                                    return;
                                }
                            };
                        }
                    }
                }
            });

            // ASIDE: i had completely forgotten about servicing literally the 
            // other side of a relay and i remembered about it through
            // a bug where r_send kept being dropped prematurely b/c it
            // wasn't being used.

            // create source->recipient listener
            let kill_token_ = kill_token.clone();
            tokio::task::spawn(async move {
                loop {
                    tokio::select! {
                        _ = kill_token_.cancelled() => {
                            tracing::debug!("relay: single-way relay {} -> {} closed internally", relay_addr, addr);
                            return;
                        }


                        Some(s_pkt) = r_chan.1.recv() => {
                            if let Err(e) = Self::write_packet(&mut r_send, &s_pkt).await {
                                tracing::error!("relay {} -> {} write: {}", addr, relay_addr, e.to_string());
                                kill_token_.cancel();
                                return;
                            }
                        }
                    }
                }
            });

            relays_lock
                .entry(addr)
                .and_modify(|map| {
                    if !map.contains_key(&relay_addr) {
                        map.insert(
                            relay_addr,
                            Relay {
                                source_send: source_send.clone(),
                                recipient_send: r_chan.0.clone(),
                                token: kill_token.clone(),
                            },
                        );
                    }
                })
                .or_insert_with(|| {
                    let mut map: HashMap<SocketAddr, Relay> = HashMap::new();

                    map.insert(
                        relay_addr,
                        Relay {
                            source_send: source_send.clone(),
                            recipient_send: r_chan.0.clone(),
                            token: kill_token,
                        },
                    );

                    map
                });

            

            tracing::debug!("relay: created relay for {} <-> {}", addr, relay_addr);
        }

        Ok(())
    }

    /// close all relays for a single user
    pub(crate) async fn close_all_relays_one(&self, addr: SocketAddr) -> anyhow::Result<()> {
        let mut relays_lock = self.relays.write().await;

        // kill our relays from other users first then delete ourselves
        for other in relays_lock
            .get(&addr)
            .ok_or(anyhow::anyhow!("relays don't exist"))?
            .keys()
            .cloned()
            .collect::<Vec<SocketAddr>>() {
            relays_lock.get_mut(&other).iter_mut().for_each(|a| { 
                a.retain(|oa, r| {
                    if *oa == addr {
                        r.token.cancel();
                    }

                    *oa != addr
                }); 
            });
        }

        relays_lock.remove(&addr).ok_or(anyhow::anyhow!("what?"))?;
        
        tracing::debug!("relay: closed all relays related to {}", addr);
        
        Ok(())
    }

    pub(crate) async fn relay_packet(
        &self,
        s_addr: SocketAddr,
        pkt: protocol::Packet,
        source_send: &Sender<protocol::Packet>,
        recipient_addr: &mut Option<SocketAddr>,
    ) -> anyhow::Result<()> {
        match pkt.message {
            Some(protocol::packet::Message::RelayOpen(open)) => {
                self.open_relay(s_addr, open, source_send, recipient_addr,).await?;
                return Ok(());
            }

            Some(protocol::packet::Message::RelayClose(_)) => {                
                self.close_all_relays_one(s_addr).await?;
            },
            
            _ => {}
        }

        let relays_lock = self.relays.read().await;

        if let Some(r_addr) = recipient_addr {
            // does a relay map exist for the source?
            if let Some(s_map) = relays_lock.get(&s_addr) {
                // does a relay to the recipient exist?
                if let Some(r_relay) = s_map.get(&r_addr) {
                    r_relay.recipient_send.send(pkt).await?;
                } else {
                    tracing::error!("relay: relay for {s_addr} -> {r_addr} does not exist");
                }
            } else {
                tracing::error!("relay: relay map for {s_addr} does not exist");
            }
        } else {
            tracing::error!("relay: attempting to send a message over a relay without a recipient");
        }

        Ok(())
    }
}
