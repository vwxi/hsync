//! there is only one relay per pair of clients

use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use quinn::{Connection, RecvStream, SendStream};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};
use tokio_util::sync::CancellationToken;

use crate::server::{Server, protocol};

pub(crate) struct Relay {
    pub(crate) source_send: UnboundedSender<protocol::Packet>,
    pub(crate) recipient_send: UnboundedSender<protocol::Packet>,
}

impl Server {
    pub(crate) async fn handle_incoming_relay(
        self: Arc<Self>,
        addr: SocketAddr,
        token: CancellationToken,
        mut bidi: (SendStream, RecvStream),
        mut chan: (
            UnboundedSender<protocol::Packet>,
            UnboundedReceiver<protocol::Packet>,
        ),
    ) {
        let mut recipient_addr: Option<SocketAddr> = None;

        loop {
            tokio::select! {
                _ = token.cancelled() => {
                    break;
                }

                // outbound messages
                Some(p) = chan.1.recv() => {
                    if let Err(e) = Self::write_packet(&mut bidi.0, &p).await {
                        tracing::error!("aux packet out: {}", e.to_string());

                        token.cancel();
                    }
                }

                // inbound messages
                p = Self::read_packet(&mut bidi.1) => {
                    match p {
                        Ok(Some(pkt)) => {
                            if let Err(e) = self.relay_packet(addr, pkt, &chan.0, &mut recipient_addr).await {
                                tracing::error!("aux packet handler: {}", e.to_string());
                                chan.1.close();
                            }
                        }

                        _ => {
                            tracing::debug!("ending client event thread");

                            token.cancel();
                        }
                    }
                }
            }
        }
    }

    async fn open_relay(
        self: &Arc<Self>,
        addr: SocketAddr,
        open: protocol::RelayOpen,
        source_send: &UnboundedSender<protocol::Packet>,
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
            let mut r_chan = unbounded_channel::<protocol::Packet>();

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
            tokio::task::spawn(async move {
                while let Ok(Some(r_pkt)) = Self::read_packet(&mut r_recv).await {
                    match r_pkt.message {
                        // ignore this type of message
                        Some(protocol::packet::Message::RelayOpen(_)) => {
                            continue;
                        }

                        Some(protocol::packet::Message::RelayClose(_)) => {
                            break;
                        }

                        _ => {}
                    };

                    if let Err(e) = source_send_.send(r_pkt) {
                        tracing::error!("relay {} -> {} write: {}", relay_addr, addr, e.to_string());
                        break;
                    }
                }
            });

            // ASIDE: i had completely forgotten about servicing literally the 
            // other side of a relay and i remembered about it through
            // a bug where r_send kept being dropped prematurely b/c it
            // wasn't being used.

            // create source->recipient listener
            tokio::task::spawn(async move {
                while let Some(s_pkt) = r_chan.1.recv().await {
                    if let Err(e) = Self::write_packet(&mut r_send, &s_pkt).await {
                        tracing::error!("relay {} -> {} write: {}", addr, relay_addr, e.to_string());
                        break;
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
                        },
                    );

                    map
                });

            

            tracing::debug!("relay: created relay for {} <-> {}", addr, relay_addr);
        }

        Ok(())
    }

    async fn close_relay(self: &Arc<Self>, addr: SocketAddr) -> anyhow::Result<()> {
        let mut relays_lock = self.relays.write().await;

        Ok(())
    }

    pub(crate) async fn relay_packet(
        self: &Arc<Self>,
        addr: SocketAddr,
        pkt: protocol::Packet,
        source_send: &UnboundedSender<protocol::Packet>,
        recipient_addr: &mut Option<SocketAddr>,
    ) -> anyhow::Result<()> {
        match pkt.message {
            Some(protocol::packet::Message::RelayOpen(open)) => {
                self.open_relay(addr, open, source_send, recipient_addr,).await?;
                return Ok(());
            }

            Some(protocol::packet::Message::RelayClose(_)) => self.close_relay(addr).await?,

            _ => {}
        }

        let relays_lock = self.relays.read().await;
        recipient_addr.map(|r_addr| {
            relays_lock
                .get(&addr)
                .map(|r_map| r_map.get(&r_addr))
                .flatten()
                .map(|relay| relay.recipient_send.send(pkt))
        }).ok_or(anyhow::anyhow!("could not relay packet"))?;

        Ok(())
    }
}
