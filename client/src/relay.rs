use std::{collections::hash_map::Entry, net::SocketAddr, sync::Arc};

use futures::{executor::block_on, future::join_all};
use quinn::{RecvStream, SendStream};
use r2d2::PooledConnection;
use r2d2_sqlite::SqliteConnectionManager;
use tokio::sync::{
    mpsc::{UnboundedSender, unbounded_channel},
    oneshot,
};
use tokio_util::sync::CancellationToken;

use crate::client::{Ch, Client, HEARTBEAT_INTERVAL, protocol};

pub(crate) struct Relay {
    send: UnboundedSender<Ch>,
    token: CancellationToken,
}

impl Client {
    pub(crate) async fn relay_id_send_many(
        &self,
        id: u64,
        messages: Vec<protocol::Packet>,
    ) -> anyhow::Result<()> {
        let relays_lock = self.relays.lock().await;

        if let Some(relay) = relays_lock.get(&id) {
            messages.into_iter().for_each(|m| {
                if let Err(e) = relay.send.send(Ch::OutPacket(m)) {
                    tracing::error!("relay @ {id} send many: {}", e.to_string());
                } else {
                    tracing::debug!("relay @ {id}: sent a packet");
                }
            });
        } else {
            let signal = oneshot::channel();

            self.send_ch
                .as_ref()
                .map(|ch| ch.send(Ch::OpenStream(id, signal.0)))
                .ok_or(anyhow::anyhow!("failed to open stream"))??;

            drop(relays_lock);

            let relays = self.relays.clone();
            tokio::task::spawn(async move {
                signal.1.await?;

                tracing::debug!("relay: opened for {id}");
                
                let relays_lock = relays.lock().await;
                let relay = relays_lock
                    .get(&id)
                    .ok_or(anyhow::anyhow!("relay should exist?"))?;

                // need to send this in order for recvs to work per docs
                //
                // this tells the server we wish to contact `id`
                relay.send.send(Ch::OutPacket(protocol::Packet {
                    code: protocol::Return::NoneUnspecified as i32,
                    message: Some(protocol::packet::Message::RelayOpen(protocol::RelayOpen {
                        id,
                    })),
                }))?;

                messages
                    .into_iter()
                    .map(|m| {
                        relay.send.send(Ch::OutPacket(m))?;

                        anyhow::Ok(())
                    })
                    .collect::<anyhow::Result<Vec<()>>>()?;

                anyhow::Ok(())
            });
        }

        Ok(())
    }

    // send a single packet given an id
    // and create a relay if it doesn't exist
    pub(crate) async fn relay_id_send_once(
        &self,
        id: u64,
        pkt: protocol::Packet,
    ) -> anyhow::Result<()> {
        self.relay_id_send_many(id, vec![pkt]).await
    }

    // `relay_who` is set if we know who we are relaying with already
    pub(crate) async fn handle_relay(
        self,
        mut bidi: (SendStream, RecvStream),
        global_token: CancellationToken,
        signal: Option<oneshot::Sender<()>>,
        relay_who: Option<u64>,
    ) {
        let kill_token = CancellationToken::new();
        let mut chan = unbounded_channel::<Ch>();

        let hb_send_ch = chan.0.clone();
        let hb_global_token = global_token.clone();
        let hb_kill_token = kill_token.clone();

        // add relay entry into global relay list, if exists
        if let Some(o_id) = relay_who {
            let mut relays_lock = self.relays.lock().await;
            if relays_lock.contains_key(&o_id) {
                tracing::warn!("relay already exists for id");
            } else {
                relays_lock.insert(
                    o_id,
                    Relay {
                        send: chan.0.clone(),
                        token: kill_token.clone(),
                    },
                );

                tracing::debug!("relay: outgoing relay added to relay list");
            }
        }

        signal.map(|s| s.send(()));

        tracing::debug!("relay {:?} has stream id {}", relay_who, bidi.0.id());

        let futs = vec![
            tokio::spawn(async move {
                let mut recv_id: Option<u64> = relay_who;

                loop {
                    tokio::select! {
                        _ = global_token.cancelled() => {
                            tracing::warn!("relay: aux relay has been closed externally");
                            kill_token.cancel();

                            break;
                        }

                        _ = kill_token.cancelled() => {
                            tracing::warn!("relay: aux relay has been closed internally");
                            break;
                        }

                        outp = chan.1.recv() => {
                            match outp {
                                Some(Ch::OutPacket(pkt)) => {
                                    if let Err(e) = Self::write_packet(&mut bidi.0, &pkt).await {
                                        tracing::error!("aux packet out: {}", e.to_string());

                                        kill_token.cancel();
                                    }
                                },
                                _ => {
                                    tracing::error!("cloneable relay chan is nothing/closed");
                                    kill_token.cancel();
                                }
                            }
                        }

                        p = Self::read_packet(&mut bidi.1) => {
                            match p {
                                Ok(Some(pkt)) => {
                                    if let Err(e) = self.handle_aux_packet(pkt, &chan.0, &mut recv_id, &kill_token).await {
                                        tracing::error!("aux packet handler: {}", e.to_string());
                                        kill_token.cancel();
                                    }
                                }

                                a => {
                                    tracing::debug!("ending relay for {:?} event thread, {:?}", relay_who, a);
                                    kill_token.cancel();
                                }
                            }
                        }
                    }
                }
            }),
            // heartbeat thread
            tokio::spawn(async move {
                tracing::debug!(
                    "relay: starting heartbeat thread for relay ID {:?}",
                    relay_who
                );

                loop {
                    tokio::select! {
                        _ = tokio::time::sleep(tokio::time::Duration::from_secs(HEARTBEAT_INTERVAL)) => {
                            if let Err(e) = hb_send_ch.send(Ch::OutPacket(protocol::Packet {
                                code: protocol::Return::NoneUnspecified as i32,
                                message: None,
                            })) {
                                tracing::error!("relay ID {:?} heartbeat send error: {}", relay_who, e.to_string());
                                break;
                            }
                        }

                        _ = hb_global_token.cancelled() => {
                            tracing::warn!("relay: heartbeat relay for relay ID {:?} has been closed externally", relay_who);
                            break;
                        }

                        _ = hb_kill_token.cancelled() => {
                            tracing::warn!("relay: heartbeat relay for relay ID {:?} has been closed internally", relay_who);
                            break;
                        }
                    }
                }
            }),
        ];

        join_all(futs).await;

        tracing::debug!("relay: handled new relay");
    }

    pub(crate) async fn handle_bulk_transfer(
        &self, 
        db: PooledConnection<SqliteConnectionManager>,
        bt: protocol::BulkTransfer, 
        send: &UnboundedSender<Ch>
    ) -> anyhow::Result<()> {
        let filepath = self.join_file_and_folder(&db.query_row(
            "SELECT name FROM filenames WHERE hash = ?1", 
            [bt.namehash as i64], 
            |r| r.get::<_, String>(0)
        )?)?;

        for block in bt.blocks {
            // if blocks exists, serve it
            if let Ok(r) = self.fetch_block(&db, &filepath, bt.namehash as i64, block) {
                send.send(Ch::OutPacket(protocol::Packet {
                    code: protocol::Return::NoneUnspecified as i32,
                    message: Some(protocol::packet::Message::Transfer(protocol::Transfer { 
                        metadata: Some(block), 
                        mode: protocol::DataMode::WholeUnspecified as i32, 
                        data: Some(r) 
                    }))
                }))?;
            }
        }

        Ok(())
    }

    async fn handle_aux_packet(
        &self,
        pkt: protocol::Packet,
        send: &UnboundedSender<Ch>,
        recv_id: &mut Option<u64>,
        token: &CancellationToken,
    ) -> anyhow::Result<()> {
        // responded to our heartbeat
        if pkt.message.is_none() {
            return Ok(());
        }

        let message = pkt
            .message
            .ok_or(anyhow::anyhow!("packet requires a message payload"))?;

        let db = self.db_pool.get()?;

        // client can/will only respond to manifests and transfers
        match message {
            // on receiving this, the client will now attribute this stream to an id
            protocol::packet::Message::RelayOpen(open) => {
                let mut relays_lock = self.relays.lock().await;
                if relays_lock.contains_key(&open.id) || recv_id.is_some() {
                    tracing::warn!("relay already exists for id");
                    anyhow::bail!("relay already exists for id");
                }

                relays_lock.insert(
                    open.id,
                    Relay {
                        send: send.clone(),
                        token: token.clone(),
                    },
                );

                *recv_id = Some(open.id);

                tracing::debug!("relay: associated relay to ID {}", open.id);
            }

            protocol::packet::Message::RelayClose(_) => {
                if let Some(rid) = recv_id.as_ref() {
                    let mut relays_lock = self.relays.lock().await;
                    relays_lock.remove(rid);

                    tracing::debug!("relay: removed relay for ID {}", rid);
                }
            }

            protocol::packet::Message::BulkTransfer(bulk_transfer) => {
                self.handle_bulk_transfer(db, bulk_transfer, send).await?;
            }

            protocol::packet::Message::Transfer(transfer) => {
                self.handle_transfer(protocol::Return::NoneUnspecified, transfer, send).await?;
            }

            _ => {}
        }

        Ok(())
    }

    /// helper function that groups blocks by their origins and
    /// sends out bulk transfer requests 
    pub(crate) async fn bulk_request_blocks(&self, version: u64, namehash: u64, blocks: Vec<protocol::BlockMetadata>) -> anyhow::Result<()> {
        blocks
            .chunk_by(|a, b| a.origin == b.origin)
            .map(|blocks| {
                
                let origin = blocks
                    .first()
                    .ok_or(anyhow::anyhow!("empty chunk?"))?
                    .origin
                    .ok_or(anyhow::anyhow!("no origin?"))?;

                let num_blocks = blocks.len();

                let bulk_transfer = protocol::BulkTransfer {
                    version,
                    namehash,
                    blocks: blocks.to_vec(),
                };

                block_on(self.relay_id_send_once(
                    origin,
                    protocol::Packet {
                        code: protocol::Return::NoneUnspecified as i32,
                        message: Some(protocol::packet::Message::BulkTransfer(bulk_transfer)),
                    },
                ))?;

                tracing::debug!("bulk: sent ID {} a transfer request for {} blocks", origin, num_blocks);

                anyhow::Ok(())
            })
            .collect::<anyhow::Result<Vec<()>>>()?;
        
        Ok(())
    }
}
