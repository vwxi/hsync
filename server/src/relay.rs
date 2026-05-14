use std::{net::SocketAddr, sync::Arc};

use quinn::{RecvStream, SendStream};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio_util::sync::CancellationToken;

use crate::server::{Server, protocol};

impl Server {
    pub(crate) async fn handle_aux_stream(
        self: Arc<Self>,
        addr: SocketAddr,
        token: CancellationToken,
        mut bidi: (SendStream, RecvStream),
        mut recv_chan: UnboundedReceiver<protocol::Packet>,
    ) {
        loop {
            tokio::select! {
                _ = token.cancelled() => {
                    break;
                }

                // outbound messages
                Some(p) = recv_chan.recv() => {
                    if let Err(e) = Self::write_packet(&mut bidi.0, &p).await {
                        tracing::error!("aux packet out: {}", e.to_string());

                        token.cancel();
                    }
                }

                // inbound messages
                p = Self::read_packet(&mut bidi.1) => {
                    match p {
                        Ok(Some(pkt)) => {
                            if let Err(e) = self.handle_aux_packet(addr, pkt).await {
                                tracing::error!("aux packet handler: {}", e.to_string());
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

    pub(crate) async fn handle_aux_packet(
        self: &Arc<Self>,
        addr: SocketAddr,
        pkt: protocol::Packet,
    ) -> anyhow::Result<()> {
        let message = pkt
            .message
            .ok_or(anyhow::anyhow!("packet requires a message payload"))?;

        match message {
            protocol::packet::Message::RelayOpen(relay_open) => {}

            protocol::packet::Message::RelayClose(_) => {}

            _ => {}
        }

        Ok(())
    }
}
