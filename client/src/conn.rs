//! inter-user connection manager
//! 
//! responsible for attempting a direct connection first
//! before falling back on a relay from the server

use std::{collections::HashMap, sync::{Arc, Weak}};

use tokio::sync::{Mutex, mpsc::UnboundedSender, oneshot};

use crate::{client::{Ch, Client, protocol}, direct::AddrPair};

#[async_trait::async_trait]
pub(crate) trait Connection {
    /// talk to the client to acquire any necessary resources (stream, info, etc.)
    async fn init(&self, recv_id: u64, send_ch: UnboundedSender<Ch>) -> anyhow::Result<()>;

    /// send packet over
    async fn send(&self, pkt: protocol::Packet) -> anyhow::Result<()>;
} 

/// the connection manager will always try a direct connection
/// to a client before falling back onto the server. 
/// 
/// a connection is either direct or relayed, never both.
#[derive(Clone)]
pub(crate) struct ConnManager {
    /// messages queued for relays/directs
    pub(crate) message_queue: Arc<Mutex<HashMap<u64, Vec<protocol::Packet>>>>,
    pub(crate) conns: Arc<Mutex<HashMap<u64, Arc<dyn Connection>>>>,
    pub(crate) send_ch: Option<UnboundedSender<Ch>>,
}

impl ConnManager {
    pub(crate) fn new() -> Self {
        ConnManager { 
            message_queue: Arc::new(Mutex::new(HashMap::new())), 
            conns: Arc::new(Mutex::new(HashMap::new())), 
            send_ch: None,
        }
    }

    /// this returns true when a connection is still processing
    async fn queue_messages(&self, origin: u64, pkts: Vec<protocol::Packet>) -> bool {
        let mut mqueue_lock = self.message_queue.lock().await;

        if let Some(entry) = mqueue_lock.get_mut(&origin) {
            tracing::debug!("conmgr: queueing {} message(s) for {}", pkts.len(), origin);
            
            pkts.into_iter().for_each(|m| entry.push(m));
            
            return true;
        } else {
            mqueue_lock.insert(origin, pkts);
        }

        false
    }

    /// this doesnt only connect but also drains the message queue when it's done
    /// 
    /// if a direct connection does not work
    async fn connect(&self, origin: u64) -> anyhow::Result<()> {
        

        Ok(())
    }

    pub(crate) async fn send_many(&self, origin: u64, pkts: Vec<protocol::Packet>) -> anyhow::Result<()> {
        let conns_lock = self.conns.lock().await;

        if let Some(conn) = conns_lock.get(&origin) {
            for pkt in pkts {
                conn.send(pkt).await?;
            }
        } else {
            if self.queue_messages(origin, pkts).await {
                return Ok(());
            }

            drop(conns_lock);

            self.connect(origin).await?;
        }

        todo!();
    }

    pub(crate) async fn send_once(&self, origin: u64, pkt: protocol::Packet) -> anyhow::Result<()> {
        self.send_many(origin, vec![pkt]).await
    }
}