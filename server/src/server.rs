use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use crate::Config;
use anyhow::Context;
use prost::Message;
use quinn::{Endpoint, RecvStream, SendStream, crypto::rustls::QuicServerConfig};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, pem::PemObject};
use tokio::{
    io::AsyncReadExt,
    select,
    sync::{
        Mutex,
        mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel},
    },
};

pub mod protocol {
    include!(concat!(env!("OUT_DIR"), "/hsync.rs"));
}

const INITIAL_QUERY: &str = "

";

pub type UserId = u64;

pub struct Server {
    max_conns: Option<usize>,
    endpoint: Endpoint,
    db_pool: Pool<SqliteConnectionManager>,
    streams: Mutex<HashMap<SocketAddr, UnboundedSender<protocol::Packet>>>,
}

pub struct Client {}

impl Server {
    pub fn new(config: Config) -> anyhow::Result<Server> {
        // INIT QUIC ENDPOINT
        let key = if config.key.extension().is_some_and(|x| x == "der") {
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                std::fs::read(config.key).context("failed to read private key file")?,
            ))
        } else {
            PrivateKeyDer::from_pem_file(config.key)
                .context("failed to read PEM from private key file")?
        };

        let cert_chain = if config.cert.extension().is_some_and(|x| x == "der") {
            vec![CertificateDer::from(
                std::fs::read(config.cert).context("failed to read certificate chain file")?,
            )]
        } else {
            CertificateDer::pem_file_iter(config.cert)
                .context("failed to read PEM from certificate chain file")?
                .collect::<Result<_, _>>()
                .context("invalid PEM-encoded certificate")?
        };

        let server_crypto = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)?;
        let mut server_config =
            quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_crypto)?));
        let transport_config = Arc::get_mut(&mut server_config.transport).unwrap();
        transport_config.max_concurrent_uni_streams(0_u8.into());

        let endpoint = quinn::Endpoint::server(server_config, config.bind)?;

        // INIT SQLITE
        let manager = SqliteConnectionManager::memory();
        let pool = Pool::new(manager)?;
        {
            let conn = pool.get()?;
            conn.execute(INITIAL_QUERY, ())?;
        }

        Ok(Server {
            max_conns: config.max_conns,
            endpoint,
            db_pool: pool,
            streams: Mutex::new(HashMap::new()),
        })
    }

    pub async fn run(self: &Arc<Self>) -> anyhow::Result<()> {
        while let Some(conn) = self.endpoint.accept().await {
            if !self
                .max_conns
                .map_or_else(|| true, |max| self.endpoint.open_connections() <= max)
            {
                // too many connections
                conn.refuse();
            } else if !conn.remote_address_validated() {
                let _ = conn.retry();
            } else {
                // accept connection
                let s = self.clone();
                tokio::spawn(async move {
                    if let Err(e) = s.handle_conn(conn).await {
                        tracing::error!("conn error: {}", e.to_string());
                    }
                });
            }
        }

        Ok(())
    }

    async fn handle_conn(self: Arc<Self>, conn: quinn::Incoming) -> anyhow::Result<()> {
        let conn = conn.await?;
        let mut buf = String::new();

        let mut stream = match conn.accept_bi().await {
            Ok(s) => s,
            Err(_) => anyhow::bail!("bidi stream could not be accepted"),
        };

        let (send, mut recv) = unbounded_channel::<protocol::Packet>();

        {
            let mut lock = self.streams.lock().await;
            lock.insert(conn.remote_address(), send);
        }

        select! {
            // to send over the wire
            m = recv.recv() => {
                if let Some(m) = m {
                    let encoded = m.encode_to_vec();
                    stream.0.write_all(&encoded).await?;
                }
            }

            // what we receive
            sz = stream.1.read_to_string(&mut buf) => {

            }
        }

        Ok(())
    }
}
