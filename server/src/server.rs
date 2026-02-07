use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use crate::Config;
use anyhow::Context;
use prost::Message;
use quinn::{Endpoint, RecvStream, SendStream, crypto::rustls::QuicServerConfig};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rcgen::{CertifiedKey, generate_simple_self_signed};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, pem::PemObject};
use tokio::{
    io::AsyncReadExt,
    select,
    sync::{
        Mutex,
        mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel},
    },
};
use tracing::{Instrument, Span, instrument};

pub mod protocol {
    include!(concat!(env!("OUT_DIR"), "/hsync.rs"));
}

const ALPN_QUIC_HSYNC: &[&[u8]] = &[b"hsync"];
const USERS_INSERT_STMT: &str =
    "CREATE TABLE IF NOT EXISTS users (id INTEGER, current_folder INTEGER)";
const FOLDERS_INSERT_STMT: &str = "CREATE TABLE IF NOT EXISTS folders (password TEXT)";
const ENTRIES_INSERT_STMT: &str =
    "CREATE TABLE IF NOT EXISTS entries (folder INTEGER, name INTEGER, hash INTEGER)";

pub type UserId = u64;

pub struct Server {
    max_conns: Option<usize>,
    endpoint: Endpoint,
    db_pool: Pool<SqliteConnectionManager>,
    streams: Mutex<HashMap<SocketAddr, UnboundedSender<protocol::Packet>>>,
}

impl Server {
    pub fn new(config: Config) -> anyhow::Result<Server> {
        // INIT QUIC ENDPOINT

        // if no path is provided, generate a selfsigned key-cert pair to use
        let (key, cert_chain) = if let (Some(keypath), Some(certpath)) = (config.key, config.cert) {
            tracing::info!(
                "using keyfile {} and certfile {}",
                keypath.to_string_lossy(),
                certpath.to_string_lossy(),
            );

            (
                if keypath.extension().is_some_and(|x| x == "der") {
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                        std::fs::read(keypath).context("failed to read private key file")?,
                    ))
                } else {
                    PrivateKeyDer::from_pem_file(keypath)
                        .context("failed to read PEM from private key file")?
                },
                if certpath.extension().is_some_and(|x| x == "der") {
                    vec![CertificateDer::from(
                        std::fs::read(certpath).context("failed to read certificate chain file")?,
                    )]
                } else {
                    CertificateDer::pem_file_iter(certpath)
                        .context("failed to read PEM from certificate chain file")?
                        .collect::<Result<_, _>>()
                        .context("invalid PEM-encoded certificate")?
                },
            )
        } else {
            tracing::info!("generating self-signed key-cert pair");

            let subject_alt_names = vec!["localhost".to_string()];
            let CertifiedKey { cert, signing_key } =
                generate_simple_self_signed(subject_alt_names)?;

            (
                PrivateKeyDer::Pkcs8(
                    PrivatePkcs8KeyDer::from_pem(
                        rustls::pki_types::pem::SectionKind::PrivateKey,
                        signing_key.serialize_der(),
                    )
                    .ok_or(anyhow::anyhow!("could not load PEM private key"))?,
                ),
                vec![CertificateDer::from(cert)],
            )
        };

        let mut server_crypto = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)?;

        server_crypto.alpn_protocols = ALPN_QUIC_HSYNC.iter().map(|&x| x.into()).collect();

        let mut server_config =
            quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_crypto)?));
        let transport_config = Arc::get_mut(&mut server_config.transport).unwrap();
        transport_config.max_concurrent_uni_streams(0_u8.into());

        let endpoint = quinn::Endpoint::server(server_config, config.bind)?;

        tracing::info!("initialized QUIC endpoint at {}", config.bind);

        // INIT SQLITE
        let manager = SqliteConnectionManager::memory();
        let pool = Pool::new(manager)?;
        {
            let conn = pool.get()?;
            conn.execute(USERS_INSERT_STMT, ())?;
            conn.execute(FOLDERS_INSERT_STMT, ())?;
            conn.execute(ENTRIES_INSERT_STMT, ())?;
        }

        tracing::info!("initialized db");

        Ok(Server {
            max_conns: config.max_conns,
            endpoint,
            db_pool: pool,
            streams: Mutex::new(HashMap::new()),
        })
    }

    pub async fn run(self: &Arc<Self>, span: Span) -> anyhow::Result<()> {
        async move {
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
                        tracing::debug!("new connection from {}", conn.remote_address());
                        if let Err(e) = s.handle_conn(conn).await {
                            tracing::error!("conn error: {}", e.to_string());
                        }
                    });
                }
            }

            Ok(())
        }
        .instrument(span)
        .await
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
            // outgoing messages to client
            Some(m) = recv.recv() => {
                let encoded = m.encode_to_vec();
                stream.0.write_all(&encoded).await?;
            }

            // incoming from client
            _ = stream.1.read_to_string(&mut buf) => {
                let msg = protocol::Packet::decode(buf.as_bytes())?;

                if let Err(e) = self.handle_packet(msg).await {
                    tracing::error!("packet handler: {:?}", e);
                }
            }
        }

        Ok(())
    }

    async fn handle_packet(self: &Arc<Self>, pkt: protocol::Packet) -> anyhow::Result<()> {
        let message = pkt
            .message
            .ok_or(anyhow::anyhow!("why is this happening?"))?;

        match message {
            protocol::packet::Message::Auth(auth) => {}

            protocol::packet::Message::Die(die) => {}

            protocol::packet::Message::Compare(compare) => {}
        }

        Ok(())
    }
}
