use std::{
    ffi::{OsStr, OsString},
    io::Read,
    sync::Arc,
};

use futures::StreamExt;
use glob::glob;
use inotify::{Event, EventMask, EventStream, Inotify, WatchDescriptor, WatchMask};
use prost::Message;
use quinn::{Connection, Endpoint, RecvStream, SendStream, crypto::rustls::QuicClientConfig};
use r2d2::{Pool, PooledConnection};
use r2d2_sqlite::SqliteConnectionManager;
use rustls::{
    DigitallySignedStruct, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use tokio::{
    select,
    sync::{
        Mutex,
        mpsc::{UnboundedSender, unbounded_channel},
    },
};
use xxhash_rust;

use crate::Config;

pub mod protocol {
    include!(concat!(env!("OUT_DIR"), "/hsync.rs"));
}

/// WARNING: This is insecure and should only be used for development!
/// This verifier accepts any certificate without validation.
#[derive(Debug)]
struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self(Arc::new(rustls::crypto::ring::default_provider())))
    }
}

impl ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

const ALPN_QUIC_HSYNC: &[&[u8]] = &[b"hsync"];
const BUF_SIZE: usize = 1024;
const INITIAL_QUERY: &str = "
CREATE TABLE IF NOT EXISTS files (name INTEGER, hash INTEGER)
";

pub struct Client {
    config: Config,
    stream: EventStream<[u8; BUF_SIZE]>,
    wd: WatchDescriptor,
    db_pool: Pool<SqliteConnectionManager>,
    endpoint: Endpoint,
    send_ch: Mutex<Option<UnboundedSender<protocol::Packet>>>,
}

impl Drop for Client {
    fn drop(&mut self) {
        // disconnect from server
        self.endpoint
            .close(quinn::VarInt::from_u32(0), b"client dropped");
    }
}

impl Client {
    pub fn new(config: Config) -> anyhow::Result<Client> {
        // create inotify stream
        // TODO: for subfolders we need to abstract out this part into something
        //       you can deploy for any number of folders
        let notify = Inotify::init()?;
        let wd = notify
            .watches()
            .add(config.folder.clone(), WatchMask::all())?;

        let buf = [0u8; 1024];
        let stream = notify.into_event_stream(buf)?;

        tracing::info!("created inotify for folder {}", config.folder);

        // process all files currently in folder
        let manager = SqliteConnectionManager::memory();
        let db_pool = Pool::new(manager)?;
        {
            let conn = db_pool.get()?;
            conn.execute(INITIAL_QUERY, ())?;
            Self::process_files_into_db(config.folder.clone(), &conn)?;
        }

        tracing::info!(
            "initialized metadata db and processed folder {}",
            config.folder
        );

        // connect to server
        //
        // todo: make the secure mode work
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut endpoint = quinn::Endpoint::client(config.bind)?;
        endpoint.set_default_client_config(if config.insecure {
            let mut rustls_config = rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()?
                .dangerous()
                .with_custom_certificate_verifier(SkipServerVerification::new())
                .with_no_client_auth();

            rustls_config.alpn_protocols = ALPN_QUIC_HSYNC.iter().map(|p| p.to_vec()).collect();

            quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(rustls_config)?))
        } else {
            quinn::ClientConfig::try_with_platform_verifier()?
        });

        Ok(Client {
            config,
            stream,
            wd,
            db_pool,
            endpoint,
            send_ch: Mutex::new(None),
        })
    }

    /// this function will init the
    async fn connect(&mut self) -> anyhow::Result<(Connection, SendStream, RecvStream)> {
        let conn = self
            .endpoint
            // NOTE: what is this second parameter supposed to be
            .connect(self.config.addr, "localhost")?
            .await?;

        let (send, recv) = conn.open_bi().await?;

        Ok((conn, send, recv))
    }

    /// hash any files in folder and register them in database
    /// hashes are checked on any changes and are checked with
    /// the server
    fn process_files_into_db(
        folder: String,
        db: &PooledConnection<SqliteConnectionManager>,
    ) -> anyhow::Result<()> {
        let folder = format!("{}/*", folder);

        for entry in glob(&folder)? {
            match entry {
                Ok(path) => {
                    let mut file = std::fs::File::open(path.clone()).unwrap();
                    let mut buffer = Vec::new();
                    buffer.clear();
                    let _ = file.read_to_end(&mut buffer);

                    let name = (xxhash_rust::xxh3::xxh3_64(
                        path.to_str()
                            .ok_or(anyhow::anyhow!("bad file name"))?
                            .as_bytes(),
                    )) as i64;
                    let hash = xxhash_rust::xxh3::xxh3_64(&buffer) as i64;

                    tracing::debug!(
                        "processed {} -> ({}: {})",
                        path.to_string_lossy(),
                        name,
                        hash
                    );

                    db.execute(
                        "INSERT INTO files (name, hash) VALUES (?1, ?2)",
                        (name, hash),
                    )?;
                }
                _ => continue,
            }
        }

        Ok(())
    }

    fn handle_file_event(&mut self, event: Event<OsString>) -> anyhow::Result<()> {
        tracing::debug!("event: {:?}", event);

        match event.mask {
            EventMask::CREATE => {}
            EventMask::DELETE => {}
            EventMask::DELETE_SELF => {
                // destroy client because folder is no longer watchable
                return Err(anyhow::anyhow!("folder is no longer watchable"));
            }
            _ => {}
        }

        Ok(())
    }

    fn handle_server_event(&mut self, packet: protocol::Packet) -> anyhow::Result<()> {
        Ok(())
    }

    #[tokio::main]
    pub async fn client_main(config: Config) -> anyhow::Result<()> {
        let mut client = Self::new(config)?;
        let mut buf = [0u8; BUF_SIZE];
        let (conn, mut send, mut recv) = client.connect().await?;
        let (send_ch, mut recv_ch) = unbounded_channel::<protocol::Packet>();

        {
            let mut lock = client.send_ch.lock().await;
            *lock = Some(send_ch);
        }

        loop {
            select! {
                // events from inotify
                Some(Ok(event)) = client.stream.next() => {
                    client.handle_file_event(event)?;
                },

                // outgoing messages to server
                Some(m) = recv_ch.recv() => {
                    let encoded = m.encode_to_vec();
                    send.write_all(&encoded).await?;
                },

                // events from server
                // TODO: how do we stop inotify from renotifying us
                //       maybe increment (stream.next) until we are done updating
                //       or maybe keep a map of (filename, num of ignores) and decrement until 0 and remove
                m = recv.read(&mut buf) => {
                    match m {
                        // stream has stopped, maybe closed
                        Ok(None) => break,
                        Err(e) => anyhow::bail!("server stream: {}", e),
                        _ => {}
                    }

                    let pkt = protocol::Packet::decode(&buf[..])?;

                    client.handle_server_event(pkt)?;
                }
            }
        }

        Ok(())
    }
}
