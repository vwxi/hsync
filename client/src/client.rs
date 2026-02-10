use std::{
    ffi::{OsStr, OsString},
    fs::metadata,
    io::Read,
    os::unix::ffi::OsStrExt,
    path::PathBuf,
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
    io::{AsyncReadExt, AsyncWriteExt},
    select,
    sync::{
        Mutex, MutexGuard,
        mpsc::{UnboundedSender, unbounded_channel},
    },
};
use tracing::instrument;
use xxhash_rust;

use crate::Config;

pub mod protocol {
    include!(concat!(env!("OUT_DIR"), "/hsync.rs"));
}

const ALPN_QUIC_HSYNC: &[&[u8]] = &[b"hsync"];
const BUF_SIZE: usize = 16384;
const BLOCK_SIZE: usize = 2048;
const INIT_FILE_TABLE_QUERY: &str =
    "CREATE TABLE IF NOT EXISTS filenames (name TEXT, hash INTEGER)";
const INIT_BLOCK_TABLE_QUERY: &str = "CREATE TABLE IF NOT EXISTS blocks (file INTEGER, offset INTEGER, hash INTEGER, timestamp INTEGER, UNIQUE(file, offset))";

/// to be used with --insecure flag
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
        // process all files currently in folder
        let current_folder = PathBuf::from(".");

        let folder = config.folder.as_ref().unwrap_or(&current_folder);
        let manager = if let Some(ref db) = config.db {
            SqliteConnectionManager::file(db)
        } else {
            SqliteConnectionManager::memory()
        };

        let db_pool = Pool::new(manager)?;
        let mut diff_buffer = [0u8; BLOCK_SIZE];
        {
            let conn = db_pool.get()?;
            conn.execute(INIT_FILE_TABLE_QUERY, ())?;
            conn.execute(INIT_BLOCK_TABLE_QUERY, ())?;
            Self::process_files_into_db(&folder, &mut diff_buffer, &conn)?;
        }

        tracing::info!(
            "initialized block database and processed folder {}",
            folder.to_string_lossy()
        );

        // create inotify stream
        // TODO: for subfolders we need to abstract out this part into something
        //       you can deploy for any number of folders
        let notify = Inotify::init()?;
        let wd = notify
            .watches()
            .add(folder, WatchMask::all() & !WatchMask::ONESHOT)?;

        let buf = [0u8; BUF_SIZE];
        let stream = notify.into_event_stream(buf)?;

        tracing::info!("created inotify for folder {}", folder.to_string_lossy());

        // connect to server
        //
        // todo: make the secure mode work
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut endpoint = quinn::Endpoint::client(config.bind)?;
        endpoint.set_default_client_config(if config.insecure {
            tracing::warn!("running in insecure mode.");

            let mut rustls_config = rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()?
                .dangerous()
                .with_custom_certificate_verifier(SkipServerVerification::new())
                .with_no_client_auth();

            rustls_config.alpn_protocols = ALPN_QUIC_HSYNC.iter().map(|p| p.to_vec()).collect();

            quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(rustls_config)?))
        } else {
            tracing::warn!("running in secure mode.");

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

    /// this function will init the connection
    async fn connect(&mut self) -> anyhow::Result<(Connection, SendStream, RecvStream)> {
        let conn = self
            .endpoint
            // NOTE: what is this second parameter supposed to be
            .connect(self.config.addr, "localhost")?
            .await?;

        let (mut send, recv) = conn.open_bi().await?;

        {
            let pkt = protocol::Packet {
                message: Some(protocol::packet::Message::Auth(protocol::Auth {
                    id: rand::random(),
                    room: self.config.code.clone(),
                    passcode: self.config.password.clone(),
                })),
            };

            Self::write_packet(&mut send, &pkt).await?;
        }

        Ok((conn, send, recv))
    }

    /// processes files into entry database
    fn process_files_into_db(
        folder: &PathBuf,
        buf: &mut [u8],
        db: &PooledConnection<SqliteConnectionManager>,
    ) -> anyhow::Result<()> {
        let folder_glob = format!(
            "{}/*",
            folder.to_str().ok_or(anyhow::anyhow!("malformed folder"))?
        );

        for entry in glob(&folder_glob)? {
            match entry {
                Ok(path) => {
                    Self::check_diff(
                        &path,
                        buf,
                        std::time::SystemTime::now()
                            .duration_since(std::time::SystemTime::UNIX_EPOCH)?
                            .as_secs() as i64,
                        db,
                    )?;

                    tracing::debug!("parsed blocks for file {}", path.to_string_lossy());
                }
                _ => continue,
            }
        }

        Ok(())
    }

    async fn write_packet(stream: &mut SendStream, pkt: &protocol::Packet) -> anyhow::Result<()> {
        let encoded = pkt.encode_to_vec();
        let len = encoded.len() as u32;
        stream.write_u32(len).await?;
        stream.write_all(&encoded).await?;
        stream.flush().await?;
        Ok(())
    }

    async fn read_packet(stream: &mut RecvStream) -> anyhow::Result<Option<protocol::Packet>> {
        let len = match stream.read_u32().await {
            Ok(len) => len,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e.into()),
        };

        let mut buf = vec![0u8; len as usize];
        stream.read_exact(&mut buf).await?;
        let pkt = protocol::Packet::decode(&buf[..])?;
        Ok(Some(pkt))
    }

    // check differences in a single file and report back a diff object
    fn check_diff(
        path: &PathBuf,
        buf: &mut [u8],
        new_timestamp: i64,
        db: &PooledConnection<SqliteConnectionManager>,
    ) -> anyhow::Result<()> {
        let mut file = std::fs::File::open(&path)?;
        let pathname = path.to_str().ok_or(anyhow::anyhow!("malformed filename"))?;
        let hashed_filename = xxhash_rust::xxh3::xxh3_64(pathname.as_bytes()) as i64;
        let mut offset = 0isize;

        db.execute(
            "INSERT INTO filenames (name, hash) VALUES (?1, ?2)",
            (pathname, hashed_filename),
        )?;

        // NOTE: files are addressed in the block store by hash(filename).
        //       if we have files with different filenames but identical content,
        //       there will be redundant storage. in the future, consider loading
        //       whole file, hashing contents then hashing blocks.
        loop {
            let sz = file.read(buf)?;

            tracing::debug!("[file {}] read {} bytes", pathname, sz);

            let current_hash = xxhash_rust::xxh3::xxh3_64(buf) as i64;

            let mut stmt = db.prepare(
                "
                    INSERT INTO blocks (file, offset, hash, timestamp)
                    VALUES (?1, ?2, ?3, ?4)
                    ON CONFLICT(file, offset) DO UPDATE SET
                        hash = excluded.hash,
                        timestamp = excluded.timestamp
                    WHERE excluded.timestamp > blocks.timestamp
                      AND excluded.hash != blocks.hash
                    RETURNING hash, timestamp
                    ",
            )?;

            let _ = stmt.query_one(
                [hashed_filename, offset as i64, current_hash, new_timestamp],
                |row| {
                    tracing::debug!(
                        "[file {}] updated block {} (now {}, {})",
                        pathname,
                        offset,
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                    );

                    Ok(())
                },
            );

            offset += sz as isize;

            if sz < BLOCK_SIZE || sz == 0 {
                break;
            }
        }

        Ok(())
    }

    fn handle_file_event(
        &mut self,
        buf: &mut [u8],
        db: &PooledConnection<SqliteConnectionManager>,
        event: Event<OsString>,
    ) -> anyhow::Result<()> {
        match event.mask {
            EventMask::CREATE => {}
            EventMask::DELETE => {}
            EventMask::MODIFY => {
                let filename = if let Some(folder) = self.config.folder.clone() {
                    folder
                } else {
                    // in the event that we are not hosting the folder,
                    // the cwd will serve as the folder in which synced files are put
                    PathBuf::from(".")
                }
                .join(
                    event
                        .name
                        .as_ref()
                        .ok_or(anyhow::anyhow!("event has no filename"))?
                        .to_str()
                        .ok_or(anyhow::anyhow!("malformed filename"))?,
                );

                let new_timestamp = metadata(&filename)?
                    .accessed()?
                    .duration_since(std::time::SystemTime::UNIX_EPOCH)?
                    .as_secs() as i64;

                Self::check_diff(&filename, buf, new_timestamp, db)?;
            }
            EventMask::DELETE_SELF | EventMask::IGNORED => {
                // destroy client because folder is no longer watchable
                return Err(anyhow::anyhow!("folder is no longer watchable"));
            }
            _ => {}
        }

        Ok(())
    }

    async fn send_manifest(&mut self) -> anyhow::Result<()> {
        let db = self.db_pool.get()?;
        let mut send_ch = self.send_ch.lock().await;

        let mut query_files = db.prepare("SELECT DISTINCT file FROM blocks")?;
        let _ = query_files.query_map((), |row| {
            let file_hash = row.get::<_, i64>(0)?;

            let mut manifest = protocol::FileManifest::default();

            let mut name_stmt = db.prepare("SELECT name FROM filenames WHERE hash = ?1")?;
            name_stmt.query_one([&file_hash], |r| {
                manifest.filename = r.get::<_, String>(0)?;

                Ok(())
            })?;

            let mut query_blocks =
                db.prepare("SELECT offset, hash, timestamp FROM blocks WHERE file = ?1")?;

            let _ = query_blocks.query_map((), |block| {
                let (offset, hash, timestamp) = (
                    block.get::<_, i64>(0)? as u64,
                    block.get::<_, i64>(1)? as u64,
                    block.get::<_, i64>(2)? as u64,
                );

                manifest.blocks.push(protocol::BlockMetadata {
                    offset,
                    hash,
                    timestamp,
                });

                Ok(())
            })?;

            let _ = send_ch.as_mut().map(|ch| {
                if let Err(e) = ch.send(protocol::Packet {
                    message: Some(protocol::packet::Message::Manifest(manifest)),
                }) {
                    anyhow::bail!("failed to send message: {}", e.to_string());
                }

                Ok(())
            });

            Ok(())
        })?;

        Ok(())
    }

    fn handle_server_event(&mut self, packet: protocol::Packet) -> anyhow::Result<()> {
        tracing::debug!("recved pkt: {:?}", packet);

        let message = packet
            .message
            .ok_or(anyhow::anyhow!("empty packet from server"))?;

        match message {
            protocol::packet::Message::RoomInfo(room_info) => {
                tracing::info!("folder has been added to server.");
                tracing::info!(
                    "to sync as a client, connect using this code: {}",
                    room_info.code
                );

                // get started on syncing
            }
            _ => {}
        }

        Ok(())
    }

    #[tokio::main]
    pub async fn client_main(config: Config) -> anyhow::Result<()> {
        let mut client = Self::new(config)?;
        let (_conn, mut send, mut recv) = client.connect().await?;
        let (send_ch, mut recv_ch) = unbounded_channel::<protocol::Packet>();
        let db = client.db_pool.get()?;
        let mut diff_buffer = [0u8; BLOCK_SIZE];

        {
            let mut lock = client.send_ch.lock().await;
            *lock = Some(send_ch);
        }

        loop {
            select! {
                // outgoing messages to server
                Some(m) = recv_ch.recv() => {
                    tracing::debug!("to send: {:?}", m);
                    Self::write_packet(&mut send, &m).await?;
                },

                // events from inotify
                Some(Ok(event)) = client.stream.next() => {
                    client.handle_file_event(&mut diff_buffer, &db, event)?;
                },

                // incoming messages from server
                // TODO: how do we stop inotify from renotifying us
                //       maybe increment (stream.next) until we are done updating
                //       or maybe keep a map of (filename, num of ignores) and decrement until 0 and remove
                pkt = Self::read_packet(&mut recv) => {
                    match pkt? {
                        Some(pkt) => client.handle_server_event(pkt)?,
                        None => break,
                    }
                }
            }
        }

        Ok(())
    }
}
