use std::{
    collections::{HashMap, HashSet},
    ffi::{OsStr, OsString},
    fs::metadata,
    io::{Read, Seek, SeekFrom, Write},
    os::unix::{ffi::OsStrExt, fs::FileExt},
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
use rusqlite::fallible_iterator::FallibleIterator;
use rustls::{
    DigitallySignedStruct, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    select,
    sync::{Mutex, MutexGuard, mpsc},
};
use tracing::instrument;
use xxhash_rust;

use crate::Config;

pub mod protocol {
    include!(concat!(env!("OUT_DIR"), "/hsync.rs"));
}

const HEARTBEAT_INTERVAL: u64 = 5;
const REFRESH_INTERVAL: u64 = 5;
const REFRESH_ATTEMPTS: u64 = 3;
const ALPN_QUIC_HSYNC: &[&[u8]] = &[b"hsync"];
const BUF_SIZE: usize = 16384;
const CREATE_FILENAMES_STMT: &str = "CREATE TABLE IF NOT EXISTS filenames (name TEXT PRIMARY KEY, hash INTEGER, timestamp INTEGER, UNIQUE(name, hash))";
const CREATE_BLOCKS_STMT: &str = "CREATE TABLE IF NOT EXISTS blocks (file INTEGER, start INTEGER, end INTEGER, hash INTEGER, UNIQUE(file, start, end, hash))";
const CREATE_JOURNAL_STMT: &str = "CREATE TABLE IF NOT EXISTS journal (file INTEGER, start INTEGER, end INTEGER, hash INTEGER, cookie INTEGER, contents BLOB, UNIQUE(file, start, end, hash, cookie))";

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

#[derive(Debug, Clone)]
enum Ch {
    InPacket(protocol::Packet),
    OutPacket(protocol::Packet),
    Event(Event<OsString>),
    Refresh,
}

#[derive(Debug, PartialEq, Eq, Hash, Copy, Clone)]
struct TransferMetadata {
    pub op_type: protocol::delta::OpType,
    pub start: u64,
    pub end: u64,
    pub hash: u64,
    pub attempts: u64,
    pub timestamp: u64,
    pub cookie: Option<u64>,
}

pub struct Client {
    config: Config,
    wd: WatchDescriptor,
    db_pool: Arc<Pool<SqliteConnectionManager>>,
    endpoint: Endpoint,
    send_ch: Option<mpsc::UnboundedSender<Ch>>,
    current_accesses: Mutex<HashSet<i64>>,
    outgoing_transfer_requests: Mutex<HashMap<i64, HashSet<TransferMetadata>>>,
    outgoing_manifest_requests: Mutex<HashSet<i64>>,
    queued_manifests: Mutex<HashMap<i64, protocol::FileManifest>>,
}

impl Drop for Client {
    fn drop(&mut self) {
        // disconnect from server
        tracing::info!("disconnecting from server");

        self.send_ch.as_ref().map(|ch| {
            ch.send(Ch::OutPacket(protocol::Packet {
                code: protocol::Return::NoneUnspecified as i32,
                message: Some(protocol::packet::Message::Die(protocol::Die {
                    reason: Some(String::from("disconnecting")),
                })),
            }))
        });

        self.endpoint
            .close(quinn::VarInt::from_u32(0), b"client dropped");
    }
}

impl Client {
    pub fn new(config: Config) -> anyhow::Result<(Client, EventStream<[u8; BUF_SIZE]>)> {
        // process all files currently in folder
        let current_folder = PathBuf::from(".");

        let folder = config.folder.as_ref().unwrap_or(&current_folder);
        let manager = if let Some(ref db) = config.db {
            SqliteConnectionManager::file(db)
        } else {
            SqliteConnectionManager::file("file:blockstore?mode=memory&cache=shared")
        };

        let db_pool = Pool::new(manager)?;
        {
            let conn = db_pool.get()?;
            conn.execute(CREATE_FILENAMES_STMT, ())?;
            conn.execute(CREATE_BLOCKS_STMT, ())?;
            conn.execute(CREATE_JOURNAL_STMT, ())?;

            Self::process_files_into_db(&folder, &conn)?;
        }

        tracing::info!(
            "initialized block database and processed folder {}",
            folder.to_string_lossy()
        );

        // create inotify stream
        // TODO: for subfolders we need to abstract out this part into something
        //       you can deploy for any number of folders
        let notify = Inotify::init()?;
        let wd = notify.watches().add(
            folder,
            WatchMask::all()
                & !(WatchMask::ONESHOT
                    | WatchMask::ACCESS
                    | WatchMask::OPEN
                    | WatchMask::ATTRIB
                    | WatchMask::CLOSE_NOWRITE),
        )?;

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

        Ok((
            Client {
                config,
                wd,
                db_pool: Arc::new(db_pool),
                endpoint,
                send_ch: None,
                current_accesses: Mutex::new(HashSet::new()),
                outgoing_transfer_requests: Mutex::new(HashMap::new()),
                outgoing_manifest_requests: Mutex::new(HashSet::new()),
                queued_manifests: Mutex::new(HashMap::new()),
            },
            stream,
        ))
    }

    /// this function will init the connection
    async fn connect(&mut self) -> anyhow::Result<(Connection, SendStream, RecvStream)> {
        let conn = self
            .endpoint
            // NOTE: what is this second parameter supposed to be
            .connect(self.config.addr, "localhost")?
            .await?;

        let (send, recv) = conn.open_bi().await?;

        Ok((conn, send, recv))
    }

    fn timestamp() -> anyhow::Result<u64> {
        Ok(std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)?
            .as_secs())
    }

    /// processes files into entry database
    fn process_files_into_db(
        folder: &PathBuf,
        db: &PooledConnection<SqliteConnectionManager>,
    ) -> anyhow::Result<()> {
        let folder_glob = format!(
            "{}/*",
            folder.to_str().ok_or(anyhow::anyhow!("malformed folder"))?
        );

        let current_timestamp = Self::timestamp()? as i64;

        for entry in glob(&folder_glob)? {
            match entry {
                Ok(path) => {
                    Self::process_change_get_blocks(&path, current_timestamp, None, db)?;

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

    async fn maybe_request_file_manifest(&self, path: &PathBuf) -> anyhow::Result<bool> {
        let filename = path
            .file_name()
            .ok_or(anyhow::anyhow!("cannot request a directory object"))?
            .to_str()
            .ok_or(anyhow::anyhow!("cannot re-encode file path"))?;

        Ok(if !path.exists() {
            tracing::debug!("sending whatis for file {}", filename);

            let hash = xxhash_rust::xxh3::xxh3_64(filename.as_bytes()) as i64;

            if !self.outgoing_manifest_requests.lock().await.insert(hash) {
                tracing::debug!("we already asked for this manifest");
                return Ok(false);
            }

            self.send_ch
                .as_ref()
                .map(|ch| {
                    ch.send(Ch::OutPacket(protocol::Packet {
                        code: protocol::Return::NoneUnspecified as i32,
                        message: Some(protocol::packet::Message::Whatis(protocol::WhatIs {
                            filename: String::from(filename),
                        })),
                    }))
                })
                .ok_or(anyhow::anyhow!("could not request file {}", filename))??;

            false
        } else {
            true
        })
    }

    // we store the block to be transferred later
    fn journal_block(
        db: &PooledConnection<SqliteConnectionManager>,
        namehash: i64,
        start: i64,
        end: i64,
        cookie: Option<i64>,
        data: &[u8],
        hash: i64,
    ) -> anyhow::Result<()> {
        if let Some(cookie) = cookie {
            db.execute(
                "INSERT OR IGNORE INTO journal (file, start, end, hash, cookie, contents) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                (
                    namehash,
                    start,
                    end,
                    hash,
                    cookie,
                    rusqlite::blob::ZeroBlob((end - start) as i32)
                ),
            )?;

            let rowid = db.last_insert_rowid();
            let mut blob = db.blob_open(rusqlite::MAIN_DB, "journal", "contents", rowid, false)?;

            if blob.write(&data)? != data.len() {
                anyhow::bail!("did not write full block to database");
            }

            blob.close()?;

            tracing::debug!(
                "journal: stored block {}:[{}, {}] (ck: {:?})",
                namehash as u64,
                start,
                end,
                cookie
            );
        } else {
            db.execute(
                "INSERT OR IGNORE INTO blocks (file, start, end, hash) VALUES (?1, ?2, ?3, ?4)",
                [namehash, start, end, hash],
            )?;
        }

        Ok(())
    }

    fn fetch_block(
        &mut self,
        db: &PooledConnection<SqliteConnectionManager>,
        filepath: &PathBuf,
        namehash: i64,
        mut metadata: protocol::BlockMetadata,
    ) -> anyhow::Result<Vec<u8>> {
        // if cookie is present, get from journal
        // otherwise, get it from the main table
        if let Some(cookie) = metadata.cookie {
            let res: (i64, i64) = match db.query_one(
                "SELECT ROWID, hash FROM journal WHERE file = ?1 AND start = ?2 AND end = ?3 AND cookie = ?4 LIMIT 1",
                [namehash, metadata.start as i64, metadata.end as i64, cookie as i64],
                |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)),
            ) {
                Ok(r) => r,
                Err(e) => {
                    self.send_ch
                        .as_ref()
                        .map(|ch| ch.send(Ch::OutPacket(protocol::Packet {
                            code: protocol::Return::BlockNotFound as i32,
                            message: Some(protocol::packet::Message::Transfer(
                                protocol::Transfer {
                                    metadata: Some(metadata),
                                    mode: protocol::DataMode::WholeUnspecified as i32,
                                    data: None,
                                },
                            )),
                        })))
                        .ok_or(anyhow::anyhow!("could not send block error"))??;

                    anyhow::bail!("could not find block {}:{}:[{}, {}], {}",
                        metadata.namehash(), metadata.hash, metadata.start, metadata.end, e.to_string());
                }
            };

            let size_to_read = (metadata.end - metadata.start) as usize;
            let mut data: Vec<u8> = vec![0u8; size_to_read];
            let mut contents =
                db.blob_open(rusqlite::MAIN_DB, "journal", "contents", res.0, true)?;
            contents.read_exact(&mut data)?;

            metadata.hash = res.1 as u64;

            // write journaled block to file
            {
                let mut file = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(filepath)?;

                Self::modify_block(&mut file, metadata.start, &data)?;
            }

            // insert into main block
            db.execute(
                "INSERT OR IGNORE INTO blocks (file, start, end, hash) VALUES (?1, ?2, ?3, ?4)",
                [
                    namehash as i64,
                    metadata.start as i64,
                    metadata.end as i64,
                    res.1,
                ],
            )?;

            // delete from journal
            db.execute(
                "DELETE FROM journal WHERE file = ?1 AND start = ?2 AND end = ?3 AND hash = ?4",
                [
                    namehash as i64,
                    metadata.start as i64,
                    metadata.end as i64,
                    res.1,
                ],
            )?;

            tracing::debug!(
                "journal: fetched block {}:[{}, {}] (ck: {:?})",
                namehash,
                metadata.start,
                metadata.end,
                metadata.cookie
            );

            Ok(data)
        } else {
            let mut file = std::fs::OpenOptions::new()
                .read(true)
                .write(false)
                .open(filepath)?;

            let mut block = vec![0u8; (metadata.end - metadata.start) as usize];
            file.seek(SeekFrom::Start(metadata.start))?;
            file.read_exact(&mut block)?;

            Ok(block)
        }
    }

    // modify db and report back the new block list
    fn process_change_get_blocks(
        path: &PathBuf,
        current_timestamp: i64,
        cookie: Option<i64>,
        db: &PooledConnection<SqliteConnectionManager>,
    ) -> anyhow::Result<Vec<(u64, u64, u64)>> {
        let filename = path
            .file_name()
            .and_then(|f| f.to_str())
            .ok_or(anyhow::anyhow!("malformed filename"))?;
        let namehash = xxhash_rust::xxh3::xxh3_64(filename.as_bytes()) as i64;

        tracing::debug!("begin checking blocks for {}", filename);

        db.execute(
            "INSERT INTO filenames (name, hash, timestamp) VALUES (?1, ?2, ?3)
             ON CONFLICT(name) DO UPDATE SET timestamp=excluded.timestamp",
            (filename, namehash, current_timestamp),
        )?;

        if let Ok(file) = std::fs::File::open(&path) {
            // TODO: adapt this for subfolders when it gets implemented
            let mut blocks: Vec<(u64, u64, u64)> = vec![];

            // NOTE: files are addressed in the block store by hash(filename).
            //       if we have files with different filenames but identical content,
            //       there will be redundant storage. in the future, consider loading
            //       whole file, hashing contents then hashing blocks.
            let chunker = fastcdc::v2020::StreamCDC::new(file, 4096, 16384, 65535);

            for chunk in chunker {
                let block = chunk?;

                let block_hash = xxhash_rust::xxh3::xxh3_64(block.data.as_slice());

                let ex: Result<i64, _> = db.query_one(
                    "SELECT hash FROM blocks WHERE file = ?1 AND start = ?2 AND end = ?3 LIMIT 1",
                    (
                        namehash,
                        block.offset as i64,
                        (block.offset as usize + block.length) as i64,
                    ),
                    |r| r.get(0),
                );

                if let Ok(existing_hash) = ex {
                    if existing_hash != block_hash as i64 {
                        tracing::debug!(
                            "block exists and conflicts, {}:[{}, {}]",
                            existing_hash,
                            block.offset,
                            block.offset + block.length as u64
                        );

                        // no cookie means this is the initial run at the start of the program
                        // cookie means we are journaling to send over to the server later
                        Self::journal_block(
                            &db,
                            namehash,
                            block.offset as i64,
                            (block.offset + block.length as u64) as i64,
                            cookie,
                            &block.data,
                            block_hash as i64,
                        )?;
                    } else {
                        tracing::debug!(
                            "block exists and does not conflict, {}:[{}, {}]",
                            existing_hash,
                            block.offset,
                            block.offset + block.length as u64
                        );
                    }
                } else {
                    tracing::debug!(
                        "block is new, {}:[{}, {}]",
                        block_hash,
                        block.offset,
                        block.offset + block.length as u64
                    );

                    Self::journal_block(
                        &db,
                        namehash,
                        block.offset as i64,
                        (block.offset + block.length as u64) as i64,
                        cookie,
                        &block.data,
                        block_hash as i64,
                    )?;
                }

                blocks.push((block.offset, block.offset + block.length as u64, block_hash));
            }

            Ok(blocks)
        } else {
            let mut stmt = db.prepare("SELECT start, end, hash FROM blocks WHERE file = ?1")?;

            Ok(stmt
                .query([namehash])?
                .map(|r| {
                    Ok((
                        r.get::<_, i64>(0)? as u64,
                        r.get::<_, i64>(1)? as u64,
                        r.get::<_, i64>(2)? as u64,
                    ))
                })
                .collect()?)
        }
    }

    async fn handle_file_event(&mut self, event: Event<OsString>) -> anyhow::Result<()> {
        let db = self.db_pool.get()?;

        let event_file = event
            .name
            .as_ref()
            .ok_or(anyhow::anyhow!("event has no filename"))?
            .to_str()
            .ok_or(anyhow::anyhow!("malformed filename"))?;

        let filename = if let Some(folder) = self.config.folder.clone() {
            folder
        } else {
            // in the event that we are not hosting the folder,
            // the cwd will serve as the folder in which synced files are put
            PathBuf::from(".")
        }
        .join(event_file);

        // TODO: one of the biggest issues is that this wont support
        //       files in subfolders. we will fix this eventually.

        match event.mask {
            EventMask::CREATE => {
                self.send_ch
                    .as_ref()
                    .map(|ch| {
                        ch.send(Ch::OutPacket(protocol::Packet {
                            code: protocol::Return::NoneUnspecified as i32,
                            message: Some(protocol::packet::Message::Event(protocol::Event {
                                event: protocol::FileEvent::CreateUnspecified as i32,
                                filename: String::from(event_file),
                            })),
                        }))
                    })
                    .ok_or(anyhow::anyhow!("failed to relay create event"))??;
            }
            EventMask::DELETE | EventMask::MOVED_TO => {
                self.send_ch
                    .as_ref()
                    .map(|ch| {
                        ch.send(Ch::OutPacket(protocol::Packet {
                            code: protocol::Return::NoneUnspecified as i32,
                            message: Some(protocol::packet::Message::Event(protocol::Event {
                                event: protocol::FileEvent::Delete as i32,
                                filename: String::from(event_file),
                            })),
                        }))
                    })
                    .ok_or(anyhow::anyhow!("failed to relay delete event"))??;
            }
            EventMask::MODIFY => {
                // if we are currently accessing this, skip
                let namehash = xxhash_rust::xxh3::xxh3_64(event_file.as_bytes()) as i64;
                let current_timestamp = Self::timestamp()? as i64;

                {
                    let mut accesses_lock = self.current_accesses.lock().await;
                    let mut transfers_lock = self.outgoing_transfer_requests.lock().await;

                    if accesses_lock.contains(&namehash) {
                        tracing::debug!("accessing {} already, skip", event_file);
                        accesses_lock.remove(&namehash);

                        return Ok(());
                    }

                    if let Ok(last_timestamp) = db.query_one(
                        "SELECT timestamp FROM filenames WHERE hash = ?1",
                        [namehash],
                        |r| r.get::<_, i64>(0),
                    ) {
                        // don't check blocks if we did this the instant before
                        if current_timestamp - last_timestamp <= 2 {
                            return Ok(());
                        }
                    }

                    if let Some(transfers) = transfers_lock.get(&namehash) {
                        if transfers.is_empty() {
                            transfers_lock.remove(&namehash);
                        } else {
                            let pathname = filename
                                .file_name()
                                .and_then(|f| f.to_str())
                                .ok_or(anyhow::anyhow!("malformed filename"))?;

                            tracing::debug!(
                                "{} waits on {} transfers already, skip",
                                event_file,
                                transfers_lock
                                    .get(&namehash)
                                    .ok_or(anyhow::anyhow!("wtf"))?
                                    .len()
                            );

                            db.execute(
                                "INSERT INTO filenames (name, hash, timestamp) VALUES (?1, ?2, ?3)
                                 ON CONFLICT(name) DO UPDATE SET timestamp=excluded.timestamp",
                                (pathname, namehash, current_timestamp),
                            )?;

                            return Ok(());
                        }
                    }
                }

                tracing::info!("WRITE TO {}", event_file);

                // if this fails, then we are trying to fetch some sort of swap file
                let metadata = metadata(&filename)?;

                let new_timestamp = Self::timestamp()? as i64;

                let cookie = rand::random::<i64>();

                let mut manifest = protocol::FileManifest {
                    filename: String::from(event_file),
                    timestamp: new_timestamp as u64,
                    size: metadata.len(),
                    cookie: Some(cookie as u64),
                    blocks: vec![],
                };

                for change in Self::process_change_get_blocks(
                    &filename,
                    current_timestamp,
                    Some(cookie),
                    &db,
                )? {
                    manifest.blocks.push(protocol::BlockMetadata {
                        start: change.0,
                        end: change.1,
                        hash: change.2,
                        namehash: None,
                        cookie: Some(cookie as u64),
                    });
                }

                {
                    let mut accesses_lock = self.current_accesses.lock().await;
                    accesses_lock.remove(&namehash);
                }

                self.send_ch.as_ref().map(|ch| {
                    ch.send(Ch::OutPacket(protocol::Packet {
                        code: protocol::Return::NoneUnspecified as i32,
                        message: Some(protocol::packet::Message::Manifest(manifest)),
                    }))
                });

                tracing::debug!("sending manifest for file {}", event_file);
            }
            EventMask::DELETE_SELF | EventMask::IGNORED => {
                // destroy client because folder is no longer watchable
                anyhow::bail!("folder is no longer watchable");
            }
            _ => {}
        }

        Ok(())
    }

    async fn handle_roominfo(&mut self, room_info: protocol::RoomInfo) -> anyhow::Result<()> {
        tracing::info!("connect to this room using this code: {}", room_info.code);

        let db = self.db_pool.get()?;
        {
            for file in room_info.files {
                let mut stmt = db.prepare("SELECT * FROM filenames WHERE name = ?1")?;

                // if file does not exist, request manifest
                if stmt.query_one([file.name.clone()], |_| Ok(())).is_err() {
                    tracing::debug!("file {} does not exist, requesting manifest", file.name);

                    self.send_ch
                        .as_ref()
                        .map(|ch| {
                            ch.send(Ch::OutPacket(protocol::Packet {
                                code: protocol::Return::NoneUnspecified as i32,
                                message: Some(protocol::packet::Message::Whatis(
                                    protocol::WhatIs {
                                        filename: file.name.clone(),
                                    },
                                )),
                            }))
                        })
                        .ok_or(anyhow::anyhow!("could not request file {}", file.name))??;
                }
            }
        }

        // get starting on syncing
        self.send_manifest().await?;

        Ok(())
    }

    async fn send_manifest(&mut self) -> anyhow::Result<()> {
        let conn = self.db_pool.get()?;

        let mut query_files = conn.prepare("SELECT name, hash FROM filenames")?;
        let mut files = query_files.query(())?;

        while let Ok(Some(row)) = files.next() {
            let filename = row.get::<_, String>(0)?;
            let filehash = row.get::<_, i64>(1)?;

            let mut manifest = protocol::FileManifest::default();

            manifest.filename = filename;

            let mut query_blocks =
                conn.prepare("SELECT start, end, hash FROM blocks WHERE file = ?1")?;
            let mut blocks = query_blocks.query([&filehash])?;

            while let Ok(Some(block)) = blocks.next() {
                let (start, end, hash) = (
                    block.get::<_, i64>(0)? as u64,
                    block.get::<_, i64>(1)? as u64,
                    block.get::<_, i64>(2)? as u64,
                );

                // manifest block
                manifest.blocks.push(protocol::BlockMetadata {
                    start,
                    end,
                    namehash: None,
                    cookie: None,
                    hash,
                });
            }

            tracing::debug!("sending manifest for file {}", manifest.filename);

            let _ = self.send_ch.as_mut().map(|ch| {
                if let Err(e) = ch.send(Ch::OutPacket(protocol::Packet {
                    code: protocol::Return::NoneUnspecified as i32,
                    message: Some(protocol::packet::Message::Manifest(manifest)),
                })) {
                    anyhow::bail!("failed to send message: {}", e.to_string());
                }

                Ok(())
            });
        }

        Ok(())
    }

    async fn handle_transfer(
        &mut self,
        code: protocol::Return,
        transfer: protocol::Transfer,
    ) -> anyhow::Result<()> {
        let db = self.db_pool.get()?;

        let metadata = transfer
            .metadata
            .ok_or(anyhow::anyhow!("transfer request with no metadata"))?;

        let namehash = metadata
            .namehash
            .ok_or(anyhow::anyhow!("malformed transfer request"))? as i64;

        match code {
            protocol::Return::BlockMismatch | protocol::Return::BlockNotFound => {
                let mut outgoing_lock = self.outgoing_transfer_requests.lock().await;
                if let Some(reqs) = outgoing_lock.get_mut(&namehash) {
                    reqs.retain(|r| !(r.start == metadata.start && r.end == metadata.end));
                    return Ok(());
                }
            }

            _ => {}
        };

        let filename: String = {
            let mut stmt = db.prepare("SELECT name FROM filenames WHERE hash = ?1")?;
            stmt.query_row([namehash], |row| row.get(0))?
        };

        let folder = self
            .config
            .folder
            .clone()
            .unwrap_or_else(|| PathBuf::from("."));
        let filepath = folder.join(&filename);

        // maybe we do not have the file yet, we should not satisfy a transfer for
        // a file we do not have.
        if !self.maybe_request_file_manifest(&filepath).await? {
            tracing::debug!("file {} does not exist yet, asking for manifest", filename);

            // send done signal anyways
            self.send_ch
                .as_ref()
                .map(|ch| {
                    ch.send(Ch::OutPacket(protocol::Packet {
                        code: protocol::Return::NoneUnspecified as i32,
                        message: Some(protocol::packet::Message::Done(protocol::TransferDone {
                            namehash: namehash as u64,
                        })),
                    }))
                })
                .ok_or(anyhow::anyhow!("failed to send done signal after transfer"))??;

            return Ok(());
        }

        // we are receiving data from the server
        if let Some(data) = transfer.data {
            {
                let hash = xxhash_rust::xxh3::xxh3_64(&data);
                if hash != metadata.hash {
                    tracing::debug!("hash mismatch on transfer. skipping");

                    // send done signal anyways
                    self.send_ch
                        .as_ref()
                        .map(|ch| {
                            ch.send(Ch::OutPacket(protocol::Packet {
                                code: protocol::Return::NoneUnspecified as i32,
                                message: Some(protocol::packet::Message::Done(
                                    protocol::TransferDone {
                                        namehash: namehash as u64,
                                    },
                                )),
                            }))
                        })
                        .ok_or(anyhow::anyhow!("failed to send done signal after transfer"))??;

                    return Ok(());
                }
            }

            let mut outgoing_lock = self.outgoing_transfer_requests.lock().await;

            if let Some(transfer) = outgoing_lock.get_mut(&namehash) {
                if let Some(t) = transfer
                    .iter()
                    .find(|e| e.start == metadata.start && e.end == metadata.end)
                {
                    let op_type = t.op_type;

                    transfer.retain(|e| !(e.start == metadata.start && e.end == metadata.end));

                    let datahash = xxhash_rust::xxh3::xxh3_64(data.as_slice()) as i64;

                    if let Err(e) = db.execute(
                        "INSERT OR IGNORE INTO blocks (hash, start, end, file) VALUES (?1, ?2, ?3, ?4)",
                        [
                            datahash,
                            metadata.start as i64,
                            metadata.end as i64,
                            namehash,
                        ],
                    ) {
                        anyhow::bail!(
                            "failed to update block metadata in database: {}",
                            e.to_string()
                        );
                    }

                    // add access to set
                    {
                        let mut accesses_lock = self.current_accesses.lock().await;
                        accesses_lock.insert(namehash);
                    }

                    let mut file = std::fs::OpenOptions::new()
                        .read(true)
                        .write(true)
                        .open(&filepath)?;

                    let block_hash = xxhash_rust::xxh3::xxh3_64(data.as_slice());

                    match op_type {
                        protocol::delta::OpType::Insert => {
                            if let Err(e) =
                                Self::insert_block(&mut file, metadata.start, data.as_slice())
                            {
                                anyhow::bail!(
                                    "failed to insert block [{}, {}] to file {}: {}",
                                    metadata.start,
                                    metadata.end,
                                    filepath.to_string_lossy(),
                                    e.to_string()
                                );
                            }
                        }

                        protocol::delta::OpType::Modify
                        | protocol::delta::OpType::EqualUnspecified => {
                            if let Err(e) =
                                Self::modify_block(&mut file, metadata.start, data.as_slice())
                            {
                                anyhow::bail!(
                                    "failed to modify block [{}, {}] in file {}: {}",
                                    metadata.start,
                                    metadata.end,
                                    filepath.to_string_lossy(),
                                    e.to_string()
                                );
                            }
                        }

                        _ => {}
                    }

                    tracing::debug!(
                        "applied block [{}, {}] to file {}, {}",
                        metadata.start,
                        metadata.end,
                        filepath.to_string_lossy(),
                        block_hash,
                    );

                    if transfer.is_empty() {
                        tracing::debug!("done with {}", namehash as u64);

                        outgoing_lock.remove(&namehash);

                        {
                            let mut accesses_lock = self.current_accesses.lock().await;
                            accesses_lock.remove(&namehash);
                        }

                        self.send_ch
                            .as_ref()
                            .map(|ch| {
                                ch.send(Ch::OutPacket(protocol::Packet {
                                    code: protocol::Return::NoneUnspecified as i32,
                                    message: Some(protocol::packet::Message::Done(
                                        protocol::TransferDone {
                                            namehash: namehash as u64,
                                        },
                                    )),
                                }))
                            })
                            .ok_or(anyhow::anyhow!("failed to send done signal"))??;
                    }
                }
            }
        } else {
            // otherwise, we are fulfilling a data request
            let data = self.fetch_block(&db, &filepath, namehash, metadata.clone())?;

            self.send_ch
                .as_ref()
                .map(|ch| {
                    ch.send(Ch::OutPacket(protocol::Packet {
                        code: protocol::Return::NoneUnspecified as i32,
                        message: Some(protocol::packet::Message::Transfer(protocol::Transfer {
                            metadata: Some(metadata),
                            mode: protocol::DataMode::WholeUnspecified as i32,
                            data: Some(data),
                        })),
                    }))
                })
                .ok_or(anyhow::anyhow!("failed to send transfer data"))??;

            tracing::debug!(
                "sending data for {}:[{}, {}]",
                metadata.hash,
                metadata.start,
                metadata.end,
            );
        }

        Ok(())
    }

    pub fn truncate_range(
        file: &mut std::fs::File,
        start: u64,
        mut end: u64,
    ) -> anyhow::Result<()> {
        let file_len = file.metadata()?.len();

        if end > file_len {
            end = file_len;
        }

        if start >= end {
            tracing::debug!("ignoring range [{}, {}]", start, end);
            return Ok(());
        }

        tracing::debug!("true range [{}, {}]", start, end);

        // If we're truncating at the end, we can just resize.
        if end == file_len {
            file.set_len(start)?;
            return Ok(());
        }

        let range_len = end - start;
        let mut buf = vec![0u8; 1024];

        file.seek(SeekFrom::Start(end))?;
        let mut write_pos = start;

        loop {
            let n = file.read(&mut buf)?;
            if n == 0 {
                break;
            }

            file.write_all_at(&buf[..n], write_pos)?;
            write_pos += n as u64;
        }

        file.set_len(file_len - range_len)?;

        Ok(())
    }

    fn modify_block(file: &mut std::fs::File, offset: u64, data: &[u8]) -> anyhow::Result<()> {
        if data.is_empty() {
            anyhow::bail!("cannot modify empty data");
        }

        let file_len = file.metadata()?.len();
        let write_len = data.len() as u64;

        if offset + write_len >= file_len {
            file.set_len(offset + write_len)?;
        }

        file.write_all_at(&data, offset)?;

        Ok(())
    }

    fn insert_block(file: &mut std::fs::File, offset: u64, data: &[u8]) -> anyhow::Result<()> {
        if data.is_empty() {
            anyhow::bail!("cannot insert empty data");
        }

        let file_len = file.metadata()?.len();
        let insert_len = data.len() as u64;

        if offset > file_len {
            file.set_len(offset)?;
            file.seek(SeekFrom::Start(offset))?;
            file.write_all(data)?;
            file.sync_all()?;

            return Ok(());
        }

        let new_len = file_len
            .checked_add(insert_len)
            .ok_or_else(|| anyhow::anyhow!("file size overflow"))?;
        file.set_len(new_len)?;

        let mut buffer = vec![0u8; 8192];
        let mut read_pos = file_len;

        while read_pos > offset {
            let chunk_size = std::cmp::min(read_pos - offset, buffer.len() as u64) as usize;
            read_pos -= chunk_size as u64;

            file.seek(SeekFrom::Start(read_pos))?;
            file.read_exact(&mut buffer[..chunk_size])?;

            file.seek(SeekFrom::Start(read_pos + insert_len))?;
            file.write_all(&buffer[..chunk_size])?;
        }

        file.seek(SeekFrom::Start(offset))?;
        file.write_all(data)?;
        file.sync_all()?;

        Ok(())
    }

    async fn request_block(
        &mut self,
        namehash: i64,
        transfer_metadata: TransferMetadata,
    ) -> anyhow::Result<()> {
        // request transfer
        let mut outgoing_lock = self.outgoing_transfer_requests.lock().await;

        outgoing_lock
            .entry(namehash)
            .and_modify(|o| {
                o.insert(transfer_metadata);
            })
            .or_insert_with(|| {
                let mut set: HashSet<TransferMetadata> = HashSet::new();
                set.insert(transfer_metadata);
                set
            });

        self.send_ch
            .as_ref()
            .map(|ch| {
                ch.send(Ch::OutPacket(protocol::Packet {
                    code: protocol::Return::NoneUnspecified as i32,
                    message: Some(protocol::packet::Message::Transfer(protocol::Transfer {
                        metadata: Some(protocol::BlockMetadata {
                            start: transfer_metadata.start,
                            end: transfer_metadata.end,
                            namehash: Some(namehash as u64),
                            hash: transfer_metadata.hash,
                            cookie: transfer_metadata.cookie,
                        }),
                        mode: protocol::DataMode::WholeUnspecified as i32,
                        data: None,
                    })),
                }))
            })
            .ok_or(anyhow::anyhow!("could not request data transfer"))??;

        Ok(())
    }

    async fn handle_delta(&mut self, mut delta: protocol::Delta) -> anyhow::Result<()> {
        let db = self.db_pool.get()?;

        let folder = self
            .config
            .folder
            .clone()
            .unwrap_or_else(|| PathBuf::from("."));
        let filepath = folder.join(&delta.filename);

        let namehash = xxhash_rust::xxh3::xxh3_64(delta.filename.as_bytes()) as i64;

        // we don't have this file yet, we should ask for it
        if !self.maybe_request_file_manifest(&filepath).await? {
            tracing::debug!(
                "file {} does not exist yet, asking for manifest",
                delta.filename
            );

            // send done signal anyways
            self.send_ch
                .as_ref()
                .map(|ch| {
                    ch.send(Ch::OutPacket(protocol::Packet {
                        code: protocol::Return::NoneUnspecified as i32,
                        message: Some(protocol::packet::Message::Done(protocol::TransferDone {
                            namehash: namehash as u64,
                        })),
                    }))
                })
                .ok_or(anyhow::anyhow!("failed to send done signal after delta"))??;

            return Ok(());
        }

        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(filepath)?;

        // inserts should be sorted by starts ascending
        // deletes should be sorted by starts descending
        delta.ops.sort_by(|a, b| match (a.op_type(), b.op_type()) {
            (protocol::delta::OpType::Delete, protocol::delta::OpType::Delete) => {
                a.start.cmp(&b.start).reverse()
            }
            (protocol::delta::OpType::Insert, protocol::delta::OpType::Delete)
            | (protocol::delta::OpType::Delete, protocol::delta::OpType::Insert) => {
                std::cmp::Ordering::Equal
            }
            _ => a.start.cmp(&b.start),
        });

        for op in dbg!(delta.ops) {
            let existing_hash: Result<i64, _> = {
                let mut stmt = db.prepare(
                    "SELECT hash FROM blocks WHERE file = ?1 AND start = ?2 AND end = ?3 LIMIT 1",
                )?;

                stmt.query_row((namehash, op.start as i64, op.end as i64), |row| row.get(0))
            };

            let timestamp = Self::timestamp()?;
            let transfer_metadata = TransferMetadata {
                op_type: op.op_type(),
                start: op.start,
                end: op.end,
                hash: op.hash,
                attempts: 0,
                timestamp,
                cookie: Some(delta.cookie),
            };

            match op.op_type() {
                protocol::delta::OpType::Insert | protocol::delta::OpType::Modify => {
                    if let Ok(hash) = existing_hash {
                        if hash as u64 == op.hash {
                            tracing::debug!(
                                "delta: block [{}, {}] hash matches, skipping",
                                op.start,
                                op.end
                            );
                            continue;
                        } else {
                            tracing::debug!(
                                "delta: block {} ({}, {}) does not exist, requesting from server",
                                op.hash,
                                op.start,
                                op.end
                            );

                            self.request_block(namehash, transfer_metadata).await?;
                        }
                    } else {
                        tracing::debug!(
                            "delta: block {} ({}, {}) does not exist, requesting from server",
                            op.hash,
                            op.start,
                            op.end
                        );

                        self.request_block(namehash, transfer_metadata).await?;
                    }
                }

                protocol::delta::OpType::Delete => {
                    if let Ok(hash) = existing_hash {
                        // remove block from file and metadata table
                        db.execute("DELETE FROM blocks WHERE file = ?1 AND hash = ?2 AND start = ?3 AND end = ?4",
                            [
                                namehash,
                                hash,
                                op.start as i64,
                                op.end as i64,
                            ]
                        )?;

                        {
                            let mut accesses_lock = self.current_accesses.lock().await;
                            accesses_lock.insert(namehash);
                        }

                        Self::truncate_range(&mut file, op.start, op.end)?;

                        {
                            let mut accesses_lock = self.current_accesses.lock().await;
                            accesses_lock.remove(&namehash);
                        }

                        tracing::debug!(
                            "delta: deleting block [{},{}] for file {}",
                            op.start,
                            op.end,
                            delta.filename
                        );
                    }
                }

                _ => {}
            }
        }

        let has_pending_transfers = {
            let outgoing_lock = self.outgoing_transfer_requests.lock().await;
            outgoing_lock.contains_key(&namehash)
        };

        // if there arent any transfers needed send done
        if !has_pending_transfers {
            self.send_ch
                .as_ref()
                .map(|ch| {
                    ch.send(Ch::OutPacket(protocol::Packet {
                        code: protocol::Return::NoneUnspecified as i32,
                        message: Some(protocol::packet::Message::Done(protocol::TransferDone {
                            namehash: namehash as u64,
                        })),
                    }))
                })
                .ok_or(anyhow::anyhow!("failed to send done signal after delta"))??;

            tracing::debug!(
                "delta: no transfers needed for {}, sending done",
                delta.filename
            );
        }

        Ok(())
    }

    fn create_file_entry(
        &self,
        db: &PooledConnection<SqliteConnectionManager>,
        name_string: &str,
        name_hash: i64,
    ) -> anyhow::Result<()> {
        let folder = self
            .config
            .folder
            .clone()
            .unwrap_or_else(|| PathBuf::from("."));
        let filepath = folder.join(name_string);

        db.execute(
            "INSERT OR IGNORE INTO filenames (name, hash, timestamp) SELECT ?1, ?2, ?3 WHERE NOT EXISTS (SELECT 1 FROM filenames WHERE name = ?1)",
            (name_string, name_hash, Self::timestamp()? as i64),
        )?;

        if metadata(&filepath).is_err() {
            std::fs::File::create_new(filepath)?;
        }

        Ok(())
    }

    fn delete_file_by_hash(
        &mut self,
        db: &PooledConnection<SqliteConnectionManager>,
        name_hash: i64,
    ) -> anyhow::Result<()> {
        db.execute("DELETE FROM blocks WHERE file = ?1", [name_hash])?;

        tracing::debug!("deleted all blocks related to file {} in folder", name_hash,);

        let filename: String = db.query_one(
            "SELECT name FROM filenames WHERE hash = ?1",
            [name_hash],
            |r| r.get(0),
        )?;

        db.execute("DELETE FROM filenames WHERE hash = ?1", [name_hash])?;

        tracing::debug!(
            "deleted filename entry for namehash {} in folder",
            name_hash,
        );

        let folder = self
            .config
            .folder
            .clone()
            .unwrap_or_else(|| PathBuf::from("."));
        let filepath = folder.join(&filename);

        if metadata(&filepath).is_ok() {
            std::fs::remove_file(&filepath)?;
        }

        Ok(())
    }

    async fn handle_ext_file_event(&mut self, event: protocol::Event) -> anyhow::Result<()> {
        let db = self.db_pool.get()?;

        let namehash = xxhash_rust::xxh3::xxh3_64(event.filename.as_bytes()) as i64;

        tracing::debug!("ext file event: {:?} {}", event.event(), event.filename);

        match event.event() {
            protocol::FileEvent::CreateUnspecified => {
                self.create_file_entry(&db, &event.filename, namehash)?;
            }

            protocol::FileEvent::Delete => {
                self.delete_file_by_hash(&db, namehash)?;
            }
        }

        Ok(())
    }

    async fn handle_manifest(
        &mut self,
        code: protocol::Return,
        manifest: protocol::FileManifest,
    ) -> anyhow::Result<()> {
        // TODO: SET A HARD LIMIT ON FILE SIZES

        let namehash = xxhash_rust::xxh3::xxh3_64(manifest.filename.as_bytes()) as i64;

        // queue this for later
        if code == protocol::Return::TransfersPending {
            tracing::debug!("transfer pending, delay");

            let mut queue_lock = self.queued_manifests.lock().await;
            queue_lock.insert(namehash, manifest);

            return Ok(());
        }

        if manifest.blocks.is_empty() {
            self.send_ch
                .as_ref()
                .map(|ch| {
                    ch.send(Ch::OutPacket(protocol::Packet {
                        code: protocol::Return::EmptyManifest as i32,
                        message: Some(protocol::packet::Message::Die(protocol::Die {
                            reason: Some(String::from("sent empty manifest")),
                        })),
                    }))
                })
                .ok_or(anyhow::anyhow!("could not send manifest fail message"))??;

            return Ok(());
        }

        let db = self.db_pool.get()?;

        let exists_in_db: bool = db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM filenames WHERE name = ?1)",
                [&manifest.filename],
                |row| row.get(0),
            )
            .unwrap_or(false);

        if !exists_in_db {
            tracing::debug!("file {} is not part of folder, adding", manifest.filename);

            self.create_file_entry(&db, &manifest.filename, namehash)?;
        }

        {
            let mut set: HashSet<TransferMetadata> = HashSet::new();
            let timestamp = Self::timestamp()?;

            manifest
                .blocks
                .iter()
                .map(|block| {
                    let mut stmt = db.prepare(
                        "SELECT * FROM blocks WHERE hash = ?1 AND start = ?2 AND end = ?3",
                    )?;

                    if stmt
                        .query_one(
                            (block.hash as i64, block.start as i64, block.end as i64),
                            |_| Ok(()),
                        )
                        .is_err()
                    {
                        // cookies from manifests are None
                        set.insert(TransferMetadata {
                            op_type: protocol::delta::OpType::EqualUnspecified,
                            start: block.start,
                            end: block.end,
                            hash: block.hash,
                            attempts: 0,
                            timestamp,
                            cookie: block.cookie,
                        });

                        let mut block_with_namehash = block.clone();
                        block_with_namehash.namehash = Some(namehash as u64);

                        self.send_ch
                            .as_ref()
                            .map(|ch| {
                                ch.send(Ch::OutPacket(protocol::Packet {
                                    code: protocol::Return::NoneUnspecified as i32,
                                    message: Some(protocol::packet::Message::Transfer(
                                        protocol::Transfer {
                                            metadata: Some(block_with_namehash),
                                            mode: protocol::DataMode::WholeUnspecified as i32,
                                            data: None,
                                        },
                                    )),
                                }))
                            })
                            .ok_or(anyhow::anyhow!("could not send transfer request"))??;

                        tracing::debug!(
                            "requesting block [{}, {}] from client for file {}",
                            block.start,
                            block.end,
                            manifest.filename
                        );
                    } else {
                        tracing::debug!(
                            "do not need block {}:[{}, {}] in file {}",
                            block.hash,
                            block.start,
                            block.end,
                            manifest.filename
                        );
                    }

                    Ok::<(), anyhow::Error>(())
                })
                .collect::<anyhow::Result<()>>()?;

            if set.is_empty() {
                // send done signal anyways
                tracing::debug!("required set is empty, done with {}", namehash as u64);

                self.send_ch
                    .as_ref()
                    .map(|ch| {
                        ch.send(Ch::OutPacket(protocol::Packet {
                            code: protocol::Return::NoneUnspecified as i32,
                            message: Some(protocol::packet::Message::Done(
                                protocol::TransferDone {
                                    namehash: namehash as u64,
                                },
                            )),
                        }))
                    })
                    .ok_or(anyhow::anyhow!("failed to send done signal after transfer"))??;
            } else {
                // wait on this
                let mut outgoing_lock = self.outgoing_transfer_requests.lock().await;
                outgoing_lock.insert(namehash, set);
            }
        }

        Ok(())
    }

    async fn handle_sendagain(&mut self, sendagain: protocol::SendAgain) -> anyhow::Result<()> {
        // if there's a queued manifest, send it over now
        let mut queue_lock = self.queued_manifests.lock().await;

        tracing::warn!("sending queued manifest for {}", sendagain.namehash);

        self.send_ch.as_ref().map(|ch| {
            ch.send(Ch::OutPacket(protocol::Packet {
                code: protocol::Return::NoneUnspecified as i32,
                message: Some(
                    // we should resend a manifest
                    if let Some(next_manifest) = queue_lock.remove(&(sendagain.namehash as i64)) {
                        protocol::packet::Message::Manifest(next_manifest)
                    } else {
                        // we are done and should send a done to unlock the file on the server
                        protocol::packet::Message::Done(protocol::TransferDone {
                            namehash: sendagain.namehash,
                        })
                    },
                ),
            }))
        });

        Ok(())
    }

    async fn handle_server_event(&mut self, packet: protocol::Packet) -> anyhow::Result<()> {
        // responded to our heartbeat
        if packet.message.is_none() {
            return Ok(());
        }

        let code = packet.code();
        let message = packet.message.unwrap();

        match message {
            protocol::packet::Message::RoomInfo(room_info) => {
                self.handle_roominfo(room_info).await?;
            }

            protocol::packet::Message::Event(event) => {
                self.handle_ext_file_event(event).await?;
            }

            protocol::packet::Message::Manifest(manifest) => {
                self.handle_manifest(code, manifest).await?
            }

            protocol::packet::Message::Transfer(transfer) => {
                self.handle_transfer(code, transfer).await?
            }

            protocol::packet::Message::Delta(delta) => self.handle_delta(delta).await?,

            protocol::packet::Message::SendAgain(sendagain) => {
                self.handle_sendagain(sendagain).await?
            }

            _ => {}
        }

        Ok(())
    }

    async fn check_queued_manifests(&mut self) -> anyhow::Result<()> {
        let mut manifests_lock = self.queued_manifests.lock().await;

        manifests_lock.drain().for_each(|(namehash, manifest)| {
            tracing::debug!("sending queued manifest for {}", namehash as u64);

            self.send_ch.as_ref().map(|ch| {
                ch.send(Ch::OutPacket(protocol::Packet {
                    code: protocol::Return::NoneUnspecified as i32,
                    message: Some(protocol::packet::Message::Manifest(manifest)),
                }))
            });
        });

        Ok(())
    }

    async fn check_outgoing_transfers(&mut self) -> anyhow::Result<()> {
        let current_timestamp = Self::timestamp()?;

        for (namehash, requests) in self.outgoing_transfer_requests.lock().await.iter_mut() {
            let temp: Vec<TransferMetadata> = requests
                .drain()
                .filter(|req| {
                    if req.attempts + 1 >= REFRESH_ATTEMPTS {
                        tracing::debug!(
                            "request for {}:{}:[{}, {}] max attempts reached",
                            namehash,
                            req.cookie.unwrap_or(0),
                            req.start,
                            req.end,
                        );

                        if let Err(e) = self
                            .send_ch
                            .as_ref()
                            .map(|ch| {
                                ch.send(Ch::OutPacket(protocol::Packet {
                                    code: protocol::Return::NoneUnspecified as i32,
                                    message: Some(protocol::packet::Message::Done(
                                        protocol::TransferDone {
                                            namehash: *namehash as u64,
                                        },
                                    )),
                                }))
                            })
                            .ok_or(anyhow::anyhow!(
                                "failed to send done signal after max attempts"
                            ))
                        {
                            tracing::error!("max attempts done error: {}", e.to_string());
                        }

                        return false;
                    }

                    let metadata = protocol::BlockMetadata {
                        namehash: Some(*namehash as u64),
                        start: req.start,
                        end: req.end,
                        hash: req.hash,
                        cookie: req.cookie,
                    };

                    if let Err(e) = self
                        .send_ch
                        .as_ref()
                        .map(|ch| {
                            ch.send(Ch::OutPacket(protocol::Packet {
                                code: protocol::Return::NoneUnspecified as i32,
                                message: Some(protocol::packet::Message::Transfer(
                                    protocol::Transfer {
                                        metadata: Some(metadata),
                                        mode: protocol::DataMode::WholeUnspecified as i32,
                                        data: None,
                                    },
                                )),
                            }))
                        })
                        .ok_or(anyhow::anyhow!("could not send transfer request"))
                    {
                        tracing::error!("resend transfer error: {}", e.to_string());

                        return true;
                    }

                    tracing::debug!(
                        "resending transfer request: {}:{}:[{}, {}]",
                        namehash,
                        req.cookie.unwrap_or(0),
                        req.start,
                        req.end,
                    );

                    true
                })
                .map(|req| TransferMetadata {
                    op_type: req.op_type,
                    start: req.start,
                    end: req.end,
                    hash: req.hash,
                    attempts: req.attempts + 1,
                    timestamp: current_timestamp,
                    cookie: req.cookie,
                })
                .collect();

            temp.iter().for_each(|req| {
                requests.insert(*req);
            });
        }

        Ok(())
    }

    #[tokio::main]
    pub async fn client_main(config: Config) -> anyhow::Result<()> {
        let (mut client_, mut inotify_stream) = Self::new(config)?;
        let (_, mut send, mut recv) = client_.connect().await?;

        let (send_ch, mut recv_ch) = mpsc::unbounded_channel::<Ch>();

        client_.send_ch = Some(send_ch.clone());

        let hb_send_ch = send_ch.clone();
        let rf_send_ch = send_ch.clone();
        let in_send_ch = send_ch.clone();
        let se_send_ch = send_ch.clone();

        let futs = vec![
            // handle channel thread
            tokio::spawn(async move {
                let mut client = client_;

                tracing::debug!("starting channel handler thread");

                // send initial auth packet
                {
                    let pkt = protocol::Packet {
                        code: protocol::Return::NoneUnspecified as i32,
                        message: Some(protocol::packet::Message::Auth(protocol::Auth {
                            folder: client.config.code.clone(),
                            password: client.config.password.clone(),
                        })),
                    };

                    if let Err(e) = Self::write_packet(&mut send, &pkt).await {
                        tracing::error!("could not send auth packet: {}", e.to_string());
                        return;
                    }
                }

                loop {
                    match recv_ch.recv().await {
                        // packet coming in from the wire
                        Some(Ch::InPacket(pkt)) => {
                            if let Err(e) = client.handle_server_event(pkt).await {
                                tracing::error!(
                                    "server event error: {}\n{}",
                                    e.to_string(),
                                    e.backtrace()
                                );
                            }
                        }

                        // we have to send this over the wire
                        Some(Ch::OutPacket(pkt)) => {
                            if let Err(e) = Self::write_packet(&mut send, &pkt).await {
                                tracing::error!(
                                    "write packet error: {}\n{}",
                                    e.to_string(),
                                    e.backtrace()
                                );
                            }
                        }

                        Some(Ch::Event(ev)) => {
                            if let Err(e) = client.handle_file_event(ev).await {
                                tracing::error!(
                                    "handle event error: {}\n{}",
                                    e.to_string(),
                                    e.backtrace()
                                );
                            }
                        }

                        // check on outgoing transfer requests
                        Some(Ch::Refresh) => {
                            if let Err(e) = client.check_queued_manifests().await {
                                tracing::error!("queued manifests check error: {}", e.to_string());
                            }

                            if let Err(e) = client.check_outgoing_transfers().await {
                                tracing::error!("outgoing transfer check error: {}", e.to_string());
                            }
                        }

                        None => {
                            tracing::error!("recv queue error");
                        }
                    }
                }
            }),
            // heartbeat thread
            tokio::spawn(async move {
                tracing::debug!("starting heartbeat thread");

                loop {
                    tokio::time::sleep(tokio::time::Duration::from_secs(HEARTBEAT_INTERVAL)).await;

                    if let Err(e) = hb_send_ch.send(Ch::OutPacket(protocol::Packet {
                        code: protocol::Return::NoneUnspecified as i32,
                        message: None,
                    })) {
                        tracing::error!("heartbeat send error: {}", e.to_string());
                    }
                }
            }),
            // refresh thread
            tokio::spawn(async move {
                tracing::debug!("starting refresh thread");

                loop {
                    tokio::time::sleep(tokio::time::Duration::from_secs(REFRESH_INTERVAL)).await;

                    if let Err(e) = rf_send_ch.send(Ch::Refresh) {
                        tracing::error!("refresh error: {}", e.to_string());
                    }
                }
            }),
            // inotify stream thread
            tokio::spawn(async move {
                tracing::debug!("starting inotify stream thread");

                loop {
                    if let Some(Ok(event)) = inotify_stream.next().await {
                        if let Err(e) = in_send_ch.send(Ch::Event(event)) {
                            tracing::error!("inotify send error: {}", e.to_string());
                        }
                    }
                }
            }),
            // server event thread
            tokio::spawn(async move {
                tracing::debug!("starting server event thread");

                loop {
                    if let Ok(Some(pkt)) = Self::read_packet(&mut recv).await {
                        if let Err(e) = se_send_ch.send(Ch::InPacket(pkt)) {
                            tracing::error!("server event read error: {}", e.to_string());
                        }
                    }
                }
            }),
        ];

        futures::future::join_all(futs).await;

        Ok(())
    }
}
