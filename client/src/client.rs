use std::{
    collections::{HashMap, HashSet, VecDeque},
    ffi::{OsStr, OsString},
    fs::metadata,
    io::{Read, Seek, SeekFrom, Write},
    os::unix::{ffi::OsStrExt, fs::FileExt},
    path::PathBuf,
    sync::Arc,
};

use futures::{StreamExt, executor::block_on, future::join_all};
use glob::glob;
use notify::Watcher;
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
use rustls_platform_verifier::BuilderVerifierExt;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    select,
    sync::{
        Mutex, MutexGuard,
        mpsc::{self, UnboundedSender, unbounded_channel},
        oneshot,
    },
};
use tracing::instrument;
use xxhash_rust;

use crate::{Config, relay::Relay, util::ClearFlags};

pub mod protocol {
    include!(concat!(env!("OUT_DIR"), "/hsync.rs"));
}

pub(crate) const HEARTBEAT_INTERVAL: u64 = 5;
const NOTIFY_TIMEOUT: u64 = 2000;
const NOTIFY_TICK_RATE: u64 = 2000;
const REFRESH_INTERVAL: u64 = 3;
const REFRESH_ATTEMPTS: u64 = 3;
const ALPN_QUIC_HSYNC: &[&[u8]] = &[b"hsync"];
const BUF_SIZE: usize = 16384;
const EV_BUF_SIZE: usize = 32;
const MAX_FILE_SIZE_MB: usize = 24;

/// name string <-> name hash
const CREATE_FILENAMES_STMT: &str = "CREATE TABLE IF NOT EXISTS filenames (name TEXT PRIMARY KEY, hash INTEGER, timestamp INTEGER, datahash INTEGER, version INTEGER DEFAULT 0, UNIQUE(name, hash))";
/// block metadata tied to files in folder
const CREATE_BLOCKS_STMT: &str = "CREATE TABLE IF NOT EXISTS blocks (file INTEGER, start INTEGER, end INTEGER, hash INTEGER, version INTEGER DEFAULT 0, UNIQUE(file, start, end, hash))";
/// temp blocks waiting to be sent to server or waiting to be applied to files
const CREATE_JOURNAL_STMT: &str = "CREATE TABLE IF NOT EXISTS journal (file INTEGER, start INTEGER, end INTEGER, hash INTEGER, cookie INTEGER, op INTEGER, contents BLOB, version INTEGER DEFAULT 0)";

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

#[derive(Debug)]
pub(crate) enum Ch {
    InPacket(protocol::Packet),
    OutPacket(protocol::Packet),
    Event(notify_debouncer_full::DebouncedEvent),
    Refresh,
    OpenStream(u64, oneshot::Sender<()>),
}

#[derive(Debug, PartialEq, Eq, Hash, Copy, Clone)]
pub(crate) struct TransferMetadata {
    pub op_type: protocol::delta::OpType,
    pub start: u64,
    pub end: u64,
    pub hash: u64,
    pub namehash: u64,
    pub attempts: u64,
    pub timestamp: u64,
    pub cookie: Option<u64>,
}

#[derive(Clone)]
pub struct Client {
    pub(crate) config: Config,
    watcher: Arc<
        notify_debouncer_full::Debouncer<
            notify::RecommendedWatcher,
            notify_debouncer_full::RecommendedCache,
        >,
    >,
    pub(crate) db_pool: Arc<Pool<SqliteConnectionManager>>,
    endpoint: Endpoint,
    pub(crate) send_ch: Option<mpsc::UnboundedSender<Ch>>,
    /// file access lock
    pub(crate) current_accesses: Arc<Mutex<HashSet<i64>>>,
    pub(crate) outgoing_transfer_requests: Arc<Mutex<HashMap<i64, HashSet<TransferMetadata>>>>,
    outgoing_manifest_requests: Arc<Mutex<HashSet<i64>>>,
    /// (cookie, manifest)
    queued_manifests: Arc<Mutex<HashMap<i64, VecDeque<(u64, protocol::FileManifest)>>>>,
    pub(crate) relays: Arc<Mutex<HashMap<u64, Relay>>>,
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
    pub fn new(
        mut config: Config,
    ) -> anyhow::Result<(
        Client,
        tokio::sync::mpsc::UnboundedReceiver<
            Result<Vec<notify_debouncer_full::DebouncedEvent>, Vec<notify::Error>>,
        >,
    )> {
        // process all files currently in folder
        let current_folder = std::env::current_dir()?;

        if config.folder.is_none() {
            config.folder = Some(current_folder.clone());
        }

        let folder = config.folder.as_ref().unwrap_or(&current_folder);

        let manager = if let Some(ref db) = config.db {
            SqliteConnectionManager::file(db)
        } else {
            SqliteConnectionManager::file("file:blockstore?mode=memory&cache=shared")
        };

        tracing::info!(
            "initialized block database and processed folder {}",
            folder.to_string_lossy()
        );

        // create notify stream
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<
            Result<Vec<notify_debouncer_full::DebouncedEvent>, Vec<notify::Error>>,
        >();

        let mut watcher = notify_debouncer_full::new_debouncer_opt(
            std::time::Duration::from_millis(NOTIFY_TIMEOUT),
            Some(std::time::Duration::from_millis(NOTIFY_TICK_RATE)),
            move |res| {
                let _ = tx.send(res);
            },
            notify_debouncer_full::RecommendedCache::new(),
            notify::Config::default(),
        )?;

        watcher.watch(folder, notify::RecursiveMode::Recursive)?;

        tracing::info!("created notify for folder {}", folder.to_string_lossy());

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
            tracing::warn!("running with TLS");

            let mut rustls_config = rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()?
                .with_platform_verifier()?
                .with_no_client_auth();

            rustls_config.alpn_protocols = ALPN_QUIC_HSYNC.iter().map(|p| p.to_vec()).collect();

            quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(rustls_config)?))
        });

        let db_pool = Pool::new(manager)?;
        let client = Client {
            config: config.clone(),
            watcher: Arc::new(watcher),
            db_pool: Arc::new(db_pool),
            endpoint,
            send_ch: None,
            current_accesses: Arc::new(Mutex::new(HashSet::new())),
            outgoing_transfer_requests: Arc::new(Mutex::new(HashMap::new())),
            outgoing_manifest_requests: Arc::new(Mutex::new(HashSet::new())),
            queued_manifests: Arc::new(Mutex::new(HashMap::new())),
            relays: Arc::new(Mutex::new(HashMap::new())),
        };

        {
            let conn = client.db_pool.get()?;
            conn.execute(CREATE_FILENAMES_STMT, ())?;
            conn.execute(CREATE_BLOCKS_STMT, ())?;
            conn.execute(CREATE_JOURNAL_STMT, ())?;

            client.process_files_into_db(&folder, &conn)?;
        }

        Ok((client, rx))
    }

    /// this function will init the connection
    async fn connect(&mut self) -> anyhow::Result<(Connection, SendStream, RecvStream)> {
        let conn = self
            .endpoint
            // NOTE: what is this second parameter supposed to be
            .connect(self.config.addr, "localhost")?
            .await?;

        let (send, recv) = conn.open_bi().await?;

        tracing::debug!("initial connection {}", send.id());

        Ok((conn, send, recv))
    }

    /// processes files into entry database
    fn process_files_into_db(
        &self,
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
                    if path.is_file() {
                        let current_datahash = self.get_file_hash(&path)? as i64;

                        self.process_change(
                            db,
                            &path,
                            current_datahash,
                            current_timestamp,
                            None,
                        )?;
                    } else if path.is_dir() {
                        self.process_files_into_db(&path, db)?;
                    }
                }
                _ => continue,
            }
        }

        Ok(())
    }

    async fn maybe_request_file_manifest(
        &self,
        path: &PathBuf,
    ) -> anyhow::Result<bool> {
        let relative_path = self.resolve_relative_path(path)?;
        let namehash = xxhash_rust::xxh3::xxh3_64(relative_path.as_bytes()) as i64;

        Ok(if !path.exists() {
            tracing::debug!("sending whatis for file {}", relative_path);

            if !self
                .outgoing_manifest_requests
                .lock()
                .await
                .insert(namehash)
            {
                tracing::debug!("we already asked for this manifest");
                return Ok(false);
            }

            self.send_ch
                .as_ref()
                .map(|ch| {
                    ch.send(Ch::OutPacket(protocol::Packet {
                        code: protocol::Return::NoneUnspecified as i32,
                        message: Some(protocol::packet::Message::Whatis(protocol::WhatIs {
                            filename: relative_path.clone(),
                        })),
                    }))
                })
                .ok_or(anyhow::anyhow!("could not request file {}", relative_path))??;

            false
        } else {
            true
        })
    }

    /// process change in a file and then return the new chunk data for this file
    fn process_change(
        &self,
        db: &PooledConnection<SqliteConnectionManager>,
        path: &PathBuf,
        current_datahash: i64,
        current_timestamp: i64,
        cookie: Option<i64>,
    ) -> anyhow::Result<Vec<(u64, u64, u64)>> {
        let relative_path = self.resolve_relative_path(path)?;

        let namehash = xxhash_rust::xxh3::xxh3_64(relative_path.as_bytes()) as i64;

        tracing::debug!("begin checking blocks for {}", relative_path);

        db.execute(
            "INSERT INTO filenames (name, hash, timestamp, datahash) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(name) DO UPDATE SET timestamp=excluded.timestamp, datahash=excluded.datahash, version=excluded.version+1",
            (&relative_path, namehash, current_timestamp, current_datahash),
        )?;

        if let Ok(file) = std::fs::File::open(&path) {
            let mut blocks: Vec<(u64, u64, u64)> = vec![];
            let mut b_new = 0u64;

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
                            None,
                            Some(&block.data),
                            block_hash as i64,
                        )?;

                        b_new += 1;
                    } else {
                        // tracing::debug!(
                        //     "block exists and does not conflict, {}:[{}, {}]",
                        //     existing_hash,
                        //     block.offset,
                        //     block.offset + block.length as u64
                        // );
                    }
                } else {
                    tracing::debug!(
                        "block is new, {}:[{}, {}]",
                        block_hash,
                        block.offset,
                        block.offset + block.length as u64
                    );

                    // tracing::debug!(
                    //     "block is new, {}:[{}, {}]",
                    //     block_hash,
                    //     block.offset,
                    //     block.offset + block.length as u64
                    // );

                    Self::journal_block(
                        &db,
                        namehash,
                        block.offset as i64,
                        (block.offset + block.length as u64) as i64,
                        cookie,
                        Some(protocol::delta::OpType::Insert),
                        Some(&block.data),
                        block_hash as i64,
                    )?;

                    b_new += 1;
                }

                blocks.push((block.offset, block.offset + block.length as u64, block_hash));
            }

            tracing::debug!("processed change for file {}", relative_path);

            if b_new == 0 {
                return Ok(vec![]);
            }

            Ok(blocks)
        } else {
            let mut stmt = db.prepare("SELECT start, end, hash FROM blocks WHERE file = ?1")?;

            tracing::debug!("processed change for file {}", relative_path);

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

    async fn queue_manifest(
        &mut self,
        namehash: i64,
        manifest: protocol::FileManifest,
    ) -> anyhow::Result<()> {
        let mut queue_lock = self.queued_manifests.lock().await;
        queue_lock
            .entry(namehash)
            .and_modify(|q| {
                q.push_back((manifest.cookie(), manifest.clone()));
            })
            .or_insert_with(|| {
                let mut q: VecDeque<(u64, protocol::FileManifest)> = VecDeque::new();
                q.push_back((manifest.cookie(), manifest));

                q
            });

        Ok(())
    }

    async fn send_queued_manifest(&self, namehash: i64) -> anyhow::Result<()> {
        let mut queue_lock = self.queued_manifests.lock().await;
        
        let queue = queue_lock.get_mut(&namehash).ok_or(anyhow::anyhow!("could not acquire queue for namehash"))?;
        let manifest = queue.pop_front().ok_or(anyhow::anyhow!("queue for namehash is empty"))?;

        if queue.is_empty() {
            queue_lock.remove(&namehash).ok_or(anyhow::anyhow!("queue doesn't exist in queue list but is used anyways?"))?;

            tracing::debug!("manifest: removed queue for {namehash}");
        }

        self.send_ch.as_ref().map(|ch| ch.send(Ch::OutPacket(protocol::Packet {
            code: protocol::Return::NoneUnspecified as i32,
            message: Some(protocol::packet::Message::Manifest(manifest.1)),
        }))).ok_or(anyhow::anyhow!("could not send a manifest we were waiting on"))??;

        Ok(())
    }

    async fn handle_file_event(
        &mut self,
        event: notify_debouncer_full::DebouncedEvent,
    ) -> anyhow::Result<()> {
        let db = self.db_pool.get()?;

        let event_path = event
            .event
            .paths
            .first()
            .ok_or(anyhow::anyhow!("no event file found"))?;

        let relative_path = self.resolve_relative_path(event_path)?;

        let namehash = xxhash_rust::xxh3::xxh3_64(relative_path.as_bytes()) as i64;

        // ignore any events relating to a directory
        if event_path.is_dir() {
            return Ok(());
        }

        // if accessed then this is triggered by an external file event
        {
            let mut accesses_lock = self.current_accesses.lock().await;
            if accesses_lock.remove(&namehash) {
                return Ok(());
            }
        }

        match event.event.kind {
            notify::event::EventKind::Remove(notify::event::RemoveKind::File) => {
                self.send_ch
                    .as_ref()
                    .map(|ch| {
                        ch.send(Ch::OutPacket(protocol::Packet {
                            code: protocol::Return::NoneUnspecified as i32,
                            message: Some(protocol::packet::Message::Event(protocol::Event {
                                event: protocol::FileEvent::Delete as i32,
                                filename: String::from(relative_path),
                            })),
                        }))
                    })
                    .ok_or(anyhow::anyhow!("failed to relay delete event"))??;
            }

            notify::event::EventKind::Create(notify::event::CreateKind::File)
            | notify::event::EventKind::Modify(notify::event::ModifyKind::Data(
                notify::event::DataChange::Any,
            )) => {
                // if we are currently accessing this, skip
                let current_timestamp = Self::timestamp()? as i64;
                let current_datahash = self.get_file_hash(event_path)? as i64;

                // if hash is the same, stop
                if let Ok(old_datahash) = db.query_row(
                    "SELECT datahash FROM filenames WHERE hash = ?1",
                    [namehash],
                    |r| r.get::<_, i64>(0),
                ) {
                    if old_datahash == current_datahash {
                        return Ok(());
                    }
                }

                // increment current version
                let current_version = (db.query_row(
                    "UPDATE filenames SET version = version + 1 WHERE hash = ?1 RETURNING version",
                    [namehash],
                    |r| r.get::<_, i64>(0),
                )? as u64)
                    .saturating_sub(1);

                // if this fails, then we are trying to fetch some sort of swap file
                let metadata = metadata(event_path)?;
                let cookie = rand::random::<i64>();

                let mut manifest = protocol::FileManifest {
                    version: current_version + 1,
                    filename: relative_path.clone(),
                    timestamp: current_timestamp as u64,
                    size: metadata.len(),
                    hash: Some(current_datahash as u64),
                    cookie: Some(cookie as u64),
                    blocks: vec![],
                };

                let change = self.process_change(
                    &db,
                    event_path,
                    current_datahash,
                    current_timestamp,
                    Some(cookie),
                )?;

                // ignore if there are zero changes
                if change.is_empty() {
                    tracing::debug!("no changes. skipping");

                    return Ok(());
                }

                for c in change {
                    manifest.blocks.push(protocol::BlockMetadata {
                        start: c.0,
                        end: c.1,
                        hash: c.2,
                        origin: None,
                        namehash: None,
                        cookie: Some(cookie as u64),
                    });
                }

                if {
                    let transfers_lock = self.outgoing_transfer_requests.lock().await;

                    transfers_lock.contains_key(&namehash)
                } {
                    self.queue_manifest(namehash, manifest).await?;

                    tracing::debug!(
                        "queueing manifest for file {} (ck: {})",
                        relative_path,
                        cookie as u64,
                    );
                } else {
                    self.send_ch.as_ref().map(|ch| {
                        ch.send(Ch::OutPacket(protocol::Packet {
                            code: protocol::Return::NoneUnspecified as i32,
                            message: Some(protocol::packet::Message::Manifest(manifest)),
                        }))
                    });

                    tracing::debug!(
                        "sending manifest for file {} (ck: {})",
                        relative_path,
                        cookie as u64
                    );
                }
            }

            _ => {}
        }

        Ok(())
    }

    async fn handle_roominfo(&mut self, room_info: protocol::RoomInfo) -> anyhow::Result<()> {
        tracing::info!("connect to this room using this code: {}", room_info.code);

        let db = self.db_pool.get()?;
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
                            message: Some(protocol::packet::Message::Whatis(protocol::WhatIs {
                                filename: file.name.clone(),
                            })),
                        }))
                    })
                    .ok_or(anyhow::anyhow!("could not request file {}", file.name))??;
            }
        }

        // get starting on syncing
        self.send_own_manifests().await?;

        Ok(())
    }

    async fn send_own_manifests(&mut self) -> anyhow::Result<()> {
        let conn = self.db_pool.get()?;

        let mut query_files = conn.prepare("SELECT name, hash, version FROM filenames")?;
        let mut files = query_files.query(())?;

        while let Ok(Some(row)) = files.next() {
            let filename = row.get::<_, String>(0)?;
            let namehash = row.get::<_, i64>(1)?;
            let version = row.get::<_, i64>(2)? as u64;

            let mut manifest = protocol::FileManifest::default();

            manifest.hash = Some(self.get_file_hash(&self.join_file_and_folder(&filename)?)?);
            manifest.filename = filename;
            manifest.version = version;

            let mut query_blocks =
                conn.prepare("SELECT start, end, hash FROM blocks WHERE file = ?1")?;
            let mut blocks = query_blocks.query([&namehash])?;

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
                    origin: None,
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

                if let Err(e) = ch.send(Ch::OutPacket(protocol::Packet {
                    code: protocol::Return::NoneUnspecified as i32,
                    message: Some(protocol::packet::Message::Done(protocol::TransferDone {
                        namehash: namehash as u64,
                        cookie: None,
                    })),
                })) {
                    anyhow::bail!("failed to send message: {}", e.to_string());
                }

                Ok(())
            });
        }

        Ok(())
    }

    pub(crate) async fn handle_transfer(
        &self,
        code: protocol::Return,
        transfer: protocol::Transfer,
        send: &UnboundedSender<Ch>,
    ) -> anyhow::Result<()> {
        let db = self.db_pool.get()?;

        let metadata = transfer
            .metadata
            .ok_or(anyhow::anyhow!("transfer request with no metadata"))?;

        let namehash = metadata
            .namehash
            .ok_or(anyhow::anyhow!("malformed transfer request"))? as i64;

        let filename: String = {
            let mut stmt = db.prepare("SELECT name FROM filenames WHERE hash = ?1")?;
            stmt.query_row([namehash], |row| row.get(0))?
        };

        match code {
            protocol::Return::BlockMismatch | protocol::Return::BlockNotFound => {
                anyhow::bail!(
                    "server miss {}:[{}, {}] (ck: {})",
                    namehash as u64,
                    metadata.start,
                    metadata.end,
                    metadata.cookie()
                );
            }

            _ => {}
        };

        let filepath = self.join_file_and_folder(&filename)?;

        // maybe we do not have the file yet, we should not satisfy a transfer for
        // a file we do not have.
        if !self.maybe_request_file_manifest(&filepath).await? {
            tracing::debug!(
                "xfer: file {} does not exist yet, asking for manifest",
                filename
            );

            return Ok(());
        }

        // we are receiving data from the server
        if let Some(data) = transfer.data {
            let block_hash = xxhash_rust::xxh3::xxh3_64(&data);
            if block_hash != metadata.hash {
                tracing::debug!("xfer: hash mismatch. skipping");
                return Ok(());
            }

            let mut transfers_lock = self.outgoing_transfer_requests.lock().await;

            if let Some(entry) = transfers_lock.get_mut(&namehash) {
                if let Some(t) = entry.iter().find(|e| {
                    e.start == metadata.start
                        && e.end == metadata.end
                        && e.cookie == metadata.cookie
                }) {
                    let op = t.op_type;

                    entry.retain(|e| {
                        !(e.start == metadata.start
                            && e.end == metadata.end
                            && e.cookie == metadata.cookie)
                    });

                    // add access to set
                    {
                        let mut accesses_lock = self.current_accesses.lock().await;
                        accesses_lock.insert(namehash);
                    }

                    Self::hydrate_block(
                        &db,
                        namehash,
                        metadata.start as i64,
                        metadata.end as i64,
                        metadata.cookie() as i64,
                        &data,
                        metadata.hash as i64,
                    )?;

                    tracing::debug!(
                        "xfer: hydrated block op {:?} [{}, {}] to file {}, {}",
                        op,
                        metadata.start,
                        metadata.end,
                        filepath.to_string_lossy(),
                        block_hash,
                    );

                    if entry.is_empty() {
                        drop(transfers_lock);

                        self.apply_journaled_delta(db, namehash, metadata.cookie() as i64)
                            .await?;

                        self.clear_file_temp_data(namehash, ClearFlags::Transfers).await?;

                        self.send_ch.as_ref().map(|ch| ch.send(Ch::OutPacket(protocol::Packet {
                            code: protocol::Return::NoneUnspecified as i32,
                            message: Some(protocol::packet::Message::Done(
                                protocol::TransferDone {
                                    namehash: namehash as u64,
                                    cookie: metadata.cookie,
                                },
                            )),
                        }))).ok_or(anyhow::anyhow!("could not tell server we were done"))??;

                        // we cannot care about the result of this
                        // but send a queued manifest if any
                        let _ = block_on(self.send_queued_manifest(namehash));
                    }
                }
            }
        } else {
            // otherwise, we are fulfilling a data request
            let data = match self.fetch_block(&db, &filepath, namehash, metadata.clone()) {
                Ok(d) => d,
                Err(e) => {
                    tracing::error!("{}", e.to_string());

                    send.send(Ch::OutPacket(protocol::Packet {
                        code: protocol::Return::BlockNotFound as i32,
                        message: Some(protocol::packet::Message::Transfer(
                            protocol::Transfer {
                                metadata: Some(metadata),
                                mode: protocol::DataMode::WholeUnspecified as i32,
                                data: None,
                            },
                        )),
                    }))?;

                    return Ok(());
                }
            };

            send.send(Ch::OutPacket(protocol::Packet {
                code: protocol::Return::NoneUnspecified as i32,
                message: Some(protocol::packet::Message::Transfer(protocol::Transfer {
                    metadata: Some(metadata),
                    mode: protocol::DataMode::WholeUnspecified as i32,
                    data: Some(data),
                })),
            }))?;
        }

        Ok(())
    }

    async fn handle_delta(&mut self, delta: protocol::Delta) -> anyhow::Result<()> {
        let db = self.db_pool.get()?;
        let filepath = self.join_file_and_folder(&delta.filename)?;
        let namehash = xxhash_rust::xxh3::xxh3_64(delta.filename.as_bytes()) as i64;

        // we don't have this file yet or the file is wrong with stuff queued, we should ask for it
        if !self
            .maybe_request_file_manifest(&filepath)
            .await?
        {
            tracing::debug!(
                "delta: file {} does not exist yet, asking for manifest",
                delta.filename
            );

            return Ok(());
        }

        {
            let datahash = self.get_file_hash(&filepath)?;
            if datahash != delta.hash {
                self.clear_file_temp_data(namehash, ClearFlags::all()).await?;
            }
        }

        // vec for blocks we will batch request 
        let mut req_blocks: Vec<protocol::BlockMetadata> = vec![];

        for op in delta.ops {
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
                namehash: namehash as u64,
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
                                "delta: block {} ({}, {}) does not exist, requesting",
                                op.hash,
                                op.start,
                                op.end
                            );

                            self.prepare_block_request(namehash, delta.cookie as i64, transfer_metadata)
                                .await?;

                            req_blocks.push(protocol::BlockMetadata {
                                start: op.start,
                                end: op.end,
                                namehash: Some(namehash as u64),
                                hash: op.hash,
                                origin: Some(delta.origin),
                                cookie: Some(delta.cookie),
                            });
                        }
                    } else {
                        tracing::debug!(
                            "delta: block {} ({}, {}) does not exist, requesting",
                            op.hash,
                            op.start,
                            op.end
                        );

                        self.prepare_block_request(namehash, delta.cookie as i64, transfer_metadata)
                            .await?;

                        req_blocks.push(protocol::BlockMetadata {
                            start: op.start,
                            end: op.end,
                            namehash: Some(namehash as u64),
                            hash: op.hash,
                            origin: Some(delta.origin),
                            cookie: Some(delta.cookie),
                        });
                    }
                }

                protocol::delta::OpType::Delete => {
                    // remove block from file and metadata table

                    Self::journal_block(
                        &db,
                        namehash,
                        op.start as i64,
                        op.end as i64,
                        Some(delta.cookie as i64),
                        Some(protocol::delta::OpType::Delete),
                        None,
                        op.hash as i64,
                    )?;
                }

                _ => {}
            }
        }

        if req_blocks.is_empty() {
            tracing::debug!("delta: no deltas to wait on, apply delta and notify done");
            
            self.apply_journaled_delta(db, namehash, delta.cookie as i64).await?;
            self.clear_file_temp_data(namehash, ClearFlags::all()).await?;
            
            self.send_ch.as_ref().map(|ch| ch.send(Ch::OutPacket(protocol::Packet {
                code: protocol::Return::NoneUnspecified as i32,
                message: Some(protocol::packet::Message::Done(protocol::TransferDone {
                    namehash: namehash as u64,
                    cookie: Some(delta.cookie),
                }))
            }))).ok_or(anyhow::anyhow!("message send failure"))??;
        } else {
            tracing::debug!("delta: broadcasted xfers for {}, waiting", delta.filename);
            
            self.bulk_request_blocks(delta.version, namehash as u64, req_blocks).await?;
        }

        Ok(())
    }

    fn create_file_entry(
        &self,
        db: &PooledConnection<SqliteConnectionManager>,
        name_string: &str,
        namehash: i64,
    ) -> anyhow::Result<()> {
        let filepath = self.join_file_and_folder(name_string)?;
        let parent = filepath.parent().ok_or(anyhow::anyhow!("no path parent"))?;

        if filepath.is_dir() {
            anyhow::bail!("cannot process a directory path");
        }

        if filepath.exists() {
            return Ok(());
        }

        db.execute(
            "INSERT OR REPLACE INTO filenames (name, hash, timestamp) SELECT ?1, ?2, ?3 WHERE NOT EXISTS (SELECT 1 FROM filenames WHERE name = ?1)",
            (name_string, namehash, Self::timestamp()? as i64),
        )?;

        if !parent.exists() {
            std::fs::create_dir(parent)?;
        }

        if metadata(&filepath).is_err() {
            std::fs::File::create_new(filepath)?;
        }

        tracing::debug!("created file {}", name_string);

        Ok(())
    }

    fn delete_file_by_hash(
        &mut self,
        db: &PooledConnection<SqliteConnectionManager>,
        namehash: i64,
    ) -> anyhow::Result<()> {
        let filename: String = db.query_one(
            "SELECT name FROM filenames WHERE hash = ?1",
            [namehash],
            |r| r.get(0),
        )?;

        let filepath = self.join_file_and_folder(&filename)?;
        let parent = filepath.parent().ok_or(anyhow::anyhow!("no path parent"))?;

        if !filepath.exists() {
            return Ok(());
        }

        db.execute("DELETE FROM blocks WHERE file = ?1", [namehash])?;
        db.execute("DELETE FROM filenames WHERE hash = ?1", [namehash])?;

        tracing::debug!("deleted all blocks related to file {} in folder", namehash,);

        std::fs::remove_file(&filepath)?;

        tracing::debug!("deleted filename entry for namehash {} in folder", namehash,);

        // if directory is empty, delete it
        if parent.read_dir()?.peekable().peek().is_none() {
            tracing::debug!("deleted empty folder {}", parent.to_string_lossy());
            std::fs::remove_dir(&parent)?;
        }

        Ok(())
    }

    async fn handle_ext_file_event(&mut self, event: protocol::Event) -> anyhow::Result<()> {
        let db = self.db_pool.get()?;

        let namehash = xxhash_rust::xxh3::xxh3_64(event.filename.as_bytes()) as i64;

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
        mut manifest: protocol::FileManifest,
    ) -> anyhow::Result<()> {
        // TODO: SET A HARD LIMIT ON FILE SIZES

        let namehash = xxhash_rust::xxh3::xxh3_64(manifest.filename.as_bytes()) as i64;

        // queue this for later
        if code == protocol::Return::TransfersPending {
            tracing::debug!("transfer pending, queue {}", namehash);

            self.queue_manifest(namehash, manifest).await?;

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

        let file_size_mb = manifest.blocks
            .iter()
            .max_by(|a, b| a.end.cmp(&b.end))
            .ok_or(anyhow::anyhow!("file has no end?"))?.end as usize / 1024 / 1024;

        if file_size_mb > MAX_FILE_SIZE_MB {
            tracing::error!("{file_size_mb} MB larger than allowed maximum, ignoring");

            self.send_ch
                .as_ref()
                .map(|ch| {
                    ch.send(Ch::OutPacket(protocol::Packet {
                        code: protocol::Return::SizeLimit as i32,
                        message: Some(protocol::packet::Message::Done(protocol::TransferDone {
                            namehash: namehash as u64,
                            cookie: manifest.cookie,
                        })),
                    }))
                })
                .ok_or(anyhow::anyhow!("could not send manifest fail done message"))??;

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

        if exists_in_db {
            // we have to delete everything and start over
            tracing::debug!("delete everything about {} and start over", manifest.filename);

            self.delete_file_by_hash(&db, namehash)?;
            self.create_file_entry(&db, &manifest.filename, namehash)?;

        } else {
            tracing::debug!("file {} is not part of folder, adding", manifest.filename);

            self.create_file_entry(&db, &manifest.filename, namehash)?;
        }

        // blocks may come from different origins
        // so missing blocks will be requested, accounted for and eventually marked as received
        {
            let mut transfers_lock = self.outgoing_transfer_requests.lock().await;

            let timestamp = Self::timestamp()?;

            // process the blocks in the manifest:
            // - if it doesn't exist, create a hollow journal block that will be filled later
            // - account for blocks awaiting fill long term for the periodic check
            //   but also keep blocks we need to request to sort and batch query to peers
            let req_blocks = manifest
                .blocks
                .iter_mut()
                .map(|block| {
                    let mut stmt = db.prepare(
                        "SELECT * FROM blocks WHERE file = ?1 AND hash = ?2 AND start = ?3 AND end = ?4",
                    )?;

                    // because manifests can come from clients doing batch requests
                    // we will think about the block's namehash above the manifest's namehash
                    let used_namehash = block.namehash.unwrap_or(namehash as u64);

                    if stmt
                        .query_one(
                            (used_namehash as i64, block.hash as i64, block.start as i64, block.end as i64),
                            |_| Ok(()),
                        )
                        .is_err()
                    {
                        // block does not exist, create empty journal block

                        Self::journal_block(
                            &db,
                            used_namehash as i64,
                            block.start as i64,
                            block.end as i64,
                            Some(block.cookie() as i64),
                            Some(protocol::delta::OpType::EqualUnspecified),
                            None,
                            block.hash as i64,
                        )?;

                        transfers_lock.entry(used_namehash as i64)
                            .and_modify(|entry| {
                                entry.insert(TransferMetadata {
                                    op_type: protocol::delta::OpType::EqualUnspecified,
                                    start: block.start,
                                    end: block.end,
                                    hash: block.hash,
                                    namehash: used_namehash,
                                    attempts: 0,
                                    timestamp,
                                    cookie: block.cookie,
                                });
                            })
                            .or_insert_with(|| {
                                let mut set: HashSet<TransferMetadata> = HashSet::new();
                                set.insert(TransferMetadata {
                                    op_type: protocol::delta::OpType::EqualUnspecified,
                                    start: block.start,
                                    end: block.end,
                                    hash: block.hash,
                                    namehash: used_namehash,
                                    attempts: 0,
                                    timestamp,
                                    cookie: block.cookie,
                                });

                                set
                            });

                        let mut block_with_namehash = block.clone();
                        block_with_namehash.namehash = Some(used_namehash);

                        anyhow::Ok(block_with_namehash)
                    } else {
                        tracing::debug!(
                            "do not need block {}:[{}, {}] in file {}",
                            block.hash,
                            block.start,
                            block.end,
                            manifest.filename
                        );

                        anyhow::bail!("do not need block");
                    }
                })
                .filter_map(anyhow::Result::ok)
                .collect::<Vec<protocol::BlockMetadata>>();

            self.bulk_request_blocks(manifest.version, namehash as u64, req_blocks).await?;
        }

        Ok(())
    }

    /// remove all accounting data related to a file hash
    async fn clear_file_temp_data(&self, namehash: i64, flags: ClearFlags) -> anyhow::Result<()> {
        // fuck this crate in its ass
        // why can't i have async here
        bitflags::bitflags_match!(flags, {
            ClearFlags::Transfers => {
                tracing::debug!("gc: delete transfers for {namehash}");

                let mut transfers_lock = block_on(self.outgoing_transfer_requests.lock());
                transfers_lock.remove(&namehash);
            },

            ClearFlags::Accesses => {
                tracing::debug!("gc: delete accesses for {namehash}");

                let mut accesses_lock = block_on(self.current_accesses.lock());
                accesses_lock.remove(&namehash);
            },

            ClearFlags::Queue => {
                tracing::debug!("gc: delete queue for {namehash}");

                let mut queue_lock = block_on(self.queued_manifests.lock());
                queue_lock.remove(&namehash);
            },

            _ => {},
        });

        Ok(())
    }

    async fn handle_sendagain(&mut self, sendagain: protocol::SendAgain) -> anyhow::Result<()> {
        // if there's a queued manifest, send it over now
        if block_on(self.send_queued_manifest(sendagain.namehash as i64)).is_err() {
            self.send_ch.as_ref().map(|ch| {
                ch.send(Ch::OutPacket(protocol::Packet {
                    code: protocol::Return::NoneUnspecified as i32,
                    message: Some( 
                        // we are done and should send a done to unlock the file on the server
                        protocol::packet::Message::Done(protocol::TransferDone {
                            namehash: sendagain.namehash,
                            cookie: None,
                        })
                    ),
                }))
            }).ok_or(anyhow::anyhow!("could not send done to server"))??;
        }

        Ok(())
    }

    async fn handle_die(&mut self, die: protocol::Die) -> anyhow::Result<()> {
        tracing::warn!("die: {:?}", die.reason);

        Ok(())
    }

    async fn handle_whatis(&mut self, whatis: protocol::WhatIs) -> anyhow::Result<()> {
        let db = self.db_pool.get()?;

        let mut stmt = db.prepare("SELECT version, hash FROM filenames WHERE name = ?1")?;

        stmt.query_one([whatis.filename.clone()], |row| {
            let version = row.get::<_, i64>(0)? as u64;
            let namehash = row.get::<_, i64>(1)?;

            let mut blocks_stmt =
                db.prepare("SELECT hash, start, end FROM blocks WHERE file = ?1")?;

            let largest_end_offset = db.query_one(
                "SELECT MAX(end) FROM blocks WHERE file = ?1",
                [namehash],
                |r| r.get::<_, i64>(0),
            )? as u64;

            let datahash = self
                .get_file_hash(
                    &self
                        .join_file_and_folder(&whatis.filename)
                        .map_err(|_| rusqlite::Error::UnwindingPanic)?,
                )
                .map_err(|_| rusqlite::Error::UnwindingPanic)?;

            let mut manifest = protocol::FileManifest {
                version,
                filename: whatis.filename,
                timestamp: Self::timestamp().map_err(|_| rusqlite::Error::UnwindingPanic)?,
                size: largest_end_offset,
                hash: Some(datahash),
                cookie: Some(rand::random()),
                blocks: vec![],
            };

            let mut blocks = blocks_stmt.query([namehash])?;
            while let Ok(Some(block)) = blocks.next() {
                manifest.blocks.push(protocol::BlockMetadata {
                    hash: block.get::<_, i64>(0)? as u64,
                    start: block.get::<_, i64>(1)? as u64,
                    end: block.get::<_, i64>(2)? as u64,
                    origin: None,
                    cookie: manifest.cookie,
                    namehash: None,
                });
            }

            tracing::debug!("sending manifest for file {}", manifest.filename);

            self.send_ch
                .as_ref()
                .map(|ch| {
                    ch.send(Ch::OutPacket(protocol::Packet {
                        code: protocol::Return::NoneUnspecified as i32,
                        message: Some(protocol::packet::Message::Manifest(manifest)),
                    }))
                })
                .ok_or(rusqlite::Error::UnwindingPanic)?
                .map_err(|_| rusqlite::Error::UnwindingPanic)?;

            Ok(())
        })?;

        Ok(())
    }

    async fn handle_done(&mut self, done: protocol::TransferDone) -> anyhow::Result<()> {
        let db = self.db_pool.get()?;

        let cookie = done
            .cookie
            .ok_or(anyhow::anyhow!("server should always send cookie for gc"))?;

        db.execute(
            "DELETE FROM journal WHERE file = ?1 AND cookie = ?2",
            [done.namehash as i64, cookie as i64],
        )?;

        //tracing::debug!("journal: gc namehash {} cookie {}", done.namehash, cookie);

        Ok(())
    }

    async fn handle_server_event(
        &mut self,
        packet: protocol::Packet,
        send_ch: &UnboundedSender<Ch>,
    ) -> anyhow::Result<()> {
        // responded to our heartbeat
        if packet.message.is_none() {
            return Ok(());
        }

        let code = packet.code();
        let message = packet.message.unwrap();

        match message {
            protocol::packet::Message::Die(die) => {
                self.handle_die(die).await?;
            }

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
                self.handle_transfer(code, transfer, send_ch).await?
            }

            protocol::packet::Message::Delta(delta) => self.handle_delta(delta).await?,

            protocol::packet::Message::SendAgain(sendagain) => {
                self.handle_sendagain(sendagain).await?
            }

            protocol::packet::Message::Whatis(whatis) => self.handle_whatis(whatis).await?,

            protocol::packet::Message::Done(done) => self.handle_done(done).await?,

            _ => {}
        }

        Ok(())
    }

    async fn check_outgoing_transfers(&mut self) -> anyhow::Result<()> {
        let current_timestamp = Self::timestamp()?;

        for (namehash, entry) in self.outgoing_transfer_requests.lock().await.iter_mut() {
            let temp: Vec<TransferMetadata> = entry
                .drain()
                .filter(|req| {
                    if req.attempts + 1 >= REFRESH_ATTEMPTS {
                        // tracing::debug!(
                        //     "request for {}:{}:[{}, {}] max attempts reached",
                        //     namehash,
                        //     req.cookie.unwrap_or(0),
                        //     req.start,
                        //     req.end,
                        // );

                        return false;
                    }

                    let metadata = protocol::BlockMetadata {
                        namehash: Some(*namehash as u64),
                        start: req.start,
                        end: req.end,
                        hash: req.hash,
                        origin: None,
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
                        .ok_or(anyhow::anyhow!("could not send xfer request"))
                    {
                        tracing::error!("resend xfer error: {}", e.to_string());

                        return true;
                    }

                    // tracing::debug!(
                    //     "resending xfer for {}:{}:[{}, {}]",
                    //     namehash,
                    //     req.cookie.unwrap_or(0),
                    //     req.start,
                    //     req.end,
                    // );

                    true
                })
                .map(|req| TransferMetadata {
                    op_type: req.op_type,
                    start: req.start,
                    end: req.end,
                    hash: req.hash,
                    namehash: req.namehash,
                    attempts: req.attempts + 1,
                    timestamp: current_timestamp,
                    cookie: req.cookie,
                })
                .collect();

            temp.iter().for_each(|req| {
                entry.insert(*req);
            });
        }

        Ok(())
    }

    #[tokio::main]
    pub async fn client_main(config: Config) -> anyhow::Result<()> {
        let (mut client, mut notify_ch) = Self::new(config)?;
        let (conn, mut send, mut recv) = client.connect().await?;

        let token = tokio_util::sync::CancellationToken::new();
        let term_token = token.clone();
        let hb_token = token.clone();
        let rf_token = token.clone();
        let in_token = token.clone();
        let se_token = token.clone();

        let (send_ch, mut recv_ch) = mpsc::unbounded_channel::<Ch>();

        client.send_ch = Some(send_ch.clone());

        let hb_send_ch = send_ch.clone();
        let rf_send_ch = send_ch.clone();
        let in_send_ch = send_ch.clone();
        let se_send_ch = send_ch.clone();

        let futs = vec![
            // term thread
            tokio::spawn(async move {
                let _ = tokio::signal::ctrl_c().await;
                term_token.cancel();
            }),
            // handle channel thread
            tokio::spawn(async move {
                let mut event_buffer = vec![];

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
                    tokio::select! {
                        Ok(incoming_bidi) = conn.accept_bi() => {
                            tracing::debug!("relay: incoming bidi ({})", incoming_bidi.0.id());
                            tokio::task::spawn(client.clone().handle_relay(incoming_bidi, token.clone(), None, None));
                        }

                        sz = recv_ch.recv_many(&mut event_buffer, EV_BUF_SIZE) => {
                            for i in event_buffer.drain(..sz) {
                                match i {
                                    // packet coming in from the wire
                                    Ch::InPacket(pkt) => {
                                        if let Err(e) = client.handle_server_event(pkt, &send_ch).await {
                                            tracing::error!("server event: {}, {}", e.to_string(), e.backtrace());
                                        }
                                    }

                                    // we have to send this over the wire
                                    Ch::OutPacket(pkt) => {
                                        if let Err(e) = Self::write_packet(&mut send, &pkt).await {
                                            tracing::error!("write packet: {}", e.to_string(),);
                                        }
                                    }

                                    Ch::Event(ev) => {
                                        if let Err(e) = client.handle_file_event(ev).await {
                                            tracing::error!("handle event: {}", e.to_string(),);
                                        }
                                    }

                                    // check on outgoing transfer requests
                                    Ch::Refresh => {
                                        if let Err(e) = client.check_outgoing_transfers().await {
                                            tracing::error!("outgoing transfer check: {}", e.to_string());
                                        }
                                    }

                                    // open stream
                                    Ch::OpenStream(id, signal) => {
                                        match conn.open_bi().await {
                                            Ok(outgoing_bidi) => {
                                                tokio::task::spawn(client.clone().handle_relay(outgoing_bidi, token.clone(), Some(signal), Some(id)));

                                                tracing::debug!("relay: spawned a relay for {}", id);
                                            }

                                            Err(e) => {
                                                tracing::error!("outgoing bidi stream for {id}: {}", e.to_string());
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        _ = token.cancelled() => {
                            tracing::warn!("client closing!");
                            break;
                        }
                    }
                }
            }),
            // heartbeat thread
            tokio::spawn(async move {
                tracing::debug!("starting heartbeat thread");

                loop {
                    tokio::select! {
                        _ = tokio::time::sleep(tokio::time::Duration::from_secs(HEARTBEAT_INTERVAL)) => {
                            if let Err(e) = hb_send_ch.send(Ch::OutPacket(protocol::Packet {
                                code: protocol::Return::NoneUnspecified as i32,
                                message: None,
                            })) {
                                tracing::error!("heartbeat send error: {}", e.to_string());
                                break;
                            }
                        }

                        _ = hb_token.cancelled() => {
                            break;
                        }
                    }
                }
            }),
            // refresh thread
            tokio::spawn(async move {
                tracing::debug!("starting refresh thread");

                loop {
                    tokio::select! {
                        _ = tokio::time::sleep(tokio::time::Duration::from_secs(HEARTBEAT_INTERVAL)) => {
                            if let Err(e) = rf_send_ch.send(Ch::Refresh) {
                                tracing::error!("refresh error: {}", e.to_string());
                                break;
                            }
                        }

                        _ = rf_token.cancelled() => {
                            break;
                        }
                    }
                }
            }),
            // notify stream thread
            tokio::spawn(async move {
                tracing::debug!("starting notify stream thread");

                loop {
                    tokio::select! {
                        _ = in_token.cancelled() => { break; }

                        Some(Ok(events)) = notify_ch.recv() => {
                            for event in events {
                                if let Err(e) = in_send_ch.send(Ch::Event(event)) {
                                    tracing::error!("inotify send error: {}", e.to_string());
                                    break;
                                }
                            }
                        }
                    }
                }
            }),
            // server event thread
            tokio::spawn(async move {
                tracing::debug!("starting server event thread");

                loop {
                    tokio::select! {
                        Ok(Some(pkt)) = Self::read_packet(&mut recv) => {
                            if let Err(e) = se_send_ch.send(Ch::InPacket(pkt)) {
                                tracing::error!("server event read error: {}", e.to_string());
                                break;
                            }
                        }

                        _ = se_token.cancelled() => {
                            break;
                        }
                    }
                }
            }),
        ];

        join_all(futs).await;

        Ok(())
    }
}
