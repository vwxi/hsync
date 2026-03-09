use std::{
    collections::{HashMap, HashSet},
    ffi::{OsStr, OsString},
    fs::metadata,
    io::{Read, Seek, SeekFrom, Write},
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
use rusqlite::fallible_iterator::FallibleIterator;
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

const HEARTBEAT_INTERVAL: u64 = 5;
const CHANGE_TIME_DELTA_THRESHOLD: i64 = 5;
const ALPN_QUIC_HSYNC: &[&[u8]] = &[b"hsync"];
const BUF_SIZE: usize = 16384;
const BLOCK_SIZE: usize = 2048;
const CREATE_FILENAMES_STMT: &str = "CREATE TABLE IF NOT EXISTS filenames (name TEXT, hash INTEGER, timestamp INTEGER, UNIQUE(name, hash))";
const CREATE_BLOCKS_STMT: &str = "CREATE TABLE IF NOT EXISTS blocks (file INTEGER, start INTEGER, end INTEGER, hash INTEGER, UNIQUE(file, start, end, hash))";

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
    outgoing_transfer_requests: Mutex<HashMap<i64, HashSet<(u64, u64)>>>,
    outgoing_manifest_requests: Mutex<HashSet<i64>>,
}

impl Drop for Client {
    fn drop(&mut self) {
        // disconnect from server
        tokio::task::block_in_place(|| {
            let send_ch = self.send_ch.blocking_lock();

            send_ch.as_ref().map(|ch| {
                ch.send(protocol::Packet {
                    code: protocol::Return::NoneUnspecified as i32,
                    message: Some(protocol::packet::Message::Die(protocol::Die {
                        reason: Some(String::from("disconnecting")),
                    })),
                })
            })
        });

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
            SqliteConnectionManager::file("file:blockstore?mode=memory&cache=shared")
        };

        let db_pool = Pool::new(manager)?;
        {
            let conn = db_pool.get()?;
            conn.execute(CREATE_FILENAMES_STMT, ())?;
            conn.execute(CREATE_BLOCKS_STMT, ())?;

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
                & !(WatchMask::ONESHOT | WatchMask::ACCESS | WatchMask::OPEN | WatchMask::CLOSE),
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

        Ok(Client {
            config,
            stream,
            wd,
            db_pool,
            endpoint,
            send_ch: Mutex::new(None),
            outgoing_transfer_requests: Mutex::new(HashMap::new()),
            outgoing_manifest_requests: Mutex::new(HashSet::new()),
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
                code: protocol::Return::NoneUnspecified as i32,
                message: Some(protocol::packet::Message::Auth(protocol::Auth {
                    folder: self.config.code.clone(),
                    password: self.config.password.clone(),
                })),
            };

            Self::write_packet(&mut send, &pkt).await?;
        }

        Ok((conn, send, recv))
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

        for entry in glob(&folder_glob)? {
            match entry {
                Ok(path) => {
                    dbg!(Self::check_blocks(
                        &path,
                        std::time::SystemTime::now()
                            .duration_since(std::time::SystemTime::UNIX_EPOCH)?
                            .as_secs() as i64,
                        db,
                    ))?;

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
            Err(e) => return Err(dbg!(e.into())),
        };

        let mut buf = vec![0u8; len as usize];
        stream.read_exact(&mut buf).await?;
        let pkt = protocol::Packet::decode(&buf[..])?;
        Ok(Some(pkt))
    }

    async fn maybe_request_file_manifest(&mut self, path: &PathBuf) -> anyhow::Result<bool> {
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
                .lock()
                .await
                .as_ref()
                .map(|ch| {
                    ch.send(protocol::Packet {
                        code: protocol::Return::NoneUnspecified as i32,
                        message: Some(protocol::packet::Message::Whatis(protocol::WhatIs {
                            filename: String::from(filename),
                        })),
                    })
                })
                .ok_or(anyhow::anyhow!("could not request file {}", filename))??;

            false
        } else {
            true
        })
    }

    // check differences in a single file and report back the list of blocks
    fn check_blocks(
        path: &PathBuf,
        new_timestamp: i64,
        db: &PooledConnection<SqliteConnectionManager>,
    ) -> anyhow::Result<Vec<(u64, u64, u64)>> {
        let pathname = path
            .file_name()
            .and_then(|f| f.to_str())
            .ok_or(anyhow::anyhow!("malformed filename"))?;
        let hashed_filename = xxhash_rust::xxh3::xxh3_64(pathname.as_bytes()) as i64;

        tracing::debug!("begin checking blocks for {}", pathname);

        if let Ok(old_timestamp) = db.query_one(
            "SELECT timestamp FROM filenames WHERE name = ?1 AND hash = ?2",
            (pathname, hashed_filename),
            |r| r.get::<_, i64>(0),
        ) {
            // since inotify does not differentiate between us and any other process
            // we have to check if the change is older than some threshold because
            // otherwise it could just be us writing to a file.
            if dbg!(new_timestamp - old_timestamp) < CHANGE_TIME_DELTA_THRESHOLD {
                tracing::debug!("change time delta does not exceed threshold, skipping");

                return Ok(vec![]);
            }
        }

        db.execute(
            "INSERT OR IGNORE INTO filenames (name, hash, timestamp) VALUES (?1, ?2, ?3)",
            (
                pathname,
                hashed_filename,
                std::time::SystemTime::now()
                    .duration_since(std::time::SystemTime::UNIX_EPOCH)?
                    .as_secs() as i64,
            ),
        )?;

        if let Ok(file) = std::fs::OpenOptions::new()
            .read(true)
            .write(false)
            .open(&path)
        {
            // TODO: adapt this for subfolders when it gets implemented
            let mut changes: Vec<(u64, u64, u64)> = vec![];

            // NOTE: files are addressed in the block store by hash(filename).
            //       if we have files with different filenames but identical content,
            //       there will be redundant storage. in the future, consider loading
            //       whole file, hashing contents then hashing blocks.
            let chunker = fastcdc::v2020::StreamCDC::new(file, 4096, 16384, 65535);

            for chunk in chunker {
                let chunk = chunk?;

                let block_hash = xxhash_rust::xxh3::xxh3_64(chunk.data.as_slice());

                let ex: Result<i64, _> = db.query_one(
                    "SELECT hash FROM blocks WHERE file = ?1 AND start = ?2 AND end = ?3 AND hash = ?4 LIMIT 1",
                    (
                        hashed_filename,
                        chunk.offset as i64,
                        (chunk.offset as usize + chunk.length) as i64,
                        block_hash as i64,
                    ),
                    |r| r.get(0));

                // changes recorded are blocks that change hash
                // or blocks that do not exist
                if let Ok(existing_hash) = dbg!(ex) {
                    if existing_hash != block_hash as i64 {
                        tracing::debug!(
                            "block exists and conflicts, {}:[{}, {}]",
                            existing_hash,
                            chunk.offset,
                            chunk.offset + chunk.length as u64
                        );

                        db.execute(
                            "INSERT OR IGNORE INTO blocks (file, start, end, hash) VALUES (?1, ?2, ?3, ?4)",
                            (
                                hashed_filename,
                                chunk.offset as i64,
                                (chunk.offset + chunk.length as u64) as i64,
                                block_hash as i64,
                            ),
                        )?;
                    } else {
                        tracing::debug!(
                            "block exists and does not conflict, {}:[{}, {}]",
                            existing_hash,
                            chunk.offset,
                            chunk.offset + chunk.length as u64
                        );
                    }
                } else {
                    tracing::debug!(
                        "block is new, {}:[{}, {}]",
                        block_hash,
                        chunk.offset,
                        chunk.offset + chunk.length as u64
                    );

                    db.execute(
                        "INSERT OR IGNORE INTO blocks (file, start, end, hash) VALUES (?1, ?2, ?3, ?4)",
                        (
                            hashed_filename,
                            chunk.offset as i64,
                            (chunk.offset + chunk.length as u64) as i64,
                            block_hash as i64,
                        ),
                    )?;
                }

                changes.push((chunk.offset, chunk.offset + chunk.length as u64, block_hash));
            }

            Ok(changes)
        } else {
            let mut stmt = db.prepare("SELECT start, end, hash FROM blocks WHERE file = ?1")?;

            Ok(stmt
                .query([hashed_filename])?
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

    async fn handle_file_event(
        &mut self,
        buf: &mut [u8],
        db: &PooledConnection<SqliteConnectionManager>,
        event: Event<OsString>,
    ) -> anyhow::Result<()> {
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
                let send_ch = self.send_ch.lock().await;
                send_ch
                    .as_ref()
                    .map(|ch| {
                        ch.send(protocol::Packet {
                            code: protocol::Return::NoneUnspecified as i32,
                            message: Some(protocol::packet::Message::Event(protocol::Event {
                                event: protocol::FileEvent::CreateUnspecified as i32,
                                filename: String::from(event_file),
                            })),
                        })
                    })
                    .ok_or(anyhow::anyhow!("failed to relay create event"))??;
            }
            EventMask::DELETE | EventMask::MOVED_TO => {
                let send_ch = self.send_ch.lock().await;
                send_ch
                    .as_ref()
                    .map(|ch| {
                        ch.send(protocol::Packet {
                            code: protocol::Return::NoneUnspecified as i32,
                            message: Some(protocol::packet::Message::Event(protocol::Event {
                                event: protocol::FileEvent::Delete as i32,
                                filename: String::from(event_file),
                            })),
                        })
                    })
                    .ok_or(anyhow::anyhow!("failed to relay delete event"))??;
            }
            EventMask::MODIFY | EventMask::MOVED_FROM => {
                // if this fails, then we are trying to fetch some sort of swap file
                let metadata = metadata(&filename)?;

                let new_timestamp = metadata
                    .accessed()?
                    .duration_since(std::time::SystemTime::UNIX_EPOCH)?
                    .as_secs() as i64;

                let send_ch = self.send_ch.lock().await;

                let mut manifest = protocol::FileManifest {
                    filename: String::from(event_file),
                    timestamp: new_timestamp as u64,
                    size: metadata.len(),
                    blocks: vec![],
                };

                for change in dbg!(Self::check_blocks(&filename, new_timestamp, db))? {
                    manifest.blocks.push(protocol::BlockMetadata {
                        start: change.0,
                        end: change.1,
                        hash: change.2,
                        namehash: None,
                    });
                }

                send_ch.as_ref().map(|ch| {
                    dbg!(ch.send(protocol::Packet {
                        code: protocol::Return::NoneUnspecified as i32,
                        message: Some(protocol::packet::Message::Manifest(manifest)),
                    }))
                });
            }
            EventMask::DELETE_SELF | EventMask::IGNORED => {
                // destroy client because folder is no longer watchable
                return Err(anyhow::anyhow!("folder is no longer watchable"));
            }
            _ => {}
        }

        Ok(())
    }

    async fn handle_roominfo(&mut self, room_info: protocol::RoomInfo) -> anyhow::Result<()> {
        tracing::info!("connect to this room using this code: {}", room_info.code);

        let db = self.db_pool.get()?;
        {
            let send_ch = self.send_ch.lock().await;

            for file in room_info.files {
                let mut stmt = db.prepare("SELECT * FROM filenames WHERE name = ?1")?;

                // if file does not exist, request manifest
                if stmt.query_one([file.name.clone()], |_| Ok(())).is_err() {
                    tracing::debug!("file {} does not exist, requesting manifest", file.name);

                    send_ch
                        .as_ref()
                        .map(|ch| {
                            ch.send(protocol::Packet {
                                code: protocol::Return::NoneUnspecified as i32,
                                message: Some(protocol::packet::Message::Whatis(
                                    protocol::WhatIs {
                                        filename: file.name.clone(),
                                    },
                                )),
                            })
                        })
                        .ok_or(anyhow::anyhow!("could not request file {}", file.name))??;
                }
            }
        }

        // get started on syncing
        self.send_manifest().await?;

        Ok(())
    }

    async fn send_manifest(&mut self) -> anyhow::Result<()> {
        let conn = self.db_pool.get()?;

        let mut send_ch = self.send_ch.lock().await;

        let mut query_files = conn.prepare("SELECT DISTINCT file FROM blocks")?;
        let mut files = query_files.query(())?;

        while let Ok(Some(row)) = files.next() {
            let file_hash = row.get::<_, i64>(0)?;

            let mut manifest = protocol::FileManifest::default();

            let mut name_stmt = conn.prepare("SELECT name FROM filenames WHERE hash = ?1")?;
            let _ = name_stmt.query_one([&file_hash], |r| {
                manifest.filename = r.get::<_, String>(0)?;

                Ok(())
            })?;

            let mut query_blocks =
                conn.prepare("SELECT start, end, hash FROM blocks WHERE file = ?1")?;
            let mut blocks = query_blocks.query([&file_hash])?;

            while let Ok(Some(block)) = blocks.next() {
                let (start, end, hash) = (
                    block.get::<_, i64>(0)? as u64,
                    block.get::<_, i64>(1)? as u64,
                    block.get::<_, i64>(2)? as u64,
                );

                manifest.blocks.push(protocol::BlockMetadata {
                    start,
                    end,
                    namehash: None,
                    hash,
                });
            }

            tracing::debug!("sending manifest for file {}", manifest.filename);

            let _ = send_ch.as_mut().map(|ch| {
                if let Err(e) = ch.send(protocol::Packet {
                    code: protocol::Return::NoneUnspecified as i32,
                    message: Some(protocol::packet::Message::Manifest(manifest)),
                }) {
                    anyhow::bail!("failed to send message: {}", e.to_string());
                }

                Ok(())
            });
        }

        Ok(())
    }

    async fn handle_transfer(&mut self, transfer: protocol::Transfer) -> anyhow::Result<()> {
        tracing::debug!("handling a transfer!!! handling a transfer!!! ");

        let db = self.db_pool.get()?;
        let metadata = transfer
            .metadata
            .ok_or(anyhow::anyhow!("transfer request with no metadata"))?;

        let namehash = metadata
            .namehash
            .ok_or(anyhow::anyhow!("malformed transfer request"))? as i64;

        let mut stmt = db.prepare("SELECT name FROM filenames WHERE hash = ?1")?;
        let filename: String = stmt.query_row([namehash], |row| row.get(0))?;

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
            return Ok(());
        }

        let send_ch = self.send_ch.lock().await;

        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&filepath)?;

        // we are receiving data from the server
        if let Some(data) = transfer.data {
            let mut outgoing_lock = self.outgoing_transfer_requests.lock().await;
            tracing::debug!("contains? {}", outgoing_lock.contains_key(&namehash));

            outgoing_lock.entry(namehash).and_modify(|reqs| {
                if reqs.contains(&(metadata.start, metadata.end)) {
                    if !reqs.remove(&(metadata.start, metadata.end)) {
                        tracing::warn!(
                            "satisfied nonexistent transfer request for {}:[{}, {}]",
                            namehash,
                            metadata.start,
                            metadata.end
                        );
                    } else {
                        tracing::warn!("bingors");
                    }

                    let datahash = xxhash_rust::xxh3::xxh3_64(data.as_slice()) as i64;

                    if let Err(e) = db.execute(
                        "INSERT OR IGNORE INTO blocks (hash, start, end) VALUES (?1, ?2, ?3)",
                        [datahash, metadata.start as i64, metadata.end as i64],
                    ) {
                        tracing::error!(
                            "failed to update block metadata in database: {}",
                            e.to_string()
                        );

                        return;
                    }

                    if let Err(e) =
                        Self::expand_and_write(&mut file, dbg!(metadata.start), data.as_slice())
                    {
                        tracing::error!(
                            "failed to write block [{}, {}] to file {}: {}",
                            metadata.start,
                            metadata.end,
                            filepath.to_string_lossy(),
                            e.to_string()
                        );

                        return;
                    }

                    tracing::debug!(
                        "applied block [{}, {}] to file {}",
                        metadata.start,
                        metadata.end,
                        filepath.to_string_lossy()
                    );
                } else {
                    tracing::error!("damnit");
                }
            });
        } else {
            // otherwise, we are fulfilling a data request
            let mut file = std::fs::File::open(&filepath)?;
            file.seek(SeekFrom::Start(metadata.start))?;

            let length = (metadata.end - metadata.start) as usize;
            let mut data = vec![0u8; length];
            file.read_exact(&mut data)?;

            send_ch
                .as_ref()
                .map(|ch| {
                    ch.send(protocol::Packet {
                        code: protocol::Return::NoneUnspecified as i32,
                        message: Some(protocol::packet::Message::Transfer(protocol::Transfer {
                            metadata: Some(metadata),
                            mode: protocol::DataMode::WholeUnspecified as i32,
                            data: Some(data),
                        })),
                    })
                })
                .ok_or(anyhow::anyhow!("failed to send transfer data"))??;

            tracing::debug!(
                "fulfilling transfer request for {}:[{}, {}] size {}",
                metadata.hash,
                metadata.start,
                metadata.end,
                length
            );
        }

        Ok(())
    }

    pub fn truncate_range(file: &mut std::fs::File, start: u64, end: u64) -> anyhow::Result<()> {
        if start >= end {
            return Ok(());
        }

        let file_len = file.metadata()?.len();

        if end > file_len {
            anyhow::bail!("end offset is beyond end of file");
        }

        let range_len = end - start;
        let tail_len = file_len - end;

        if tail_len > 0 {
            let mut buf = vec![0u8; 64 * 1024];
            let mut moved: u64 = 0;

            while moved < tail_len {
                let to_move = std::cmp::min(buf.len() as u64, tail_len - moved) as usize;

                file.seek(SeekFrom::Start(end + moved))?;
                file.read_exact(&mut buf[..to_move])?;

                file.seek(SeekFrom::Start(start + moved))?;
                file.write_all(&buf[..to_move])?;

                moved += to_move as u64;
            }
        }

        file.set_len(file_len - range_len)?;
        file.sync_all()?;

        Ok(())
    }

    fn expand_and_write(file: &mut std::fs::File, offset: u64, data: &[u8]) -> anyhow::Result<()> {
        if data.is_empty() {
            return Ok(());
        }

        let file_len = file.metadata()?.len();
        let data_len = data.len() as u64;

        if offset > file_len {
            file.set_len(offset + data_len)?;
        }

        file.seek(SeekFrom::Start(offset))?;
        file.write_all(data)?;

        Ok(())
    }

    async fn handle_delta(&mut self, delta: protocol::Delta) -> anyhow::Result<()> {
        let db = self.db_pool.get()?;

        let folder = self
            .config
            .folder
            .clone()
            .unwrap_or_else(|| PathBuf::from("."));
        let filepath = folder.join(&delta.filename);

        // we don't have this file yet, we should ask for it
        if !self.maybe_request_file_manifest(&filepath).await? {
            tracing::debug!(
                "file {} does not exist yet, asking for manifest",
                delta.filename
            );
            return Ok(());
        }

        let namehash = xxhash_rust::xxh3::xxh3_64(delta.filename.as_bytes()) as i64;

        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(filepath)?;

        for op in delta.ops {
            // Check if block hash matches existing hash in database
            let mut stmt = db.prepare(
                "SELECT hash FROM blocks WHERE file = ?1 AND start = ?2 AND end = ?3 LIMIT 1",
            )?;

            let existing_hash: Result<i64, _> =
                stmt.query_row((namehash, op.start as i64, op.end as i64), |row| row.get(0));

            match op.op_type() {
                protocol::delta::OpType::Insert => {
                    if let Ok(hash) = existing_hash {
                        if hash as u64 == op.hash {
                            tracing::debug!(
                                "block [{}, {}] hash matches, skipping",
                                op.start,
                                op.end
                            );
                            continue;
                        } else {
                            // request transfer
                            let mut outgoing_lock = self.outgoing_transfer_requests.lock().await;
                            outgoing_lock
                                .entry(namehash)
                                .and_modify(|o| {
                                    o.insert((op.start, op.end));
                                })
                                .or_insert_with(|| {
                                    let mut set: HashSet<(u64, u64)> = HashSet::new();
                                    set.insert((op.start, op.end));
                                    set
                                });

                            self.send_ch
                                .lock()
                                .await
                                .as_ref()
                                .map(|ch| {
                                    ch.send(protocol::Packet {
                                        code: protocol::Return::NoneUnspecified as i32,
                                        message: Some(protocol::packet::Message::Transfer(
                                            protocol::Transfer {
                                                metadata: Some(protocol::BlockMetadata {
                                                    start: op.start,
                                                    end: op.end,
                                                    namehash: Some(namehash as u64),
                                                    hash: op.hash,
                                                }),
                                                mode: protocol::DataMode::WholeUnspecified as i32,
                                                data: None,
                                            },
                                        )),
                                    })
                                })
                                .ok_or(anyhow::anyhow!("could not request data transfer"))??;
                        }
                    } else {
                        tracing::debug!(
                            "INSERT: block {} ({}, {}) does not exist, requesting from server",
                            op.hash,
                            op.start,
                            op.end
                        );

                        let mut outgoing_lock = self.outgoing_transfer_requests.lock().await;
                        outgoing_lock
                            .entry(namehash)
                            .and_modify(|o| {
                                o.insert((op.start, op.end));
                            })
                            .or_insert_with(|| {
                                let mut set: HashSet<(u64, u64)> = HashSet::new();
                                set.insert((op.start, op.end));
                                set
                            });

                        // request transfer
                        self.send_ch
                            .lock()
                            .await
                            .as_ref()
                            .map(|ch| {
                                ch.send(protocol::Packet {
                                    code: protocol::Return::NoneUnspecified as i32,
                                    message: Some(protocol::packet::Message::Transfer(
                                        protocol::Transfer {
                                            metadata: Some(protocol::BlockMetadata {
                                                start: op.start,
                                                end: op.end,
                                                namehash: Some(namehash as u64),
                                                hash: op.hash,
                                            }),
                                            mode: protocol::DataMode::WholeUnspecified as i32,
                                            data: None,
                                        },
                                    )),
                                })
                            })
                            .ok_or(anyhow::anyhow!("could not request data transfer"))??;
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

                        Self::truncate_range(&mut file, op.start, op.end)?;

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

        Ok(())
    }

    fn create_file_entry(
        db: &PooledConnection<SqliteConnectionManager>,
        name_string: &str,
        path: &PathBuf,
        name_hash: i64,
    ) -> anyhow::Result<()> {
        db.execute(
            "INSERT OR IGNORE INTO filenames (name, hash) SELECT ?1, ?2 WHERE NOT EXISTS (SELECT 1 FROM filenames WHERE name = ?1)",
            (name_string, name_hash),
        )?;

        let _ = std::fs::File::create_new(path);

        Ok(())
    }

    fn delete_file_entry(
        self: &Arc<Self>,
        db: &PooledConnection<SqliteConnectionManager>,
        folder_id: i64,
        name_hash: i64,
    ) -> anyhow::Result<()> {
        db.execute("DELETE FROM blocks WHERE file = ?1", [name_hash])?;

        tracing::debug!(
            "deleted all blocks related to file {} in folder {}",
            name_hash,
            folder_id
        );

        let filename: String = db.query_one(
            "SELECT name FROM filenames WHERE hash = ?1",
            [name_hash],
            |r| r.get(0),
        )?;

        db.execute("DELETE FROM filenames WHERE hash = ?1", [name_hash])?;

        tracing::debug!(
            "deleted filename entry for namehash {} in folder {}",
            name_hash,
            folder_id
        );

        let folder = self
            .config
            .folder
            .clone()
            .unwrap_or_else(|| PathBuf::from("."));
        let filepath = folder.join(&filename);

        std::fs::remove_file(&filepath)?;

        Ok(())
    }

    async fn handle_manifest(&mut self, manifest: protocol::FileManifest) -> anyhow::Result<()> {
        let send = self.send_ch.lock().await;

        // TODO: SET A HARD LIMIT ON FILE SIZES

        if manifest.blocks.is_empty() {
            send.as_ref()
                .map(|ch| {
                    ch.send(protocol::Packet {
                        code: protocol::Return::EmptyManifest as i32,
                        message: Some(protocol::packet::Message::Die(protocol::Die {
                            reason: Some(String::from("sent empty manifest")),
                        })),
                    })
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

        let namehash = xxhash_rust::xxh3::xxh3_64(manifest.filename.as_bytes()) as i64;

        if !exists_in_db {
            tracing::debug!("file {} is not part of folder, adding", manifest.filename);

            let folder = self
                .config
                .folder
                .clone()
                .unwrap_or_else(|| PathBuf::from("."));
            let filepath = folder.join(&manifest.filename);

            Self::create_file_entry(&db, &manifest.filename, &filepath, namehash)?;
        }

        {
            let mut set: HashSet<(u64, u64)> = HashSet::new();
            manifest
                .blocks
                .iter()
                .map(|block| {
                    let mut stmt = db.prepare(
                        "SELECT * FROM blocks WHERE hash = ?1 AND start = ?2 AND end = ?3",
                    )?;

                    tracing::debug!(
                        "checking for block {}:[{}, {}]",
                        block.hash,
                        block.start,
                        block.end
                    );

                    if stmt
                        .query_one(
                            (block.hash as i64, block.start as i64, block.end as i64),
                            |_| Ok(()),
                        )
                        .is_err()
                    {
                        set.insert((block.start, block.end));

                        let mut block_with_namehash = block.clone();
                        block_with_namehash.namehash = Some(namehash as u64);

                        send.as_ref()
                            .map(|ch| {
                                ch.send(protocol::Packet {
                                    code: protocol::Return::NoneUnspecified as i32,
                                    message: Some(protocol::packet::Message::Transfer(
                                        protocol::Transfer {
                                            metadata: Some(block_with_namehash),
                                            mode: protocol::DataMode::WholeUnspecified as i32,
                                            data: None,
                                        },
                                    )),
                                })
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

            let mut outgoing_lock = self.outgoing_transfer_requests.lock().await;
            outgoing_lock.insert(namehash, set);
        }

        Ok(())
    }

    async fn handle_server_event(&mut self, packet: protocol::Packet) -> anyhow::Result<()> {
        // responded to our heartbeat
        if packet.message.is_none() {
            return Ok(());
        }

        let message = packet.message.unwrap();

        match message {
            protocol::packet::Message::RoomInfo(room_info) => {
                self.handle_roominfo(room_info).await?;
            }

            protocol::packet::Message::Event(event) => {
                tracing::debug!("event: {:?}", event);
            }

            protocol::packet::Message::Manifest(manifest) => self.handle_manifest(manifest).await?,

            protocol::packet::Message::Transfer(transfer) => self.handle_transfer(transfer).await?,

            protocol::packet::Message::Delta(delta) => self.handle_delta(delta).await?,

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

        // you need to find a way to get this into separate tasks
        loop {
            select! {
                // heartbeat timer
                _ = tokio::time::sleep(tokio::time::Duration::from_secs(HEARTBEAT_INTERVAL)) => {
                    Self::write_packet(&mut send, &protocol::Packet {
                        code: protocol::Return::NoneUnspecified as i32,
                        message: None,
                    }).await?;
                },

                // outgoing messages to server
                Some(m) = recv_ch.recv() => {
                    Self::write_packet(&mut send, &m).await?;
                },

                // events from inotify
                Some(Ok(event)) = client.stream.next() => {
                    if let Err(e) = client.handle_file_event(&mut diff_buffer, &db, event).await {
                        tracing::error!("inotify event error: {}", e.to_string());
                    }
                },

                // incoming messages from server
                // TODO: how do we stop inotify from renotifying us
                //       maybe increment (stream.next) until we are done updating
                //       or maybe keep a map of (filename, num of ignores) and decrement until 0 and remove
                pkt = Self::read_packet(&mut recv) => {
                    match dbg!(pkt)? {
                        Some(pkt) => {
                            tracing::debug!("p: {:?}", pkt);

                            if let Err(e) = client.handle_server_event(pkt).await {
                                tracing::error!("server event error: {}", e.backtrace());
                            }
                        },
                        None => break,
                    }
                }
            }
        }

        Ok(())
    }
}
