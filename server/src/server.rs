use std::{
    collections::{HashMap, HashSet},
    io::{Read, Seek, Write},
    net::SocketAddr,
    sync::Arc,
};

use crate::Config;
use anyhow::Context;
use blake2::Digest;
use prost::Message;
use quinn::{Endpoint, RecvStream, SendStream, crypto::rustls::QuicServerConfig};
use r2d2::{Pool, PooledConnection};
use r2d2_sqlite::SqliteConnectionManager;
use rand::prelude::*;
use rcgen::{CertifiedKey, generate_simple_self_signed};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, pem::PemObject};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    select,
    sync::{
        Mutex, RwLock,
        mpsc::{UnboundedSender, unbounded_channel},
    },
};
use tracing::{Instrument, Span};

pub mod protocol {
    include!(concat!(env!("OUT_DIR"), "/hsync.rs"));
}

const CHARSET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
const REFRESH_INTERVAL: u64 = 5;
const REFRESH_ATTEMPTS: u64 = 3;
const ALPN_QUIC_HSYNC: &[&[u8]] = &[b"hsync"];
const CREATE_USERS_STMT: &str = "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, addr TEXT, current_folder INTEGER)";
const CREATE_FOLDERS_STMT: &str = "CREATE TABLE IF NOT EXISTS folders (id INTEGER PRIMARY KEY AUTOINCREMENT, code TEXT, password TEXT, UNIQUE(code))";
const CREATE_FILENAMES_STMT: &str = "CREATE TABLE IF NOT EXISTS filenames (folder INTEGER, name TEXT UNIQUE, namehash INTEGER UNIQUE)";
const CREATE_BLOCKS_STMT: &str = "CREATE TABLE IF NOT EXISTS blocks (folder INTEGER, name INTEGER, hash INTEGER, start INTEGER, end INTEGER, contents BLOB)";
const CREATE_JOURNAL_STMT: &str = "CREATE TABLE IF NOT EXISTS journal (folder INTEGER, name INTEGER, start INTEGER, end INTEGER, hash INTEGER, cookie INTEGER, op INTEGER, contents BLOB, UNIQUE(folder, name, start, end, cookie))";

#[derive(Debug, Clone)]
enum Ch {
    OutPacket(protocol::Packet),
    Refresh,
}

#[derive(Debug, PartialEq, Eq, Hash)]
struct TransferMetadata {
    pub hash: u64,
    pub start: u64,
    pub end: u64,
    pub attempts: u64,
    pub timestamp: u64,
    pub cookie: Option<u64>,
}

#[derive(Debug)]
struct IncompleteTransfer {
    pub transfers: HashSet<TransferMetadata>,
    pub who: SocketAddr,
}

struct LockState {
    pub by: SocketAddr,
    pub cookie: u64,
}

pub struct Server {
    config: Config,
    endpoint: Endpoint,
    db_pool: Pool<SqliteConnectionManager>,
    streams: RwLock<HashMap<SocketAddr, UnboundedSender<Ch>>>,
    locks: Mutex<HashMap<(i64, i64), LockState>>,
    outgoing_transfer_requests: Mutex<HashMap<i64, IncompleteTransfer>>,
}

impl Server {
    pub fn new(config: Config) -> anyhow::Result<Server> {
        // INIT QUIC ENDPOINT

        // if no path is provided, generate a selfsigned key-cert pair to use
        let (key, cert_chain) = if let (Some(keypath), Some(certpath)) = (&config.key, &config.cert)
        {
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

        if cfg!(debug_assertions) {
            transport_config.max_idle_timeout(None);
        }

        let endpoint = quinn::Endpoint::server(server_config, config.bind)?;

        tracing::info!("initialized QUIC endpoint at {}", config.bind);

        // INIT SQLITE
        let manager = if let Some(db) = &config.db {
            SqliteConnectionManager::file(db)
        } else {
            SqliteConnectionManager::file("file:hsyncdb?mode=memory&cache=shared")
        };

        let pool = Pool::new(manager)?;
        {
            let conn = pool.get()?;
            conn.execute(CREATE_USERS_STMT, ())?;
            conn.execute(CREATE_FOLDERS_STMT, ())?;
            conn.execute(CREATE_FILENAMES_STMT, ())?;
            conn.execute(CREATE_BLOCKS_STMT, ())?;
            conn.execute(CREATE_JOURNAL_STMT, ())?;
        }

        tracing::info!("initialized db");

        Ok(Server {
            config,
            endpoint,
            db_pool: pool,
            streams: RwLock::new(HashMap::new()),
            locks: Mutex::new(HashMap::new()),
            outgoing_transfer_requests: Mutex::new(HashMap::new()),
        })
    }

    fn timestamp() -> anyhow::Result<u64> {
        Ok(std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)?
            .as_secs())
    }

    pub async fn run(self: &Arc<Self>, span: Span) -> anyhow::Result<()> {
        async move {
            while let Some(conn) = self.endpoint.accept().await {
                if !self
                    .config
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

        let (mut conn_send, mut conn_recv) = match conn.accept_bi().await {
            Ok(s) => {
                tracing::debug!("accepted bidi stream");
                s
            }
            Err(_) => anyhow::bail!("bidi stream could not be accepted"),
        };

        let (send, mut recv) = unbounded_channel::<Ch>();

        let token = tokio_util::sync::CancellationToken::new();
        let ce_token = token.clone();
        let rf_token = token.clone();

        let rf_send_ch = send.clone();
        let self_ = self.clone();
        let self2_ = self.clone();

        let addr = conn.remote_address();

        {
            let mut lock = self.streams.write().await;
            lock.insert(conn.remote_address(), send);
        }

        let futs = vec![
            // handle channel thread
            tokio::spawn(async move {
                tracing::debug!("starting channel handler thread");

                loop {
                    tokio::select! {
                        m = recv.recv() => {
                            match m {
                                Some(Ch::OutPacket(pkt)) => {
                                    match Self::write_packet(&mut conn_send, &pkt).await {
                                        Err(e) => {
                                            tracing::error!("write packet error: {}", e.to_string());

                                            token.cancel();
                                        }
                                        _ => {}
                                    }
                                }
                                Some(Ch::Refresh) => {
                                    if let Err(e) = self_.check_outgoing_transfers().await {
                                        tracing::error!("outgoing transfer check error: {}", e.to_string());
                                    }
                                }
                                None => {
                                    tracing::error!("recv queue error");
                                }
                            }
                        }

                        _ = token.cancelled() => {
                            tracing::debug!("ending channel handler thread");

                            let _ = self_.handle_die(addr, protocol::Die { reason: None }).await;

                            break;
                        }
                    }
                }
            }),
            // client event thread
            tokio::spawn(async move {
                tracing::debug!("starting client event thread");

                loop {
                    tokio::select! {
                        _ = ce_token.cancelled() => {
                            break;
                        }

                        p = Self::read_packet(&mut conn_recv) => {
                            match p {
                                Ok(Some(pkt)) => {
                                    if let Err(e) = self2_.handle_packet(conn.remote_address(), pkt).await {
                                        tracing::error!("packet handler: {}", e.to_string());
                                    }
                                }

                                _ => {
                                    tracing::debug!("ending client event thread");

                                    ce_token.cancel();
                                }
                            }
                        }
                    }
                }
            }),
            // refresh thread
            tokio::spawn(async move {
                tracing::debug!("starting refresh thread");

                loop {
                    tokio::select! {
                        _ = tokio::time::sleep(tokio::time::Duration::from_secs(REFRESH_INTERVAL)) => {
                            if let Err(e) = rf_send_ch.send(Ch::Refresh) {
                                tracing::error!("refresh error: {}", e.to_string());
                            }
                        }

                        _ = rf_token.cancelled() => {
                            tracing::debug!("ending refresh thread");

                            break;
                        }
                    }
                }
            }),
        ];

        futures::future::join_all(futs).await;

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

    async fn handle_packet(
        self: &Arc<Self>,
        addr: SocketAddr,
        pkt: protocol::Packet,
    ) -> anyhow::Result<()> {
        // respond to a heartbeat
        if pkt.message.is_none() {
            let streams_lock = self.streams.read().await;
            streams_lock
                .get(&addr)
                .ok_or(anyhow::anyhow!("could not find stream"))?
                .send(Ch::OutPacket(protocol::Packet {
                    code: protocol::Return::NoneUnspecified as i32,
                    message: None,
                }))?;

            return Ok(());
        }

        let message = pkt
            .message
            .ok_or(anyhow::anyhow!("why is this happening?"))?;

        match message {
            protocol::packet::Message::Auth(auth) => self.handle_auth(addr, auth).await?,

            protocol::packet::Message::Die(die) => self.handle_die(addr, die).await?,

            protocol::packet::Message::Manifest(manifest) => {
                self.handle_manifest(addr, manifest).await?
            }

            protocol::packet::Message::Event(event) => self.handle_event(addr, event).await?,

            protocol::packet::Message::Transfer(transfer) => {
                self.clone().handle_transfer(addr, transfer).await?
            }

            protocol::packet::Message::Whatis(whatis) => self.handle_whatis(addr, whatis).await?,

            protocol::packet::Message::Done(done) => self.handle_done(addr, done).await?,

            _ => {}
        }

        Ok(())
    }

    #[cfg(not(debug_assertions))]
    fn generate_folder_code() -> String {
        let mut rng = rand::rng();
        let mut segments: Vec<String> = Vec::with_capacity(5);

        for _ in 0..5 {
            let segment: String = (0..5)
                .map(|_| {
                    let idx = rng.random_range(0..CHARSET.len());
                    CHARSET[idx] as char
                })
                .collect();
            segments.push(segment);
        }

        segments.join("-")
    }

    #[cfg(debug_assertions)]
    fn generate_folder_code() -> String {
        String::from("code")
    }

    fn enum_files_from_folder(
        db: &PooledConnection<SqliteConnectionManager>,
        folder_id: i64,
    ) -> anyhow::Result<Vec<protocol::room_info::File>> {
        let mut stmt = db.prepare("SELECT name FROM filenames WHERE folder = ?1")?;
        Ok(stmt
            .query_map([folder_id], |r| {
                let name = r.get::<_, String>(0)?;

                Ok(protocol::room_info::File { name })
            })?
            .filter_map(|r| r.ok())
            .collect::<Vec<protocol::room_info::File>>())
    }

    fn delete_delta(
        db: &PooledConnection<SqliteConnectionManager>,
        folder_id: i64,
        namehash: i64,
        cookie: Option<i64>,
    ) -> anyhow::Result<()> {
        if let Some(cookie) = cookie {
            db.execute(
                "DELETE FROM journal WHERE folder = ?1 AND name = ?2 AND cookie = ?3",
                (folder_id, namehash, cookie),
            )?;
        } else {
            db.execute(
                "DELETE FROM journal WHERE folder = ?1 AND name = ?2",
                (folder_id, namehash),
            )?;
        }

        Ok(())
    }

    async fn handle_done(
        self: &Arc<Self>,
        addr: SocketAddr,
        done: protocol::TransferDone,
    ) -> anyhow::Result<()> {
        let db = self.db_pool.get()?;

        let folder_id = {
            let mut stmt = db.prepare("SELECT current_folder FROM users WHERE addr = ?1")?;
            stmt.query_one([addr.to_string()], |r| r.get::<_, i64>(0))?
        };

        let cookie: Option<i64> = {
            let mut locks_lock = self.locks.lock().await;
            if let Some(lock_state) = locks_lock.get(&(folder_id, done.namehash as i64)) {
                if lock_state.by == addr {
                    let c = lock_state.cookie as i64;

                    locks_lock.remove(&(folder_id, done.namehash as i64));

                    Some(c)
                } else {
                    None
                }
            } else {
                None
            }
        };

        if let Some(cookie) = cookie {
            tracing::info!("lock released by {:?} for file {}", addr, done.namehash);

            {
                let mut outgoing_lock = self.outgoing_transfer_requests.lock().await;
                outgoing_lock.remove(&(done.namehash as i64));
            }

            Self::delete_delta(&db, folder_id, done.namehash as i64, Some(cookie))?;
        }

        Ok(())
    }

    async fn handle_auth(
        self: &Arc<Self>,
        addr: SocketAddr,
        auth: protocol::Auth,
    ) -> anyhow::Result<()> {
        let db = self.db_pool.get()?;
        let streams_lock = self.streams.read().await;
        let stream = streams_lock
            .get(&addr)
            .ok_or(anyhow::anyhow!("could not find stream for client"))?;

        if let Some(folder_code) = auth.folder {
            // user wants to join a folder and is new
            let mut stmt = db.prepare("SELECT id, password FROM folders WHERE code = ?1")?;
            stmt.query_one([&folder_code], |row| {
                let (folder_id, folder_pass_hash) =
                    (row.get::<_, i64>(0)?, row.get::<_, String>(1)?);

                let mut hasher = blake2::Blake2b512::new();
                hasher.update(&auth.password);
                let final_hash = hasher.finalize();
                let digest = base16ct::lower::encode_string(&final_hash);

                stream
                    .send(Ch::OutPacket(protocol::Packet {
                        code: protocol::Return::NoneUnspecified as i32,
                        message: Some(if digest == folder_pass_hash {
                            if db
                                .execute(
                                    "INSERT INTO users (addr, current_folder) VALUES (?1, ?2)",
                                    (addr.to_string(), folder_id),
                                )
                                .is_ok()
                            {
                                if let Ok(files) = Self::enum_files_from_folder(&db, folder_id) {
                                    protocol::packet::Message::RoomInfo(protocol::RoomInfo {
                                        id: folder_id as u64,
                                        code: folder_code.clone(),
                                        files,
                                    })
                                } else {
                                    protocol::packet::Message::Die(protocol::Die {
                                        reason: Some(String::from("failed to enumerate directory")),
                                    })
                                }
                            } else {
                                protocol::packet::Message::Die(protocol::Die {
                                    reason: Some(String::from("could not add user to db")),
                                })
                            }
                        } else {
                            protocol::packet::Message::Die(protocol::Die {
                                reason: Some(String::from("auth failure")),
                            })
                        }),
                    }))
                    .map_err(|_| rusqlite::Error::UnwindingPanic)?;

                Ok(())
            })?;
        } else {
            // user wants to create a folder and is new
            stream.send(Ch::OutPacket(protocol::Packet {
                code: protocol::Return::NoneUnspecified as i32,
                message: Some(
                    if let Ok((folder_code, folder_id)) = {
                        // generate folder and return folder code

                        let mut hasher = blake2::Blake2b512::new();
                        hasher.update(&auth.password);
                        let final_hash = hasher.finalize();
                        let digest = base16ct::lower::encode_string(&final_hash);

                        let (folder_code, folder_id) = loop {
                            let folder_code = Self::generate_folder_code();

                            let mut stmt = db.prepare(
                                "
                                INSERT INTO folders (code, password)
                                VALUES (?1, ?2)
                                RETURNING code, id
                                ",
                            )?;

                            if let Ok((code, id)) = stmt.query_row([&folder_code, &digest], |row| {
                                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
                            }) {
                                tracing::debug!("created new room {}", folder_code);
                                break Ok::<(String, i64), anyhow::Error>((code, id));
                            }
                        }?;

                        // add user
                        db.execute(
                            "INSERT INTO users (addr, current_folder) VALUES (?1, ?2)",
                            (addr.to_string(), folder_id),
                        )?;

                        tracing::debug!("added new user for folder {}", folder_id);

                        Ok::<(String, i64), anyhow::Error>((folder_code, folder_id))
                    } {
                        let mut stmt =
                            db.prepare("SELECT name FROM filenames WHERE folder = ?1")?;

                        let files: Vec<protocol::room_info::File> = stmt
                            .query_map([folder_id], |row| {
                                let name = row.get::<_, String>(0)?;

                                Ok(protocol::room_info::File { name })
                            })?
                            .filter_map(|r| r.ok())
                            .collect();

                        protocol::packet::Message::RoomInfo(protocol::RoomInfo {
                            id: folder_id as u64,
                            code: folder_code,
                            files,
                        })
                    } else {
                        protocol::packet::Message::Die(protocol::Die {
                            reason: Some(String::from("failed to authenticate")),
                        })
                    },
                ),
            }))?;
        }
        Ok(())
    }

    /// if a client disconnects before a delta xfer is complete,
    /// the data will be corrupted. this routine allows a file to be restored
    /// by clearing the files and requesting xfers from any other client
    async fn clean_file(
        self: &Arc<Self>,
        db: PooledConnection<SqliteConnectionManager>,
        ignore_addr: SocketAddr,
        folder_id: i64,
        namehash: i64,
    ) -> anyhow::Result<()> {
        let filename: String = db.query_one(
            "SELECT name FROM filenames WHERE folder = ?1 AND namehash = ?2",
            [folder_id, namehash],
            |r| r.get(0),
        )?;

        db.execute(
            "DELETE FROM blocks WHERE folder = ?1 AND name = ?2",
            (folder_id, namehash),
        )?;

        let streams_lock = self.streams.read().await;
        for stream in streams_lock.iter() {
            if *stream.0 == ignore_addr {
                continue;
            }

            tracing::debug!("trying to clean {} by asking {}", filename, stream.0);

            stream.1.send(Ch::OutPacket(protocol::Packet {
                code: protocol::Return::NoneUnspecified as i32,
                message: Some(protocol::packet::Message::Whatis(protocol::WhatIs {
                    filename,
                })),
            }))?;

            return Ok(());
        }

        Ok(())
    }

    async fn handle_die(
        self: &Arc<Self>,
        addr: SocketAddr,
        die: protocol::Die,
    ) -> anyhow::Result<()> {
        let db = self.db_pool.get()?;

        let folder_id = {
            let mut stmt = db.prepare("SELECT current_folder FROM users WHERE addr = ?1")?;
            stmt.query_one([addr.to_string()], |r| r.get::<_, i64>(0))?
        };

        // delete folder if last user left in folder
        db.execute(
            "DELETE FROM folders WHERE(SELECT COUNT(*)FROM users WHERE
            current_folder=folders.id)=1 AND EXISTS(SELECT 1 FROM users WHERE
            current_folder=folders.id AND addr=?1)",
            [addr.to_string()],
        )?;

        db.execute("DELETE FROM users WHERE addr = ?1", [addr.to_string()])?;

        // remove stream
        {
            let mut streams_lock = self.streams.write().await;
            streams_lock
                .remove(&addr)
                .ok_or(anyhow::anyhow!("tried to remove non-existant stream"))?;
        }

        // remove any deltas or xfer requests
        {
            let mut outgoing_lock = self.outgoing_transfer_requests.lock().await;
            if let Some((namehash, _)) = outgoing_lock.iter_mut().find(|(_, v)| v.who == addr) {
                Self::delete_delta(&db, folder_id, *namehash, None)?;

                // TODO: MARK FILE AS "DIRTY" AND REQUEST FILE AGAIN FROM ANY OTHER USER
                // IF NO OTHER USERS, DELETE FILE ENTRY
                self.clean_file(db, addr, folder_id, *namehash).await?;
            }

            outgoing_lock.retain(|_, v| v.who != addr);
        }

        tracing::debug!("peer {} disconnected: {:?}", addr, die.reason);

        Ok(())
    }

    async fn handle_manifest(
        self: &Arc<Self>,
        addr: SocketAddr,
        manifest: protocol::FileManifest,
    ) -> anyhow::Result<()> {
        let streams_lock = self.streams.read().await;
        let stream = streams_lock
            .get(&addr)
            .ok_or(anyhow::anyhow!("could not find stream for peer"))?;

        // reject empty manifests
        if manifest.blocks.is_empty() {
            stream.send(Ch::OutPacket(protocol::Packet {
                code: protocol::Return::NoneUnspecified as i32,
                message: Some(protocol::packet::Message::Die(protocol::Die {
                    reason: Some(String::from("rejecting empty manifest")),
                })),
            }))?;

            return Ok(());
        }

        let namehash = xxhash_rust::xxh3::xxh3_64(manifest.filename.as_bytes()) as i64;

        let db = self.db_pool.get()?;

        let folder_id: i64 = db.query_row(
            "SELECT current_folder FROM users WHERE addr = ?1",
            [addr.to_string()],
            |row| row.get(0),
        )?;

        let exists_in_db: bool = db.query_row(
            "SELECT EXISTS(SELECT 1 FROM filenames WHERE folder = ?1 AND name = ?2)",
            (folder_id, &manifest.filename),
            |row| row.get(0),
        )?;

        if !exists_in_db {
            tracing::debug!(
                "file {} is not part of folder {}, adding",
                manifest.filename,
                folder_id
            );

            self.create_file_entry(folder_id, &manifest.filename, namehash)
                .await?;
        }

        // are other clients done transferring etc
        {
            let mut locks_lock = self.locks.lock().await;
            match locks_lock.get(&(folder_id, namehash)) {
                // if locked, reject
                Some(lock_state) => {
                    tracing::debug!("file locked by {:?}, rejecting {:?}", lock_state.by, addr);
                    stream.send(Ch::OutPacket(protocol::Packet {
                        code: protocol::Return::TransfersPending as i32,
                        message: Some(protocol::packet::Message::Manifest(manifest)),
                    }))?;
                    return Ok(());
                }
                // otherwise
                _ => {
                    locks_lock.insert(
                        (folder_id, namehash),
                        LockState {
                            by: addr,
                            cookie: manifest.cookie(),
                        },
                    );
                    tracing::debug!("lock acquired by {:?} for file {}", addr, namehash);
                }
            }
        }

        let mut set: HashSet<TransferMetadata> = HashSet::new();
        let timestamp = Self::timestamp()?;

        manifest
            .blocks
            .iter()
            .map(|block| {
                let mut stmt =
                    db.prepare("SELECT * FROM blocks WHERE folder = ?1 AND name = ?2 AND hash = ?3 AND start = ?4 AND end = ?5")?;

                if stmt
                    .query_one(
                        (folder_id, namehash, block.hash as i64, block.start as i64, block.end as i64),
                        |_| Ok(()),
                    )
                    .is_err()
                {
                    set.insert(TransferMetadata {
                        hash: block.hash,
                        start: block.start,
                        end: block.end,
                        timestamp,
                        attempts: 0,
                        cookie: block.cookie,
                    });

                    let mut block_with_namehash = block.clone();
                    block_with_namehash.namehash = Some(namehash as u64);
                    block_with_namehash.cookie = block.cookie;

                    stream.send(Ch::OutPacket(protocol::Packet {
                        code: protocol::Return::NoneUnspecified as i32,
                        message: Some(protocol::packet::Message::Transfer(protocol::Transfer {
                            metadata: Some(block_with_namehash),
                            mode: protocol::DataMode::WholeUnspecified as i32,
                            data: None,
                        })),
                    }))?;

                    // tracing::debug!(
                    //     "requesting block {}:[{}, {}] from client for file {}",
                    //     block.hash,
                    //     block.start,
                    //     block.end,
                    //     manifest.filename
                    // );
                }

                Ok::<(), anyhow::Error>(())
            })
            .collect::<anyhow::Result<()>>()?;

        if set.is_empty() {
            // ignore this, go away
            tracing::debug!("manifest is identical, ignoring");

            let mut locks_lock = self.locks.lock().await;
            locks_lock.remove(&(folder_id, namehash));

            return Ok(());
        }

        {
            let new_blocks = manifest
                .blocks
                .iter()
                .map(|m| (m.hash, m.start, m.end))
                .collect();

            let datahash = manifest
                .hash
                .ok_or(anyhow::anyhow!("manifest needs a data hash"))?;

            // add data hash to journal w/o any other data
            // no start,end,contents means full file data hash
            db.execute(
                "INSERT OR REPLACE INTO journal (folder, name, hash, cookie)
                 VALUES (?1, ?2, ?3, ?4)",
                (
                    folder_id,
                    namehash,
                    datahash as i64,
                    manifest.cookie() as i64,
                ),
            )?;

            // delta has its own cookie and is stored in journal until it is time to apply
            self.process_delta(
                db,
                folder_id,
                namehash,
                manifest.cookie() as i64,
                new_blocks,
            )
            .await?;

            let mut outgoing_lock = self.outgoing_transfer_requests.lock().await;
            outgoing_lock.insert(
                namehash,
                IncompleteTransfer {
                    transfers: set,
                    who: addr,
                },
            );
        }

        tracing::debug!(
            "received manifest for file {} cookie {}",
            manifest.filename,
            manifest.cookie()
        );

        Ok(())
    }

    async fn create_file_entry(
        self: &Arc<Self>,
        folder_id: i64,
        name_string: &str,
        namehash: i64,
    ) -> anyhow::Result<()> {
        let db = self.db_pool.get()?;

        db.execute(
            "INSERT OR REPLACE INTO filenames (folder, name, namehash) SELECT ?1, ?2, ?3 WHERE NOT EXISTS (SELECT 1 FROM filenames WHERE folder = ?1 AND name = ?2)",
            (folder_id, name_string, namehash),
        )?;

        tracing::debug!("propagating create file {}", name_string);

        self.streams
            .read()
            .await
            .iter()
            .map(|s| {
                s.1.send(Ch::OutPacket(protocol::Packet {
                    code: protocol::Return::NoneUnspecified as i32,
                    message: Some(protocol::packet::Message::Event(protocol::Event {
                        event: protocol::FileEvent::CreateUnspecified as i32,
                        filename: String::from(name_string),
                    })),
                }))?;
                anyhow::Ok(())
            })
            .collect::<anyhow::Result<()>>()?;

        Ok(())
    }

    async fn delete_file_entry(
        self: &Arc<Self>,
        folder_id: i64,
        namehash: i64,
    ) -> anyhow::Result<()> {
        let db = self.db_pool.get()?;

        db.execute(
            "DELETE FROM blocks WHERE folder = ?1 AND name = ?2",
            (folder_id, namehash),
        )?;

        tracing::debug!(
            "deleted all blocks related to file {} in folder {}",
            namehash,
            folder_id
        );

        let filename = db.query_one(
            "DELETE FROM filenames WHERE folder = ?1 AND namehash = ?2 RETURNING name",
            (folder_id, namehash),
            |r| r.get::<_, String>(0),
        )?;

        tracing::debug!(
            "deleted filename entry for namehash {} in folder {}",
            namehash,
            folder_id
        );

        tracing::debug!("propagating delete file {}", filename);

        self.streams
            .read()
            .await
            .iter()
            .map(|s| {
                s.1.send(Ch::OutPacket(protocol::Packet {
                    code: protocol::Return::NoneUnspecified as i32,
                    message: Some(protocol::packet::Message::Event(protocol::Event {
                        event: protocol::FileEvent::Delete as i32,
                        filename: filename.clone(),
                    })),
                }))?;
                anyhow::Ok(())
            })
            .collect::<anyhow::Result<()>>()?;

        Ok(())
    }

    async fn handle_event(
        self: &Arc<Self>,
        addr: SocketAddr,
        event: protocol::Event,
    ) -> anyhow::Result<()> {
        let db = self.db_pool.get()?;
        let folder_id: i64 = db.query_row(
            "SELECT current_folder FROM users WHERE addr = ?1",
            [addr.to_string()],
            |row| row.get(0),
        )?;

        let file_namehash: i64 = db
            .query_row(
                "SELECT namehash FROM filenames WHERE folder = ?1 AND name = ?2",
                (folder_id, &event.filename),
                |row| row.get::<_, i64>(0),
            )
            .or_else(|_| {
                Ok::<i64, anyhow::Error>(
                    xxhash_rust::xxh3::xxh3_64(event.filename.as_bytes()) as i64
                )
            })?;

        let streams_lock = self.streams.read().await;
        let _ = streams_lock
            .iter()
            .map(|s| {
                if *s.0 == addr {
                    return Ok(());
                }

                s.1.send(Ch::OutPacket(protocol::Packet {
                    code: protocol::Return::NoneUnspecified as i32,
                    message: Some(protocol::packet::Message::Event(event.clone())),
                }))
            })
            .collect::<Result<(), _>>();

        let _ = match event.event() {
            protocol::FileEvent::CreateUnspecified => {
                self.create_file_entry(folder_id, &event.filename, file_namehash)
                    .await
            }

            protocol::FileEvent::Delete => self.delete_file_entry(folder_id, file_namehash).await,
        };

        Ok(())
    }

    /// aggregates all of the hashes in order by offset
    /// from the temp and the current then
    async fn process_delta(
        self: &Arc<Self>,
        db: PooledConnection<SqliteConnectionManager>,
        folder_id: i64,
        namehash: i64,
        cookie: i64,
        new_blocks: Vec<(u64, u64, u64)>,
    ) -> anyhow::Result<()> {
        let old_blocks: Vec<(u64, u64, u64)> = {
            let mut stmt = db.prepare(
                "SELECT hash, start, end FROM blocks WHERE folder = ?1 AND name = ?2 ORDER BY start ASC"
            )?;

            stmt.query_map((folder_id, namehash), |row| {
                Ok((
                    row.get::<_, i64>(0)? as u64,
                    row.get::<_, i64>(1)? as u64,
                    row.get::<_, i64>(2)? as u64,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?
        };

        let diff_ops: Vec<protocol::delta::Operation> =
            similar::capture_diff_slices(similar::Algorithm::Myers, &old_blocks, &new_blocks)
                .iter()
                .flat_map(|x| x.iter_changes(&old_blocks, &new_blocks))
                .filter(|x| x.tag() != similar::ChangeTag::Equal)
                .map(|x| {
                    let (hash, start, end) =
                        (x.value().0 as i64, x.value().1 as i64, x.value().2 as i64);

                    Ok::<protocol::delta::Operation, anyhow::Error>(protocol::delta::Operation {
                        op_type: match x.tag() {
                            similar::ChangeTag::Equal => protocol::delta::OpType::EqualUnspecified,
                            similar::ChangeTag::Insert => protocol::delta::OpType::Insert,
                            similar::ChangeTag::Delete => protocol::delta::OpType::Delete,
                        } as i32,
                        hash: hash as u64,
                        start: start as u64,
                        end: end as u64,
                    })
                })
                .filter_map(|f| f.ok())
                .collect();

        let mut final_ops = Vec::new();
        let mut i = 0;
        while i < diff_ops.len() {
            if i + 1 < diff_ops.len()
                && diff_ops[i].op_type == protocol::delta::OpType::Delete as i32
                && diff_ops[i + 1].op_type == protocol::delta::OpType::Insert as i32
                && diff_ops[i].start == diff_ops[i + 1].start
                && diff_ops[i].end == diff_ops[i + 1].end
            {
                let mut modify_op = diff_ops[i + 1].clone();
                modify_op.op_type = protocol::delta::OpType::Modify as i32;

                final_ops.push(modify_op);
                i += 2;
            } else {
                final_ops.push(diff_ops[i].clone());
                i += 1;
            }
        }

        // insert delta ops without data, transfers will fill these out
        for op in final_ops {
            db.execute(
                "INSERT OR REPLACE INTO journal (folder, name, start, end, hash, cookie, op, contents) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                (
                    folder_id,
                    namehash,
                    op.start as i64,
                    op.end as i64,
                    op.hash as i64,
                    cookie,
                    op.op_type,
                    Option::<rusqlite::blob::ZeroBlob>::None,
                )
            )?;
        }

        Ok(())
    }

    fn apply_journaled_delta(
        self: &Arc<Self>,
        db: PooledConnection<SqliteConnectionManager>,
        folder_id: i64,
        namehash: i64,
        cookie: i64,
    ) -> anyhow::Result<protocol::Delta> {
        // fetch delta ops sorted in proper order
        let mut stmt = db.prepare(
            "SELECT hash, start, end, op FROM journal WHERE name = ?1 AND cookie = ?2
             ORDER BY CASE WHEN op = 3 THEN 0 ELSE 1 END, CASE WHEN op = 3 THEN -start ELSE start END",
        )?;

        let filename: String = db.query_row(
            "SELECT name FROM filenames WHERE folder = ?1 AND namehash = ?2",
            [folder_id, namehash],
            |r| r.get(0),
        )?;

        let largest_end_offset = match db.query_row(
            "SELECT MAX(end) FROM blocks WHERE folder = ?1 AND name = ?2",
            [folder_id, namehash],
            |r| r.get::<_, i64>(0),
        ) {
            Ok(eo) => eo as u64,
            Err(_) => 0u64,
        };

        let datahash = db.query_row(
            "DELETE FROM journal
             WHERE folder = ?1 AND name = ?2 AND cookie = ?3
             AND start IS NULL AND end IS NULL AND contents IS NULL
             RETURNING hash",
            (folder_id, namehash, cookie),
            |r| r.get::<_, i64>(0),
        )? as u64;

        let mut ops = stmt.query([namehash, cookie])?;
        let mut delta = protocol::Delta {
            size: largest_end_offset,
            filename,
            cookie: cookie as u64,
            hash: datahash,
            ops: vec![],
        };

        while let Ok(Some(row)) = ops.next() {
            let (hash, start, end, op) = (
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                protocol::delta::OpType::try_from(row.get::<_, i64>(3)? as i32)?,
            );

            delta.ops.push(protocol::delta::Operation {
                op_type: op as i32,
                start: start as u64,
                end: end as u64,
                hash: hash as u64,
            });

            match op {
                protocol::delta::OpType::Delete => {
                    db.execute(
                        "DELETE FROM blocks
                         WHERE folder = ?1 AND name = ?2 AND hash = ?3 AND start = ?4 AND end = ?5",
                        (folder_id, namehash, hash as i64, start as i64, end),
                    )?;
                }

                protocol::delta::OpType::Insert | protocol::delta::OpType::EqualUnspecified => {
                    db.execute(
                        "INSERT OR REPLACE INTO blocks
                         SELECT folder, name, hash, start, end, contents FROM journal
                         WHERE folder = ?1 AND name = ?2 AND hash = ?3 AND start = ?4 AND end = ?5 AND cookie = ?6",
                         (
                             folder_id, namehash, hash as i64, start as i64, end, cookie
                         ))?;
                }

                protocol::delta::OpType::Modify => {
                    db.execute(
                        "DELETE FROM blocks
                              WHERE folder = ?1 AND name = ?2 AND start = ?3 AND end = ?4",
                        (folder_id, namehash, start as i64, end),
                    )?;

                    db.execute(
                        "INSERT INTO blocks (folder, name, hash, start, end, contents)
                         SELECT folder, name, hash, start, end, contents
                         FROM journal
                         WHERE folder = ?1 AND name = ?2 AND start = ?3 AND end = ?4 AND hash = ?5 AND cookie = ?6",
                        (
                             folder_id, namehash, start as i64, end, hash as i64, cookie
                         ))?;
                }
            }

            db.execute(
                "DELETE FROM journal
                 WHERE folder = ?1 AND name = ?2 AND hash = ?3 AND start = ?4 AND end = ?5 AND cookie = ?6",
                 (
                     folder_id, namehash, hash as i64, start as i64, end, cookie
                 ))?;

            tracing::debug!(
                "applied {:?} to file {}:{}:{}:[{}, {}] (ck: {})",
                op,
                folder_id,
                namehash as u64,
                hash as u64,
                start as u64,
                end as u64,
                cookie as u64
            );
        }

        Ok(delta)
    }

    async fn handle_transfer(
        self: Arc<Self>,
        addr: SocketAddr,
        transfer: protocol::Transfer,
    ) -> anyhow::Result<()> {
        let db = self.db_pool.get()?;

        let mut metadata = transfer
            .metadata
            .ok_or(anyhow::anyhow!("cannot handle transfer with no metadata"))?;

        let namehash = metadata
            .namehash
            .ok_or(anyhow::anyhow!("transfer metadata missing namehash"))?;

        let folder_id: i64 = db.query_row(
            "SELECT current_folder FROM users WHERE addr = ?1",
            [addr.to_string()],
            |row| row.get(0),
        )?;

        let streams_lock = self.streams.read().await;

        // we are getting a response
        if let Some(data) = transfer.data {
            let hash = xxhash_rust::xxh3::xxh3_64(&data);
            if hash != metadata.hash {
                tracing::debug!(
                    "hash mismatch - {} != {} (ck: {})",
                    hash,
                    metadata.hash,
                    metadata.cookie()
                );
                return Ok(());
            }

            let mut outgoing_lock = self.outgoing_transfer_requests.lock().await;

            if let Some(entry) = outgoing_lock.get_mut(&(namehash as i64)) {
                if entry
                    .transfers
                    .iter()
                    .find(|e| {
                        e.start == metadata.start
                            && e.end == metadata.end
                            && e.cookie == metadata.cookie
                            && e.hash == metadata.hash
                    })
                    .is_some()
                {
                    if hash == metadata.hash {
                        let rowid = db.query_row(
                        "UPDATE journal
                         SET contents = ?7
                         WHERE folder = ?1 AND name = ?2 AND start = ?3 AND end = ?4 AND hash = ?5 AND cookie = ?6
                         RETURNING ROWID",
                        (
                            folder_id,
                            namehash as i64,
                            metadata.start as i64,
                            metadata.end as i64,
                            hash as i64,
                            metadata.cookie() as i64,
                            Some(rusqlite::blob::ZeroBlob(
                                (metadata.end - metadata.start) as i32,
                            )),
                        ),
                        |r| r.get::<_, i64>(0)
                    )?;

                        let mut blob =
                            db.blob_open(rusqlite::MAIN_DB, "journal", "contents", rowid, false)?;

                        if blob.write(&data)? != data.len() {
                            anyhow::bail!("did not write full block to database");
                        }

                        blob.close()?;

                        tracing::debug!(
                            "got back data for {}:[{}, {}]",
                            namehash,
                            metadata.start,
                            metadata.end
                        );
                    } else {
                        tracing::debug!("hash mismatch - {} != {}", hash, metadata.hash);
                    }
                }

                entry.transfers.retain(|e| {
                    !(e.start == metadata.start
                        && e.end == metadata.end
                        && e.cookie == metadata.cookie
                        && e.hash == metadata.hash)
                });

                if entry.transfers.is_empty() {
                    let who = entry.who;

                    let _ = entry;

                    outgoing_lock
                        .remove(&(namehash as i64))
                        .ok_or(anyhow::anyhow!("what?"))?;

                    if hash != metadata.hash {
                        {
                            let mut locks_lock = self.locks.lock().await;
                            locks_lock.remove(&(folder_id, namehash as i64));
                        }

                        return Ok(());
                    }

                    let delta = self.apply_journaled_delta(
                        db,
                        folder_id,
                        namehash as i64,
                        metadata.cookie() as i64,
                    )?;

                    drop(outgoing_lock);

                    tracing::info!(
                        "transfer queue satisfied for file {namehash}. broadcasting delta"
                    );

                    let _ = streams_lock
                        .iter()
                        .map(|s| {
                            if *s.0 == who {
                                // tell peer to send queued manifest again if necessary
                                s.1.send(Ch::OutPacket(protocol::Packet {
                                    code: protocol::Return::NoneUnspecified as i32,
                                    message: Some(protocol::packet::Message::SendAgain(
                                        protocol::SendAgain { namehash },
                                    )),
                                }))?;

                                tracing::debug!("send {} to send {} again", s.0, namehash);

                                return Ok(());
                            }

                            if let Err(e) = s.1.send(Ch::OutPacket(protocol::Packet {
                                code: protocol::Return::NoneUnspecified as i32,
                                message: Some(protocol::packet::Message::Delta(delta.clone())),
                            })) {
                                tracing::error!("delta broadcast error: {}", e.to_string());
                            }

                            tracing::debug!("sent delta to {}", addr);

                            Ok(())
                        })
                        .collect::<anyhow::Result<()>>();
                }
            }
        } else {
            // we are getting a request for block data
            // tracing::debug!(
            //     "client wants block {}:{}:[{}, {}]",
            //     namehash,
            //     metadata.hash,
            //     metadata.start,
            //     metadata.end
            // );

            let res: (i64, i64) = match db.query_row(
                "SELECT ROWID, hash FROM blocks WHERE folder = ?1 AND name = ?2 AND start = ?3 AND end = ?4 LIMIT 1",
                [folder_id, namehash as i64, metadata.start as i64, metadata.end as i64],
                |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)),
            ) {
                Ok(r) => r,
                Err(e) => {
                    streams_lock
                        .get(&addr)
                        .ok_or(anyhow::anyhow!("could not get client stream"))?
                        .send(Ch::OutPacket(protocol::Packet {
                            code: protocol::Return::BlockNotFound as i32,
                            message: Some(protocol::packet::Message::Transfer(
                                protocol::Transfer {
                                    metadata: Some(metadata),
                                    mode: protocol::DataMode::WholeUnspecified as i32,
                                    data: None,
                                },
                            )),
                        }))?;

                    {
                        let mut locks_lock = self.locks.lock().await;
                        locks_lock.remove(&(folder_id, namehash as i64));
                    }

                    anyhow::bail!("could not find block {}:[{}, {}]", metadata.namehash(), metadata.start, metadata.end);
                }
            };

            let size_to_read = (metadata.end - metadata.start) as usize;
            let mut data: Vec<u8> = vec![0u8; size_to_read];
            let mut contents =
                db.blob_open(rusqlite::MAIN_DB, "blocks", "contents", res.0, true)?;
            contents.read_exact(&mut data)?;

            let block_hash = xxhash_rust::xxh3::xxh3_64(&data);

            metadata.hash = if block_hash == res.1 as u64 {
                res.1 as u64
            } else {
                block_hash
            };

            streams_lock
                .get(&addr)
                .ok_or(anyhow::anyhow!("could not get client stream"))?
                .send(Ch::OutPacket(protocol::Packet {
                    code: protocol::Return::NoneUnspecified as i32,
                    message: Some(protocol::packet::Message::Transfer(protocol::Transfer {
                        metadata: Some(metadata),
                        mode: protocol::DataMode::WholeUnspecified as i32,
                        data: Some(data),
                    })),
                }))?;

            // tracing::debug!(
            //     "satisfied transfer request for {}:[{}, {}]",
            //     namehash,
            //     metadata.start,
            //     metadata.end
            // );
        }

        Ok(())
    }

    async fn handle_whatis(
        self: &Arc<Self>,
        addr: SocketAddr,
        whatis: protocol::WhatIs,
    ) -> anyhow::Result<()> {
        let db = self.db_pool.get()?;
        let streams_lock = self.streams.read().await;
        let stream = streams_lock
            .get(&addr)
            .ok_or(anyhow::anyhow!("could not find stream for client"))?;

        let folder_id: i64 = db.query_row(
            "SELECT current_folder FROM users WHERE addr = ?1",
            [addr.to_string()],
            |row| row.get(0),
        )?;

        let mut stmt = db.prepare("SELECT namehash FROM filenames WHERE name = ?1")?;

        stmt.query_one([whatis.filename.clone()], |row| {
            let filehash = row.get::<_, i64>(0)?;

            let mut blocks_stmt =
                db.prepare("SELECT hash, start, end FROM blocks WHERE folder = ?1 AND name = ?2")?;

            let largest_end_offset = match db.query_one(
                "SELECT MAX(end) FROM blocks WHERE folder = ?1 AND name = ?2",
                [folder_id, filehash],
                |r| r.get::<_, i64>(0),
            ) {
                Ok(eo) => eo as u64,
                Err(_) => 0u64,
            };

            let mut manifest = protocol::FileManifest {
                filename: whatis.filename,
                timestamp: Self::timestamp().map_err(|_| rusqlite::Error::UnwindingPanic)?,
                size: largest_end_offset,
                hash: None,
                cookie: Some(rand::random()),
                blocks: vec![],
            };

            let mut blocks = blocks_stmt.query([folder_id, filehash])?;
            while let Ok(Some(block)) = blocks.next() {
                manifest.blocks.push(protocol::BlockMetadata {
                    hash: block.get::<_, i64>(0)? as u64,
                    start: block.get::<_, i64>(1)? as u64,
                    end: block.get::<_, i64>(2)? as u64,
                    cookie: manifest.cookie,
                    namehash: None,
                });
            }

            tracing::debug!("sending manifest for file {}", manifest.filename);

            stream
                .send(Ch::OutPacket(protocol::Packet {
                    code: protocol::Return::NoneUnspecified as i32,
                    message: Some(protocol::packet::Message::Manifest(manifest)),
                }))
                .map_err(|_| rusqlite::Error::UnwindingPanic)?;

            Ok(())
        })?;

        Ok(())
    }

    async fn check_outgoing_transfers(self: &Arc<Self>) -> anyhow::Result<()> {
        let current_timestamp = Self::timestamp()?;

        for (namehash, item) in self.outgoing_transfer_requests.lock().await.iter_mut() {
            let late_requests: Vec<TransferMetadata> = item
                .transfers
                .extract_if(|e| current_timestamp - e.timestamp >= REFRESH_INTERVAL)
                .collect();

            late_requests
                .iter()
                .map(|req| {
                    if req.attempts + 1 >= REFRESH_ATTEMPTS {
                        // tracing::debug!(
                        //     "request for {}:[{}, {}] max attempts reached",
                        //     req.0,
                        //     req.1,
                        //     req.2
                        // );

                        return Ok(());
                    }

                    let metadata = protocol::BlockMetadata {
                        namehash: Some(*namehash as u64),
                        start: req.start,
                        end: req.end,
                        cookie: req.cookie,
                        hash: req.hash,
                    };

                    tokio::task::block_in_place(|| {
                        self.streams
                            .blocking_read()
                            .get(&item.who)
                            .map(|stream| {
                                stream.send(Ch::OutPacket(protocol::Packet {
                                    code: protocol::Return::NoneUnspecified as i32,
                                    message: Some(protocol::packet::Message::Transfer(
                                        protocol::Transfer {
                                            metadata: Some(metadata),
                                            mode: protocol::DataMode::WholeUnspecified as i32,
                                            data: None,
                                        },
                                    )),
                                }))?;

                                anyhow::Ok(())
                            })
                            .ok_or(anyhow::anyhow!("failed to send transfer request"))
                    })??;

                    item.transfers.insert(TransferMetadata {
                        start: req.start,
                        end: req.end,
                        attempts: req.attempts + 1,
                        timestamp: current_timestamp,
                        cookie: req.cookie,
                        hash: req.hash,
                    });

                    // tracing::debug!(
                    //     "resending transfer request: {}:[{}, {}]",
                    //     namehash,
                    //     req.0,
                    //     req.1
                    // );

                    anyhow::Ok(())
                })
                .collect::<anyhow::Result<()>>()?;
        }

        Ok(())
    }
}
