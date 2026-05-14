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
use rusqlite::fallible_iterator::FallibleIterator;
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
const CREATE_FOLDERS_STMT: &str = "CREATE TABLE IF NOT EXISTS folders (id INTEGER PRIMARY KEY AUTOINCREMENT, code TEXT UNIQUE, password TEXT)";
const CREATE_FILENAMES_STMT: &str = "CREATE TABLE IF NOT EXISTS filenames (folder INTEGER, name TEXT UNIQUE, namehash INTEGER UNIQUE, datahash INTEGER)";
const CREATE_BLOCKS_STMT: &str = "CREATE TABLE IF NOT EXISTS blocks (folder INTEGER, name INTEGER, hash INTEGER, start INTEGER, end INTEGER, origin INTEGER)";
const CREATE_JOURNAL_STMT: &str = "CREATE TABLE IF NOT EXISTS journal (folder INTEGER, name INTEGER, start INTEGER, end INTEGER, hash INTEGER, cookie INTEGER, op INTEGER, origin INTEGER, UNIQUE(folder, name, start, end, cookie))";

const EV_BUF_SIZE: usize = 32;

struct LockState {
    pub by: SocketAddr,
    pub cookie: u64,
    pub waiting: HashSet<SocketAddr>,
}

pub struct Server {
    config: Config,
    endpoint: Endpoint,
    db_pool: Pool<SqliteConnectionManager>,
    aux_streams: RwLock<HashMap<SocketAddr, UnboundedSender<protocol::Packet>>>,
    streams: RwLock<HashMap<SocketAddr, UnboundedSender<protocol::Packet>>>,
    locks: Mutex<HashMap<(i64, i64), LockState>>,
}

impl Server {
    pub fn new(config: Config) -> anyhow::Result<Arc<Server>> {
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

        Ok(Arc::new(Server {
            config,
            endpoint,
            db_pool: pool.clone(),
            aux_streams: RwLock::new(HashMap::new()),
            streams: RwLock::new(HashMap::new()),
            locks: Mutex::new(HashMap::new()),
        }))
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

        let (send, mut recv) = unbounded_channel::<protocol::Packet>();

        let token = tokio_util::sync::CancellationToken::new();
        let ce_token = token.clone();

        // jfc
        let self_ = self.clone();
        let self2 = self.clone();
        let self3 = self.clone();

        let addr = conn.remote_address();

        {
            let mut lock = self.streams.write().await;
            lock.insert(conn.remote_address(), send);
        }

        let futs = vec![
            // handle channel thread
            tokio::spawn(async move {
                let mut event_buffer = vec![];

                tracing::debug!("starting channel handler thread");

                loop {
                    tokio::select! {
                        sz = recv.recv_many(&mut event_buffer, EV_BUF_SIZE) => {
                            for pkt in event_buffer.drain(..sz) {
                                match Self::write_packet(&mut conn_send, &pkt).await {
                                    Err(e) => {
                                        tracing::error!("write packet error: {}", e.to_string());

                                        token.cancel();
                                    }
                                    _ => {}
                                }
                            }

                            event_buffer.clear();
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

                        Ok(bidi) = conn.accept_bi() => {
                            tracing::debug!("accepted aux stream {}", bidi.0.id());

                            let chan = unbounded_channel::<protocol::Packet>();

                            tokio::spawn(self2.clone().handle_aux_stream(
                                conn.remote_address(),
                                ce_token.clone(),
                                bidi,
                                chan.1
                            ));

                            // add stream to map
                            {
                                let mut aux_streams_lock = self2.aux_streams.write().await;
                                aux_streams_lock.insert(conn.remote_address(), chan.0);
                            }
                        }

                        p = Self::read_packet(&mut conn_recv) => {
                            match p {
                                Ok(Some(pkt)) => {
                                    if let Err(e) = self2.handle_packet(conn.remote_address(), pkt).await {
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
        ];

        futures::future::join_all(futs).await;

        Ok(())
    }

    pub(crate) async fn write_packet(
        stream: &mut SendStream,
        pkt: &protocol::Packet,
    ) -> anyhow::Result<()> {
        let encoded = pkt.encode_to_vec();
        let len = encoded.len() as u32;
        stream.write_u32(len).await?;
        stream.write_all(&encoded).await?;
        stream.flush().await?;
        Ok(())
    }

    pub(crate) async fn read_packet(
        stream: &mut RecvStream,
    ) -> anyhow::Result<Option<protocol::Packet>> {
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
                .send(protocol::Packet {
                    code: protocol::Return::NoneUnspecified as i32,
                    message: None,
                })?;

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

        let mut locks_lock = self.locks.lock().await;
        if let Some(lock_state) = locks_lock.get_mut(&(folder_id, done.namehash as i64)) {
            lock_state.waiting.remove(&addr);

            if lock_state.waiting.is_empty() {
                let (b, c) = (lock_state.by, lock_state.cookie as i64);

                tracing::info!("lock released by {:?} for file {}", addr, done.namehash);

                locks_lock.remove(&(folder_id, done.namehash as i64));

                // tell origin to delete journaled blocks
                {
                    let streams_lock = self.streams.read().await;
                    streams_lock
                        .get(&b)
                        .map(|s| {
                            s.send(protocol::Packet {
                                code: protocol::Return::NoneUnspecified as i32,
                                message: Some(protocol::packet::Message::Done(
                                    protocol::TransferDone {
                                        namehash: done.namehash,
                                        cookie: Some(c as u64),
                                    },
                                )),
                            })
                            .ok()
                        })
                        .ok_or(anyhow::anyhow!("origin gc fail"))?;
                }

                tracing::debug!("gc: told {} to release {}:{}", b, done.namehash, c);
            }
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
                    .send(protocol::Packet {
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
                    })
                    .map_err(|_| rusqlite::Error::UnwindingPanic)?;

                Ok(())
            })?;
        } else {
            // user wants to create a folder and is new
            stream.send(protocol::Packet {
                code: protocol::Return::NoneUnspecified as i32,
                message: Some(
                    if let Ok((folder_code, folder_id)) = {
                        // generate folder and return folder code

                        let mut hasher = blake2::Blake2b512::new();
                        hasher.update(&auth.password);
                        let final_hash = hasher.finalize();
                        let digest = base16ct::lower::encode_string(&final_hash);

                        // NOTE: in debug mode this will hang if there are more than two folders
                        // because every folder code is "code"
                        let (folder_code, folder_id) = loop {
                            let folder_code = Self::generate_folder_code();

                            if db
                                .execute(
                                    "INSERT INTO folders (code, password) VALUES (?1, ?2)",
                                    [&folder_code, &digest],
                                )
                                .is_ok()
                            {
                                tracing::debug!("created new room {}", folder_code);
                                break Ok::<(String, i64), anyhow::Error>((
                                    folder_code,
                                    db.last_insert_rowid(),
                                ));
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
            })?;
        }
        Ok(())
    }

    async fn handle_die(
        self: &Arc<Self>,
        addr: SocketAddr,
        die: protocol::Die,
    ) -> anyhow::Result<()> {
        let db = self.db_pool.get()?;

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
            stream.send(protocol::Packet {
                code: protocol::Return::NoneUnspecified as i32,
                message: Some(protocol::packet::Message::Die(protocol::Die {
                    reason: Some(String::from("rejecting empty manifest")),
                })),
            })?;

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

        let waiting: HashSet<SocketAddr> = {
            let mut stmt = db.prepare("SELECT addr FROM users WHERE current_folder = ?1")?;
            let mut users = stmt.query_map([folder_id], |r| r.get::<_, String>(0))?;
            let mut set = HashSet::new();

            while let Some(Ok(user)) = users.next() {
                set.insert(user.parse()?);
            }

            set
        };

        // are other clients done transferring etc
        {
            let mut locks_lock = self.locks.lock().await;
            match locks_lock.get(&(folder_id, namehash)) {
                // if locked, reject
                Some(_) => {
                    tracing::debug!("file locked, rejecting {:?}", addr);

                    stream.send(protocol::Packet {
                        code: protocol::Return::TransfersPending as i32,
                        message: Some(protocol::packet::Message::Manifest(manifest)),
                    })?;

                    return Ok(());
                }
                // otherwise
                _ => {
                    locks_lock.insert(
                        (folder_id, namehash),
                        LockState {
                            by: addr,
                            cookie: manifest.cookie(),
                            waiting,
                        },
                    );
                    tracing::debug!("lock acquired by {:?} for file {}", addr, namehash);
                }
            }
        }

        let new_blocks = manifest
            .blocks
            .iter()
            .map(|m| (m.hash, m.start, m.end))
            .collect();

        let user_id = db.query_row(
            "SELECT id FROM users WHERE addr = ?1 LIMIT 1",
            [addr.to_string()],
            |r| r.get::<_, i64>(0),
        )?;

        let datahash = manifest
            .hash
            .ok_or(anyhow::anyhow!("manifest needs a data hash"))?;

        // delta has its own cookie and is stored in journal until it is time to apply
        let delta = self
            .create_delta(
                db,
                folder_id,
                namehash,
                &manifest.filename,
                datahash as i64,
                user_id,
                manifest.cookie() as i64,
                new_blocks,
            )
            .await?;

        tracing::debug!(
            "received manifest for file {} cookie {}",
            manifest.filename,
            manifest.cookie()
        );

        let streams_lock = self.streams.read().await;

        let _ = streams_lock
            .iter()
            .map(|s| {
                if *s.0 == addr {
                    // tell peer to send queued manifest again if necessary
                    s.1.send(protocol::Packet {
                        code: protocol::Return::NoneUnspecified as i32,
                        message: Some(protocol::packet::Message::SendAgain(protocol::SendAgain {
                            namehash: namehash as u64,
                        })),
                    })?;

                    tracing::debug!("send {} to send {} again", s.0, namehash);

                    return Ok(());
                }

                if let Err(e) = s.1.send(protocol::Packet {
                    code: protocol::Return::NoneUnspecified as i32,
                    message: Some(protocol::packet::Message::Delta(delta.clone())),
                }) {
                    tracing::error!("delta broadcast error: {}", e.to_string());
                }

                tracing::debug!("sent delta to {}", *s.0);

                Ok(())
            })
            .collect::<anyhow::Result<()>>();

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
                s.1.send(protocol::Packet {
                    code: protocol::Return::NoneUnspecified as i32,
                    message: Some(protocol::packet::Message::Event(protocol::Event {
                        event: protocol::FileEvent::CreateUnspecified as i32,
                        filename: String::from(name_string),
                    })),
                })?;
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
                s.1.send(protocol::Packet {
                    code: protocol::Return::NoneUnspecified as i32,
                    message: Some(protocol::packet::Message::Event(protocol::Event {
                        event: protocol::FileEvent::Delete as i32,
                        filename: filename.clone(),
                    })),
                })?;
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

                s.1.send(protocol::Packet {
                    code: protocol::Return::NoneUnspecified as i32,
                    message: Some(protocol::packet::Message::Event(event.clone())),
                })
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

    /// creates delta
    async fn create_delta(
        self: &Arc<Self>,
        db: PooledConnection<SqliteConnectionManager>,
        folder_id: i64,
        namehash: i64,
        filename: &str,
        datahash: i64,
        origin_id: i64,
        cookie: i64,
        new_blocks: Vec<(u64, u64, u64)>,
    ) -> anyhow::Result<protocol::Delta> {
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

        let largest_end_offset = match db.query_row(
            "SELECT MAX(end) FROM blocks WHERE folder = ?1 AND name = ?2",
            [folder_id, namehash],
            |r| r.get::<_, i64>(0),
        ) {
            Ok(eo) => eo as u64,
            Err(_) => 0u64,
        };

        // update datahash
        db.execute(
            "UPDATE filenames SET datahash = ?1 WHERE folder = ?2 AND namehash = ?3",
            [datahash, folder_id, namehash],
        )?;

        // execute delta serverside
        let delta = protocol::Delta {
            size: largest_end_offset,
            filename: String::from(filename),
            origin: origin_id as u64,
            cookie: cookie as u64,
            hash: datahash as u64,
            ops: final_ops,
        };

        for op in &delta.ops {
            match op.op_type() {
                protocol::delta::OpType::Delete => {
                    db.execute(
                        "DELETE FROM blocks
                         WHERE folder = ?1 AND name = ?2 AND hash = ?3 AND start = ?4 AND end = ?5",
                        (
                            folder_id,
                            namehash,
                            op.hash as i64,
                            op.start as i64,
                            op.end as i64,
                        ),
                    )?;
                }

                protocol::delta::OpType::Insert | protocol::delta::OpType::EqualUnspecified => {
                    db.execute(
                        "INSERT INTO blocks (folder, name, hash, start, end, origin) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                        (
                            folder_id,
                            namehash,
                            op.hash as i64,
                            op.start as i64,
                            op.end as i64,
                            origin_id,
                        ),
                    )?;
                }

                protocol::delta::OpType::Modify => {
                    db.execute(
                        "DELETE FROM blocks WHERE folder = ?1 AND name = ?2 AND start = ?3 AND end = ?4",
                        (folder_id, namehash, op.start as i64, op.end as i64),
                    )?;

                    db.execute(
                        "INSERT INTO blocks (folder, name, hash, start, end, origin) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                        (folder_id, namehash, op.start as i64, op.end as i64, op.hash as i64, origin_id)
                    )?;
                }
            }
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
        } else {
            // we are getting a request for block data
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

            let mut blocks_stmt = db.prepare(
                "SELECT hash, start, end, origin FROM blocks WHERE folder = ?1 AND name = ?2",
            )?;

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
                    origin: block.get::<_, i64>(3).map(|o| o as u64).ok(),
                    cookie: manifest.cookie,
                    namehash: None,
                });
            }

            tracing::debug!("sending manifest for file {}", manifest.filename);

            stream
                .send(protocol::Packet {
                    code: protocol::Return::NoneUnspecified as i32,
                    message: Some(protocol::packet::Message::Manifest(manifest)),
                })
                .map_err(|_| rusqlite::Error::UnwindingPanic)?;

            Ok(())
        })?;

        Ok(())
    }
}
