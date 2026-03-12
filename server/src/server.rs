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
use rusqlite::MAIN_DB;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, pem::PemObject};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    select,
    sync::{
        Mutex,
        mpsc::{UnboundedSender, unbounded_channel},
    },
};
use tracing::{Instrument, Span};

pub mod protocol {
    include!(concat!(env!("OUT_DIR"), "/hsync.rs"));
}

const CHARSET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
const ALPN_QUIC_HSYNC: &[&[u8]] = &[b"hsync"];
const CREATE_USERS_STMT: &str = "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, addr TEXT, current_folder INTEGER)";
const CREATE_FOLDERS_STMT: &str = "CREATE TABLE IF NOT EXISTS folders (id INTEGER PRIMARY KEY AUTOINCREMENT, code TEXT, password TEXT)";
const CREATE_FILENAMES_STMT: &str = "CREATE TABLE IF NOT EXISTS filenames (folder INTEGER, name TEXT UNIQUE, namehash INTEGER UNIQUE)";
const CREATE_BLOCKS_STMT: &str = "CREATE TABLE IF NOT EXISTS blocks (folder INTEGER, name INTEGER, hash INTEGER, start INTEGER, end INTEGER, contents BLOB)";

pub type UserId = u64;

pub struct Server {
    config: Config,
    endpoint: Endpoint,
    db_pool: Pool<SqliteConnectionManager>,
    streams: Mutex<HashMap<SocketAddr, UnboundedSender<protocol::Packet>>>,
    outgoing_transfer_requests: Mutex<HashMap<i64, HashSet<(u64, u64)>>>,
    pending_deltas: Mutex<HashMap<i64, protocol::Delta>>,
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

        // TODO: WE NEED TO ADD HEARTBEATS! ADDING INFINITE TIMEOUT MEANS FUTURES
        //       CAN HOLD SO WE NEED TO ADD A HEARTBEAT MECHANISM

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
        }

        tracing::info!("initialized db");

        Ok(Server {
            config,
            endpoint,
            db_pool: pool,
            streams: Mutex::new(HashMap::new()),
            outgoing_transfer_requests: Mutex::new(HashMap::new()),
            pending_deltas: Mutex::new(HashMap::new()),
        })
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

        let mut stream = match conn.accept_bi().await {
            Ok(s) => {
                tracing::debug!("accepted bidi stream");
                s
            }
            Err(_) => anyhow::bail!("bidi stream could not be accepted"),
        };

        let (send, mut recv) = unbounded_channel::<protocol::Packet>();

        {
            let mut lock = self.streams.lock().await;
            lock.insert(conn.remote_address(), send);
        }

        loop {
            select! {
                // outgoing messages to client
                Some(m) = recv.recv() => {
                    Self::write_packet(&mut stream.0, &m).await?;
                }

                // incoming from client
                pkt = Self::read_packet(&mut stream.1) => {
                    match pkt? {
                        Some(msg) => {
                            if let Err(e) = self.handle_packet(conn.remote_address(), msg).await {
                                tracing::error!("packet handler:\n{}", e.backtrace());
                                self.handle_die(conn.remote_address(), protocol::Die::default()).await?;

                                break;
                            }
                        }
                        None => {
                            self.handle_die(conn.remote_address(), protocol::Die::default()).await?;

                            break
                        },
                    }
                }
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

    async fn handle_packet(
        self: &Arc<Self>,
        addr: SocketAddr,
        pkt: protocol::Packet,
    ) -> anyhow::Result<()> {
        // respond to a heartbeat
        if pkt.message.is_none() {
            let streams_lock = self.streams.lock().await;
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

    async fn handle_auth(
        self: &Arc<Self>,
        addr: SocketAddr,
        auth: protocol::Auth,
    ) -> anyhow::Result<()> {
        let db = self.db_pool.get()?;
        let mut streams_lock = self.streams.lock().await;
        let stream = streams_lock
            .get_mut(&addr)
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
                        let (folder_code, folder_id) = loop {
                            let folder_code = Self::generate_folder_code();

                            let mut stmt = db.prepare(
                                "
                                INSERT INTO folders (code, password)
                                SELECT ?1, ?2
                                WHERE NOT EXISTS (
                                    SELECT 1 FROM folders WHERE code = ?1
                                )
                                RETURNING code, id;
                                ",
                            )?;

                            let mut hasher = blake2::Blake2b512::new();
                            hasher.update(&auth.password);
                            let final_hash = hasher.finalize();
                            let digest = base16ct::lower::encode_string(&final_hash);

                            if let Ok((code, id)) = stmt.query_one([&folder_code, &digest], |row| {
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

        db.execute(
            "
            DELETE FROM folders
            WHERE id IN (
                SELECT current_folder FROM users WHERE addr = ?1
            )
            AND (
                SELECT COUNT(*) FROM users WHERE current_folder = (
                    SELECT current_folder FROM users WHERE addr = ?1
                )
            ) = 1
            ",
            [addr.to_string()],
        )?;

        db.execute("DELETE FROM users WHERE addr = ?1", [addr.to_string()])?;

        let mut streams_lock = self.streams.lock().await;
        streams_lock
            .remove(&addr)
            .ok_or(anyhow::anyhow!("tried to remove non-existant stream"))?;

        tracing::debug!("peer {} disconnected", addr);

        Ok(())
    }

    async fn handle_manifest(
        self: &Arc<Self>,
        addr: SocketAddr,
        manifest: protocol::FileManifest,
    ) -> anyhow::Result<()> {
        let mut streams_lock = self.streams.lock().await;
        let stream = streams_lock
            .get_mut(&addr)
            .ok_or(anyhow::anyhow!("could not find stream for peer"))?;

        // reject empty manifests
        if manifest.blocks.is_empty() {
            stream.send(protocol::Packet {
                code: protocol::Return::NoneUnspecified as i32,
                message: Some(protocol::packet::Message::Die(protocol::Die {
                    reason: Some(String::from("failed to authenticate")),
                })),
            })?;

            return Ok(());
        }

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

        let namehash = xxhash_rust::xxh3::xxh3_64(manifest.filename.as_bytes()) as i64;

        if !exists_in_db {
            tracing::debug!(
                "file {} is not part of folder {}, adding",
                manifest.filename,
                folder_id
            );

            self.create_file_entry(&db, folder_id, &manifest.filename, namehash)?;
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

                        stream.send(protocol::Packet {
                            code: protocol::Return::NoneUnspecified as i32,
                            message: Some(protocol::packet::Message::Transfer(
                                protocol::Transfer {
                                    metadata: Some(block_with_namehash),
                                    mode: protocol::DataMode::WholeUnspecified as i32,
                                    data: None,
                                },
                            )),
                        })?;

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

        {
            let new_blocks = manifest
                .blocks
                .iter()
                .map(|m| (m.hash, m.start, m.end))
                .collect();

            let delta = self
                .process_delta(db, folder_id, namehash, new_blocks)
                .await?;

            let mut pending_lock = self.pending_deltas.lock().await;
            pending_lock.insert(namehash, delta);
        }

        tracing::debug!(
            "received manifest for file {}. processed delta and now awaiting data blocks",
            namehash as u64
        );

        Ok(())
    }

    fn create_file_entry(
        self: &Arc<Self>,
        db: &PooledConnection<SqliteConnectionManager>,
        folder_id: i64,
        name_string: &str,
        name_hash: i64,
    ) -> anyhow::Result<()> {
        db.execute(
            "INSERT OR REPLACE INTO filenames (folder, name, namehash) SELECT ?1, ?2, ?3 WHERE NOT EXISTS (SELECT 1 FROM filenames WHERE folder = ?1 AND name = ?2)",
            (folder_id, name_string, name_hash),
        )?;

        Ok(())
    }

    fn delete_file_entry(
        self: &Arc<Self>,
        db: &PooledConnection<SqliteConnectionManager>,
        folder_id: i64,
        name_hash: i64,
    ) -> anyhow::Result<()> {
        db.execute(
            "DELETE FROM blocks WHERE folder = ?1 AND name = ?2",
            (folder_id, name_hash),
        )?;

        tracing::debug!(
            "deleted all blocks related to file {} in folder {}",
            name_hash,
            folder_id
        );

        db.execute(
            "DELETE FROM filenames WHERE folder = ?1 AND namehash = ?2",
            (folder_id, name_hash),
        )?;

        tracing::debug!(
            "deleted filename entry for namehash {} in folder {}",
            name_hash,
            folder_id
        );

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

        let streams_lock = self.streams.lock().await;
        streams_lock
            .iter()
            .map(|s| {
                s.1.send(protocol::Packet {
                    code: protocol::Return::NoneUnspecified as i32,
                    message: Some(protocol::packet::Message::Event(event.clone())),
                })
            })
            .collect::<Result<(), _>>()?;

        match event.event() {
            protocol::FileEvent::CreateUnspecified => {
                self.create_file_entry(&db, folder_id, &event.filename, file_namehash)
            }

            protocol::FileEvent::Delete => self.delete_file_entry(&db, folder_id, file_namehash),
        }?;

        Ok(())
    }

    /// aggregates all of the hashes in order by offset
    /// from the temp and the current then
    async fn process_delta(
        self: &Arc<Self>,
        db: PooledConnection<SqliteConnectionManager>,
        folder_id: i64,
        name_hash: i64,
        new_blocks: Vec<(u64, u64, u64)>,
    ) -> anyhow::Result<protocol::Delta> {
        let filename: String = db.query_one(
            "SELECT name FROM filenames WHERE folder = ?1 AND namehash = ?2",
            [folder_id, name_hash],
            |r| r.get(0),
        )?;

        let old_blocks: Vec<(u64, u64, u64)> = {
            let mut stmt = db.prepare(
                "SELECT hash, start, end FROM blocks WHERE folder = ?1 AND name = ?2 ORDER BY start ASC"
            )?;

            stmt.query_map((folder_id, name_hash), |row| {
                Ok((
                    row.get::<_, i64>(0)? as u64,
                    row.get::<_, i64>(1)? as u64,
                    row.get::<_, i64>(2)? as u64,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?
        };

        let largest_end_offset = new_blocks
            .iter()
            .map(|e| e.2)
            .max()
            .ok_or(anyhow::anyhow!("could not get largest size"))?
            as u64;

        let diff = protocol::Delta {
            size: largest_end_offset,
            filename,
            ops: similar::capture_diff_slices(similar::Algorithm::Myers, &old_blocks, &new_blocks)
                .iter()
                .flat_map(|x| x.iter_changes(&old_blocks, &new_blocks))
                .map(|x| {
                    let (new_hash, start, end) =
                        (x.value().0 as i64, x.value().1 as i64, x.value().2 as i64);

                    match x.tag() {
                        similar::ChangeTag::Delete => {
                            let old_hash = old_blocks
                                .get(
                                    x.old_index()
                                        .ok_or(anyhow::anyhow!("internal delta error"))?,
                                )
                                .ok_or(anyhow::anyhow!("internal delta fail"))?
                                .0;

                            db.execute(
                                "DELETE FROM blocks WHERE hash = ?1 AND start = ?2 AND end = ?3",
                                (old_hash as i64, start, end),
                            )?;
                        }
                        _ => {}
                    };

                    Ok::<protocol::delta::Operation, anyhow::Error>(protocol::delta::Operation {
                        op_type: match x.tag() {
                            similar::ChangeTag::Equal => protocol::delta::OpType::EqualUnspecified,
                            similar::ChangeTag::Insert => protocol::delta::OpType::Insert,
                            similar::ChangeTag::Delete => protocol::delta::OpType::Delete,
                        } as i32,
                        hash: new_hash as u64,
                        start: start as u64,
                        end: end as u64,
                    })
                })
                .filter_map(|f| f.ok())
                .collect(),
        };

        Ok(diff)
    }

    async fn handle_transfer(
        self: Arc<Self>,
        addr: SocketAddr,
        transfer: protocol::Transfer,
    ) -> anyhow::Result<()> {
        let db = self.db_pool.get()?;

        let metadata = transfer
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

        let mut streams_lock = self.streams.lock().await;

        // we are getting a response
        if let Some(data) = transfer.data {
            let mut outgoing_lock = self.outgoing_transfer_requests.lock().await;
            if let Some(requests) = outgoing_lock.get_mut(&(namehash as i64)) {
                if requests.contains(&(metadata.start, metadata.end)) {
                    db.execute(
                        "INSERT INTO blocks (folder, name, hash, start, end, contents) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                        (folder_id, namehash as i64, metadata.hash as i64, metadata.start as i64, metadata.end as i64, rusqlite::blob::ZeroBlob((metadata.end - metadata.start) as i32)),
                    )?;

                    let rowid = db.last_insert_rowid();
                    let mut blob =
                        db.blob_open(rusqlite::MAIN_DB, "blocks", "contents", rowid, false)?;

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
                }

                requests.remove(&(metadata.start, metadata.end));
                if requests.is_empty() {
                    outgoing_lock.remove(&(namehash as i64));

                    let pending_lock = self.pending_deltas.lock().await;
                    if let Some(delta) = pending_lock.get(&(namehash as i64)) {
                        tracing::info!(
                            "transfer queue satisfied for file {namehash}. broadcasting delta"
                        );

                        streams_lock
                            .iter()
                            .map(|s| {
                                if *s.0 == addr {
                                    return Ok(());
                                }

                                if let Err(e) = s.1.send(protocol::Packet {
                                    code: protocol::Return::NoneUnspecified as i32,
                                    message: Some(protocol::packet::Message::Delta(delta.clone())),
                                }) {
                                    tracing::error!("delta broadcast error: {}", e.to_string());
                                }

                                Ok(())
                            })
                            .collect::<anyhow::Result<()>>()?;
                    }
                }
            }
        } else {
            // we are getting a request for block data
            let rowid: i64 = db.query_one(
                "SELECT ROWID FROM blocks WHERE name = ?1 AND hash = ?2 AND start = ?3 AND end = ?4",
                [
                    namehash as i64,
                    metadata.hash as i64,
                    metadata.start as i64,
                    metadata.end as i64
                ],
                |r| r.get(0))?;

            let size_to_read = (metadata.end - metadata.start) as usize;
            let mut data: Vec<u8> = vec![0u8; size_to_read];
            let mut contents =
                db.blob_open(rusqlite::MAIN_DB, "blocks", "contents", rowid, true)?;
            contents.read_exact(&mut data)?;

            streams_lock
                .get_mut(&addr)
                .ok_or(anyhow::anyhow!("could not get client stream"))?
                .send(protocol::Packet {
                    code: protocol::Return::NoneUnspecified as i32,
                    message: Some(protocol::packet::Message::Transfer(protocol::Transfer {
                        metadata: Some(metadata),
                        mode: protocol::DataMode::WholeUnspecified as i32,
                        data: Some(data),
                    })),
                })?;

            tracing::debug!(
                "satisfied transfer request for {}:[{}, {}]",
                namehash,
                metadata.start,
                metadata.end
            );
        }

        Ok(())
    }

    async fn handle_whatis(
        self: &Arc<Self>,
        addr: SocketAddr,
        whatis: protocol::WhatIs,
    ) -> anyhow::Result<()> {
        let db = self.db_pool.get()?;
        let mut streams_lock = self.streams.lock().await;
        let stream = streams_lock
            .get_mut(&addr)
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

            let largest_end_offset = db.query_one(
                "SELECT MAX(end) FROM blocks WHERE folder = ?1 AND name = ?2",
                [folder_id, filehash],
                |r| r.get::<_, i64>(0),
            )? as u64;

            let mut manifest = protocol::FileManifest {
                filename: whatis.filename,
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|_| rusqlite::Error::UnwindingPanic)?
                    .as_secs(),
                size: largest_end_offset,
                blocks: vec![],
            };

            let mut blocks = blocks_stmt.query([folder_id, filehash])?;
            while let Ok(Some(block)) = blocks.next() {
                manifest.blocks.push(protocol::BlockMetadata {
                    hash: block.get::<_, i64>(0)? as u64,
                    start: block.get::<_, i64>(1)? as u64,
                    end: block.get::<_, i64>(2)? as u64,
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
