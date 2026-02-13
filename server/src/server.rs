use std::{collections::HashMap, net::SocketAddr, sync::Arc};

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
const CREATE_FILENAMES_STMT: &str =
    "CREATE TABLE IF NOT EXISTS filenames (folder INTEGER, name TEXT, namehash INTEGER)";
const CREATE_BLOCKS_STMT: &str = "CREATE TABLE IF NOT EXISTS blocks (time DATETIME DEFAULT CURRENT_TIMESTAMP, folder INTEGER, name INTEGER, hash INTEGER, contents BLOB)";

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

        // TODO: WE NEED TO ADD HEARTBEATS! ADDING INFINITE TIMEOUT MEANS FUTURES
        //       CAN HOLD SO WE NEED TO ADD A HEARTBEAT MECHANISM

        let endpoint = quinn::Endpoint::server(server_config, config.bind)?;

        tracing::info!("initialized QUIC endpoint at {}", config.bind);

        // INIT SQLITE
        let manager = if let Some(db) = config.db {
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
            tracing::debug!("waiting...");
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
                                tracing::error!("packet handler: {:?}", e);
                            }
                        }
                        None => {
                            break
                        },
                    }
                }
            }
        }

        Ok(())
    }

    async fn write_packet(stream: &mut SendStream, pkt: &protocol::Packet) -> anyhow::Result<()> {
        tracing::debug!("write packet: {:?}", pkt);

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
        let message = pkt
            .message
            .ok_or(anyhow::anyhow!("why is this happening?"))?;

        tracing::debug!("pkt recvd: {:?}", message);

        match message {
            protocol::packet::Message::Auth(auth) => dbg!(self.handle_auth(addr, auth).await)?,

            protocol::packet::Message::Die(die) => self.handle_die(addr, die).await?,

            protocol::packet::Message::Manifest(manifest) => {
                self.handle_manifest(addr, manifest).await?
            }

            protocol::packet::Message::Event(event) => self.handle_event(addr, event).await?,

            _ => {}
        }

        Ok(())
    }

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
                        message: Some(if digest == folder_pass_hash {
                            if db
                                .execute(
                                    "INSERT INTO users (addr, current_folder) VALUES (?1, ?2)",
                                    (addr.to_string(), folder_id),
                                )
                                .is_ok()
                            {
                                protocol::packet::Message::RoomInfo(protocol::RoomInfo {
                                    id: folder_id as u64,
                                    code: folder_code.clone(),
                                })
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
                    .map_err(|_| rusqlite::Error::InvalidQuery)?;

                Ok(())
            })?;
        } else {
            // user wants to create a folder and is new
            stream.send(protocol::Packet {
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
                        protocol::packet::Message::RoomInfo(protocol::RoomInfo {
                            id: folder_id as u64,
                            code: folder_code,
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

        if !exists_in_db {
            tracing::debug!(
                "file {} is not part of folder {}, adding",
                manifest.filename,
                folder_id
            );

            let namehash = xxhash_rust::xxh3::xxh3_64(manifest.filename.as_bytes()) as i64;
            self.create_file_entry(&db, folder_id, &manifest.filename, namehash)?;
        }

        for block in manifest.blocks {
            match db.query_row(
                "SELECT hash FROM entries WHERE folder = ?1 AND name = ?2 AND offset = ?3",
                (folder_id, &manifest.filename, block.offset as i64),
                |row| row.get::<_, i64>(0),
            ) {
                // file block exists already, update
                Ok(current_block_hash) => {
                    let current_block_hash = current_block_hash as u64;
                }

                // file block does not exist, request it
                // TODO: set a hard limit on filesize so we avoid some sort of DoS
                //       where you can just invent blocks at huge offsets
                Err(_) => {
                    tracing::debug!(
                        "[file {}] block @ offset {} DNE. requesting.",
                        manifest.filename,
                        block.offset,
                    );

                    stream.send(protocol::Packet {
                        message: Some(protocol::packet::Message::Transfer(protocol::Transfer {
                            metadata: Some(block),
                            mode: protocol::DataMode::WholeUnspecified as i32,
                            data: None,
                        })),
                    })?;
                }
            }
        }

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
            "INSERT INTO filenames (folder, name, namehash) SELECT ?1, ?2, ?3 WHERE NOT EXISTS (SELECT 1 FROM filenames WHERE folder = ?1 AND name = ?2)",
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

        db.execute("DELETE FROM filenames WHERE folder = ?1", [folder_id])?;

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
        let folder_id: i64 = dbg!(db.query_row(
            "SELECT current_folder FROM users WHERE addr = ?1",
            [addr.to_string()],
            |row| row.get(0),
        ))?;

        let file_namehash: i64 = dbg!(db.query_row(
            "SELECT hash FROM filenames WHERE folder = ?1 AND name = ?2",
            (folder_id, &event.filename),
            |row| row.get::<_, i64>(0),
        ))?;

        match event.event() {
            protocol::FileEvent::CreateUnspecified => {
                self.create_file_entry(&db, folder_id, &event.filename, file_namehash)
            }

            protocol::FileEvent::Delete => self.delete_file_entry(&db, folder_id, file_namehash),
        }?;

        Ok(())
    }
}
