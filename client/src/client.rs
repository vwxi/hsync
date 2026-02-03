use std::{ffi::OsStr, io::Read};

use glob::glob;
use inotify::{Event, EventMask, Inotify, WatchDescriptor, WatchMask};
use r2d2::{Pool, PooledConnection};
use r2d2_sqlite::SqliteConnectionManager;
use xxhash_rust;

use crate::Config;

pub mod protocol {
    include!(concat!(env!("OUT_DIR"), "/hsync.rs"));
}

const INITIAL_QUERY: &str = "
CREATE TABLE IF NOT EXISTS files (name INTEGER, hash INTEGER)
";

pub struct Client {
    config: Config,
    notify: Inotify,
    wd: WatchDescriptor,
    db_pool: Pool<SqliteConnectionManager>,
}

impl Client {
    pub fn new(config: Config) -> anyhow::Result<Client> {
        // register inotify instance
        let notify = Inotify::init()?;
        let wd = notify
            .watches()
            .add(config.folder.clone(), WatchMask::all())?;

        // process all files currently in folder
        let manager = SqliteConnectionManager::memory();
        let pool = Pool::new(manager)?;
        {
            let conn = pool.get()?;
            conn.execute(INITIAL_QUERY, ())?;
            Self::process_files_into_db(config.folder.clone(), &conn)?;
        }

        Ok(Client {
            config,
            notify,
            wd,
            db_pool: pool,
        })
    }

    /// hash any files in folder and register them in database
    /// hashes are checked on any changes and are checked with
    /// the server
    fn process_files_into_db(
        folder: String,
        db: &PooledConnection<SqliteConnectionManager>,
    ) -> anyhow::Result<()> {
        let folder = format!("{}/**", folder);

        for entry in glob(&folder)? {
            match entry {
                Ok(path) => {
                    let mut file = std::fs::File::open(path.clone()).unwrap();
                    let mut buffer = Vec::new();
                    buffer.clear();
                    let _ = file.read_to_end(&mut buffer);

                    let name = i64::try_from(xxhash_rust::xxh3::xxh3_64(
                        path.to_str()
                            .ok_or(anyhow::anyhow!("bad file name"))?
                            .as_bytes(),
                    ))?;
                    let hash = i64::try_from(xxhash_rust::xxh3::xxh3_64(&buffer))?;

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

    pub fn connect(&mut self) -> anyhow::Result<()> {
        Ok(())
    }

    pub fn kill(self) -> anyhow::Result<()> {
        // remove watch and end notify object
        self.notify.watches().remove(self.wd)?;
        self.notify.close()?;

        // disconnect from server

        Ok(())
    }

    pub fn handle_event(&mut self, event: Event<&OsStr>) -> anyhow::Result<()> {
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

    pub fn handle(&mut self, buffer: &mut [u8]) -> anyhow::Result<()> {
        let events = self.notify.read_events(buffer)?;

        for event in events {
            self.handle_event(event)?;
        }

        Ok(())
    }
}
