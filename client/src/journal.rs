//! journal related operations

use std::{io::{Read, Seek, SeekFrom, Write}, path::PathBuf};

use r2d2::PooledConnection;
use r2d2_sqlite::SqliteConnectionManager;

use crate::{client::{Ch, Client, protocol}, util::db_keep_trying};

impl Client {
    /// journal block for after modify etc
    pub(crate) fn journal_block(
        db: &PooledConnection<SqliteConnectionManager>,
        namehash: i64,
        start: i64,
        end: i64,
        cookie: Option<i64>,
        op_type: Option<protocol::delta::OpType>,
        data: Option<&[u8]>,
        hash: i64,
    ) -> anyhow::Result<()> {
        if let Some(cookie) = cookie {
            db.execute(
                "INSERT INTO journal (file, start, end, hash, cookie, op, contents) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                (
                    namehash,
                    start,
                    end,
                    hash,
                    cookie,
                    op_type.map(|o| o as i64),
                    data.as_ref().map(|_| rusqlite::blob::ZeroBlob((end - start) as i32)),
                ),
            )?;

            if let Some(data) = data {
                let rowid = db.last_insert_rowid();
                let mut blob =
                    db.blob_open(rusqlite::MAIN_DB, "journal", "contents", rowid, false)?;

                if blob.write(&data)? != data.len() {
                    anyhow::bail!("did not write full block to database");
                }

                blob.close()?;
            }

            // tracing::debug!(
            //     "journal: stored block {}:[{}, {}] (ck: {:?}) with {}",
            //     namehash as u64,
            //     start,
            //     end,
            //     cookie,
            //     if data.is_some() { "data" } else { "no data" }
            // );
        } else {
            db.execute(
                "INSERT OR IGNORE INTO blocks (file, start, end, hash) VALUES (?1, ?2, ?3, ?4)",
                [namehash, start, end, hash],
            )?;
        }

        Ok(())
    }

    /// fill empty journal blocks with xfer data
    pub(crate) fn hydrate_block(
        db: &PooledConnection<SqliteConnectionManager>,
        namehash: i64,
        start: i64,
        end: i64,
        cookie: i64,
        data: &[u8],
        hash: i64,
    ) -> anyhow::Result<()> {
        let rowid = db.query_row(
            "UPDATE journal
             SET contents = ?6
             WHERE file = ?1 AND start = ?2 AND end = ?3 AND hash = ?4 AND cookie = ?5
             RETURNING ROWID",
            (
                namehash,
                start,
                end,
                hash,
                cookie,
                Some(rusqlite::blob::ZeroBlob((end - start) as i32)),
            ),
            |r| r.get::<_, i64>(0),
        )?;

        let mut blob = db.blob_open(rusqlite::MAIN_DB, "journal", "contents", rowid, false)?;

        if blob.write(&data)? != data.len() {
            anyhow::bail!("did not write full block to database");
        }

        blob.close()?;

        Ok(())
    }

    /// fetch a block to serve. the block will come from these origins in this order:
    /// - the journal
    /// - underlying file data
    pub(crate) fn fetch_block(
        &self,
        db: &PooledConnection<SqliteConnectionManager>,
        filepath: &PathBuf,
        namehash: i64,
        metadata: protocol::BlockMetadata,
    ) -> anyhow::Result<Vec<u8>> {
        // if cookie is present, get from journal
        // otherwise, get it from the main table
        if let Some(cookie) = metadata.cookie {
            match db.query_one(
                "SELECT ROWID FROM journal WHERE file = ?1 AND hash = ?2 AND cookie = ?3 LIMIT 1",
                [namehash, metadata.hash as i64, cookie as i64],
                |r| r.get::<_, i64>(0),
            ) {
                Ok(rowid) => {
                    let size_to_read = (metadata.end - metadata.start) as usize;
                    let mut data: Vec<u8> = vec![0u8; size_to_read];
                    let mut contents =
                        db.blob_open(rusqlite::MAIN_DB, "journal", "contents", rowid, true)?;
                    contents.read_exact(&mut data)?;

                    // insert into main block
                    db.execute(
                        "INSERT OR REPLACE INTO blocks (file, start, end, hash) VALUES (?1, ?2, ?3, ?4)",
                        [
                            namehash as i64,
                            metadata.start as i64,
                            metadata.end as i64,
                            metadata.hash as i64,
                        ],
                    )?;

                    // tracing::debug!(
                    //     "journal: fetched block {}:[{}, {}] (ck: {:?})",
                    //     namehash,
                    //     metadata.start,
                    //     metadata.end,
                    //     metadata.cookie
                    // );

                    Ok(data)
                },
                Err(_) => {
                    // if not journaled then it was probably an unchanged block
                    // try again and if fails again then it really does not exist
                    if let Ok(block_data) = (|| {
                        let mut file = std::fs::OpenOptions::new()
                            .read(true)
                            .write(false)
                            .open(filepath)?;

                        let mut block_data = vec![0u8; (metadata.end - metadata.start) as usize];
                        file.seek(SeekFrom::Start(metadata.start))?;
                        file.read_exact(&mut block_data)?;

                        let datahash = xxhash_rust::xxh3::xxh3_64(&block_data);
                        if datahash == metadata.hash {
                            anyhow::Ok(block_data)
                        } else {
                            anyhow::bail!("bad datahash in fetch_block");
                        }
                    })() {
                        // db.execute(
                        //     "INSERT OR REPLACE INTO blocks (file, start, end, hash) VALUES (?1, ?2, ?3, ?4)",
                        //     [
                        //         namehash as i64,
                        //         metadata.start as i64,
                        //         metadata.end as i64,
                        //         metadata.hash as i64,
                        //     ],
                        // )?;

                        tracing::debug!(
                            "fs: fetched block {}:[{}, {}] (ck: {:?})",
                            namehash,
                            metadata.start,
                            metadata.end,
                            metadata.cookie
                        );

                        Ok(block_data)
                    } else {
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

                        anyhow::bail!("client miss {}:{}:[{}, {}] (ck: {:?})",
                            metadata.namehash(), metadata.hash, metadata.start, metadata.end, metadata.cookie);
                    }
                }
            }
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
    
    /// drain the journal of a file's blocks given a cookie
    /// but treat as a delta. return number of fs ops to ignore in notify queue
    /// 
    /// returns number of blocks processed
    pub(crate) async fn apply_journaled_delta(
        &self,
        db: PooledConnection<SqliteConnectionManager>,
        namehash: i64,
        cookie: i64,
    ) -> anyhow::Result<u64> {
        {
            let mut accesses_lock = self.current_accesses.lock().await;
            accesses_lock.insert(namehash);
        }

        let filename: String = db.query_one(
            "SELECT name FROM filenames WHERE hash = ?1",
            [namehash],
            |r| r.get(0),
        )?;

        let filepath = self.join_file_and_folder(&filename)?;

        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(filepath)?;

        // fetch delta ops sorted in proper order
        // deletes order start offsets descending
        // everything else ascending
        // this way we don't mess up the offsets of anything 
        let mut stmt = db.prepare(
            "SELECT ROWID, hash, start, end, op FROM journal WHERE file = ?1 AND cookie = ?2
             ORDER BY 
             CASE WHEN op = ?3 THEN start END DESC,
             CASE WHEN op <> ?3 THEN start END ASC",
        )?;

        let mut ops = stmt.query([
            namehash, 
            cookie, 
            protocol::delta::OpType::Delete as i64, 
        ])?;

        let mut count = 0u64;

        while let Ok(Some(row)) = ops.next() {
            let (rowid, hash, start, end, op) = (
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)? as u64,
                row.get::<_, i64>(2)? as u64,
                row.get::<_, i64>(3)? as u64,
                protocol::delta::OpType::try_from(row.get::<_, i64>(4)? as i32)?,
            );

            let size_to_read = (end - start) as usize;

            tracing::debug!("delta: {:?} [{}, {}] ({}) ", op, start, end, hash);
            
            match op {
                protocol::delta::OpType::Delete => {
                    Self::truncate_range(&mut file, start, end)?;

                    db_keep_trying(|| db.execute(
                        "DELETE FROM blocks WHERE file = ?1 AND start = ?2 AND end = ?3 AND hash = ?4",
                        [namehash as i64, start as i64, end as i64, hash as i64],
                    ))?;

                    tracing::debug!("delta: {namehash}: delete [{start}, {end}] (hash: {hash})");
                }

                protocol::delta::OpType::Insert | protocol::delta::OpType::EqualUnspecified => {
                    let mut data: Vec<u8> = vec![0u8; size_to_read];
                    let mut contents =
                        db.blob_open(rusqlite::MAIN_DB, "journal", "contents", rowid, true)?;
                    contents.read_exact(&mut data)?;
                    contents.close()?;

                    Self::insert_block(&mut file, start, &data)?;
                }

                protocol::delta::OpType::Modify => {
                    let mut data: Vec<u8> = vec![0u8; size_to_read];
                    let mut contents =
                        db.blob_open(rusqlite::MAIN_DB, "journal", "contents", rowid, true)?;
                    contents.read_exact(&mut data)?;
                    contents.close()?;

                    Self::modify_block(&mut file, start, &data)?;
                }
            }

            // remove entry from journal
            db_keep_trying(|| db.execute(
                "DELETE FROM journal WHERE file = ?1 AND start = ?2 AND end = ?3 AND hash = ?4 AND cookie = ?5",
                [
                    namehash as i64,
                    start as i64,
                    end as i64,
                    hash as i64,
                    cookie,
                ],
            ))?;

            if op != protocol::delta::OpType::Delete {
                db.execute(
                    "INSERT OR REPLACE INTO blocks (file, start, end, hash) VALUES (?1, ?2, ?3, ?4)",
                    [namehash as i64, start as i64, end as i64, hash as i64],
                )?;
            }

            count += 1;
        }

        tracing::debug!("applied delta, {} blocks", count);

        Ok(count)
    }
}