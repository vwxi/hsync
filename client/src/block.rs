//! file block related operations

use std::{collections::HashSet, io::{Read, Seek, SeekFrom, Write}, os::unix::fs::FileExt, path::PathBuf};

use r2d2::PooledConnection;
use r2d2_sqlite::SqliteConnectionManager;

use crate::client::{Ch, Client, TransferMetadata, protocol};

impl Client {
    /// cut a piece out of a file and resize accordingly
    pub(crate) fn truncate_range(
        file: &mut std::fs::File,
        start: u64,
        mut end: u64,
    ) -> anyhow::Result<()> {
        let file_len = file.metadata()?.len();

        if end > file_len {
            end = file_len;
        }

        if start >= end {
            return Ok(());
        }

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

    /// in place write over of a block
    pub(crate) fn modify_block(file: &mut std::fs::File, offset: u64, data: &[u8]) -> anyhow::Result<()> {
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

    /// insert the block by shifting data forward and filling in with data
    pub(crate) fn insert_block(file: &mut std::fs::File, offset: u64, data: &[u8]) -> anyhow::Result<()> {
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

    /// helper function to basically account for the request we're about to send
    /// in the journal and in the accounting maps
    pub(crate) async fn prepare_block_request(
        &mut self,
        namehash: i64,
        cookie: i64,
        transfer_metadata: TransferMetadata,
    ) -> anyhow::Result<()> {
        let db = self.db_pool.get()?;

        let mut outgoing_lock = self.outgoing_transfer_requests.lock().await;

        outgoing_lock
            .entry(namehash)
            .and_modify(|o| {
                o.insert(transfer_metadata);
            })
            .or_insert_with(|| {
                let mut transfers: HashSet<TransferMetadata> = HashSet::new();
                transfers.insert(transfer_metadata);

                transfers
            });

        Self::journal_block(
            &db,
            namehash,
            transfer_metadata.start as i64,
            transfer_metadata.end as i64,
            Some(cookie),
            Some(transfer_metadata.op_type),
            None,
            transfer_metadata.hash as i64,
        )?;

        Ok(())
    }

}