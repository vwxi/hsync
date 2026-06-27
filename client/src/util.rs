//! utility functions

use std::{io::Read, ops::BitOr, path::PathBuf};

use prost::Message;
use quinn::{RecvStream, SendStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::client::{Client, protocol};

bitflags::bitflags! {
    #[derive(PartialEq, Eq)]
    pub(crate) struct ClearFlags: u8 {
        const Transfers = 1;
        const Accesses = 2;
        const Queue = 4;
    }
}

impl Client {
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
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                tracing::error!("stream: {:?} {:?}", stream.id().initiator(), stream.id());
                return Ok(None)
            },
            Err(e) => return Err(e.into()),
        };

        let mut buf = vec![0u8; len as usize];
        stream.read_exact(&mut buf).await?;
        let pkt = protocol::Packet::decode(&buf[..])?;
        Ok(Some(pkt))
    }

    pub(crate) fn get_file_hash(&self, filepath: &PathBuf) -> anyhow::Result<u64> {
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(false)
            .open(filepath)?;

        let mut hasher = xxhash_rust::xxh3::Xxh3::new();

        let mut block = vec![0u8; 1024];

        loop {
            let read = file.read(&mut block)?;
            if read == 0 {
                break;
            }

            hasher.update(&block[..read]);
        }

        Ok(hasher.digest())
    }

    pub(crate) fn join_file_and_folder(&self, name: &str) -> anyhow::Result<PathBuf> {
        let folder = self
            .config
            .folder
            .clone()
            .unwrap_or_else(|| PathBuf::from("."));

        Ok(folder.join(name))
    }

    pub(crate) fn resolve_relative_path(&self, path: &PathBuf) -> anyhow::Result<String> {
        let relative_path = String::from(
            path.strip_prefix(
                self.config
                    .folder
                    .as_ref()
                    .ok_or(anyhow::anyhow!("no folder found"))?,
            )?
            .to_str()
            .ok_or(anyhow::anyhow!("relative path encode error"))?,
        );

        Ok(relative_path)
    }

    pub(crate) fn timestamp() -> anyhow::Result<u64> {
        Ok(std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)?
            .as_secs())
    }
}