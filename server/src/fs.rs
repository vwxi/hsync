/// hsyncfs - expose block database as a file system
///
/// why? enabling a new type of topology where the server is actually
/// an active user in a folder that can push changes
///
/// inode format:
/// [upper 16 bits folder id][lower 48 bits filenames rowid]
/// when lower 48 bits are zero this means that the ino belongs to a folder
/// but this does not matter because readdir callback ignores lower bits anyway
///
/// current issue: how to represent subfolders knowing only that
///                         file names in subfolders contain slash characters
use std::{
    path::PathBuf,
    sync::atomic::AtomicU64,
    time::{Duration, UNIX_EPOCH},
};

use r2d2::{Pool, PooledConnection};
use r2d2_sqlite::SqliteConnectionManager;

const FS_NAME: &str = "hsyncfs";
const FILE_HANDLE_READ_BIT: u64 = 1 << 63;
const FILE_HANDLE_WRITE_BIT: u64 = 1 << 62;

pub struct Fs {
    pub db_pool: Pool<SqliteConnectionManager>,
    counter: AtomicU64,
}

#[derive(Debug)]
struct FileInfo {
    pub ino: u64,
    pub folder_id: i64,
    pub namehash: i64,
    pub name: String,
    pub size: i64,
    pub num_blocks: i64,
}

#[derive(Debug)]
struct FolderInfo {
    pub name: String,
    pub ino: u64,
}

#[derive(Debug)]
struct FolderContents {
    pub info: FolderInfo,
    pub files: Vec<FileInfo>,
}

impl Fs {
    fn get_handle(&self) -> u64 {
        self.counter
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            | FILE_HANDLE_READ_BIT
            | FILE_HANDLE_WRITE_BIT
    }

    fn dir_exists(&self, dir_ino: i64) -> anyhow::Result<bool> {
        let db = self.db_pool.get()?;

        Ok(db.query_row(
            "SELECT DISTINCT COUNT(*) FROM filenames WHERE folder = ?1",
            [((dir_ino as u64 >> 48) & 0xffff) as i64],
            |r| r.get::<_, i64>(0),
        )? > 0)
    }

    fn file_info(&self, file_ino: i64) -> anyhow::Result<FileInfo> {
        let db = self.db_pool.get()?;

        let folder_id = ((file_ino as u64) >> 48) & 0xffff;
        let file_id = (file_ino as u64) & 0xffffffffffff;

        let (name, namehash) = db.query_row(
            "SELECT name, namehash FROM filenames WHERE folder = ?1 AND ROWID = ?2",
            [folder_id as i64, file_id as i64],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)),
        )?;

        let (size, num_blocks) = db.query_row(
            "SELECT DISTINCT COUNT(*), MAX(end) FROM blocks WHERE folder = ?1 AND name = ?2",
            [folder_id as i64, namehash],
            |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)),
        )?;

        Ok(FileInfo {
            ino: file_ino as u64,
            folder_id: folder_id as i64,
            name,
            namehash,
            size,
            num_blocks,
        })
    }

    fn list_root_folders(&self) -> anyhow::Result<Vec<FolderInfo>> {
        let db = self.db_pool.get()?;
        let mut folders: Vec<FolderInfo> = vec![];

        let mut stmt = db.prepare("SELECT DISTINCT folder FROM filenames ORDER BY folder ASC")?;
        let mut folder_entries = stmt.query([])?;

        while let Ok(Some(entry)) = folder_entries.next() {
            let id = entry.get::<_, i64>(0)? as u64;
            folders.push(FolderInfo {
                name: String::from(format!("{}", id)),
                ino: (id & 0xffff) << 48,
            });
        }

        Ok(folders)
    }

    fn list_folder_contents(&self, folder_id: i64) -> anyhow::Result<FolderContents> {
        let db = self.db_pool.get()?;
        let mut stmt = db.prepare("SELECT ROWID FROM filenames WHERE folder = ?1")?;
        let mut entries = stmt.query([folder_id])?;

        let mut contents = FolderContents {
            info: FolderInfo {
                name: (folder_id as u64).to_string(),
                ino: (folder_id as u64 & 0xffff) << 48,
            },
            files: vec![],
        };

        while let Ok(Some(entry)) = entries.next() {
            let rowid = entry.get::<_, i64>(0)?;

            let ino = ((rowid as u64) & 0xffffffffffff) | (((folder_id as u64) & 0xffff) << 48);

            match dbg!(self.file_info(ino as i64)) {
                Ok(fi) => {
                    contents.files.push(dbg!(fi));
                }
                _ => {}
            }
        }

        Ok(contents)
    }

    fn mk_fileattr(
        req: &fuser::Request,
        ino: fuser::INodeNo,
        size: u64,
        blocks: u64,
        kind: fuser::FileType,
        nlink: u32,
        blksize: u32,
    ) -> fuser::FileAttr {
        fuser::FileAttr {
            ino,
            size,
            blocks,
            atime: UNIX_EPOCH,
            mtime: UNIX_EPOCH,
            ctime: UNIX_EPOCH,
            crtime: UNIX_EPOCH,
            kind,
            perm: 0o755,
            nlink,
            uid: req.uid(),
            gid: req.gid(),
            rdev: 0,
            blksize,
            flags: 0,
        }
    }
}

impl fuser::Filesystem for Fs {
    fn getattr(
        &self,
        req: &fuser::Request,
        ino: fuser::INodeNo,
        _fh: Option<fuser::FileHandle>,
        reply: fuser::ReplyAttr,
    ) {
        let folder_id = (u64::from(ino) >> 48) & 0xffff;
        let file_id = u64::from(ino) & 0xffffffffffff;

        let folder_exists = match self.dir_exists(folder_id as i64) {
            Ok(e) => e,
            Err(_) => {
                reply.error(fuser::Errno::ENOENT);
                return;
            }
        };

        // if directory/root
        if ino == fuser::INodeNo::ROOT || folder_exists {
            let attr = Self::mk_fileattr(req, ino, 0, 0, fuser::FileType::Directory, 2, 512);

            reply.attr(&Duration::from_secs(1), &attr);
        } else {
            let file_info = match self.file_info(file_id as i64) {
                Ok(fi) => fi,
                Err(_) => {
                    reply.error(fuser::Errno::ENOENT);
                    return;
                }
            };

            let attr = Self::mk_fileattr(
                req,
                ino,
                file_info.size as u64,
                file_info.num_blocks as u64,
                fuser::FileType::RegularFile,
                2,
                512,
            );

            reply.attr(&Duration::from_secs(1), &attr);
        }
    }

    fn opendir(
        &self,
        _req: &fuser::Request,
        ino: fuser::INodeNo,
        _flags: fuser::OpenFlags,
        reply: fuser::ReplyOpen,
    ) {
        match self.dir_exists(u64::from(ino) as i64) {
            Ok(e) if !e && ino != fuser::INodeNo::ROOT => {
                reply.error(fuser::Errno::ENOTDIR);
                return;
            }
            Err(_) => {
                reply.error(fuser::Errno::ENOTDIR);
                return;
            }

            _ => {}
        };

        reply.opened(
            fuser::FileHandle(self.get_handle()),
            fuser::FopenFlags::all() & !fuser::FopenFlags::FOPEN_PASSTHROUGH,
        );
    }

    fn lookup(
        &self,
        req: &fuser::Request,
        parent: fuser::INodeNo,
        name: &std::ffi::OsStr,
        reply: fuser::ReplyEntry,
    ) {
        tracing::debug!("lookup {} (parent: {})", name.to_string_lossy(), parent);

        if let Err(e) = (|| {
            let name = name
                .to_str()
                .ok_or(anyhow::anyhow!("encode error"))?
                .to_string();

            if parent == fuser::INodeNo::ROOT {
                // lookup hsycnfs (parent: 1)
                if name == FS_NAME {
                    let attr = Self::mk_fileattr(
                        req,
                        fuser::INodeNo::ROOT,
                        0,
                        0,
                        fuser::FileType::Directory,
                        2,
                        512,
                    );

                    // wtf is generation
                    reply.entry(&Duration::from_secs(1), &attr, fuser::Generation(0));
                } else {
                    // otherwise it should be a folder id which is just a number
                    // because we are still in root folder
                    let folder_num = match name.parse::<u64>() {
                        Ok(f) => f,
                        _ => {
                            reply.error(fuser::Errno::ENOENT);
                            anyhow::bail!("non-id folders do not exist in root");
                        }
                    };

                    let folder_id = (folder_num & 0xffff) << 48;

                    match self.dir_exists(folder_id as i64) {
                        Ok(e) if e => {
                            let attr = Self::mk_fileattr(
                                req,
                                fuser::INodeNo(folder_id),
                                0,
                                0,
                                fuser::FileType::Directory,
                                2,
                                512,
                            );

                            tracing::debug!("opendir {:#x}", folder_id);

                            reply.entry(&Duration::from_secs(1), &attr, fuser::Generation(0));
                        }

                        _ => {
                            reply.error(fuser::Errno::ENOENT);
                            anyhow::bail!("directory does not exist");
                        }
                    }
                }
            }

            anyhow::Ok(())
        })() {
            tracing::error!("lookup error: {}", e.to_string());
        }
    }

    fn readdir(
        &self,
        _req: &fuser::Request,
        ino: fuser::INodeNo,
        fh: fuser::FileHandle,
        offset: u64,
        mut reply: fuser::ReplyDirectory,
    ) {
        // if the root directory, list all the folders
        if ino == fuser::INodeNo::ROOT {
            match self.list_root_folders() {
                Ok(folders) => {
                    for (index, folder) in folders.iter().skip(offset as usize).enumerate() {
                        let res = reply.add(
                            fuser::INodeNo(folder.ino),
                            offset + index as u64 + 1,
                            fuser::FileType::Directory,
                            &folder.name,
                        );

                        tracing::debug!(
                            "\tfolder ino {} name {}: {}",
                            folder.ino,
                            folder.name,
                            res
                        );

                        if res {
                            break;
                        }
                    }
                }

                Err(_) => {
                    reply.error(fuser::Errno::ENOENT);
                    return;
                }
            }

            reply.ok();
        } else {
            // not a root dir, let's read folder id
            let folder_id = (u64::from(ino) >> 48) & 0xffff;

            match dbg!(self.dir_exists(u64::from(ino) as i64)) {
                Ok(e) if e => match dbg!(self.list_folder_contents(folder_id as i64)) {
                    Ok(contents) => {
                        for (index, file) in contents.files.iter().skip(offset as usize).enumerate()
                        {
                            if reply.add(
                                fuser::INodeNo(file.ino),
                                offset + index as u64 + 1,
                                fuser::FileType::RegularFile,
                                &file.name,
                            ) {
                                break;
                            }
                        }

                        reply.ok();
                    }

                    _ => {
                        reply.error(fuser::Errno::ENOENT);
                        return;
                    }
                },

                _ => {
                    reply.error(fuser::Errno::ENOENT);
                }
            }
        }
    }
}

pub async fn hsyncfs_create(rootpath: PathBuf, db_pool: Pool<SqliteConnectionManager>) {
    let path = rootpath.join(std::path::PathBuf::from(format!("{}/", FS_NAME)));

    let mut options = fuser::Config::default();
    options.mount_options = vec![
        fuser::MountOption::RO,
        fuser::MountOption::FSName(FS_NAME.to_string()),
    ];
    options.acl = fuser::SessionACL::Owner;
    options.n_threads = None;
    options.clone_fd = false;

    // mount in same directory as db
    let fs = Fs {
        db_pool,
        counter: AtomicU64::new(0),
    };

    if !path.exists() {
        std::fs::create_dir(&path).unwrap();
    }

    tracing::info!("mounting hsyncfs to {}", path.to_string_lossy());

    fuser::mount2(fs, &path, &options).unwrap();
}
