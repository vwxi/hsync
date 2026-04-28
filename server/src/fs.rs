/// hsyncfs - expose block database as a file system
///
/// why? enabling a new type of topology where the server is actually
/// an active user in a folder that can push changes
///
/// current issue: how to represent subfolders knowing only that
///                         file names in subfolders contain slash characters
/// thought process:
/// caching directory structures in memory,
/// when listing out folder contents, process folder
use std::{
    collections::{HashMap, HashSet},
    num::NonZeroUsize,
    path::PathBuf,
    sync::atomic::AtomicU64,
    time::{Duration, UNIX_EPOCH},
};

use r2d2::{Pool, PooledConnection};
use r2d2_sqlite::SqliteConnectionManager;

const FS_NAME: &str = "hsyncfs";
const FILE_HANDLE_READ_BIT: u64 = 1 << 63;
const FILE_HANDLE_WRITE_BIT: u64 = 1 << 62;
const SUBDIR_CACHE_SIZE: usize = 2048;

/// inode format:
/// MSB ---> LSB
/// [16 bits folder id] [16 bits internal folder id] [32 bits filenames rowid]
///
/// internal folder id is completely seperate from filenames rowid.
/// that is to say that the rowid is from the greater filenames table and
/// the internal folder id is only for FUSE accounting
///
/// examples:
/// [folder id] [16 bits zero] [32 bits zero] - main project folders on root dir
/// [folder id] [internal folder id] [32 bits zero] - project subfolder entity
/// [folder id] [16 bits zero] [rowid] - project file in project root
/// [folder id] [internal folder id] [rowid] - project file in subfolder
///
#[bitfields::bitfield(u64, order = msb)]
#[derive(Clone, Copy)]
struct Inode {
    pub folder_id: u16,
    pub internal_folder_id: u16,
    pub rowid: u32,
}

impl From<fuser::INodeNo> for Inode {
    fn from(value: fuser::INodeNo) -> Self {
        Inode(value.0)
    }
}

impl From<Inode> for fuser::INodeNo {
    fn from(value: Inode) -> Self {
        fuser::INodeNo(value.0)
    }
}

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
enum FolderItem {
    Directory(FolderInfo),
    File(FileInfo),
}

#[derive(Debug)]
struct FolderContents {
    pub info: FolderInfo,
    pub items: Vec<FolderItem>,
}

impl Fs {
    fn get_handle(&self) -> u64 {
        self.counter
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            | FILE_HANDLE_READ_BIT
            | FILE_HANDLE_WRITE_BIT
    }

    // check if inode represents a project folder / subfolder
    fn is_dir(&self, ino: Inode) -> anyhow::Result<bool> {
        let db = self.db_pool.get()?;

        // folder
        Ok(ino.rowid() == 0
            && (db.query_row(
            "SELECT DISTINCT COUNT(*) FROM filenames WHERE folder = ?1 AND subdir IS NULL",
            [ino.folder_id() as i64],
            |r| r.get::<_, i64>(0),
            )? > 0
        // subfolder
            || db.query_row(
                "SELECT DISTINCT COUNT(*) FROM filenames WHERE folder = ?1 AND subdir = ?2",
                [ino.folder_id() as i64, ino.internal_folder_id() as i64],
                |r| r.get::<_, i64>(0),
            )? > 0))
    }

    fn entry_info(&self, parent_ino: Inode, name: &str) -> anyhow::Result<FolderItem> {
        let db = self.db_pool.get()?;

        // entry is a file
        if let Ok(rowid) = db.query_row(
            "SELECT ROWID FROM filenames WHERE folder = ?1 AND name LIKE ?2 AND subdir IS ?3 LIMIT 1",
            (
                parent_ino.folder_id() as i64,
                if parent_ino.internal_folder_id() == 0 {
                    String::from(name)
                } else {
                    "%/".to_owned() + name
                },
                if parent_ino.internal_folder_id() == 0 {
                    None
                } else {
                    Some(parent_ino.internal_folder_id() as i64)
                },
            ),
            |r| r.get::<_, i64>(0),
        ) {
            return Ok(FolderItem::File(
                self.file_info(
                    InodeBuilder::new()
                        .with_folder_id(parent_ino.folder_id())
                        .with_internal_folder_id(parent_ino.internal_folder_id())
                        .with_rowid(rowid as u32)
                        .build(),
                )?,
            ));
        }

        // entry is a subfolder
        Ok(FolderItem::Directory(FolderInfo {
            name: String::from(name),
            ino: InodeBuilder::new()
                .with_folder_id(parent_ino.folder_id())
                .with_internal_folder_id(if parent_ino.internal_folder_id() == 0 {
                    // is subfolder in project root?
                    tracing::debug!("subfolder in project root");

                    db.query_row(
                        "SELECT ROWID FROM subdirs WHERE folder = ?1 AND path = ?2 LIMIT 1",
                        (parent_ino.folder_id() as i64, name),
                        |r| r.get::<_, i64>(0),
                    )? as u16
                } else {
                    // subfolder is under another subfolder in project root
                    tracing::debug!("subfolder in another subfolder in project root");

                    db.query_row(
                        "SELECT ROWID FROM subdirs WHERE folder = ?1 AND parent = ?2 AND path LIKE ?3 LIMIT 1",
                        (parent_ino.folder_id() as i64, parent_ino.internal_folder_id() as i64, "%/".to_owned() + name),
                        |r| r.get::<_, i64>(0),
                    )? as u16
                })
                .with_rowid(0)
                .build()
                .0,
        }))
    }

    fn file_info(&self, file_ino: Inode) -> anyhow::Result<FileInfo> {
        let db = self.db_pool.get()?;

        let (name, namehash) = db.query_row(
            "SELECT name, namehash FROM filenames WHERE folder = ?1 AND ROWID = ?2",
            [file_ino.folder_id() as i64, file_ino.rowid() as i64],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)),
        )?;

        let (size, num_blocks) = db.query_row(
            "SELECT DISTINCT COUNT(*), MAX(end) FROM blocks WHERE folder = ?1 AND name = ?2",
            [file_ino.folder_id() as i64, namehash],
            |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)),
        )?;

        Ok(FileInfo {
            ino: file_ino.into(),
            folder_id: file_ino.folder_id() as i64,
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
            let mut ino = Inode(0);
            ino.set_folder_id(entry.get::<_, i64>(0)? as u16);

            folders.push(FolderInfo {
                name: String::from(format!("{}", ino.folder_id())),
                ino: ino.into(),
            });
        }

        Ok(folders)
    }

    fn list_folder_contents(
        &self,
        folder_id: i64,
        internal_folder_id: i64,
    ) -> anyhow::Result<FolderContents> {
        let db = self.db_pool.get()?;

        let mut contents = FolderContents {
            info: FolderInfo {
                name: (folder_id as u64).to_string(),
                ino: {
                    let mut i = Inode(0);
                    i.set_folder_id(folder_id as u16);
                    i.set_internal_folder_id(internal_folder_id as u16);
                    i.into()
                },
            },
            items: vec![],
        };

        // find all subdirectories of current folder and add them first
        let mut stmt = db.prepare(if internal_folder_id == 0 {
            "SELECT ROWID, path FROM subdirs WHERE folder = ?1 AND parent IS NULL"
        } else {
            "SELECT ROWID, LTRIM(path, (SELECT path FROM subdirs WHERE ROWID = ?2)) FROM subdirs WHERE folder = ?1 AND parent = ?2"
        })?;

        let mut entries = if internal_folder_id == 0 {
            stmt.query([folder_id])?
        } else {
            stmt.query([folder_id, internal_folder_id])?
        };

        while let Ok(Some(row)) = entries.next() {
            contents.items.push(FolderItem::Directory(FolderInfo {
                // first layer folders do not need string stripping
                name: if internal_folder_id == 0 {
                    row.get::<_, String>(1)?
                } else {
                    let raw = row.get::<_, String>(1)?;
                    String::from(&raw[1..])
                },
                ino: InodeBuilder::new()
                    .with_folder_id(folder_id as u16)
                    .with_internal_folder_id(row.get::<_, i64>(0)? as u16)
                    .with_rowid(0)
                    .build()
                    .0,
            }))
        }

        // get root files first. if directory, list as directory
        let mut stmt = db.prepare(if internal_folder_id == 0 {
            "SELECT ROWID, name FROM filenames WHERE folder = ?1 AND subdir IS NULL"
        } else {
            "SELECT ROWID, name FROM filenames WHERE folder = ?1 AND subdir = ?2"
        })?;

        let mut entries = if internal_folder_id == 0 {
            stmt.query([folder_id])?
        } else {
            stmt.query([folder_id, internal_folder_id])?
        };

        while let Ok(Some(entry)) = entries.next() {
            let (rowid, name) = (entry.get::<_, i64>(0)?, entry.get::<_, String>(1)?);

            let mut ino = Inode(0);
            ino.set_folder_id(folder_id as u16);

            // check if need to set internal folder id
            {
                if let Some(subfolder) = name.rsplit_once("/").map(|f| f.0) {
                    let internal_folder_id = db.query_row(
                        "SELECT ROWID FROM subdirs WHERE folder = ?1 AND path = ?2 LIMIT 1",
                        (folder_id, subfolder),
                        |r| r.get::<_, i64>(0),
                    )?;

                    ino.set_internal_folder_id(internal_folder_id as u16);
                }
            }

            ino.set_rowid(rowid as u32);

            match self.file_info(ino) {
                Ok(fi) => {
                    contents.items.push(FolderItem::File(fi));
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
            perm: 0o666,
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
        let folder_exists = match self.is_dir(ino.into()) {
            Ok(e) => e,
            Err(_) => {
                reply.error(fuser::Errno::ENOENT);
                return;
            }
        };

        // if directory/root
        if ino == fuser::INodeNo::ROOT || folder_exists {
            let attr = Self::mk_fileattr(req, ino, 0, 0, fuser::FileType::Directory, 0, 512);

            reply.attr(&Duration::from_secs(1), &attr);
        } else {
            let file_info = match self.file_info(ino.into()) {
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
                0,
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
        if ino == fuser::INodeNo::ROOT {
            reply.opened(
                fuser::FileHandle(self.get_handle()),
                fuser::FopenFlags::all() & !fuser::FopenFlags::FOPEN_PASSTHROUGH,
            );

            return;
        }

        match self.is_dir(ino.into()) {
            Ok(e) if !e => {
                tracing::error!("opendir: {} does not exist", ino);
                reply.error(fuser::Errno::ENOTDIR);
                return;
            }
            Err(_) => {
                tracing::error!("opendir: error checking {}", ino);
                reply.error(fuser::Errno::ENOTDIR);
                return;
            }

            _ => {}
        };

        reply.opened(
            fuser::FileHandle(self.get_handle()),
            fuser::FopenFlags::all()
                & !(fuser::FopenFlags::FOPEN_PASSTHROUGH | fuser::FopenFlags::FOPEN_CACHE_DIR),
        );
    }

    fn lookup(
        &self,
        req: &fuser::Request,
        parent: fuser::INodeNo,
        name: &std::ffi::OsStr,
        reply: fuser::ReplyEntry,
    ) {
        if let Err(e) = (|| {
            let name = name
                .to_str()
                .ok_or(anyhow::anyhow!("encode error"))?
                .to_string();

            if parent == fuser::INodeNo::ROOT {
                // lookup self (parent: 1)
                if name == FS_NAME {
                    let attr = Self::mk_fileattr(
                        req,
                        fuser::INodeNo::ROOT,
                        0,
                        0,
                        fuser::FileType::Directory,
                        0,
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

                    let mut i = Inode(0);
                    i.set_folder_id(folder_num as u16);

                    match self.is_dir(i) {
                        Ok(e) if e => {
                            let attr = Self::mk_fileattr(
                                req,
                                i.into(),
                                0,
                                0,
                                fuser::FileType::Directory,
                                0,
                                512,
                            );

                            reply.entry(&Duration::from_secs(1), &attr, fuser::Generation(0));
                        }

                        _ => {
                            reply.error(fuser::Errno::ENOENT);
                            anyhow::bail!("directory does not exist");
                        }
                    }
                }
            } else {
                // item is in a subfolder
                let parent_ino: Inode = parent.into();

                if self.is_dir(parent_ino)? {
                    match self.entry_info(parent_ino, &name)? {
                        FolderItem::Directory(dir) => {
                            let attr = Self::mk_fileattr(
                                req,
                                fuser::INodeNo(dir.ino),
                                0,
                                0,
                                fuser::FileType::Directory,
                                0,
                                512,
                            );

                            tracing::debug!(
                                "lookup: {} is a folder (ino: {:#x})",
                                dir.name,
                                dir.ino
                            );

                            reply.entry(&Duration::from_secs(1), &attr, fuser::Generation(0));
                        }

                        FolderItem::File(file) => {
                            let attr = Self::mk_fileattr(
                                req,
                                fuser::INodeNo(file.ino),
                                file.size as u64,
                                file.num_blocks as u64,
                                fuser::FileType::RegularFile,
                                0,
                                512,
                            );

                            tracing::debug!("lookup: {} is a file", name);

                            reply.entry(&Duration::from_secs(1), &attr, fuser::Generation(0));
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
                    for (index, folder) in folders.iter().enumerate() {
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
            let ino: Inode = ino.into();

            if let Err(e) = (move || {
                if self.is_dir(ino)? {
                    for (index, entry) in self
                        .list_folder_contents(
                            ino.folder_id() as i64,
                            ino.internal_folder_id() as i64,
                        )?
                        .items
                        .iter()
                        .skip(offset as usize)
                        .enumerate()
                    {
                        match entry {
                            FolderItem::Directory(dir) => {
                                if reply.add(
                                    fuser::INodeNo(dir.ino),
                                    offset + index as u64 + 1,
                                    fuser::FileType::Directory,
                                    &dir.name,
                                ) {
                                    break;
                                }
                            }

                            FolderItem::File(file) => {
                                if reply.add(
                                    fuser::INodeNo(file.ino),
                                    offset + index as u64 + 1,
                                    fuser::FileType::RegularFile,
                                    &file
                                        .name
                                        .rsplit_once("/")
                                        .map_or_else(|| file.name.clone(), |p| String::from(p.1)),
                                ) {
                                    break;
                                }
                            }
                        }
                    }

                    reply.ok();
                } else {
                    // readdir should only read directories
                    reply.error(fuser::Errno::ENOENT);
                }

                anyhow::Ok(())
            })() {
                tracing::error!("readdir: {}", e.to_string());
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
