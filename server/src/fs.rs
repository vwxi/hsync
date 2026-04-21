use std::{
    path::PathBuf,
    sync::atomic::AtomicU64,
    time::{Duration, UNIX_EPOCH},
};

/// hsyncfs - expose block database as a file system
///
/// why? enabling a new type of topology where the server is actually
/// an active user in a folder that can push changes
///
/// structure:
/// root
/// |_ <folder id>
///     |_ <files>
///
use r2d2::{Pool, PooledConnection};
use r2d2_sqlite::SqliteConnectionManager;

const FS_NAME: &str = "hsyncfs";
const FILE_HANDLE_READ_BIT: u64 = 1 << 63;
const FILE_HANDLE_WRITE_BIT: u64 = 1 << 62;

pub struct Fs {
    pub db_pool: Pool<SqliteConnectionManager>,
    counter: AtomicU64,
}

impl Fs {
    fn get_handle(&self) -> u64 {
        self.counter
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            | FILE_HANDLE_READ_BIT
            | FILE_HANDLE_WRITE_BIT
    }

    fn dir_exists(&self, dir_name: i64) -> anyhow::Result<bool> {
        let db = self.db_pool.get()?;

        Ok(db.query_row(
            "SELECT COUNT(*) FROM folders WHERE id = ?1",
            [dir_name],
            |r| r.get::<_, i64>(0),
        )? > 0)
    }

    fn file_lookup(&mut self, name: &str) -> anyhow::Result<()> {
        let db = self.db_pool.get()?;

        Ok(())
    }
}

impl fuser::Filesystem for Fs {
    fn getattr(
        &self,
        _req: &fuser::Request,
        ino: fuser::INodeNo,
        fh: Option<fuser::FileHandle>,
        reply: fuser::ReplyAttr,
    ) {
        // is this fs root
        if ino == fuser::INodeNo::ROOT {
            let attr = fuser::FileAttr {
                ino,
                size: 0,
                blocks: 0,
                atime: UNIX_EPOCH,
                mtime: UNIX_EPOCH,
                ctime: UNIX_EPOCH,
                crtime: UNIX_EPOCH,
                kind: fuser::FileType::Directory,
                perm: 0o755,
                nlink: 2,
                uid: 501,
                gid: 20,
                rdev: 0,
                flags: 0,
                blksize: 512,
            };

            reply.attr(&Duration::from_secs(1), &attr);
        } else {
            reply.error(fuser::Errno::ENOENT);
        }
    }

    fn opendir(
        &self,
        _req: &fuser::Request,
        ino: fuser::INodeNo,
        _flags: fuser::OpenFlags,
        reply: fuser::ReplyOpen,
    ) {
        if ino != fuser::INodeNo::ROOT {
            reply.error(fuser::Errno::ENOTDIR);
            return;
        }

        reply.opened(
            fuser::FileHandle(self.get_handle()),
            fuser::FopenFlags::all(),
        );
    }

    // fn lookup(
    //     &mut self,
    //     _req: &fuser::Request,
    //     _parent: u64,
    //     name: &std::ffi::OsStr,
    //     reply: fuser::ReplyEntry,
    // ) {
    //     tracing::debug!("fs lookup: {}", name.to_str().unwrap());

    //     reply.entry(
    //         &std::time::Duration::from_secs(1),
    //         attr,
    //         fuser::Generation(0),
    //     );

    //     // match self.file_lookup(name.to_str().unwrap()) {
    //     //     Ok(_) => {}
    //     //     Err(e) => {
    //     //         tracing::error!("fs lookup: {}", e.to_string());
    //     //         reply.error(libc::ENOENT);
    //     //     }
    //     // };
    // }
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
