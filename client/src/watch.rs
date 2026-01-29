use inotify::{Inotify, WatchMask};

struct Watch {
    pub obj: Inotify,
}
