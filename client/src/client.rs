use std::ffi::OsStr;

use inotify::{Event, EventMask, Inotify, WatchDescriptor, WatchMask};

use crate::Config;

pub struct Client {
    config: Config,
    notify: Inotify,
    wd: WatchDescriptor,
}

impl Client {
    pub fn new(config: Config) -> anyhow::Result<Client> {
        // register inotify instance
        let notify = Inotify::init()?;
        let wd = notify
            .watches()
            .add(config.folder.clone(), WatchMask::all())?;

        Ok(Client { config, notify, wd })
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
