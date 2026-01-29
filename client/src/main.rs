mod client;

use clap::Parser;
use std::{fs::metadata, net::SocketAddr};

use crate::client::Client;

#[derive(Parser, Debug, Clone)]
#[command(name = "hsync")]
#[command(version = "1.0.0")]
#[command(about = "folder sync over internet", long_about = None)]
struct Config {
    #[arg(short, long, value_name = "FOLDER")]
    folder: String,

    #[arg(short, long, value_name = "TOBIND", default_value = "[::]:0")]
    bind: SocketAddr,

    #[arg(short, long, value_name = "ADDR")]
    addr: String,

    #[arg(short, long, value_name = "PORT")]
    port: u16,
}

fn main() -> anyhow::Result<()> {
    let config = Config::parse();

    if !metadata(&config.folder)?.is_dir() {
        anyhow::bail!("path is not a folder");
    }

    let mut client = Client::new(config)?;
    let mut buffer = [0u8; 1024];

    loop {
        if client.handle(&mut buffer).is_err() {
            client.kill()?;
            break;
        }
    }

    Ok(())
}
