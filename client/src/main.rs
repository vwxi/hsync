mod client;

use clap::Parser;
use std::{fs::metadata, net::SocketAddr};
use tokio::select;

use crate::client::Client;

/// a client can do one of two things:
/// 1. start syncing a folder
/// 2. connect to a currently syncing folder
#[derive(Parser, Debug, Clone)]
#[command(name = "hsync")]
#[command(version = "1.0.0")]
#[command(about = "folder sync over internet", long_about = None)]
struct Config {
    /// if present, it will initiate with the server as
    /// a new folder.
    ///
    /// TODO: make this optional so we can do either or
    #[arg(short, long, value_name = "FOLDER")]
    folder: String,

    /// if present, it will initiate as a client syncing
    /// up with an existing folder
    #[arg(short, long, value_name = "ID")]
    id: Option<String>,

    /// this is obligatory
    #[arg(short, long, value_name = "PASSWORD")]
    password: String,

    #[arg(short, long, value_name = "TOBIND", default_value = "[::]:0")]
    bind: SocketAddr,

    #[arg(short, long, value_name = "ADDR")]
    addr: SocketAddr,

    #[arg(short, long, value_name = "INSECURE")]
    insecure: bool,
}

fn main() -> anyhow::Result<()> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Failed to install default CryptoProvider");

    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    let config = Config::parse();

    if !metadata(&config.folder)?.is_dir() {
        anyhow::bail!("path is not a folder");
    }

    if let Err(e) = Client::client_main(config) {
        tracing::error!("{}, killing client", e);
    }

    Ok(())
}
