/// the syncing server only servers to mediate between
/// peers wrt events and resolving edit conflicts.
///
/// that being said, all state is temporary.
///
/// issues that have to be thought through:
/// 1. bootstrapping: how does the client on first connect get what it is missing from the server/other clients?
///                   does the server send an entry directory? (that seems like it won't scale at all)
///
mod server;

use clap::Parser;
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
use tracing::{Instrument, info_span};

use crate::server::Server;

#[derive(Parser, Debug, Clone)]
#[command(name = "hsync-server")]
#[command(version = "1.0.0")]
#[command(about = "server for hsync file sync service", long_about = None)]
struct Config {
    #[arg(short, long, value_name = "TOBIND", default_value = "[::]:7777")]
    bind: SocketAddr,

    #[arg(short, long, value_name = "PRIVKEY")]
    key: Option<PathBuf>,

    #[arg(short, long, value_name = "CERT")]
    cert: Option<PathBuf>,

    #[arg(short, long, value_name = "MAXCONNS")]
    max_conns: Option<usize>,

    #[arg(short, long, value_name = "DB")]
    db: Option<PathBuf>,
}

fn main() {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Failed to install default CryptoProvider");

    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    let config = Config::parse();

    if let Err(e) = run(config) {
        tracing::error!("{:?}", e);
    }
}

#[tokio::main]
async fn run(config: Config) -> anyhow::Result<()> {
    let server = Arc::new(Server::new(config)?);
    let span = info_span!("run thread");

    let span2 = span.clone();
    server.run(span2).instrument(span).await
}
