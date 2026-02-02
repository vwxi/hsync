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

use anyhow::Context;
use clap::Parser;
use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use crate::server::Server;

#[derive(Parser, Debug, Clone)]
#[command(name = "hsync-server")]
#[command(version = "1.0.0")]
#[command(about = "server for hsync file sync service", long_about = None)]
struct Config {
    #[arg(short, long, value_name = "TOBIND", default_value = "[::]:7777")]
    bind: SocketAddr,

    #[arg(short, long, value_name = "PRIVKEY")]
    key: PathBuf,

    #[arg(short, long, value_name = "CERT")]
    cert: PathBuf,

    #[arg(short, long, value_name = "MAXCONNS")]
    max_conns: Option<usize>,
}

fn main() {
    let config = Config::parse();

    std::process::exit(if run(config).is_err() { 1 } else { 0 });
}

#[tokio::main]
async fn run(config: Config) -> anyhow::Result<()> {
    let server = Arc::new(Server::new(config)?);

    server.run().await
}
