//! routines for handling direct connections

use futures::future::join_all;
use quinn::Incoming;

use crate::client::Client;

impl Client {
    pub(crate) async fn handle_direct(conn: Incoming) -> anyhow::Result<()> {
        let conn = conn.await?;
        
        let futs = vec![
            tokio::spawn(async move {
                
            })
        ];

        join_all(futs).await;

        Ok(())
    }
}
