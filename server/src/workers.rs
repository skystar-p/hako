use std::{sync::Arc, time::Duration};

use crate::{config::Config, state::State};

pub async fn delete_expired(state: Arc<State>, config: Config) {
    if config.expiry.unwrap_or(0) == 0 {
        return;
    }
    let expiry = config.expiry.unwrap() as f64;

    let mut interval = tokio::time::interval(Duration::from_secs(config.delete_interval));
    let pool = &state.pool;

    loop {
        interval.tick().await;

        let mut client = {
            match pool.get().await {
                Ok(client) => client,
                Err(err) => {
                    log::error!("could not get client from pool: {:?}", err);
                    continue;
                }
            }
        };

        // make transaction object
        let tx = {
            match client.transaction().await {
                Ok(tx) => tx,
                Err(err) => {
                    log::error!("could not build transaction object: {:?}", err);
                    continue;
                }
            }
        };

        // prepare statement
        let query =
            "delete from files where (now() > created_at + $1 * interval '1' second) returning id";
        let stmt = {
            match tx.prepare(query).await {
                Ok(stmt) => stmt,
                Err(err) => {
                    log::error!("could not prepare statement: {:?}", err);
                    continue;
                }
            }
        };

        // insert row
        let result = tx.query(&stmt, &[&expiry]).await;

        let rows = match result {
            Ok(rows) => rows,
            Err(err) => {
                log::error!("failed to delete expired files: {:?}", err);
                continue;
            }
        };

        for row in rows {
            if row.len() != 1 {
                continue;
            }
            let deleted: i64 = row.get(0);
            log::info!("deleted expired file id: {}", deleted);
        }

        // commit
        if let Err(err) = tx.commit().await {
            log::error!("failed to commit: {:?}", err);
            continue;
        }
    }
}
