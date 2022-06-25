use std::{sync::Arc, time::Duration};

use rusqlite::params;

use crate::{config::Config, state::State};

pub async fn delete_expired(state: Arc<State>, config: Config) {
    if config.expiry.unwrap_or(0) == 0 {
        log::info!("expiry not specified. expiry worker will not run");
        return;
    }
    let expiry = config.expiry.unwrap() as f64;

    let mut interval = tokio::time::interval(Duration::from_secs(config.delete_interval));

    log::info!("starting expiry worker...");
    loop {
        interval.tick().await;

        let conn = &mut state.conn.lock().await;

        // make transaction object
        let tx = match conn.transaction() {
            Ok(tx) => tx,
            Err(err) => {
                log::error!("could not build transaction object: {:?}", err);
                continue;
            }
        };

        {
            // prepare statement
            let query =
                "delete from file_contents where file_id in (select id from files where (unixepoch(current_timestamp) > unixepoch(created_at) + ?1)) returning file_id";
            let mut stmt = match tx.prepare(query) {
                Ok(stmt) => stmt,
                Err(err) => {
                    log::error!("could not prepare statement: {:?}", err);
                    continue;
                }
            };

            // insert row
            let result = stmt.query(params![&expiry]);

            let mut rows = match result {
                Ok(rows) => rows,
                Err(err) => {
                    log::error!("failed to delete expired files: {:?}", err);
                    continue;
                }
            };

            // get deleted file ids
            let mut file_ids = Vec::new();
            while let Some(row) = rows.next().map_or(None, |row| row) {
                let id: Option<i64> = row.get(0).ok();
                if let Some(id) = id {
                    file_ids.push(id);
                }
            }

            // remove all duplicate file ids
            file_ids.sort();
            file_ids.dedup();

            // update available field for each file row
            for file_id in file_ids {
                let query = "update files set available = false where id = ?1";
                let mut stmt = {
                    match tx.prepare(query) {
                        Ok(stmt) => stmt,
                        Err(err) => {
                            log::error!("could not prepare statement: {:?}", err);
                            continue;
                        }
                    }
                };

                // update row
                let result = stmt.execute(params![&file_id]);
                if let Err(err) = result {
                    log::error!("failed to query: {:?}", err);
                    continue;
                }
                log::info!("deleted expired file: id {}", file_id);
            }
        }

        // commit
        if let Err(err) = tx.commit() {
            log::error!("failed to commit: {:?}", err);
            continue;
        }
    }
}
