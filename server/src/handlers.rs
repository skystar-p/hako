use std::{collections::HashMap, convert::TryInto, sync::Arc};

use axum::{
    body::{Body, Bytes},
    extract::{ContentLengthLimit, Extension, Multipart, Query},
    http::StatusCode,
    response::Json,
};
use serde::Serialize;

use crate::state::State;

pub async fn ping() -> &'static str {
    "pong"
}

// 10MiB
const PREPARE_LENGTH_LIMIT: u64 = 10 * 1024 * 1024;

#[derive(Serialize)]
pub struct PrepareUploadResp {
    id: i64,
}

pub async fn prepare_upload(
    state: Extension<Arc<State>>,
    mut multipart: ContentLengthLimit<Multipart, PREPARE_LENGTH_LIMIT>,
) -> Result<Json<PrepareUploadResp>, StatusCode> {
    let mut salt: Option<Bytes> = None;
    let mut stream_nonce: Option<Bytes> = None;
    let mut filename_nonce: Option<Bytes> = None;
    let mut filename: Option<Bytes> = None;

    while let Ok(field) = multipart.0.next_field().await {
        if let Some(field) = field {
            let name = {
                if let Some(name) = field.name() {
                    name.to_owned()
                } else {
                    return Err(StatusCode::BAD_REQUEST);
                }
            };

            // check field name first, then read body
            match name.as_ref() {
                "salt" | "stream_nonce" | "filename_nonce" | "filename" => {}
                _ => {
                    // unallowed part. ignore
                    continue;
                }
            }

            // now read some body
            let bytes = {
                if let Ok(bytes) = field.bytes().await {
                    bytes
                } else {
                    return Err(StatusCode::BAD_REQUEST);
                }
            };

            // check body validity
            match name.as_ref() {
                "salt" => {
                    // salt should have 32 bytes length
                    if bytes.len() != 32 {
                        log::error!("invalid salt length: {}", bytes.len());
                        return Err(StatusCode::BAD_REQUEST);
                    }
                    salt = Some(bytes);
                }
                "stream_nonce" => {
                    // stream nonce should have 19 bytes length
                    if bytes.len() != 19 {
                        log::error!("invalid stream nonce length: {}", bytes.len());
                        return Err(StatusCode::BAD_REQUEST);
                    }
                    stream_nonce = Some(bytes);
                }
                "filename_nonce" => {
                    // filename nonce should have 24 bytes length
                    if bytes.len() != 24 {
                        log::error!("invalid filename nonce length: {}", bytes.len());
                        return Err(StatusCode::BAD_REQUEST);
                    }
                    filename_nonce = Some(bytes);
                }
                "filename" => {
                    filename = Some(bytes);
                }
                _ => {}
            }
        } else {
            break;
        }
    }

    if [&salt, &stream_nonce, &filename_nonce, &filename]
        .iter()
        .any(|o| o.is_none())
    {
        return Err(StatusCode::BAD_REQUEST);
    }

    let pool = &state.0.pool;

    let mut client = {
        match pool.get().await {
            Ok(client) => client,
            Err(err) => {
                log::error!("could not get client from pool: {:?}", err);
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        }
    };

    // make transaction object
    let tx = {
        match client.transaction().await {
            Ok(tx) => tx,
            Err(err) => {
                log::error!("could not build transaction object: {:?}", err);
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        }
    };

    // prepare statement
    let query = "insert into files (filename, salt, stream_nonce, filename_nonce) values ($1, $2, $3, $4) returning id";
    let stmt = {
        match tx.prepare(query).await {
            Ok(stmt) => stmt,
            Err(err) => {
                log::error!("could not prepare statement: {:?}", err);
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        }
    };

    // insert row
    let result = tx
        .query(
            &stmt,
            &[
                &filename.unwrap().to_vec(),
                &salt.unwrap().to_vec(),
                &stream_nonce.unwrap().to_vec(),
                &filename_nonce.unwrap().to_vec(),
            ],
        )
        .await;

    let id = match result {
        Ok(rows) => {
            if rows.is_empty() {
                log::error!("id not returned");
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            } else if rows.len() != 1 {
                log::error!("multiple id returned");
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
            if rows[0].len() != 1 {
                log::error!("invalid column length");
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
            let id: i64 = rows[0].get(0);
            id
        }
        Err(err) => {
            log::error!("failed to query: {:?}", err);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };
    // commit
    if let Err(err) = tx.commit().await {
        log::error!("failed to commit: {:?}", err);
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    Ok(Json(PrepareUploadResp { id }))
}

// 100MiB
const UPLOAD_LENGTH_LIMIT: u64 = 100 * 1024 * 1024;

pub async fn upload(
    state: Extension<Arc<State>>,
    mut multipart: ContentLengthLimit<Multipart, UPLOAD_LENGTH_LIMIT>,
) -> Result<&'static str, StatusCode> {
    let mut id: Option<Bytes> = None;
    let mut seq: Option<Bytes> = None;
    let mut is_last: Option<Bytes> = None;
    let mut content: Option<Bytes> = None;

    while let Ok(field) = multipart.0.next_field().await {
        if let Some(field) = field {
            let name = {
                if let Some(name) = field.name() {
                    name.to_owned()
                } else {
                    return Err(StatusCode::BAD_REQUEST);
                }
            };

            // check field name first, then read body
            match name.as_ref() {
                "id" | "seq" | "is_last" | "content" => {}
                _ => {
                    // unallowed part. ignore
                    continue;
                }
            }
            let bytes = {
                if let Ok(bytes) = field.bytes().await {
                    bytes
                } else {
                    return Err(StatusCode::BAD_REQUEST);
                }
            };

            match name.as_ref() {
                "id" => {
                    // id should have 8 bytes length
                    if bytes.len() != 8 {
                        log::error!("invalid id length: {}", bytes.len());
                        return Err(StatusCode::BAD_REQUEST);
                    }
                    id = Some(bytes);
                }
                "seq" => {
                    // seq should have 8 bytes length
                    if bytes.len() != 8 {
                        log::error!("invalid seq length: {}", bytes.len());
                        return Err(StatusCode::BAD_REQUEST);
                    }
                    seq = Some(bytes);
                }
                "is_last" => {
                    // is_last should have 1 bytes length
                    if bytes.len() != 1 {
                        log::error!("invalid is_last length: {}", bytes.len());
                        return Err(StatusCode::BAD_REQUEST);
                    }
                    is_last = Some(bytes);
                }
                "content" => {
                    content = Some(bytes);
                }
                _ => {}
            }
        } else {
            break;
        }
    }

    if [&id, &seq, &is_last, &content].iter().any(|o| o.is_none()) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let id = id.unwrap().to_vec().try_into().unwrap();
    let id = i64::from_be_bytes(id);
    let seq = seq.unwrap().to_vec().try_into().unwrap();
    let seq = i64::from_be_bytes(seq);
    let is_last = is_last.unwrap()[0] != 0;

    let pool = &state.0.pool;

    let mut client = {
        match pool.get().await {
            Ok(client) => client,
            Err(err) => {
                log::error!("could not get client from pool: {:?}", err);
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        }
    };

    // make transaction object
    let tx = {
        match client.transaction().await {
            Ok(tx) => tx,
            Err(err) => {
                log::error!("could not build transaction object: {:?}", err);
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        }
    };

    // prepare statement
    let query = "insert into file_contents (file_id, seq, content) values ($1, $2, $3)";
    let stmt = {
        match tx.prepare(query).await {
            Ok(stmt) => stmt,
            Err(err) => {
                log::error!("could not prepare statement: {:?}", err);
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        }
    };

    // insert row
    let result = tx
        .query(&stmt, &[&id, &seq, &content.unwrap().to_vec()])
        .await;
    if let Err(err) = result {
        log::error!("failed to query: {:?}", err);
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    if is_last {
        // prepare statement
        let query = "update files set upload_complete = true where id = $1";
        let stmt = {
            match tx.prepare(query).await {
                Ok(stmt) => stmt,
                Err(err) => {
                    log::error!("could not prepare statement: {:?}", err);
                    return Err(StatusCode::INTERNAL_SERVER_ERROR);
                }
            }
        };

        // insert row
        let result = tx.query(&stmt, &[&id]).await;
        if let Err(err) = result {
            log::error!("failed to query: {:?}", err);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    }

    // commit
    if let Err(err) = tx.commit().await {
        log::error!("failed to commit: {:?}", err);
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    Ok("ok")
}

pub async fn download(
    state: Extension<Arc<State>>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Body, StatusCode> {
    let id = params.get("id").cloned();

    let id = match id {
        Some(id) => match id.parse::<i64>() {
            Ok(id) => {
                if id <= 0 {
                    log::error!("id should be positive");
                    return Err(StatusCode::BAD_REQUEST);
                }
                id
            }
            Err(_) => {
                log::error!("id should be integer");
                return Err(StatusCode::BAD_REQUEST);
            }
        },
        None => {
            log::error!("require id");
            return Err(StatusCode::BAD_REQUEST);
        }
    };

    // prepare sender
    let (mut sender, body) = Body::channel();

    tokio::spawn(async move {
        let pool = &state.0.pool;

        let client = {
            match pool.get().await {
                Ok(client) => client,
                Err(err) => {
                    log::error!("could not get client from pool: {:?}", err);
                    return Err(StatusCode::INTERNAL_SERVER_ERROR);
                }
            }
        };

        // prepare statement
        let query = "select seq from file_contents where file_id = $1 order by seq desc limit 1";
        let stmt = {
            match client.prepare(query).await {
                Ok(stmt) => stmt,
                Err(err) => {
                    log::error!("could not prepare statement: {:?}", err);
                    return Err(StatusCode::INTERNAL_SERVER_ERROR);
                }
            }
        };

        // query last seq
        let result = {
            match client.query(&stmt, &[&id]).await {
                Ok(result) => result,
                Err(err) => {
                    log::error!("failed to query: {:?}", err);
                    return Err(StatusCode::INTERNAL_SERVER_ERROR);
                }
            }
        };
        // validate query result
        if result.is_empty() {
            log::error!("file or last seq not found: id={}", id);
            return Err(StatusCode::NOT_FOUND);
        } else if result.len() != 1 {
            log::error!("multiple rows returned: id={}", id);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }

        let result = &result[0];
        if result.len() != 1 {
            log::error!("invalid column length: {}", result.len());
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }

        // extract last_seq
        let last_seq: i64 = result.get(0);
        log::info!("file id: {}, last_seq is {}", id, last_seq);

        for seq in 1..=last_seq {
            // prepare statement
            let query = "select content from file_contents where file_id = $1 and seq = $2";
            let stmt = {
                match client.prepare(query).await {
                    Ok(stmt) => stmt,
                    Err(err) => {
                        log::error!("could not prepare statement: {:?}", err);
                        return Err(StatusCode::INTERNAL_SERVER_ERROR);
                    }
                }
            };
            // query file
            let result = {
                match client.query(&stmt, &[&id, &seq]).await {
                    Ok(result) => result,
                    Err(err) => {
                        log::error!("failed to query: {:?}", err);
                        return Err(StatusCode::INTERNAL_SERVER_ERROR);
                    }
                }
            };
            // validate query result
            if result.is_empty() {
                log::error!("chunk not found: id={}, seq={}", id, seq);
                return Err(StatusCode::NOT_FOUND);
            } else if result.len() != 1 {
                log::error!("multiple chunk returned: id={}, seq={}", id, seq);
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }

            let result = &result[0];
            if result.len() != 1 {
                log::error!("invalid column length: {}", result.len());
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }

            // extract fields
            let content: Vec<u8> = result.get(0);

            log::info!("file id: {}, sending chunk {}", id, seq);
            match sender.send_data(Bytes::from(content)).await {
                Ok(_) => {}
                Err(e) => {
                    sender.abort();
                    log::error!(
                        "failed to send chunk: id={}, seq={}, error={:?}",
                        id,
                        seq,
                        e
                    );
                    return Err(StatusCode::INTERNAL_SERVER_ERROR);
                }
            }
        }

        Ok(())
    });

    Ok(body)
}
