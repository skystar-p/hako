use std::{collections::HashMap, convert::TryInto, sync::Arc};

use axum::{
    body::{Body, Bytes},
    extract::{ContentLengthLimit, Extension, Multipart, Query},
    http::StatusCode,
    response::Json,
};
use rusqlite::params;
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
    let mut nonce: Option<Bytes> = None;
    let mut filename_nonce: Option<Bytes> = None;
    let mut filename: Option<Bytes> = None;
    let mut is_text: bool = false;

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
                "salt" | "nonce" | "filename_nonce" | "filename" | "is_text" => {}
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
                "nonce" => {
                    // stream nonce should have 19 bytes length
                    // or, if text mode, then should have 24 bytes length
                    if bytes.len() != 19 && bytes.len() != 24 {
                        log::error!("invalid nonce length: {}", bytes.len());
                        return Err(StatusCode::BAD_REQUEST);
                    }
                    nonce = Some(bytes);
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
                "is_text" => {
                    if bytes.len() != 1 {
                        return Err(StatusCode::BAD_REQUEST);
                    }
                    is_text = bytes.to_vec()[0] != 0;
                }
                _ => {}
            }
        } else {
            break;
        }
    }

    if !is_text {
        if [&salt, &nonce, &filename_nonce, &filename]
            .iter()
            .any(|o| o.is_none())
        {
            return Err(StatusCode::BAD_REQUEST);
        }
    } else if [&salt, &nonce].iter().any(|o| o.is_none()) {
        return Err(StatusCode::BAD_REQUEST);
    }

    let conn = &mut state.0.conn.lock().await;

    // begin transaction
    let tx = match conn.transaction() {
        Ok(tx) => tx,
        Err(err) => {
            log::error!("could not build transaction object: {:?}", err);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    let query = "insert into files (filename, salt, nonce, filename_nonce, is_text) values (?1, ?2, ?3, ?4, ?5) returning id";
    let id = {
        // prepare statement
        let mut stmt = match tx.prepare(query) {
            Ok(stmt) => stmt,
            Err(err) => {
                log::error!("could not prepare statement: {:?}", err);
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        };

        // insert row
        let result = stmt.query(params![
            filename.as_ref().unwrap().to_vec(),
            salt.as_ref().unwrap().to_vec(),
            nonce.as_ref().unwrap().to_vec(),
            filename_nonce.as_ref().unwrap().to_vec(),
            is_text,
        ]);

        let mut rows = result.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let row = rows.next().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        // get returned id
        if let Some(row) = row {
            row.get(0).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        } else {
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    // commit
    if let Err(err) = tx.commit() {
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

    let config = &state.0.config;
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
                    // check if chunk sequence is too big
                    let seq_u64 = bytes.to_vec().try_into().unwrap();
                    let seq_u64 = i64::from_be_bytes(seq_u64) as u64;
                    if seq_u64 > config.chunk_count_limit {
                        log::error!("seq too large: {}", seq_u64);
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

    let conn = &mut state.0.conn.lock().await;

    // make transaction object
    let tx = match conn.transaction() {
        Ok(tx) => tx,
        Err(err) => {
            log::error!("could not build transaction object: {:?}", err);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    // prepare statement
    let query = "insert into file_contents (file_id, seq, content) values (?1, ?2, ?3)";
    {
        let mut stmt = match tx.prepare(query) {
            Ok(stmt) => stmt,
            Err(err) => {
                log::error!("could not prepare statement: {:?}", err);
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        };

        // insert row
        let result = stmt.execute(params![&id, &seq, &content.unwrap().to_vec()]);
        if let Err(err) = result {
            log::error!("failed to query: {:?}", err);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    }

    if is_last {
        // prepare statement
        let query = "update files set upload_complete = true where id = ?1";
        let mut stmt = {
            match tx.prepare(query) {
                Ok(stmt) => stmt,
                Err(err) => {
                    log::error!("could not prepare statement: {:?}", err);
                    return Err(StatusCode::INTERNAL_SERVER_ERROR);
                }
            }
        };

        // update row
        let result = stmt.execute(params![&id]);
        if let Err(err) = result {
            log::error!("failed to query: {:?}", err);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    }

    // commit
    if let Err(err) = tx.commit() {
        log::error!("failed to commit: {:?}", err);
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    Ok("ok")
}

#[derive(Serialize)]
pub struct MetadataResp {
    #[serde(with = "super::utils::base64")]
    filename: Vec<u8>,
    #[serde(with = "super::utils::base64")]
    salt: Vec<u8>,
    #[serde(with = "super::utils::base64")]
    nonce: Vec<u8>,
    #[serde(with = "super::utils::base64")]
    filename_nonce: Vec<u8>,
    is_text: bool,
    size: i64,
}

pub async fn metadata(
    state: Extension<Arc<State>>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<MetadataResp>, StatusCode> {
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
            log::error!("requires id");
            return Err(StatusCode::BAD_REQUEST);
        }
    };

    let conn = &mut state.0.conn.lock().await;

    // prepare statement
    let query = "select filename, salt, nonce, filename_nonce, is_text, (select sum(length(content)) from file_contents where file_id = ?1) from files where id = ?1 and upload_complete = true";
    let mut stmt = match conn.prepare(query) {
        Ok(stmt) => stmt,
        Err(err) => {
            log::error!("could not prepare statement: {:?}", err);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    // query metadata
    let mut result = match stmt.query(params![&id]) {
        Ok(result) => result,
        Err(err) => {
            log::error!("failed to query: {:?}", err);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    let row = result
        .next()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    // get returned id
    let row = if let Some(row) = row {
        row
    } else {
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    };

    let filename: Vec<u8> = row.get(0).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let salt: Vec<u8> = row.get(1).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let nonce: Vec<u8> = row.get(2).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let filename_nonce: Vec<u8> = row.get(3).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let is_text: bool = row.get(4).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let size: i64 = row.get(5).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(MetadataResp {
        filename,
        salt,
        nonce,
        filename_nonce,
        is_text,
        size,
    }))
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

    let conn = &mut state.0.conn.lock().await;

    // prepare statement
    let query = "select seq from file_contents where file_id = ?1 order by seq desc limit 1";
    let mut stmt = {
        match conn.prepare(query) {
            Ok(stmt) => stmt,
            Err(err) => {
                log::error!("could not prepare statement: {:?}", err);
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        }
    };

    // query last seq
    let mut result = match stmt.query(params![&id]) {
        Ok(result) => result,
        Err(err) => {
            log::error!("failed to query: {:?}", err);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    let row = result
        .next()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let row = if let Some(row) = row {
        row
    } else {
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    };

    // extract last_seq
    let last_seq: i64 = row.get(0).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut contents = Vec::with_capacity(last_seq as usize);

    for seq in 1..=last_seq {
        // prepare statement
        let query = "select content from file_contents where file_id = ?1 and seq = ?2";
        let mut stmt = match conn.prepare(query) {
            Ok(stmt) => stmt,
            Err(err) => {
                log::error!("could not prepare statement: {:?}", err);
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        };
        // query file
        let mut result = match stmt.query(params![&id, &seq]) {
            Ok(result) => result,
            Err(err) => {
                log::error!("failed to query: {:?}", err);
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        };

        let row = result
            .next()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let row = if let Some(row) = row {
            row
        } else {
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        };

        // extract fields
        let content: Vec<u8> = row.get(0).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        contents.push((seq, content));
    }

    tokio::spawn(async move {
        for (seq, content) in contents {
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
