use std::sync::Arc;

use axum::{
    body::{Body, Bytes},
    extract::{ContentLengthLimit, Extension, Multipart, Path},
    http::StatusCode,
};

use crate::state::State;

pub async fn ping() -> &'static str {
    "pong"
}

// 100MiB
const CONTENT_LENGTH_LIMIT: u64 = 100 * 1024 * 1024;

pub async fn upload(
    state: Extension<Arc<State>>,
    mut multipart: ContentLengthLimit<Multipart, CONTENT_LENGTH_LIMIT>,
) -> Result<&'static str, StatusCode> {
    let mut salt: Option<Bytes> = None;
    let mut nonce: Option<Bytes> = None;
    let mut filename: Option<Bytes> = None;
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
                "salt" | "nonce" | "filename" | "content" => {}
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
                "salt" => {
                    // salt should have 32 bytes length
                    if bytes.len() != 32 {
                        log::error!("invalid salt length: {}", bytes.len());
                        return Err(StatusCode::BAD_REQUEST);
                    }
                    salt = Some(bytes);
                }
                "nonce" => {
                    // nonce should have 24 bytes length
                    if bytes.len() != 24 {
                        log::error!("invalid nonce length: {}", bytes.len());
                        return Err(StatusCode::BAD_REQUEST);
                    }
                    nonce = Some(bytes);
                }
                "filename" => {
                    filename = Some(bytes);
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
    let query = "insert into files (content, filename, salt, nonce) values ($1, $2, $3, $4)";
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
                &content.unwrap().to_vec(),
                &filename.unwrap().to_vec(),
                &salt.unwrap().to_vec(),
                &nonce.unwrap().to_vec(),
            ],
        )
        .await;
    if let Err(err) = result {
        log::error!("failed to query: {:?}", err);
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
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
    Path(id): Path<String>,
) -> Result<Body, StatusCode> {
    if id.is_empty() {
        log::error!("empty id is not allowed");
        return Err(StatusCode::BAD_REQUEST);
    }
    let id: i64 = {
        match id.parse() {
            Ok(id) => id,
            Err(_) => {
                log::error!("invalid id");
                return Err(StatusCode::BAD_REQUEST);
            }
        }
    };

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
    let query = "select content, filename, salt, nonce from files where id = $1";
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
        log::error!("file not found: {}", id);
        return Err(StatusCode::NOT_FOUND);
    } else if result.len() != 1 {
        log::error!("multiple file returned: {}", id);
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    let result = &result[0];
    if result.len() != 4 {
        log::error!("invalid column length: {}", result.len());
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    // extract fields
    let mut content: Vec<u8> = result.get(0);
    let mut filename: Vec<u8> = result.get(1);
    let mut salt: Vec<u8> = result.get(2); // 32-byte
    let mut nonce: Vec<u8> = result.get(3); // 24-byte

    let mut content_len_bytes = (content.len() as u64).to_be_bytes().to_vec();
    let mut filename_len_bytes = (filename.len() as u64).to_be_bytes().to_vec();

    // build response
    let mut body = Vec::<u8>::with_capacity(
        content_len_bytes.len()
            + filename_len_bytes.len()
            + content.len()
            + filename.len()
            + salt.len()
            + nonce.len(),
    );
    body.append(&mut content_len_bytes);
    body.append(&mut filename_len_bytes);
    body.append(&mut salt);
    body.append(&mut nonce);
    body.append(&mut filename);
    body.append(&mut content);

    Ok(Body::from(body))
}
