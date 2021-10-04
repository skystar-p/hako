use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::{ContentLengthLimit, Extension, Multipart},
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
                    // salt should have 16 bytes length
                    if bytes.len() != 16 {
                        return Err(StatusCode::BAD_REQUEST);
                    }
                    salt = Some(bytes);
                }
                "nonce" => {
                    // nonce should have 24 bytes length
                    if bytes.len() != 24 {
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
        if let Ok(client) = pool.get().await {
            client
        } else {
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    // make transaction object
    let tx = {
        if let Ok(tx) = client.transaction().await {
            tx
        } else {
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    // prepare statement
    let query = "insert into files (content, filename, salt, nonce) values ($1, $2, $3, $4)";
    let stmt = {
        if let Ok(stmt) = tx.prepare(query).await {
            stmt
        } else {
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
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
    if result.is_err() {
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }
    // commit
    if tx.commit().await.is_err() {
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    Ok("ok")
}
