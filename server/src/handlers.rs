use std::sync::Arc;

use axum::{
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
    _state: Extension<Arc<State>>,
    mut multipart: ContentLengthLimit<Multipart, CONTENT_LENGTH_LIMIT>,
) -> Result<&'static str, StatusCode> {
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
                "salt" | "nonce" | "filename" | "file" => {}
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
                }
                "nonce" => {
                    // nonce should have 24 bytes length
                    if bytes.len() != 24 {
                        return Err(StatusCode::BAD_REQUEST);
                    }
                }
                _ => {}
            }
        } else {
            return Ok("ok");
        }
    }

    Ok("ok")
}
