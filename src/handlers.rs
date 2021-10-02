use axum::{
    extract::{ContentLengthLimit, Multipart},
    http::StatusCode,
};

pub async fn ping() -> &'static str {
    "pong"
}

// 10MiB
const CONTENT_LENGTH_LIMIT: u64 = 10 * 1024 * 1024;

pub async fn upload(
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
            let bytes = {
                if let Ok(bytes) = field.bytes().await {
                    bytes
                } else {
                    return Err(StatusCode::BAD_REQUEST);
                }
            };

            println!("name = {}, byte length {}", name, bytes.len());
        } else {
            return Ok("ok");
        }
    }

    Ok("ok")
}
