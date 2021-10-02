use axum::{extract::Multipart, http::StatusCode};

pub async fn ping() -> &'static str {
    "pong"
}

pub async fn upload(mut multipart: Multipart) -> Result<&'static str, StatusCode> {
    while let Ok(field) = multipart.next_field().await {
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
