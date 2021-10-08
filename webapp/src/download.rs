use aead::generic_array::GenericArray;
use chacha20poly1305::aead::NewAead;
use chacha20poly1305::{Key, XChaCha20Poly1305};
use futures_util::TryStreamExt;
use hkdf::Hkdf;
use js_sys::{Array, Uint8Array};
use serde::Deserialize;
use sha2::Sha256;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::{spawn_local, JsFuture};
use yew::web_sys::*;
use yew::{classes, html, Component, ComponentLink, NodeRef, Properties};

use crate::utils::{build_url, BLOCK_OVERHEAD, BLOCK_SIZE};

pub enum DownloadMsg {
    Metadata(Result<FileMetadata, MetadataError>),
    PassphraseInput,
    StartDownload,
    DownloadComplete(Vec<u8>),
}

#[derive(Debug)]
pub enum MetadataError {
    FileNotFound,
    NotAvailable,
    Deserialize,
}

#[derive(Debug)]
enum MyError {
    JsValue(JsValue),
    Aead(aead::Error),
}

pub struct DownloadComponent {
    link: ComponentLink<Self>,
    passphrase_ref: NodeRef,
    passphrase_available: bool,
    file_id: i64,
    metadata: Option<Result<FileMetadata, MetadataError>>,
}

#[derive(Properties, Clone, PartialEq)]
pub struct DownloadProps {
    pub id: i64,
}

#[derive(Deserialize, Clone, Debug)]
pub struct FileMetadata {
    #[serde(with = "crate::utils::base64")]
    filename: Vec<u8>,
    #[serde(with = "crate::utils::base64")]
    salt: Vec<u8>,
    #[serde(with = "crate::utils::base64")]
    stream_nonce: Vec<u8>,
    #[serde(with = "crate::utils::base64")]
    filename_nonce: Vec<u8>,
    size: i64,
}

async fn get_file_metadata(id: i64) -> Result<FileMetadata, MetadataError> {
    let client = reqwest::Client::new();
    let resp = client
        .get(build_url("/api/metadata"))
        .query(&[("id", id)])
        .send()
        .await;
    let resp = match resp {
        Ok(resp) => {
            if resp.status() == 404 {
                return Err(MetadataError::FileNotFound);
            } else if resp.status() != 200 {
                return Err(MetadataError::NotAvailable);
            }
            resp
        }
        Err(_) => {
            return Err(MetadataError::NotAvailable);
        }
    };
    let body = match resp.bytes().await {
        Ok(body) => body,
        Err(_) => {
            return Err(MetadataError::NotAvailable);
        }
    };

    match serde_json::from_slice::<FileMetadata>(&body) {
        Ok(f) => Ok(f),
        Err(_) => Err(MetadataError::Deserialize),
    }
}

// function for streaming download. reqwest does not support stream in wasm environment
// so directly use `fetch()` and use `ReadableStream` from its body.
async fn get_download_stream(id: i64) -> Result<wasm_streams::ReadableStream, JsValue> {
    let mut opts = RequestInit::new();
    opts.method("GET");

    let url = format!("/api/download?id={}", id);
    let url = build_url(&url);
    let request = Request::new_with_str_and_init(&url, &opts)?;

    let window = window().unwrap();
    let resp = JsFuture::from(window.fetch_with_request(&request)).await?;
    let resp: Response = resp.dyn_into().unwrap();

    let stream = resp.body().unwrap();

    Ok(wasm_streams::ReadableStream::from_raw(
        stream.unchecked_into(),
    ))
}

impl Component for DownloadComponent {
    type Message = DownloadMsg;
    type Properties = DownloadProps;

    fn create(props: Self::Properties, link: ComponentLink<Self>) -> Self {
        // fetch file metadata
        let id = props.id;
        let clink = link.clone();
        spawn_local(async move {
            match get_file_metadata(id).await {
                Ok(metadata) => clink.send_message(DownloadMsg::Metadata(Ok(metadata))),
                Err(e) => clink.send_message(DownloadMsg::Metadata(Err(e))),
            }
        });

        Self {
            link,
            passphrase_ref: NodeRef::default(),
            passphrase_available: false,
            file_id: props.id,
            metadata: None,
        }
    }

    fn update(&mut self, msg: Self::Message) -> bool {
        match msg {
            DownloadMsg::Metadata(metadata) => {
                self.metadata = Some(metadata);
                true
            }
            DownloadMsg::PassphraseInput => {
                if let Some(input) = self.passphrase_ref.cast::<HtmlInputElement>() {
                    let v = input.value();
                    self.passphrase_available = !v.is_empty();
                }
                true
            }
            DownloadMsg::StartDownload => {
                let metadata = {
                    match &self.metadata {
                        Some(m) => match m {
                            Ok(m) => m,
                            Err(_) => return false,
                        },
                        None => return false,
                    }
                };

                // get passphrase from input
                let passphrase = if let Some(input) = self.passphrase_ref.cast::<HtmlInputElement>()
                {
                    input.value()
                } else {
                    log::error!("cannot get passphrase string from input");
                    return false;
                };

                let file_id = self.file_id;
                let metadata = metadata.clone();
                let clink = self.link.clone();
                spawn_local(async move {
                    let stream = match get_download_stream(file_id).await {
                        Ok(stream) => stream,
                        Err(e) => {
                            // TODO: propagate error
                            log::error!("cannot get stream: {:?}", e);
                            return;
                        }
                    };

                    let stream = stream.into_stream();
                    let stream = stream
                        .and_then(|b| async move { b.dyn_into::<Uint8Array>() })
                        .map_err(MyError::JsValue)
                        .map_ok(|arr| arr.to_vec());
                    let mut stream = Box::pin(stream);

                    // restore key from passphrase
                    let h =
                        Hkdf::<Sha256>::new(Some(metadata.salt.as_ref()), passphrase.as_bytes());
                    let mut key_slice = [0u8; 32];
                    if let Err(err) = h.expand(&[], &mut key_slice[..]) {
                        log::error!("cannot expand passphrase by hkdf: {:?}", err);
                        return;
                    }
                    let key = Key::from_slice(&key_slice);

                    // make cipher
                    let cipher = XChaCha20Poly1305::new(key);
                    let stream_nonce = GenericArray::from_slice(metadata.stream_nonce.as_ref());
                    let mut decryptor =
                        aead::stream::DecryptorBE32::from_aead(cipher, stream_nonce);

                    // preallocate buffers
                    let mut body = Vec::<u8>::with_capacity(metadata.size as usize);
                    let mut buffer = Vec::<u8>::with_capacity(BLOCK_SIZE + BLOCK_OVERHEAD);
                    let mut total_byte: usize = 0;
                    loop {
                        let chunk = match stream.try_next().await {
                            Ok(c) => match c {
                                Some(c) => c,
                                None => {
                                    let last_res = match decryptor.decrypt_last(buffer.as_ref()) {
                                        Ok(res) => res,
                                        Err(e) => {
                                            // TODO: inform to user
                                            log::error!("decryption failed: {:?}", e);
                                            return;
                                        }
                                    };
                                    body.extend(last_res);
                                    break;
                                }
                            },
                            Err(_) => {
                                return;
                            }
                        };

                        let mut chunk: &[u8] = chunk.as_ref();
                        while buffer.len() + chunk.len() >= BLOCK_SIZE + BLOCK_OVERHEAD {
                            let split_idx = BLOCK_SIZE + BLOCK_OVERHEAD - buffer.len();
                            buffer.extend(&chunk[..split_idx]);
                            let res = match decryptor
                                .decrypt_next(buffer.as_ref())
                                .map_err(MyError::Aead)
                            {
                                Ok(res) => res,
                                Err(e) => {
                                    // TODO: inform to user
                                    log::error!("decryption failed: {:?}", e);
                                    return;
                                }
                            };

                            buffer.clear();
                            chunk = &chunk[split_idx..];
                            total_byte += res.len();
                            log::info!("processed bytes: {}", total_byte);

                            body.extend(res);
                        }
                        buffer.extend(chunk);
                    }

                    clink.send_message(DownloadMsg::DownloadComplete(body));
                });

                true
            }
            DownloadMsg::DownloadComplete(decrypted) => {
                let bytes = Array::new();
                bytes.push(&Uint8Array::from(&decrypted[..]));
                let decrypted_blob = {
                    match web_sys::Blob::new_with_u8_array_sequence(&bytes) {
                        Ok(blob) => blob,
                        Err(err) => {
                            log::error!("failed to make data into blob: {:?}", err);
                            return false;
                        }
                    }
                };
                let obj_url = {
                    match Url::create_object_url_with_blob(&decrypted_blob) {
                        Ok(u) => u,
                        Err(err) => {
                            log::error!("failed to make blob into object url: {:?}", err);
                            return false;
                        }
                    }
                };

                log::info!("obj_url: {}", obj_url);
                true
            }
        }
    }

    fn change(&mut self, _props: Self::Properties) -> bool {
        false
    }

    fn view(&self) -> yew::Html {
        let mut button_class = vec![
            "border-solid",
            "bg-gray-700",
            "text-gray-300",
            "px-5",
            "py-3",
            "my-5",
            "rounded-xl",
        ];
        if self.passphrase_available {
            button_class.push("hover:bg-gray-400");
            button_class.push("hover:text-gray-700");
            button_class.push("cursor-pointer");
        } else {
            button_class.push("cursor-not-allowed");
        }

        let make_meta_span = |s: &str| {
            html! {
                <span class=classes!("text-gray-900", "mt-3")>{ s }</span>
            }
        };
        let metadata_div = match self.metadata {
            Some(ref m) => match m {
                Ok(_) => make_meta_span("Enter passphrase"),
                Err(e) => match e {
                    MetadataError::FileNotFound => make_meta_span("File not found"),
                    MetadataError::NotAvailable => make_meta_span("Server not available"),
                    MetadataError::Deserialize => make_meta_span("Malformed response from server"),
                },
            },
            None => make_meta_span("Loading..."),
        };

        let disabled = {
            if let Some(m) = &self.metadata {
                m.is_err()
            } else {
                false
            }
        };

        let passphrase_oninput = self.link.callback(|_| DownloadMsg::PassphraseInput);
        let download_onclick = self.link.callback(|_| DownloadMsg::StartDownload);

        html! {
            <>
                <div class=classes!("flex", "justify-center", "my-5")>
                    { metadata_div }
                </div>
                <div class=classes!("flex", "justify-center")>
                    <input
                        id="passphrase"
                        type="password"
                        ref={self.passphrase_ref.clone()}
                        class=classes!("px-4", "py-2", "rounded-lg", "border", "border-gray-300", "focus:outline-none", "focus:ring-2", "focus:ring-gray-200", "text-center")
                        disabled=disabled
                        placeholder={ "Passphrase" }
                        oninput={passphrase_oninput}
                    />
                </div>
                <div class=classes!("flex", "justify-center")>
                    <button
                        disabled={disabled || !self.passphrase_available}
                        onclick={download_onclick}
                        class=classes!(button_class)>
                        { "DOWNLOAD" }
                    </button>
                </div>
            </>
        }
    }
}
