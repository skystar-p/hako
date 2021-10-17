use std::borrow::Cow;
use std::string::FromUtf8Error;

use aead::generic_array::GenericArray;
use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use futures_util::{FutureExt, TryStreamExt};
use hkdf::Hkdf;
use js_sys::{Array, Uint8Array};
use serde::Deserialize;
use sha2::Sha256;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::{spawn_local, JsFuture};
use yew::{classes, html, Component, ComponentLink, Html, NodeRef, Properties};
use yew::{web_sys::*, Classes};

use crate::utils::{join_uri, BLOCK_OVERHEAD, BLOCK_SIZE};

pub enum DownloadMsg {
    Metadata(Result<FileMetadata, MetadataError>),
    PassphraseInput,
    StartDownload,
    StartFileDownload(FileMetadata, String),
    StartTextDownload(FileMetadata, String),
    Filename(Vec<u8>),
    Progress(ProgressInfo),
    DownloadError(DownloadError),
    FileDownloadComplete(Vec<u8>),
    TextDownloadComplete(Vec<u8>),
}

#[derive(Debug)]
pub enum MetadataError {
    FileNotFound,
    NotAvailable,
    Deserialize,
}

#[derive(Debug)]
pub enum DownloadError {
    KeyGeneration(Cow<'static, str>),
    JsValue(JsValue),
    Aead(aead::Error),
    MetadataError(MetadataError),
    Utf8Error(FromUtf8Error),
    Other,
}

pub enum ProgressInfo {
    DownloadBytes(usize),
}

pub struct DownloadComponent {
    link: ComponentLink<Self>,
    base_uri: String,
    passphrase_ref: NodeRef,
    a_ref: NodeRef,
    passphrase_available: bool,
    file_id: i64,
    metadata: Option<Result<FileMetadata, MetadataError>>,
    decrypted_filename: Option<String>,
    decrypted_text: Option<String>,
    downloaded_size: Option<usize>,
    download_error: Option<DownloadError>,
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
    nonce: Vec<u8>,
    #[serde(with = "crate::utils::base64")]
    filename_nonce: Vec<u8>,
    is_text: bool,
    size: i64,
}

async fn get_file_metadata(base_uri: &str, id: i64) -> Result<FileMetadata, MetadataError> {
    let client = reqwest::Client::new();
    let resp = client
        .get(join_uri(base_uri, "/api/metadata"))
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
async fn get_download_stream(
    base_uri: &str,
    id: i64,
) -> Result<wasm_streams::ReadableStream, JsValue> {
    let mut opts = RequestInit::new();
    opts.method("GET");

    let url = format!("/api/download?id={}", id);
    let url = join_uri(base_uri, &url);
    let request = Request::new_with_str_and_init(&url, &opts)?;

    let window = window().unwrap();
    let resp = JsFuture::from(window.fetch_with_request(&request)).await?;
    let resp: Response = resp.dyn_into().unwrap();

    let stream = resp.body().unwrap();

    Ok(wasm_streams::ReadableStream::from_raw(
        stream.unchecked_into(),
    ))
}

fn text_input(comp: &DownloadComponent, classes: Classes) -> Html {
    html! {
        <div class={classes}>
            <textarea class=classes!("w-1/2") rows=6>
                { comp.decrypted_text.as_ref().unwrap_or(&"".into()) }
            </textarea>
        </div>
    }
}

impl Component for DownloadComponent {
    type Message = DownloadMsg;
    type Properties = DownloadProps;

    fn create(props: Self::Properties, link: ComponentLink<Self>) -> Self {
        let base_uri = yew::utils::window().origin();
        // fetch file metadata
        let id = props.id;
        let clink = link.clone();
        let base_uri_cloned = base_uri.clone();
        spawn_local(async move {
            match get_file_metadata(&base_uri_cloned, id).await {
                Ok(metadata) => clink.send_message(DownloadMsg::Metadata(Ok(metadata))),
                Err(e) => clink.send_message(DownloadMsg::Metadata(Err(e))),
            }
        });

        Self {
            link,
            base_uri,
            passphrase_ref: NodeRef::default(),
            a_ref: NodeRef::default(),
            passphrase_available: false,
            file_id: props.id,
            metadata: None,
            decrypted_filename: None,
            decrypted_text: None,
            downloaded_size: None,
            download_error: None,
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
                let metadata = match &self.metadata {
                    Some(res) => match res {
                        Ok(metadata) => metadata,
                        Err(_) => {
                            return false;
                        }
                    },
                    None => {
                        return false;
                    }
                };

                // get passphrase from input
                let passphrase = if let Some(input) = self.passphrase_ref.cast::<HtmlInputElement>()
                {
                    input.value()
                } else {
                    let msg = "cannot get passphrase string from input";
                    self.link.send_message(DownloadMsg::DownloadError(
                        DownloadError::KeyGeneration(Cow::from(msg)),
                    ));
                    return false;
                };

                self.decrypted_filename = None;
                self.downloaded_size = None;
                self.download_error = None;

                if metadata.is_text {
                    self.link
                        .send_message(DownloadMsg::StartTextDownload(metadata.clone(), passphrase));
                } else {
                    self.link
                        .send_message(DownloadMsg::StartFileDownload(metadata.clone(), passphrase));
                }

                true
            }
            DownloadMsg::StartFileDownload(metadata, passphrase) => {
                // decrypt filename first
                // restore key from passphrase
                let h = Hkdf::<Sha256>::new(Some(metadata.salt.as_ref()), passphrase.as_bytes());
                let mut key_slice = [0u8; 32];
                if let Err(err) = h.expand(&[], &mut key_slice[..]) {
                    log::error!("cannot expand passphrase by hkdf: {:?}", err);
                    let msg = "cannot expand passphrase by hkdf";
                    self.link.send_message(DownloadMsg::DownloadError(
                        DownloadError::KeyGeneration(Cow::from(msg)),
                    ));
                    return false;
                }
                let key = Key::clone_from_slice(&key_slice);
                let cipher = XChaCha20Poly1305::new(&key);
                let filename_nonce = GenericArray::from_slice(metadata.filename_nonce.as_ref());
                let decrypted_filename = {
                    match cipher.decrypt(filename_nonce, metadata.filename.as_ref()) {
                        Ok(decrypted) => decrypted,
                        Err(err) => {
                            log::error!("failed to decrypt filename: {:?}", err);
                            self.link
                                .send_message(DownloadMsg::DownloadError(DownloadError::Aead(err)));
                            return true;
                        }
                    }
                };
                self.link
                    .send_message(DownloadMsg::Filename(decrypted_filename));

                let file_id = self.file_id;
                let metadata = metadata.clone();
                let clink = self.link.clone();
                let base_uri = self.base_uri.clone();
                spawn_local(async move {
                    let stream = match get_download_stream(&base_uri, file_id).await {
                        Ok(stream) => stream,
                        Err(e) => {
                            log::error!("cannot get stream: {:?}", e);
                            clink.send_message(DownloadMsg::DownloadError(DownloadError::JsValue(
                                e,
                            )));
                            return;
                        }
                    };

                    let stream = stream.into_stream();
                    let stream = stream
                        .and_then(|b| async move { b.dyn_into::<Uint8Array>() })
                        .map_err(DownloadError::JsValue)
                        .map_ok(|arr| arr.to_vec());
                    let mut stream = Box::pin(stream);

                    // make cipher
                    let cipher = XChaCha20Poly1305::new(&key);
                    let stream_nonce = GenericArray::from_slice(metadata.nonce.as_ref());
                    let mut decryptor =
                        aead::stream::DecryptorBE32::from_aead(cipher, stream_nonce);

                    // preallocate buffers
                    let mut body = Vec::<u8>::with_capacity(metadata.size as usize);
                    let mut buffer = Vec::<u8>::with_capacity(BLOCK_SIZE + BLOCK_OVERHEAD);
                    loop {
                        let chunk = match stream.try_next().await {
                            Ok(c) => match c {
                                Some(c) => c,
                                None => {
                                    let last_res = match decryptor.decrypt_last(buffer.as_ref()) {
                                        Ok(res) => res,
                                        Err(e) => {
                                            log::error!("decryption failed: {:?}", e);
                                            clink.send_message(DownloadMsg::DownloadError(
                                                DownloadError::Aead(e),
                                            ));
                                            return;
                                        }
                                    };
                                    clink.send_message(DownloadMsg::Progress(
                                        ProgressInfo::DownloadBytes(buffer.len()),
                                    ));
                                    body.extend(last_res);
                                    break;
                                }
                            },
                            Err(e) => {
                                clink.send_message(DownloadMsg::DownloadError(e));
                                return;
                            }
                        };

                        let mut chunk: &[u8] = chunk.as_ref();
                        while buffer.len() + chunk.len() >= BLOCK_SIZE + BLOCK_OVERHEAD {
                            let split_idx = BLOCK_SIZE + BLOCK_OVERHEAD - buffer.len();
                            buffer.extend(&chunk[..split_idx]);
                            let res = match decryptor
                                .decrypt_next(buffer.as_ref())
                                .map_err(DownloadError::Aead)
                            {
                                Ok(res) => res,
                                Err(e) => {
                                    log::error!("decryption failed: {:?}", e);
                                    clink.send_message(DownloadMsg::DownloadError(e));
                                    return;
                                }
                            };

                            clink.send_message(DownloadMsg::Progress(ProgressInfo::DownloadBytes(
                                buffer.len(),
                            )));
                            buffer.clear();
                            chunk = &chunk[split_idx..];

                            body.extend(res);
                        }
                        buffer.extend(chunk);
                    }

                    clink.send_message(DownloadMsg::FileDownloadComplete(body));
                });

                true
            }
            DownloadMsg::StartTextDownload(metadata, passphrase) => {
                // restore key from passphrase
                let h = Hkdf::<Sha256>::new(Some(metadata.salt.as_ref()), passphrase.as_bytes());
                let mut key_slice = [0u8; 32];
                if let Err(err) = h.expand(&[], &mut key_slice[..]) {
                    log::error!("cannot expand passphrase by hkdf: {:?}", err);
                    let msg = "cannot expand passphrase by hkdf";
                    self.link.send_message(DownloadMsg::DownloadError(
                        DownloadError::KeyGeneration(Cow::from(msg)),
                    ));
                    return false;
                }
                let key = Key::clone_from_slice(&key_slice);
                let cipher = XChaCha20Poly1305::new(&key);
                let nonce = *XNonce::from_slice(&metadata.nonce);

                let file_id = self.file_id;
                let base_uri = self.base_uri.clone();
                let clink = self.link.clone();
                let decrypt_fn = async move {
                    let client = reqwest::Client::new();
                    let resp = client
                        .get(join_uri(&base_uri, "/api/download"))
                        .query(&[("id", file_id)])
                        .send()
                        .await;
                    let resp = match resp {
                        Ok(resp) => {
                            if resp.status() == 404 {
                                return Err(DownloadError::MetadataError(
                                    MetadataError::FileNotFound,
                                ));
                            } else if resp.status() != 200 {
                                return Err(DownloadError::MetadataError(
                                    MetadataError::NotAvailable,
                                ));
                            }
                            resp
                        }
                        Err(_) => {
                            return Err(DownloadError::MetadataError(MetadataError::NotAvailable));
                        }
                    };
                    let body = match resp.bytes().await {
                        Ok(body) => body,
                        Err(_) => {
                            return Err(DownloadError::MetadataError(MetadataError::NotAvailable));
                        }
                    };

                    let decrypted = match cipher.decrypt(&nonce, body.as_ref()) {
                        Ok(decrypted) => decrypted,
                        Err(e) => {
                            return Err(DownloadError::Aead(e));
                        }
                    };

                    clink.send_message(DownloadMsg::TextDownloadComplete(decrypted));

                    Ok(())
                };

                let clink = self.link.clone();
                spawn_local(decrypt_fn.map(move |res| {
                    if let Err(e) = res {
                        clink.send_message(DownloadMsg::DownloadError(e));
                    }
                }));

                true
            }
            DownloadMsg::Filename(v) => {
                let filename = match String::from_utf8(v) {
                    Ok(filename) => filename,
                    Err(_) => "decrypted".into(),
                };
                self.decrypted_filename = Some(filename);

                true
            }
            DownloadMsg::Progress(info) => {
                let metadata = match &self.metadata {
                    Some(m) => match m {
                        Ok(m) => m,
                        Err(_) => {
                            return false;
                        }
                    },
                    None => {
                        return false;
                    }
                };
                match info {
                    ProgressInfo::DownloadBytes(b) => {
                        let before = self.downloaded_size.unwrap_or(0);
                        let file_size = metadata.size as usize;
                        let after = if before + b > file_size {
                            file_size
                        } else {
                            before + b
                        };
                        self.downloaded_size = Some(after);
                    }
                }

                true
            }
            DownloadMsg::DownloadError(err) => {
                self.download_error = Some(err);

                true
            }
            DownloadMsg::FileDownloadComplete(decrypted) => {
                let a = match self.a_ref.cast::<HtmlLinkElement>() {
                    Some(a) => a,
                    None => {
                        self.link
                            .send_message(DownloadMsg::DownloadError(DownloadError::Other));
                        log::error!("failed to get a ref");
                        return false;
                    }
                };

                // Touching filesystem in browser is strictly prohibited because of security
                // context, so we cannot pipe Vec<u8> into file directly. In order to invoke file
                // download for user, we have to convert it into `Blob` object and retrieve its
                // object url(which will resides in memory).
                // But we cannot use Vec<u8>'s reference directly because `Blob` is immutable
                // itself, so we have to full-copy the whole buffer. Not efficient of course...
                // In addition, moving WASM's linear memory into JS's `Uint8Array` also cause full
                // copy of buffer, which is worse... (consumes `file_size` * 3 amount of memory)
                // So in here, we use unsafe method `Uint8Array::view()` which just unsafely map
                // WASM's memory into linear `Uint8Array`'s memory representation, which will not
                // cause copy of memory. `mem_view` and decrypted content should have same
                // lifetime, and those should not be reallocated.
                unsafe {
                    let blob_parts = Array::new();
                    let mem_view = Uint8Array::view(&decrypted);
                    blob_parts.push(&mem_view);
                    let decrypted_blob = {
                        // causes full copy of buffer. this will consumes lots of memory, but there
                        // are no workaround currently.
                        match web_sys::Blob::new_with_u8_array_sequence(&blob_parts) {
                            Ok(blob) => blob,
                            Err(err) => {
                                self.link
                                    .send_message(DownloadMsg::DownloadError(DownloadError::Other));
                                log::error!("failed to make data into blob: {:?}", err);
                                return false;
                            }
                        }
                    };
                    let obj_url = {
                        match Url::create_object_url_with_blob(&decrypted_blob) {
                            Ok(u) => u,
                            Err(err) => {
                                self.link
                                    .send_message(DownloadMsg::DownloadError(DownloadError::Other));
                                log::error!("failed to make blob into object url: {:?}", err);
                                return false;
                            }
                        }
                    };

                    a.set_href(&obj_url);
                    // invoke download action
                    a.click();

                    // immediately revoke object url so that memory consumed by `Blob` object will
                    // soon released by GC.
                    if let Err(e) = Url::revoke_object_url(&obj_url) {
                        log::error!("failed to revoke object url: {:?}", e);
                    }
                }

                true
            }
            DownloadMsg::TextDownloadComplete(decrypted) => {
                let decrypted_str = match String::from_utf8(decrypted) {
                    Ok(s) => s,
                    Err(e) => {
                        self.link
                            .send_message(DownloadMsg::DownloadError(DownloadError::Utf8Error(e)));
                        return false;
                    }
                };
                self.decrypted_text = Some(decrypted_str);

                true
            }
        }
    }

    fn change(&mut self, _props: Self::Properties) -> bool {
        false
    }

    fn view(&self) -> Html {
        let passphrase_oninput = self.link.callback(|_| DownloadMsg::PassphraseInput);
        let download_onclick = self.link.callback(|_| DownloadMsg::StartDownload);

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

        let mut download_byte_class = vec!["flex", "justify-center"];
        let mut progress_class = vec!["flex", "relative", "pt-1", "justify-center"];
        let metadata_available = match &self.metadata {
            Some(m) => m.is_ok(),
            None => false,
        };
        if !metadata_available || self.downloaded_size.is_none() {
            download_byte_class.push("hidden");
            progress_class.push("hidden");
        }
        let downloaded = self.downloaded_size.unwrap_or(0);
        let file_size = match &self.metadata {
            Some(m) => match m {
                Ok(m) => m.size,
                Err(_) => 0,
            },
            None => 0,
        } as usize;
        let progress_percent_width = if file_size == 0 {
            0
        } else {
            ((downloaded as f64 / file_size as f64) * (100_f64)) as usize
        };

        let mut download_error_class = vec!["flex", "justify-center", "mb-4"];
        if self.download_error.is_none() {
            download_error_class.push("hidden");
        }
        let download_error_text: Cow<str> = match &self.download_error {
            Some(err) => match err {
                DownloadError::KeyGeneration(msg) => format!("Key error: {}", msg).into(),
                DownloadError::JsValue(_) => "File read error".into(),
                DownloadError::Aead(_) => "Decryption error".into(),
                DownloadError::MetadataError(_) => "File unavailable".into(),
                DownloadError::Utf8Error(_) => "UTF-8 conversion error".into(),
                DownloadError::Other => "Unknown error".into(),
            },
            None => "".into(),
        };
        let download_error_component = html! {
            <div class=classes!(download_error_class)>
                <span class=classes!("text-red-300")>{ download_error_text }</span>
            </div>
        };
        let decrypted_filename = self.decrypted_filename.clone().unwrap_or_else(|| "".into());

        let mut textarea_class = vec!["flex", "justify-center", "mb-4"];
        if self.decrypted_text.is_none() || self.download_error.is_some() {
            textarea_class.push("hidden");
        }

        let textarea_class = classes!(textarea_class);

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
                <div class=classes!("flex", "justify-center", "mt-5")>
                    <p class=classes!("text-gray-300", "mb-3")>{ &decrypted_filename }</p>
                </div>
                <div class=classes!(progress_class)>
                    <div class=classes!("overflow-hidden", "h-2", "mb-4", "text-xs", "flex", "rounded", "bg-blue-200", "w-1/2", "mt-4")>
                        <div style={format!("width:{}%", progress_percent_width)} class=classes!("shadow-none", "flex", "flex-col", "text-center", "whitespace-nowrap", "text-white", "justify-center", "bg-blue-400")></div>
                    </div>
                </div>
                { text_input(self, textarea_class) }
                <div class=classes!("flex", "justify-center")>
                    <button
                        disabled={disabled || !self.passphrase_available}
                        onclick={download_onclick}
                        class=classes!(button_class)>
                        { "DOWNLOAD" }
                    </button>
                </div>
                { download_error_component }
                <a download={decrypted_filename} class=classes!("hidden") ref={self.a_ref.clone()}></a>
            </>
        }
    }
}
