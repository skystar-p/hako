use std::borrow::Cow;

use aead::generic_array::GenericArray;
use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use futures_util::{FutureExt, TryStreamExt};
use hkdf::Hkdf;
use js_sys::Uint8Array;
use reqwest::multipart::{Form, Part};
use serde_json::Value;
use sha2::Sha256;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::spawn_local;
use yew::{
    classes, html,
    web_sys::{HtmlInputElement, HtmlTextAreaElement},
    ChangeData, Component, ComponentLink, Html, NodeRef,
};

use crate::utils::{join_uri, BLOCK_SIZE};

pub enum UploadMsg {
    FileChanged(web_sys::File),
    PassphraseInput,
    ChangeUploadType,
    FileUploadStart,
    TextUploadStart,
    Progress(ProgressInfo),
    UploadError(UploadError),
    UploadComplete(i64),
}

#[derive(Debug)]
pub enum UploadError {
    JsValue(JsValue),
    Aead(aead::Error),
    Remote(String),
}

#[derive(Clone)]
pub enum UploadType {
    File,
    Text,
}

pub enum ProgressInfo {
    UploadBytes(usize),
}

pub struct UploadComponent {
    link: ComponentLink<Self>,
    base_uri: String,
    selected_file: Option<web_sys::File>,
    upload_type: UploadType,
    textarea_ref: NodeRef,
    passphrase_ref: NodeRef,
    passphrase_available: bool,
    file_size: Option<usize>,
    uploaded_size: Option<usize>,
    file_id: Option<i64>,
    upload_error: Option<UploadError>,
}

fn file_input(comp: &UploadComponent) -> Html {
    let file_onchange = comp.link.batch_callback(|e| {
        if let ChangeData::Files(files) = e {
            let file = files.item(0);
            file.map(UploadMsg::FileChanged)
        } else {
            None
        }
    });

    html! {
        <div class=classes!("flex", "items-center", "justify-center", "bg-gray-lighter", "mt-12")>
            <label class=classes!("w-1/2", "flex", "flex-col", "items-center", "px-4", "py-6", "bg-gray-600", "text-gray-400", "rounded-lg", "shadow-lg", "tracking-wide", "uppercase", "border", "border-gray-400", "cursor-pointer", "hover:bg-gray-400", "hover:text-gray-600")>
                <svg class=classes!("w-8", "h-8") fill="currentColor" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20">
                    <path d="M16.88 9.1A4 4 0 0 1 16 17H5a5 5 0 0 1-1-9.9V7a3 3 0 0 1 4.52-2.59A4.98 4.98 0 0 1 17 8c0 .38-.04.74-.12 1.1zM11 11h3l-4-4-4 4h3v3h2v-3z" />
                </svg>
                <span class=classes!("mt-2", "text-base", "leading-normal")>{ "Select a file" }</span>
                <input type="file" class=classes!("hidden") onchange={file_onchange} />
            </label>
        </div>
    }
}

fn text_input(comp: &UploadComponent) -> Html {
    html! {
        <div class=classes!("flex", "justify-center")>
            <textarea ref={comp.textarea_ref.clone()} class=classes!("w-1/2") rows=6>
            </textarea>
        </div>
    }
}

impl Component for UploadComponent {
    type Message = UploadMsg;
    type Properties = ();

    fn create(_props: Self::Properties, link: ComponentLink<Self>) -> Self {
        let base_uri = yew::utils::window().origin();

        Self {
            link,
            base_uri,
            selected_file: None,
            upload_type: UploadType::File,
            textarea_ref: NodeRef::default(),
            passphrase_ref: NodeRef::default(),
            passphrase_available: false,
            file_size: None,
            uploaded_size: None,
            file_id: None,
            upload_error: None,
        }
    }

    fn update(&mut self, msg: Self::Message) -> bool {
        match msg {
            UploadMsg::FileChanged(file) => {
                let file_size = file.size() as usize;
                self.file_id = None;
                self.uploaded_size = None;
                self.file_size = Some(file_size);
                self.selected_file = Some(file);
                self.passphrase_available = false;
                if let Some(input) = self.passphrase_ref.cast::<HtmlInputElement>() {
                    input.set_value("");
                }
                true
            }
            UploadMsg::PassphraseInput => {
                if let Some(input) = self.passphrase_ref.cast::<HtmlInputElement>() {
                    let v = input.value();
                    self.passphrase_available = !v.is_empty();
                }
                true
            }
            UploadMsg::ChangeUploadType => {
                match self.upload_type {
                    UploadType::File => {
                        self.upload_type = UploadType::Text;
                    }
                    UploadType::Text => {
                        self.upload_type = UploadType::File;
                    }
                }
                true
            }
            UploadMsg::FileUploadStart => {
                self.upload_error = None;
                self.file_id = None;
                self.uploaded_size = None;
                if !self.passphrase_available {
                    return false;
                }
                let file = if let Some(file) = &self.selected_file {
                    file
                } else {
                    return false;
                };

                // get passphrase from input
                let passphrase = if let Some(input) = self.passphrase_ref.cast::<HtmlInputElement>()
                {
                    input.value()
                } else {
                    log::error!("cannot get passphrase string from input");
                    return false;
                };

                // generate salt for hkdf expand()
                let mut salt = [0u8; 32];
                if let Err(err) = getrandom::getrandom(&mut salt) {
                    log::error!("cannot get random salt value: {:?}", err);
                    return false;
                }

                // generate key by hkdf
                let h = Hkdf::<Sha256>::new(Some(&salt), passphrase.as_bytes());
                let mut key_slice = [0u8; 32];
                if let Err(err) = h.expand(&[], &mut key_slice[..]) {
                    log::error!("cannot expand passphrase by hkdf: {:?}", err);
                    return false;
                }

                // generate nonce for XChaCha20Poly1305
                let mut stream_nonce = [0u8; 19];
                if let Err(err) = getrandom::getrandom(&mut stream_nonce) {
                    log::error!("cannot get random nonce value: {:?}", err);
                    return false;
                }
                let mut filename_nonce = [0u8; 24];
                if let Err(err) = getrandom::getrandom(&mut filename_nonce) {
                    log::error!("cannot get random nonce value: {:?}", err);
                    return false;
                }

                let key = Key::from_slice(&key_slice);
                let cipher = XChaCha20Poly1305::new(key);

                let stream_nonce = GenericArray::from_slice(stream_nonce.as_ref());
                let filename_nonce = GenericArray::from_slice(filename_nonce.as_ref());

                let sys_stream = {
                    if let Ok(s) = file.stream().dyn_into() {
                        s
                    } else {
                        log::error!("file stream is not web_sys::ReadableStream");
                        return false;
                    }
                };

                // encrypt filename
                let filename = file.name();
                let encrypted_filename = {
                    match cipher.encrypt(
                        filename_nonce,
                        filename.bytes().collect::<Vec<u8>>().as_ref(),
                    ) {
                        Ok(encrypted) => encrypted,
                        Err(err) => {
                            log::error!("failed to encrypt filename: {:?}", err);
                            return true;
                        }
                    }
                };

                // read file
                let stream = wasm_streams::ReadableStream::from_raw(sys_stream).into_stream();

                // stream which read files and transforms that `Uint8Array`s to `Result<Vec<u8>>`.
                let fut = stream
                    .and_then(|b| async move { b.dyn_into::<Uint8Array>() })
                    .map_err(UploadError::JsValue)
                    .map_ok(|arr| arr.to_vec());

                let mut fut = Box::pin(fut);

                let stream_nonce = *stream_nonce;
                let filename_nonce = *filename_nonce;
                let clink = self.link.clone();
                let base_uri = self.base_uri.clone();

                // core logic of streaming upload / encryption
                let encrypt_routine = async move {
                    // use stream encryptor
                    let mut encryptor =
                        aead::stream::EncryptorBE32::from_aead(cipher, &stream_nonce);
                    // send prepare request
                    let client = reqwest::Client::new();
                    let form = Form::new()
                        .part("nonce", Part::stream(stream_nonce.to_vec()))
                        .part("filename_nonce", Part::stream(filename_nonce.to_vec()))
                        .part("salt", Part::stream(salt.to_vec()))
                        .part("filename", Part::stream(encrypted_filename));
                    let file_id = match client
                        .post(join_uri(&base_uri, "/api/prepare_upload"))
                        .multipart(form)
                        .send()
                        .await
                    {
                        Ok(resp) => {
                            if resp.status() != 200 {
                                return Err(UploadError::Remote(format!(
                                    "prepare_upload status != 200, but {}",
                                    resp.status()
                                )));
                            }
                            let b = {
                                match resp.bytes().await {
                                    Ok(b) => b.to_vec(),
                                    Err(_) => {
                                        return Err(UploadError::Remote(
                                            "failed to read resp body".into(),
                                        ));
                                    }
                                }
                            };
                            match serde_json::from_slice::<Value>(b.as_ref()) {
                                Ok(v) => {
                                    if let Some(v) = v.get("id").and_then(Value::as_i64) {
                                        v
                                    } else {
                                        return Err(UploadError::Remote(
                                            "failed to deserialize body".into(),
                                        ));
                                    }
                                }
                                Err(_) => {
                                    return Err(UploadError::Remote(
                                        "failed to deserialize body".into(),
                                    ));
                                }
                            }
                        }
                        Err(e) => {
                            log::error!("remote error: {:?}", e);
                            return Err(UploadError::Remote(
                                "failed to request prepare_upload".into(),
                            ));
                        }
                    };

                    let id = file_id.to_be_bytes();
                    let mut seq: i64 = 1;
                    let mut buffer = Vec::<u8>::with_capacity(BLOCK_SIZE);
                    // start encryption and upload
                    while let Some(v) = fut.try_next().await? {
                        let mut v: &[u8] = v.as_ref();
                        // divide inputs into fixed block size
                        while buffer.len() + v.len() >= BLOCK_SIZE {
                            let split_idx = BLOCK_SIZE - buffer.len();
                            buffer.extend(&v[..split_idx]);
                            // upload chunk to server
                            // this will block next encryption...
                            // maybe there is more good way to handle this
                            let chunk = encryptor
                                .encrypt_next(buffer.as_ref())
                                .map_err(UploadError::Aead)?;
                            let chunk_len = chunk.len();
                            let id = id.to_vec();
                            let seq_b = seq.to_be_bytes().to_vec();
                            // upload encrypted chunk to server
                            let form = Form::new()
                                .part("id", Part::bytes(id))
                                .part("seq", Part::bytes(seq_b))
                                .part("is_last", Part::bytes(vec![0]))
                                .part("content", Part::stream(chunk));
                            match client
                                .post(join_uri(&base_uri, "/api/upload"))
                                .multipart(form)
                                .send()
                                .await
                            {
                                Ok(resp) => {
                                    if resp.status() != 200 {
                                        return Err(UploadError::Remote(format!(
                                            "upload status != 200, but {}",
                                            resp.status()
                                        )));
                                    }
                                }
                                Err(_) => {
                                    return Err(UploadError::Remote(
                                        "failed to upload chunk".into(),
                                    ));
                                }
                            }
                            buffer.clear();
                            v = &v[split_idx..];
                            seq += 1;

                            clink.send_message(UploadMsg::Progress(ProgressInfo::UploadBytes(
                                chunk_len,
                            )));
                        }
                        buffer.extend(v);
                    }
                    // upload last chunk
                    let chunk = encryptor
                        .encrypt_last(buffer.as_ref())
                        .map_err(UploadError::Aead)?;
                    let id_b = id.to_vec();
                    let seq = seq.to_be_bytes().to_vec();
                    let chunk_len = chunk.len();
                    let form = Form::new()
                        .part("id", Part::bytes(id_b))
                        .part("seq", Part::bytes(seq))
                        .part("is_last", Part::bytes(vec![1]))
                        .part("content", Part::stream(chunk));
                    match client
                        .post(join_uri(&base_uri, "/api/upload"))
                        .multipart(form)
                        .send()
                        .await
                    {
                        Ok(resp) => {
                            if resp.status() != 200 {
                                return Err(UploadError::Remote(format!(
                                    "upload status != 200, but {}",
                                    resp.status()
                                )));
                            }
                        }
                        Err(_) => {
                            return Err(UploadError::Remote("failed to upload chunk".into()));
                        }
                    }
                    clink.send_message(UploadMsg::Progress(ProgressInfo::UploadBytes(chunk_len)));
                    clink.send_message(UploadMsg::UploadComplete(file_id));

                    Ok(())
                };

                let clink = self.link.clone();
                // spawn entire routine in promise
                // TODO: research Web Workers and try to gain more performance
                spawn_local(encrypt_routine.map(move |r: Result<(), UploadError>| {
                    if let Err(e) = r {
                        log::error!("encryption error: {:?}", e);
                        clink.send_message(UploadMsg::UploadError(e));
                    }
                }));

                true
            }
            UploadMsg::TextUploadStart => {
                self.upload_error = None;
                self.file_id = None;
                self.uploaded_size = None;
                if !self.passphrase_available {
                    return false;
                }
                // get content from textarea
                let content = if let Some(input) = self.textarea_ref.cast::<HtmlTextAreaElement>() {
                    input.value()
                } else {
                    log::error!("cannot get content string from textarea");
                    return false;
                };
                if content.is_empty() {
                    return false;
                }

                // get passphrase from input
                let passphrase = if let Some(input) = self.passphrase_ref.cast::<HtmlInputElement>()
                {
                    input.value()
                } else {
                    log::error!("cannot get passphrase string from input");
                    return false;
                };

                // generate salt for hkdf expand()
                let mut salt = [0u8; 32];
                if let Err(err) = getrandom::getrandom(&mut salt) {
                    log::error!("cannot get random salt value: {:?}", err);
                    return false;
                }

                // generate key by hkdf
                let h = Hkdf::<Sha256>::new(Some(&salt), passphrase.as_bytes());
                let mut key_slice = [0u8; 32];
                if let Err(err) = h.expand(&[], &mut key_slice[..]) {
                    log::error!("cannot expand passphrase by hkdf: {:?}", err);
                    return false;
                }

                let key = Key::from_slice(&key_slice);
                let cipher = XChaCha20Poly1305::new(key);

                // generate nonce for XChaCha20Poly1305
                let mut nonce = [0u8; 24];
                if let Err(err) = getrandom::getrandom(&mut nonce) {
                    log::error!("cannot get random nonce value: {:?}", err);
                    return false;
                }
                let nonce = XNonce::from_slice(&nonce);

                let encrypted = match cipher.encrypt(nonce, content.as_bytes()) {
                    Ok(encrypted) => encrypted,
                    Err(e) => {
                        self.link
                            .send_message(UploadMsg::UploadError(UploadError::Aead(e)));
                        return false;
                    }
                };

                let base_uri = self.base_uri.clone();
                let nonce = *nonce;
                let encrypt_fn = async move {
                    let client = reqwest::Client::new();
                    let form = Form::new()
                        .part("is_text", Part::bytes(vec![1]))
                        .part("nonce", Part::stream(nonce.to_vec()))
                        .part("salt", Part::stream(salt.to_vec()));
                    let file_id = match client
                        .post(join_uri(&base_uri, "/api/prepare_upload"))
                        .multipart(form)
                        .send()
                        .await
                    {
                        Ok(resp) => {
                            if resp.status() != 200 {
                                return Err(UploadError::Remote(format!(
                                    "prepare_upload status != 200, but {}",
                                    resp.status()
                                )));
                            }
                            let b = {
                                match resp.bytes().await {
                                    Ok(b) => b.to_vec(),
                                    Err(_) => {
                                        return Err(UploadError::Remote(
                                            "failed to read resp body".into(),
                                        ));
                                    }
                                }
                            };
                            match serde_json::from_slice::<Value>(b.as_ref()) {
                                Ok(v) => {
                                    if let Some(v) = v.get("id").and_then(Value::as_i64) {
                                        v
                                    } else {
                                        return Err(UploadError::Remote(
                                            "failed to deserialize body".into(),
                                        ));
                                    }
                                }
                                Err(_) => {
                                    return Err(UploadError::Remote(
                                        "failed to deserialize body".into(),
                                    ));
                                }
                            }
                        }
                        Err(e) => {
                            log::error!("remote error: {:?}", e);
                            return Err(UploadError::Remote(
                                "failed to request prepare_upload".into(),
                            ));
                        }
                    };

                    let id = file_id.to_be_bytes();
                    let seq = 1_i64.to_be_bytes().to_vec();
                    let form = Form::new()
                        .part("id", Part::bytes(id.to_vec()))
                        .part("seq", Part::bytes(seq))
                        .part("is_last", Part::bytes(vec![1]))
                        .part("content", Part::stream(encrypted));
                    match client
                        .post(join_uri(&base_uri, "/api/upload"))
                        .multipart(form)
                        .send()
                        .await
                    {
                        Ok(resp) => {
                            if resp.status() != 200 {
                                return Err(UploadError::Remote(format!(
                                    "upload status != 200, but {}",
                                    resp.status()
                                )));
                            }
                        }
                        Err(_) => {
                            return Err(UploadError::Remote("failed to upload chunk".into()));
                        }
                    };

                    Ok(())
                };

                let clink = self.link.clone();
                spawn_local(encrypt_fn.map(move |res| {
                    if let Err(e) = res {
                        clink.send_message(UploadMsg::UploadError(e));
                    }
                }));

                true
            }
            UploadMsg::Progress(info) => {
                match info {
                    ProgressInfo::UploadBytes(b) => {
                        let before = self.uploaded_size.unwrap_or(0);
                        let file_size = self.file_size.unwrap_or(0);
                        let after = if before + b > file_size {
                            file_size
                        } else {
                            before + b
                        };
                        self.uploaded_size = Some(after);
                    }
                }

                true
            }
            UploadMsg::UploadError(err) => {
                self.upload_error = Some(err);

                true
            }
            UploadMsg::UploadComplete(file_id) => {
                self.file_id = Some(file_id);

                true
            }
        }
    }

    fn change(&mut self, _props: Self::Properties) -> bool {
        false
    }

    fn view(&self) -> Html {
        let upload_type = self.upload_type.clone();
        let upload_onclick = self.link.callback(move |_| match upload_type {
            UploadType::File => UploadMsg::FileUploadStart,
            UploadType::Text => UploadMsg::TextUploadStart,
        });
        let filetype_change_onclick = self.link.callback(|_| UploadMsg::ChangeUploadType);
        let passphrase_oninput = self.link.callback(|_| UploadMsg::PassphraseInput);
        let passphrase_hidden = match self.upload_type {
            UploadType::File => self.selected_file.is_none(),
            UploadType::Text => false,
        };
        let upload_button_disabled = match self.upload_type {
            UploadType::File => !self.passphrase_available || self.selected_file.is_none(),
            UploadType::Text => !self.passphrase_available,
        };

        let mut button_class = vec![
            "border-solid",
            "bg-gray-700",
            "text-gray-300",
            "px-5",
            "py-3",
            "my-5",
            "rounded-xl",
        ];
        if upload_button_disabled {
            button_class.push("cursor-not-allowed");
        } else {
            button_class.push("hover:bg-gray-400");
            button_class.push("hover:text-gray-700");
            button_class.push("cursor-pointer");
        }

        let mut upload_byte_class = vec!["flex", "justify-center"];
        let mut progress_class = vec!["flex", "relative", "pt-1", "justify-center"];
        if self.uploaded_size.is_none() {
            upload_byte_class.push("hidden");
            progress_class.push("hidden");
        }
        let uploaded = self.uploaded_size.unwrap_or(0);
        let file_size = self.file_size.unwrap_or(0);
        let progress_percent_width = if file_size == 0 {
            0
        } else {
            ((uploaded as f64 / file_size as f64) * (100_f64)) as usize
        };

        let mut file_uri_class = vec!["flex", "justify-center", "mb-4"];
        if self.file_id.is_none() || self.upload_error.is_some() {
            file_uri_class.push("hidden");
        }
        let file_uri_component = html! {
            <div class=classes!(file_uri_class)>
                <span class=classes!("mr-2")>{ "Your file: " }</span>
                <a class=classes!("text-blue-400") target="_blank" href={join_uri(&self.base_uri, &self.file_id.unwrap_or(0).to_string())}>
                    { join_uri(&self.base_uri, &self.file_id.unwrap_or(0).to_string()) }
                </a>
            </div>
        };

        let mut upload_error_class = vec!["flex", "justify-center", "mb-4"];
        if self.upload_error.is_none() {
            upload_error_class.push("hidden");
        }
        let upload_error_text: Cow<str> = match &self.upload_error {
            Some(err) => match err {
                UploadError::JsValue(_) => "File read error".into(),
                UploadError::Aead(_) => "Encryption error".into(),
                UploadError::Remote(msg) => format!("Server error: {}", msg).into(),
            },
            None => "".into(),
        };
        let upload_error_component = html! {
            <div class=classes!(upload_error_class)>
                <span class=classes!("text-red-300")>{ upload_error_text }</span>
            </div>
        };

        html! {
            <>
                {
                    match self.upload_type {
                        UploadType::File => file_input(self),
                        UploadType::Text => text_input(self),
                    }

                }
                <div class=classes!("flex", "justify-center", "mt-2")>
                    <pre class=classes!("text-gray-800")>
                        { "...or " }
                    </pre>
                    <pre class=classes!("text-blue-700", "hover:text-blue-400", "cursor-pointer") onclick={filetype_change_onclick}>
                        {
                            match self.upload_type {
                                UploadType::File => "Text",
                                UploadType::Text => "File",
                            }
                        }
                    </pre>
                </div>
                <div class=classes!("flex", "justify-center", "mt-5")>
                    <p class=classes!("text-gray-300", "mb-3")>{ self.selected_file.as_ref().map_or("".into(), |f: &web_sys::File| f.name()) }</p>
                </div>
                <div class=classes!("flex", "justify-center")>
                    <input
                        id="passphrase"
                        type="password"
                        ref={self.passphrase_ref.clone()}
                        class=classes!("px-4", "py-2", "rounded-lg", "border", "border-gray-300", "focus:outline-none", "focus:ring-2", "focus:ring-gray-200", "text-center")
                        placeholder={ "Passphrase" }
                        hidden={passphrase_hidden}
                        oninput={passphrase_oninput}
                    />
                </div>
                <div class=classes!(progress_class)>
                    <div class=classes!("overflow-hidden", "h-2", "mb-4", "text-xs", "flex", "rounded", "bg-blue-200", "w-1/2", "mt-4")>
                        <div style={format!("width:{}%", progress_percent_width)} class=classes!("shadow-none", "flex", "flex-col", "text-center", "whitespace-nowrap", "text-white", "justify-center", "bg-blue-400")></div>
                    </div>
                </div>
                <div class=classes!(upload_byte_class)>
                    <span class=classes!("text-gray-800")>
                        { uploaded } { " / " } { file_size }
                    </span>
                </div>
                <div class=classes!("flex", "justify-center")>
                    <button
                        disabled={upload_button_disabled}
                        onclick={upload_onclick}
                        class=classes!(button_class)>
                        { "UPLOAD" }
                    </button>
                </div>
                { upload_error_component }
                { file_uri_component }
            </>
        }
    }
}
