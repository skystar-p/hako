use aead::generic_array::GenericArray;
use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::{Key, XChaCha20Poly1305};
use futures_util::{FutureExt, TryStreamExt};
use hkdf::Hkdf;
use js_sys::Uint8Array;
use reqwest::multipart::{Form, Part};
use serde_json::Value;
use sha2::Sha256;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::spawn_local;
use yew::{
    classes, html, web_sys::HtmlInputElement, ChangeData, Component, ComponentLink, Html, NodeRef,
};

use crate::utils::{build_url, BLOCK_SIZE};

pub enum UploadMsg {
    FileChanged(web_sys::File),
    PassphraseInput,
    UploadStart,
}

#[derive(Debug)]
enum MyError {
    JsValue(JsValue),
    Aead(aead::Error),
    Remote(String),
}

pub struct UploadComponent {
    link: ComponentLink<Self>,
    selected_file: Option<web_sys::File>,
    passphrase_ref: NodeRef,
    passphrase_available: bool,
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

impl Component for UploadComponent {
    type Message = UploadMsg;
    type Properties = ();

    fn create(_props: Self::Properties, link: ComponentLink<Self>) -> Self {
        Self {
            link,
            selected_file: None,
            passphrase_ref: NodeRef::default(),
            passphrase_available: false,
        }
    }

    fn update(&mut self, msg: Self::Message) -> bool {
        match msg {
            UploadMsg::FileChanged(file) => {
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
            UploadMsg::UploadStart => {
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

                let fut = stream
                    .and_then(|b| async move { b.dyn_into::<Uint8Array>() })
                    .map_err(MyError::JsValue)
                    .map_ok(|arr| arr.to_vec());

                let mut fut = Box::pin(fut);

                let stream_nonce = *stream_nonce;
                let filename_nonce = *filename_nonce;
                let encrypt = async move {
                    let mut encryptor =
                        aead::stream::EncryptorBE32::from_aead(cipher, &stream_nonce);
                    // send starting request
                    let client = reqwest::Client::new();
                    let form = Form::new()
                        .part("stream_nonce", Part::stream(stream_nonce.to_vec()))
                        .part("filename_nonce", Part::stream(filename_nonce.to_vec()))
                        .part("salt", Part::stream(salt.to_vec()))
                        .part("filename", Part::stream(encrypted_filename));
                    let id = match client
                        .post(build_url("/prepare_upload"))
                        .multipart(form)
                        .send()
                        .await
                    {
                        Ok(resp) => {
                            if resp.status() != 200 {
                                return Err(MyError::Remote(format!(
                                    "prepare_upload status != 200, but {}",
                                    resp.status()
                                )));
                            }
                            let b = {
                                match resp.bytes().await {
                                    Ok(b) => b.to_vec(),
                                    Err(_) => {
                                        return Err(MyError::Remote(
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
                                        return Err(MyError::Remote(
                                            "failed to deserialize body".into(),
                                        ));
                                    }
                                }
                                Err(_) => {
                                    return Err(MyError::Remote(
                                        "failed to deserialize body".into(),
                                    ));
                                }
                            }
                        }
                        Err(e) => {
                            log::error!("remote error: {:?}", e);
                            return Err(MyError::Remote("failed to request prepare_upload".into()));
                        }
                    };

                    let id = id.to_be_bytes();
                    let mut seq: i64 = 1;
                    let mut buffer = Vec::<u8>::with_capacity(BLOCK_SIZE);
                    while let Some(v) = fut.try_next().await? {
                        let mut v: &[u8] = v.as_ref();
                        while buffer.len() + v.len() >= BLOCK_SIZE {
                            let split_idx = BLOCK_SIZE - buffer.len();
                            buffer.extend(&v[..split_idx]);
                            // upload chunk to server
                            // this will block next encryption...
                            // maybe there is more good way to handle this
                            let chunk = encryptor
                                .encrypt_next(buffer.as_ref())
                                .map_err(MyError::Aead)?;
                            let id = id.to_vec();
                            let seq_b = seq.to_be_bytes().to_vec();
                            let form = Form::new()
                                .part("id", Part::bytes(id))
                                .part("seq", Part::bytes(seq_b))
                                .part("is_last", Part::bytes(vec![0]))
                                .part("content", Part::stream(chunk));
                            match client
                                .post(build_url("/upload"))
                                .multipart(form)
                                .send()
                                .await
                            {
                                Ok(resp) => {
                                    if resp.status() != 200 {
                                        return Err(MyError::Remote(format!(
                                            "upload status != 200, but {}",
                                            resp.status()
                                        )));
                                    }
                                }
                                Err(_) => {
                                    return Err(MyError::Remote("failed to upload chunk".into()));
                                }
                            }
                            buffer.clear();
                            v = &v[split_idx..];
                            log::info!("chunk {} upload success", seq);
                            seq += 1;
                        }
                        buffer.extend(v);
                    }
                    // upload last chunk
                    let chunk = encryptor
                        .encrypt_last(buffer.as_ref())
                        .map_err(MyError::Aead)?;
                    let id = id.to_vec();
                    let seq_b = seq.to_be_bytes().to_vec();
                    let form = Form::new()
                        .part("id", Part::bytes(id))
                        .part("seq", Part::bytes(seq_b))
                        .part("is_last", Part::bytes(vec![1]))
                        .part("content", Part::stream(chunk));
                    match client
                        .post(build_url("/upload"))
                        .multipart(form)
                        .send()
                        .await
                    {
                        Ok(resp) => {
                            if resp.status() != 200 {
                                return Err(MyError::Remote(format!(
                                    "upload status != 200, but {}",
                                    resp.status()
                                )));
                            }
                        }
                        Err(_) => {
                            return Err(MyError::Remote("failed to upload chunk".into()));
                        }
                    }
                    log::info!("last chunk {} upload success", seq);

                    Ok(())
                };
                spawn_local(encrypt.map(|r: Result<(), MyError>| {
                    if let Err(e) = r {
                        log::error!("encryption error: {:?}", e);
                    }
                }));

                // TODO: show status: loading file
                true
            }
        }
    }

    fn change(&mut self, _props: Self::Properties) -> bool {
        false
    }

    fn view(&self) -> Html {
        let upload_onclick = self.link.callback(|_| UploadMsg::UploadStart);
        let passphrase_oninput = self.link.callback(|_| UploadMsg::PassphraseInput);
        let passphrase_hidden = self.selected_file.is_none();

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

        html! {
            <>
                { file_input(self) }
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
                <div class=classes!("flex", "justify-center")>
                    <button
                        disabled={!self.passphrase_available}
                        onclick={upload_onclick}
                        class=classes!(button_class)>
                        { "UPLOAD" }
                    </button>
                </div>
            </>
        }
    }
}
