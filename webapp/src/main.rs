use std::collections::HashMap;
use std::convert::TryInto;

use aead::generic_array::GenericArray;
use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::{Key, Nonce, XChaCha20Poly1305, XNonce};
use futures_util::{FutureExt, Stream, StreamExt, TryFutureExt, TryStreamExt};
use gloo_file::callbacks::FileReader;
use gloo_file::File;
use hkdf::Hkdf;
use js_sys::{Array, Uint8Array};
use reqwest::multipart::Part;
use reqwest::StatusCode;
use sha2::Sha256;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::spawn_local;
use web_sys::Url;
use yew::{
    classes, html, web_sys::HtmlInputElement, ChangeData, Component, ComponentLink, Html, NodeRef,
};

enum Msg {
    FileChanged(web_sys::File),
    PassphraseInput,
    UploadStart,
    FileReaded(String, Vec<u8>),
    UploadComplete(),
}

#[derive(Debug)]
enum MyError {
    JsValue(JsValue),
    Aead(aead::Error),
}

struct Model {
    link: ComponentLink<Self>,
    selected_file: Option<web_sys::File>,
    passphrase_ref: NodeRef,
    passphrase_available: bool,
    readers: HashMap<String, FileReader>,
}

fn file_input(comp: &Model) -> Html {
    let file_onchange = comp.link.batch_callback(|e| {
        if let ChangeData::Files(files) = e {
            let file = files.item(0);
            file.map(Msg::FileChanged)
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

impl Component for Model {
    type Message = Msg;
    type Properties = ();

    fn create(_props: Self::Properties, link: ComponentLink<Self>) -> Self {
        Self {
            link,
            selected_file: None,
            passphrase_ref: NodeRef::default(),
            passphrase_available: false,
            readers: HashMap::default(),
        }
    }

    fn update(&mut self, msg: Self::Message) -> bool {
        match msg {
            Msg::FileChanged(file) => {
                self.selected_file = Some(file);
                self.passphrase_available = false;
                if let Some(input) = self.passphrase_ref.cast::<HtmlInputElement>() {
                    input.set_value("");
                }
                true
            }
            Msg::PassphraseInput => {
                if let Some(input) = self.passphrase_ref.cast::<HtmlInputElement>() {
                    let v = input.value();
                    self.passphrase_available = !v.is_empty();
                }
                true
            }
            Msg::UploadStart => {
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

                // prepare crypto instance
                let window = {
                    if let Some(window) = web_sys::window() {
                        window
                    } else {
                        log::error!("cannot retrieve Window instance");
                        return false;
                    }
                };
                let crypto = match window.crypto() {
                    Ok(crypto) => crypto,
                    Err(err) => {
                        log::error!("cannot retrieve Crypto instance: {:?}", err);
                        return false;
                    }
                };

                // generate salt for hkdf expand()
                let mut salt = [0u8; 32];
                let rand_res = crypto.get_random_values_with_u8_array(&mut salt);
                if let Err(err) = rand_res {
                    log::error!("cannot get random salt value: {:?}", err);
                    return false;
                }
                log::info!("salt: {:?}", salt);

                // generate key by hkdf
                let h = Hkdf::<Sha256>::new(Some(&salt), passphrase.as_bytes());
                let mut key_slice = [0u8; 32];
                if let Err(err) = h.expand(&[], &mut key_slice[..]) {
                    log::error!("cannot expand passphrase by hkdf: {:?}", err);
                    return false;
                }
                log::info!("key: {:?}", key_slice);

                // generate nonce for XChaCha20Poly1305
                let mut nonce = [0u8; 19];
                let rand_res = crypto.get_random_values_with_u8_array(&mut nonce);
                if let Err(err) = rand_res {
                    log::error!("cannot get random nonce value: {:?}", err);
                    return false;
                }

                let key = Key::from_slice(&key_slice);
                let cipher = XChaCha20Poly1305::new(key);
                // let xnonce = XNonce::from_slice(&nonce);

                let xnonce = GenericArray::from_slice(nonce.as_ref());
                let mut encryptor = aead::stream::EncryptorBE32::from_aead(cipher, xnonce);

                let sys_stream = {
                    if let Ok(s) = file.stream().dyn_into() {
                        s
                    } else {
                        log::error!("file stream is not web_sys::ReadableStream");
                        return false;
                    }
                };

                // read file
                let filename = file.name();
                let stream = wasm_streams::ReadableStream::from_raw(sys_stream).into_stream();

                let fut = stream
                    .and_then(|b| async move { b.dyn_into::<Uint8Array>() })
                    .map_err(MyError::JsValue)
                    .map_ok(|arr| arr.to_vec());
                let mut fut = Box::pin(fut);

                let encrypt = async move {
                    let mut c: usize = 0;
                    while let Some(v) = fut.try_next().await? {
                        let res = encryptor.encrypt_next(v.as_ref()).map_err(MyError::Aead)?;
                        c += res.len();
                        log::info!("encrypted data: {:?}", res);
                    }
                    let res = encryptor
                        .encrypt_last(Vec::new().as_ref())
                        .map_err(MyError::Aead)?;
                    c += res.len();
                    log::info!("encrypted last data: {:?}", res);
                    log::info!("total length: {}", c);

                    Ok(())
                };
                spawn_local(encrypt.map(|r: Result<(), MyError>| {
                    if let Err(e) = r {
                        log::error!("encryption error: {:?}", e);
                    }
                }));

                // encrypt filename
                // let encrypted_filename = {
                //     match cipher.encrypt(xnonce, filename.bytes().collect::<Vec<u8>>().as_ref()) {
                //         Ok(encrypted) => encrypted,
                //         Err(err) => {
                //             log::error!("failed to encrypt filename: {:?}", err);
                //             return true;
                //         }
                //     }
                // };

                // TODO: show status: loading file
                true
            }
            Msg::FileReaded(filename, res) => {
                if self.readers.remove(&filename).is_none() {
                    // TODO: show failed status and reset state
                    return true;
                }

                // // http client
                // let client = reqwest::Client::new();
                // let form = reqwest::multipart::Form::new()
                //     .part("content", Part::stream(encrypted_content))
                //     .part("nonce", Part::stream(nonce.to_vec()))
                //     .part("salt", Part::stream(salt.to_vec()))
                //     .part("filename", Part::stream(encrypted_filename.to_vec()));

                // let clink = self.link.clone();
                // spawn_local(async move {
                //     match client
                //         .post("http://localhost:12321/upload")
                //         .multipart(form)
                //         .send()
                //         .await
                //     {
                //         Ok(resp) => {
                //             if resp.status() != StatusCode::OK {
                //                 log::error!(
                //                     "request failed: server responded with {}",
                //                     resp.status()
                //                 );
                //             } else {
                //                 clink.send_message(Msg::UploadComplete());
                //             }
                //         }
                //         Err(err) => {
                //             log::error!("failed to send multipart request: {:?}", err);
                //         }
                //     }
                // });

                true
            }
            Msg::UploadComplete() => {
                log::info!("upload success!");

                // this is test code
                // http client
                let passphrase = if let Some(input) = self.passphrase_ref.cast::<HtmlInputElement>()
                {
                    input.value()
                } else {
                    log::error!("cannot get passphrase string from input");
                    return false;
                };
                let client = reqwest::Client::new();
                spawn_local(async move {
                    let res = match client.get("http://localhost:12321/1").send().await {
                        Ok(resp) => {
                            if resp.status() != StatusCode::OK {
                                log::error!(
                                    "request failed: server responded with {}",
                                    resp.status()
                                );
                                return;
                            } else {
                                resp.bytes().await
                            }
                        }
                        Err(err) => {
                            log::error!("failed to download: {:?}", err);
                            return;
                        }
                    };

                    // TODO: match
                    let res = res.unwrap().to_vec();
                    // extract all fields
                    let content_len = u64::from_be_bytes(res[0..8].try_into().unwrap());
                    let filename_len = u64::from_be_bytes(res[8..16].try_into().unwrap());
                    log::info!("content_len = {}", content_len);
                    log::info!("filename_len = {}", filename_len);
                    let res = &res[16..];

                    let salt = &res[..32];
                    log::info!("salt = {:?}", salt);
                    let res = &res[32..];

                    let nonce = &res[..24];
                    log::info!("nonce = {:?}", nonce);
                    let res = &res[24..];

                    let filename = &res[..(filename_len as usize)];
                    let content = &res[(filename_len as usize)..];

                    let h = Hkdf::<Sha256>::new(Some(&salt), passphrase.as_bytes());
                    let mut key_slice = [0u8; 32];
                    if let Err(err) = h.expand(&[], &mut key_slice[..]) {
                        log::error!("cannot expand passphrase by hkdf: {:?}", err);
                        return;
                    }

                    let key = Key::from_slice(&key_slice);
                    let cipher = XChaCha20Poly1305::new(key);
                    let xnonce = XNonce::from_slice(nonce);

                    let decrypted_filename = cipher.decrypt(xnonce, filename).unwrap();
                    log::info!("decrypted filename: {:?}", decrypted_filename);
                    let decrypted_content = cipher.decrypt(xnonce, content).unwrap();
                    log::info!("decrypted content: {:?}", decrypted_content);

                    let bytes = Array::new();
                    bytes.push(&Uint8Array::from(&decrypted_content[..]));
                    let decrypted_blob = {
                        match web_sys::Blob::new_with_u8_array_sequence(&bytes) {
                            Ok(blob) => blob,
                            Err(err) => {
                                log::error!("failed to make data into blob: {:?}", err);
                                return;
                            }
                        }
                    };
                    let obj_url = {
                        match Url::create_object_url_with_blob(&decrypted_blob) {
                            Ok(u) => u,
                            Err(err) => {
                                log::error!("failed to make blob into object url: {:?}", err);
                                return;
                            }
                        }
                    };
                    log::info!("obj_url: {}", obj_url);
                });

                true
            }
        }
    }

    fn change(&mut self, _props: Self::Properties) -> bool {
        false
    }

    fn view(&self) -> Html {
        let upload_onclick = self.link.callback(|_| Msg::UploadStart);
        let passphrase_oninput = self.link.callback(|_| Msg::PassphraseInput);
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
            <div class=classes!("m-auto", "min-w-1/2", "border-solid", "border-2", "border-opacity-20", "rounded-xl")>
                <h1 class=classes!("text-center", "text-6xl", "text-gray-300", "font-sans", "m-5")>
                    { "Hako" }
                </h1>
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
            </div>
        }
    }
}

fn main() {
    wasm_logger::init(wasm_logger::Config::default());
    yew::start_app::<Model>();
}
