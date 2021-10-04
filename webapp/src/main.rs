use std::collections::HashMap;

use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use gloo_file::callbacks::FileReader;
use gloo_file::File;
use hkdf::Hkdf;
use js_sys::{Array, Uint8Array};
use sha2::Sha256;
use web_sys::Url;
use yew::{
    classes, html, web_sys::HtmlInputElement, ChangeData, Component, ComponentLink, Html, NodeRef,
};

enum Msg {
    FileChanged(web_sys::File),
    PassphraseInput,
    Upload,
    FileReaded(String, Vec<u8>),
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
            Msg::Upload => {
                if !self.passphrase_available {
                    return false;
                }
                let file = if let Some(file) = &self.selected_file {
                    File::from(file.clone())
                } else {
                    return false;
                };

                // read file
                let filename = file.name();

                let clink = self.link.clone();
                let fname = filename.clone();
                let task = gloo_file::callbacks::read_as_bytes(&file, move |res| match res {
                    Ok(res) => clink.send_message(Msg::FileReaded(fname, res)),
                    Err(err) => {
                        log::error!("failed to read file content: {:?}", err)
                    }
                });
                self.readers.insert(filename, task);

                // TODO: show status: loading file
                true
            }
            Msg::FileReaded(filename, res) => {
                if self.readers.remove(&filename).is_none() {
                    // TODO: show failed status and reset state
                    return true;
                }

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
                let mut key = [0u8; 32];
                if let Err(err) = h.expand(&[], &mut key[..]) {
                    log::error!("cannot expand passphrase by hkdf: {:?}", err);
                    return false;
                }
                log::info!("key: {:?}", key);

                // generate nonce for XChaCha20Poly1305
                let mut nonce = [0u8; 24];
                let rand_res = crypto.get_random_values_with_u8_array(&mut nonce);
                if let Err(err) = rand_res {
                    log::error!("cannot get random nonce value: {:?}", err);
                    return false;
                }

                let key = Key::from_slice(&key);
                let cipher = XChaCha20Poly1305::new(key);
                let nonce = XNonce::from_slice(&nonce);

                let encrypted = {
                    match cipher.encrypt(nonce, res.as_ref()) {
                        Ok(encrypted) => encrypted,
                        Err(err) => {
                            log::error!("failed to encrypt data: {:?}", err);
                            return true;
                        }
                    }
                };

                log::info!("nonce: {:?}", nonce);
                log::info!("encrypted: {:?}", encrypted);

                // this is test code
                let decrypted = cipher.decrypt(nonce, encrypted.as_ref()).unwrap();
                log::info!("decrypted: {:?}", decrypted);

                let bytes = Array::new();
                bytes.push(&Uint8Array::from(&decrypted[..]));
                let decrypted_blob = {
                    match web_sys::Blob::new_with_u8_array_sequence(&bytes) {
                        Ok(blob) => blob,
                        Err(err) => {
                            log::error!("failed to make data into blob: {:?}", err);
                            return true;
                        }
                    }
                };
                let obj_url = {
                    match Url::create_object_url_with_blob(&decrypted_blob) {
                        Ok(u) => u,
                        Err(err) => {
                            log::error!("failed to make blob into object url: {:?}", err);
                            return true;
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

    fn view(&self) -> Html {
        let upload_onclick = self.link.callback(|_| Msg::Upload);
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
