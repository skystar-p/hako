use serde::Deserialize;
use wasm_bindgen_futures::spawn_local;
use yew::{
    classes, html, web_sys::HtmlInputElement, Component, ComponentLink, NodeRef, Properties,
};

use crate::utils::build_url;

pub enum DownloadMsg {
    Metadata(Result<FileMetadata, MetadataError>),
    PassphraseInput,
    StartDownload,
}

pub enum MetadataError {
    FileNotFound,
    NotAvailable,
    Deserialize,
}

pub struct DownloadComponent {
    link: ComponentLink<Self>,
    passphrase_ref: NodeRef,
    passphrase_available: bool,
    metadata: Option<Result<FileMetadata, MetadataError>>,
}

#[derive(Properties, Clone, PartialEq)]
pub struct DownloadProps {
    pub id: i64,
}

#[derive(Deserialize, Debug)]
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
            DownloadMsg::StartDownload => true,
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
                m.is_ok()
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
                        disabled=!disabled
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
