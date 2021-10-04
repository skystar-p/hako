use yew::{
    classes, html,
    web_sys::{File, HtmlInputElement},
    ChangeData, Component, ComponentLink, Html, NodeRef,
};

enum Msg {
    FileChanged(File),
    PassphraseInput,
    Upload,
}

struct Model {
    link: ComponentLink<Self>,
    selected_file: Option<File>,
    passphrase_ref: NodeRef,
    passphrase_available: bool,
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
                    <p class=classes!("text-gray-300", "mb-3")>{ self.selected_file.as_ref().map_or("".into(), |f: &File| f.name()) }</p>
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
