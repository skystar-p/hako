use yew::{classes, html, ChangeData, Component, ComponentLink, Html};

enum Msg {
    FileChanged(String),
}

struct Model {
    link: ComponentLink<Self>,
    file_info: String,
}

fn file_input(comp: &Model) -> Html {
    let file_onchange = comp.link.batch_callback(|e| {
        if let ChangeData::Files(files) = e {
            let file = files.item(0);
            file.map(|file| Msg::FileChanged(file.name()))
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
                <input type="file" class=classes!("hidden") onchange=file_onchange />
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
            file_info: String::new(),
        }
    }

    fn update(&mut self, msg: Self::Message) -> bool {
        match msg {
            Msg::FileChanged(filename) => {
                self.file_info = filename;
                true
            }
        }
    }

    fn change(&mut self, _props: Self::Properties) -> bool {
        false
    }

    fn view(&self) -> Html {
        html! {
            <div class=classes!("m-auto", "min-w-1/2", "border-solid", "border-2", "border-opacity-20", "rounded-xl")>
                <h1 class=classes!("text-center", "text-6xl", "text-gray-300", "font-sans", "m-5")>
                    { "Hako" }
                </h1>
                { file_input(self) }
                <div class=classes!("flex", "justify-center", "mt-5")>
                    <p>{ &self.file_info }</p>
                </div>
                <div class=classes!("flex", "justify-center")>
                    <button class=classes!("border-solid", "bg-gray-700", "hover:bg-gray-400", "px-5", "py-3", "my-5", "rounded-xl", "text-gray-300", "hover:text-gray-700")>
                        { "UPLOAD" }
                    </button>
                </div>
            </div>
        }
    }
}

fn main() {
    yew::start_app::<Model>();
}
