use yew::{classes, html, Component, ComponentLink, Html};
use yew_router::router::Router;

use crate::{download::DownloadComponent, switch::AppRoute, upload::UploadComponent};

mod download;
mod switch;
mod upload;
mod utils;

struct MainComponent {}

impl Component for MainComponent {
    type Message = ();
    type Properties = ();

    fn create(_props: Self::Properties, _link: ComponentLink<Self>) -> Self {
        Self {}
    }

    fn update(&mut self, _msg: Self::Message) -> bool {
        true
    }

    fn change(&mut self, _props: Self::Properties) -> bool {
        false
    }

    fn view(&self) -> Html {
        html! {
            <div class=classes!("bg-gray-500", "h-screen", "flex")>
                <div class=classes!("m-auto", "min-w-1/2", "border-solid", "border-2", "border-opacity-20", "rounded-xl")>
                    <h1 class=classes!("text-center", "text-6xl", "text-gray-300", "font-sans", "m-5")>
                        { "Hako" }
                    </h1>
                    <Router<AppRoute>
                        render = Router::render(|switch: AppRoute| {
                            match switch {
                                AppRoute::Upload => html! { <UploadComponent /> },
                                AppRoute::Download(id) => html! { <DownloadComponent id=id /> },
                            }
                        })
                        redirect = Router::redirect(|_| { AppRoute::Upload })
                    />
                </div>
            </div>
        }
    }
}

fn main() {
    wasm_logger::init(wasm_logger::Config::default());
    yew::start_app::<MainComponent>();
}
