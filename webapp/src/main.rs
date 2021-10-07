use yew::{classes, html, Component, ComponentLink, Html};
use yew_router::router::Router;

use crate::{switch::AppRoute, upload::UploadComponent};

mod download;
mod switch;
mod upload;

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
                <Router<AppRoute>
                    render = Router::render(|switch: AppRoute| {
                        match switch {
                            AppRoute::Upload => html! { <UploadComponent /> }
                        }
                    })
                />
            </div>
        }
    }
}

fn main() {
    wasm_logger::init(wasm_logger::Config::default());
    yew::start_app::<MainComponent>();
}
