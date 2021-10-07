use yew::{html, Component, ComponentLink};

pub enum DownloadMsg {}

pub struct DownloadComponent {
    link: ComponentLink<Self>,
}

impl Component for DownloadComponent {
    type Message = DownloadMsg;
    type Properties = ();

    fn create(_props: Self::Properties, link: ComponentLink<Self>) -> Self {
        Self { link }
    }

    fn update(&mut self, msg: Self::Message) -> bool {
        true
    }

    fn change(&mut self, _props: Self::Properties) -> bool {
        false
    }

    fn view(&self) -> yew::Html {
        html! {
            <div>
                { "Hello, world!" }
            </div>
        }
    }
}
