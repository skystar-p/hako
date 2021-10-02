use std::net::SocketAddr;

use axum::{handler::get, Router};
use structopt::StructOpt;

mod config;
mod handlers;

#[tokio::main]
async fn main() {
    let app = Router::new().route("/ping", get(handlers::ping));

    let config = config::Config::from_args();

    let addr: SocketAddr = config.bind_addr.parse().expect("invalid bind addr");

    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
