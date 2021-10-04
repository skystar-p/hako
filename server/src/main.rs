use std::{net::SocketAddr, sync::Arc};

use axum::{
    handler::{get, post},
    AddExtensionLayer, Router,
};
use deadpool_postgres::Config;
use simple_logger::SimpleLogger;
use state::State;
use structopt::StructOpt;
use tokio_postgres::NoTls;
use tower_http::trace::TraceLayer;

mod config;
mod handlers;
mod state;

#[tokio::main]
async fn main() {
    SimpleLogger::new()
        .with_level(log::LevelFilter::Info)
        .init()
        .unwrap();
    let config = config::Config::from_args();

    // setup database connetion pool
    let mut db_config = Config::new();
    db_config.host = Some("localhost".into());
    db_config.port = Some(5432);
    db_config.user = Some("skystar".into());
    db_config.password = Some("skystar".into());
    db_config.dbname = Some("hako".into());

    let pool = db_config.create_pool(NoTls).unwrap();

    let shared_state = Arc::new(State { pool });

    let app = Router::new()
        .route("/ping", get(handlers::ping))
        .route("/upload", post(handlers::upload))
        .layer(TraceLayer::new_for_http())
        .layer(AddExtensionLayer::new(shared_state));

    let addr: SocketAddr = config.bind_addr.parse().expect("invalid bind addr");

    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
