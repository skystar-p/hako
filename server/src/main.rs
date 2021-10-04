use std::{net::SocketAddr, sync::Arc};

use axum::{
    handler::{get, post},
    AddExtensionLayer, Router,
};
use deadpool_postgres::Config;
use state::State;
use structopt::StructOpt;
use tokio_postgres::NoTls;

mod config;
mod handlers;
mod state;

#[tokio::main]
async fn main() {
    let config = config::Config::from_args();

    // setup database connetion pool
    let mut db_config = Config::new();
    db_config.host = Some("localhost".into());
    db_config.port = Some(5432);
    db_config.user = Some("skystar".into());
    db_config.password = Some("skystar".into());
    db_config.dbname = Some("skystar".into());

    let pool = db_config.create_pool(NoTls).unwrap();

    let shared_state = Arc::new(State { pool });

    let app = Router::new()
        .route("/ping", get(handlers::ping))
        .route("/upload", post(handlers::upload))
        .layer(AddExtensionLayer::new(shared_state));

    let addr: SocketAddr = config.bind_addr.parse().expect("invalid bind addr");

    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
