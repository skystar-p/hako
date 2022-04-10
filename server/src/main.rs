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
mod utils;
mod workers;

#[tokio::main]
async fn main() {
    SimpleLogger::new()
        .with_utc_timestamps()
        .with_level(log::LevelFilter::Info)
        .init()
        .unwrap();
    let config = config::Config::from_args();

    // setup database connetion pool
    let mut db_config = Config::new();
    db_config.host = Some(config.postgres_host.clone());
    db_config.port = Some(config.postgres_port);
    db_config.user = Some(config.postgres_user.clone());
    db_config.password = Some(config.postgres_password.clone());
    db_config.dbname = Some(config.postgres_dbname.clone());

    let pool = db_config.create_pool(NoTls).unwrap();

    let shared_state = Arc::new(State {
        pool,
        config: config.clone(),
    });
    let worker_state = shared_state.clone();

    let app = Router::new()
        .route("/api/metadata", get(handlers::metadata))
        .route("/api/download", get(handlers::download))
        .route("/api/ping", get(handlers::ping))
        .route("/api/prepare_upload", post(handlers::prepare_upload))
        .route("/api/upload", post(handlers::upload))
        .layer(TraceLayer::new_for_http())
        .layer(AddExtensionLayer::new(shared_state));

    let addr: SocketAddr = config.bind_addr.parse().expect("invalid bind addr");

    // start worker
    tokio::spawn(workers::delete_expired(worker_state, config));

    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
