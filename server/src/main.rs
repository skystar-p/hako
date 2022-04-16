use std::{net::SocketAddr, sync::Arc};

use axum::{
    routing::{get, post},
    Extension, Router,
};
use rusqlite::Connection;
use simple_logger::SimpleLogger;
use state::State;
use structopt::StructOpt;
use tokio::sync::Mutex;
use tower::ServiceBuilder;
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

    // setup database connetion
    let conn = Connection::open(config.sqlite_db_filename.clone()).unwrap();
    let bootstrap_sql = include_str!("../schema.sql");
    conn.execute_batch(bootstrap_sql).unwrap();
    let conn = Mutex::new(conn);

    let shared_state = Arc::new(State {
        conn,
        config: config.clone(),
    });
    let worker_state = shared_state.clone();

    let app = Router::new()
        .route("/api/metadata", get(handlers::metadata))
        .route("/api/download", get(handlers::download))
        .route("/api/ping", get(handlers::ping))
        .route("/api/prepare_upload", post(handlers::prepare_upload))
        .route("/api/upload", post(handlers::upload))
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(Extension(shared_state)),
        );

    let addr: SocketAddr = config.bind_addr.parse().expect("invalid bind addr");

    // start worker
    tokio::spawn(workers::delete_expired(worker_state, config));

    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
