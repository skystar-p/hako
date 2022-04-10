use rusqlite::Connection;
use tokio::sync::Mutex;

use crate::config::Config;

pub struct State {
    pub conn: Mutex<Connection>,
    pub config: Config,
}
