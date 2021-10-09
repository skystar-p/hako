use deadpool_postgres::Pool;

use crate::config::Config;

pub struct State {
    pub pool: Pool,
    pub config: Config,
}
