use structopt::StructOpt;

#[derive(Debug, Clone, StructOpt)]
pub struct Config {
    #[structopt(long, default_value = "127.0.0.1:12321", env)]
    pub bind_addr: String,

    // postgresql params
    #[structopt(long, default_value = "localhost", env)]
    pub postgres_host: String,

    #[structopt(long, default_value = "5432", env)]
    pub postgres_port: u16,

    #[structopt(long, default_value = "postgres", env)]
    pub postgres_user: String,

    #[structopt(long, default_value = "postgres", env, hide_env_values = true)]
    pub postgres_password: String,

    #[structopt(long, default_value = "hako", env)]
    pub postgres_dbname: String,

    #[structopt(long, env)]
    pub expiry: Option<usize>,

    #[structopt(long, default_value = "60", env)]
    pub delete_interval: u64,

    #[structopt(long, default_value = "128", env)]
    pub chunk_count_limit: u64,
}
