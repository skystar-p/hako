#[derive(clap::Parser, Debug, Clone)]
#[clap(author, version, about)]
pub struct Config {
    #[clap(long, env, default_value = "127.0.0.1:12321")]
    pub bind_addr: String,

    #[clap(long, env, default_value = "hako.db")]
    pub sqlite_db_filename: String,

    #[clap(long, env)]
    pub expiry: Option<usize>,

    #[clap(long, env, default_value = "60")]
    pub delete_interval: u64,

    #[clap(long, env, default_value = "128")]
    pub chunk_count_limit: u64,
}
