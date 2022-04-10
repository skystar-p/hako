use structopt::StructOpt;

#[derive(Debug, Clone, StructOpt)]
pub struct Config {
    #[structopt(long, default_value = "127.0.0.1:12321", env)]
    pub bind_addr: String,

    #[structopt(long, default_value = "hako.db", env)]
    pub sqlite_db_filename: String,

    #[structopt(long, env)]
    pub expiry: Option<usize>,

    #[structopt(long, default_value = "60", env)]
    pub delete_interval: u64,

    #[structopt(long, default_value = "128", env)]
    pub chunk_count_limit: u64,
}
