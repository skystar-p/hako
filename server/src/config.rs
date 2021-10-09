use structopt::StructOpt;

#[derive(Debug, Clone, StructOpt)]
pub struct Config {
    #[structopt(long)]
    pub bind_addr: String,

    #[structopt(long)]
    pub expiry: Option<usize>,

    #[structopt(long, default_value = "60")]
    pub delete_interval: u64,

    #[structopt(long, default_value = "128")]
    pub chunk_count_limit: u64,
}
