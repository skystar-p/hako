use structopt::StructOpt;

#[derive(Debug, StructOpt)]
pub struct Config {
    #[structopt(long)]
    pub bind_addr: String,
}
