use clap::Parser;


#[derive(Parser,Debug,Clone)]
#[command(name = "log_sentinnel")]
#[command(author = "Yann Fyzel")]
#[command(version = "2.0")]
#[command(about = "Scanneur de logs a la recherche de menaces et export des alertes en JSON", long_about = None)]

pub struct Arguments{
    #[arg(short,long,env ="LOG_FILE_PATH")]
    pub file: String,

    #[arg(short,long,env = "API_URL")]
    pub api_url : reqwest::Url,

    #[arg(short,long)]
    pub verbose: bool,

    #[arg(short,long,env="AGENT_TOKEN")]
    pub token:String,

}