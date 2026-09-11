use clap::Parser;


#[derive(Parser,Debug)]
#[command(name = "log_sentinnel")]
#[command(author = "Yann Fyzel")]
#[command(version = "2.0")]
#[command(about = "Mini scanneur de logs a la recherche de menaces et export des alertes en JSON", long_about = None)]

pub struct Arguments{
    #[arg(short,long)]
    pub file: String,

    #[arg(short,long)]
    pub query : Option<String>,

    #[arg(short,long)]
    pub verbose: bool,
    
    #[arg(short, long, default_value = "report.json")]
    pub output: String,

}