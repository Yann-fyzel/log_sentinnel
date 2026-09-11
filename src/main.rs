use std::process;
use clap::Parser;
use log_sentinnel::{Arguments, analyse};

fn main() {
    let args = Arguments::parse();

    if args.verbose {
        println!("Initialisation du scanner en mode verbeux...");
    }

    if let Err(e) = analyse(args){
        eprintln!("Application error : {e}");
        process::exit(1);
    }
    
}
