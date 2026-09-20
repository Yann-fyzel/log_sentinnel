use std::fs;

use clap::Parser;
use local_ip_address::local_ip;
use log_sentinnel::{Arguments, MonitorSchema, start_watch};

#[tokio::main]
async fn main() {
    
    env_logger::init();
    
    let args = Arguments::parse();
    
    if args.verbose {
        println!("Initialisation du scanner en mode verbeux...");
    }

    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "unknow_hostname".to_string());

    let ip_address = local_ip()
        .map(|ip| ip.to_string())
        .unwrap_or_else(|_| "127.0.0.1".to_string());

    let config_path = "rules.json";
    let liste_schemas : Vec<MonitorSchema> = match fs::read_to_string(config_path) {
        Ok(contenu)=>{
            match serde_json::from_str::<Vec<MonitorSchema>>(&contenu) {
                Ok(schemas) =>{
                    println!("📋 {} signatures de menaces chargées avec succès depuis {}", schemas.len(), config_path);
                    schemas
                },
                Err(err)=>{
                    eprintln!(" Erreur de format dans le fichier {} : {}. Utilisation d'un catalogue vide.", config_path, err);
                    vec![]
                }
            }
        },
        Err(_) =>{
            eprintln!("Fichier de règles '{}' introuvable. Lancement sans signatures.", config_path);
            vec![]
        }
    };

    println!("Surveillance active du fichier : {}", args.file);

    start_watch(args, hostname, ip_address, liste_schemas).await;
}
