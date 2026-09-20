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

    let liste_schemas = vec![
        MonitorSchema::new("Injection SQL", "UNION SELECT"),
        MonitorSchema::new("Tentative Path Traversal", "../"),
        MonitorSchema::new("Erreur Critique Ressource", "404"),
        MonitorSchema::new("Accès Admin Interdit", "/wp-admin"),
    ];

    start_watch(args, hostname, ip_address, liste_schemas).await;
}
