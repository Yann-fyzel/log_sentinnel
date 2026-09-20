use colored::*;
use crate::models::schema::MonitorSchema;
use crate::models::configuration::Arguments;
use crate::models::reporting::{AlertReport,send_alert};

use std::fs::File;
use std::sync::Arc;
use std::path::Path;
use tokio::sync::mpsc;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};



pub async  fn start_watch(
    args:Arguments,
    hostname:String,
    ip_address: String,
    schemas : Vec<MonitorSchema>,
){
    let (tx, mut rx) = mpsc::channel::<String>(1000);
    let file_path = args.file.clone();

    tokio::task::spawn_blocking(move || {
        let path = Path::new(&file_path);
        let mut last_position = match  File::open(path) {
            Ok(file) => file.metadata().map(|m| m.len()).unwrap_or(0),
            Err(_)=>0,
        };

        let (watcher_tx, watcher_rx) = std::sync::mpsc::channel();
        let mut watcher = RecommendedWatcher::new(watcher_tx, notify::Config::default()).unwrap();
        watcher.watch(path, RecursiveMode::NonRecursive).unwrap();

        for res in watcher_rx{
            match res {
                Ok(Event { kind: EventKind::Modify(_),..}) =>{
                    if let Ok(mut file) =File::open(path){
                        let current_len = file.metadata().map(|m| m.len()).unwrap_or(0);

                        if current_len < last_position {
                            println!(" Rotation de log détectée (Fichier recréé).");
                            last_position = 0;
                        }

                        if file.seek(SeekFrom::Start(last_position)).is_ok() {
                            let mut  reader = BufReader::new(file);
                            let mut line = String::new();

                            while  reader.read_line(&mut line).unwrap_or(0) > 0 {
                                if !line.trim().is_empty(){
                                    let _ = tx.blocking_send(line.clone());
                                }
                                last_position += line.len() as u64;
                                line.clear();
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    });

     // 2. Boucle asynchrone non-bloquante de traitement des alertes
    let client = Arc::new(reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap());

    let api_url = Arc::new(args.api_url);
    let token = Arc::new(args.token);
    let schemas = Arc::new(schemas);
    let hostname = Arc::new(hostname);
    let ip_address = Arc::new(ip_address);

    while let Some(log_line) = rx.recv().await {
        let schemas_clone = Arc::clone(&schemas);
        let log_line_clean  = log_line.trim().to_string();
        
        let client_clone = Arc::clone(&client);
        let url_clone = Arc::clone(&api_url);
        let token_clone = Arc::clone(&token);
        let host_clone = Arc::clone(&hostname);
        let ip_clone = Arc::clone(&ip_address);        
        

        // Analyse de la ligne par rapport à la liste des schémas de l'utilisateur
        for schema in schemas_clone.iter() {
            if log_line_clean .contains(&schema.pattern) {
                let payload = AlertReport {
                    hostname: host_clone.to_string(),
                    local_ip: ip_clone.to_string(),
                    title : schema.title.clone(),
                    type_attaque: schema.pattern.clone(),
                    log_line: log_line_clean .clone(),
                };

                if args.verbose {
                    println!("{}", format!("Menace détectée [{}] : {}", schema.title, log_line_clean).red());
                }
                
                tokio::spawn(send_alert(
                    token_clone.clone(),
                    url_clone.clone(),
                    payload,
                    client_clone.clone(),
                ));
                break;
            }
        }
    }
}