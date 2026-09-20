use colored::*;
use crate::models::schema::MonitorSchema;
use crate::models::configuration::Arguments;
use crate::models::reporting::{AlertReport,send_alert};

use std::fs::File;
use std::sync::Arc;
use std::path::Path;
use tokio::sync::{mpsc, RwLock};
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};



pub async  fn start_watch(
    args:Arguments,
    hostname:String,
    ip_address: String,
    schemas : Arc<RwLock<Vec<MonitorSchema>>>,
){
    let (tx, mut rx) = mpsc::channel::<String>(1000);
    let file_path = args.file.clone();

    // =========================================================================
    //          MONITORING DU FICHIER DE LOGS
    // =========================================================================

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

    // =========================================================================
    //      MONITORING DU FICHIER DES REGLES DE MENACES (rules.json)
    // =========================================================================
    
    let schemas_for_reload = Arc::clone(&schemas);

    tokio::task::spawn_blocking(move || {
        let config_path = Path::new("rules.json");
        let (watcher_tx, watcher_rx) = std::sync::mpsc::channel();
        let mut watcher = RecommendedWatcher::new(watcher_tx,notify::Config::default()).unwrap();
        watcher.watch(config_path,RecursiveMode::NonRecursive).unwrap();

         println!(" Moteur de Hot Reload activé sur 'rules.json'");

         for res in watcher_rx{
            match  res {
                Ok(Event { kind:EventKind::Modify(_), ..})=>{
                    std::thread::sleep(std::time::Duration::from_millis(100));

                    if let Ok(contenu) = std::fs::read_to_string(config_path){
                        if let Ok(new_rules) = serde_json::from_str::<Vec<MonitorSchema>>(&contenu){

                            let runtime = tokio::runtime::Handle::current();
                            runtime.block_on(async{
                                let mut rules = schemas_for_reload.write().await;
                                *rules = new_rules;
                            });
                        }
                    }
                }
                _ => {}
            }
         }
    });


    // =========================================================================
    //      ANALYSE ET ENVOI RÉSEAU ASYNCHRONE
    // =========================================================================
    
    let client = Arc::new(reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap());

    let token = Arc::new(args.token);
    let api_url = Arc::new(args.api_url);
    let hostname = Arc::new(hostname);
    let ip_address = Arc::new(ip_address);

    while let Some(log_line) = rx.recv().await {
        
        let url_clone = Arc::clone(&api_url);
        let token_clone = Arc::clone(&token);
        let client_clone = Arc::clone(&client);

        let host_clone = Arc::clone(&hostname);
        let ip_clone = Arc::clone(&ip_address);

        let log_line_clean  = log_line.trim().to_string();
        let schemas_clone = Arc::clone(&schemas);
        
        
        tokio::spawn(async move{
            let schema_read = schemas_clone.read().await;
            for schema in schema_read.iter() {
                
                if log_line_clean .contains(&schema.pattern) {
                    let payload = AlertReport {
                        title : schema.title.clone(),
                        priorite: schema.level.clone(),
                        log_line: log_line_clean .clone(),
                        local_ip: ip_clone.to_string(),
                        hostname: host_clone.to_string(),
                        type_attaque: schema.pattern.clone(),
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
        });
    }
}