use colored::*;
use std::{error::Error, fs::{self, File}, io::{BufRead, BufReader, ErrorKind}};
use crate::{Arguments,AlertReport,AttackSchema};

/// Analyse le fichier de logs fourni et orchestre la détection d'intrusions.
///
/// Cette fonction prend en charge deux modes opératoires :
/// 1. La recherche ciblée via une requête personnalisée (`args.query`).
/// 2. Le scan automatique multi-critères (SQLi, Directory Traversal, XSS) par défaut.
///
/// Si des menaces sont détectées, un rapport structuré au format JSON est automatiquement
/// exporté vers le chemin spécifié par `args.output`.
///
/// # Arguments
///
/// * `args` - Une structure `Arguments` contenant les paramètres passés par la ligne de commande.
///
/// # Errors
///
/// Cette fonction propage une erreur (`Box<dyn Error>`) si :
/// * Le fichier cible est introuvable ou illisible (droits insuffisants).
/// * La sérialisation ou l'écriture du rapport JSON sur le disque échoue.
///
/// # Exemples
///
/// ```rust
/// use log_sentinel::models::Arguments;
/// use log_sentinel::detector::run_analysis;
/// 
/// let args = Arguments {
///     file: String::from("serveur.log"),
///     query: None,
///     verbose: false,
///     output: String::from("rapport.json"),
/// };
/// assert!(run_analysis(args).is_ok());
/// ```
pub fn analyse (args:Arguments)-> Result<(), Box<dyn Error>>{
    
    if args.verbose {
        println!("{}", format!("[*] Étape en cours : Lecture de {}...", args.file).blue());
    }

    let file = match File::open(&args.file){
        Ok(f)=>f,
        Err(erreur)=>{
            match erreur.kind() {
                ErrorKind::NotFound =>{
                    eprint!("{}",format!("ERREUR DESTINATION : Le fichier de logs '{}' est introuvable",args.file).red().bold());
                }
                ErrorKind::PermissionDenied => {
                    eprint!("{}",format!("ERREUR DE SECURITE : Accès refusé pour '{}'. Vous n'avez pas les droits de lecture nécessaires.",args.file).red().bold());
                }
                _ => {
                    eprint!("{}",format!(" ERREUR INCONNUE : Impossible de le lire le fichier '{}' ({})",args.file,erreur).red().bold());
                }
            }
            return Err(Box::new(erreur));
        }
    };
    let reader = BufReader::new(file);
    let mut all_alertes = Vec::new();
    let mut nb_ligne = 0;

    if args.verbose{
         println!("{}", "[*] Démarrage du scan ligne par ligne...".yellow());
    }

    for line_result in reader.lines(){
        nb_ligne +=1;
        let line = line_result?;
        
        if let Some(ref custom_query) = args.query {
            // --- CAS A : RECHERCHE SUR SIGNATURE PERSONNALISÉE ---
            if line.contains(custom_query) {
                all_alertes.push(line);
            }
        } else {
            
            let schemas = [
                AttackSchema::SqlInjection, 
                AttackSchema::DirectoryTraversal, 
                AttackSchema::Xss
                ];
                
            for schema in &schemas {
                
                if line.contains(schema.as_pattern()){
                    if !all_alertes.contains(&line){
                        all_alertes.push(line.clone());
                    }
                    break;
                }
                
            }
        }
    }

    if args.verbose {
        println!("{}", format!("[*] Scan terminé. {} lignes analysées.", nb_ligne).blue());
    }

    if all_alertes.is_empty() {
        println!("{}", "Aucune menace détectée. Le fichier de logs est sain.".green().bold());
    } else {
        println!("{}", format!("AVERTISSEMENT : {} alerte(s) détectée(s) !", all_alertes.len()).red().bold());
        for line in &all_alertes {
            println!("{}", line.red());
        }
    }

    if !all_alertes.is_empty() {
        let rapport = AlertReport {
            timestamp : String::from("2026-09-11T13:30:00Z"),
            filepath_audited: args.file.clone(),
            total_alerts:all_alertes.len(),
            lines_detected: all_alertes,
        };

        let json_data = match serde_json::to_string_pretty(&rapport) {
            Ok(data) => data,
            Err(e) => {
                eprintln!("{}", format!(" ERREUR FORMATAGE : Échec de la génération du rapport JSON ({})", e).red().bold());
                return Err(Box::new(e));
            }
        };

        if let Err(erreur) = fs::write(&args.output, json_data) {
            match erreur.kind() {
                ErrorKind::PermissionDenied => {
                    eprintln!("{}", format!(" ERREUR SÉCURITÉ : Impossible d'écrire le rapport dans '{}'. Droits d'écriture insuffisants dans ce répertoire.", args.output).red().bold());
                }
                _ => {
                    eprintln!("{}", format!(" ERREUR ÉCRITURE : Impossible de sauvegarder le rapport dans '{}' ({})", args.output, erreur).red().bold());
                }
            }
            return Err(Box::new(erreur));
        }

        println!("\n{}", format!("Rapport d'audit global exporté avec succès dans : {}", args.output).green().bold());
    }
    
    Ok(())
}


#[cfg(test)]
mod test{
    use super::*;

    #[test]
    fn test_detection_intrusion_streaming(){
        
        let test_file = "logs/combined.log";
        let report_file = "reports/test_report.json";

        let args = Arguments{
            file:test_file.to_string(),
            output:report_file.to_string(),
            query:Some("UNION SELECT".to_string()),
            verbose:false,
        };

        
        let faux_logs = "\
        192.168.1.1 - GET /index.html 200
        10.0.0.99 - GET /login.php?user=admin' UNION SELECT null, password FROM admin-- 404
        192.168.1.2 - GET /style.css 200";

        fs::write(test_file, faux_logs).unwrap();

        let result = analyse(args);

        assert!(result.is_ok());

        let report_content = fs::read_to_string(report_file).unwrap();
        assert!(report_content.contains("UNION SELECT"));
        assert!(report_content.contains("\"total_alerts\": 1"));

        let _ = fs::remove_file(test_file);
        let _ = fs::remove_file(report_file);
    }
}