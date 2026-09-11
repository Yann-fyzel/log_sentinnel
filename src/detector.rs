use colored::*;
use std::{error::Error, fs};
use crate::{Arguments,AlertReport,AttackSchema};

pub fn search<'a> (query:&str, contents: &'a str,verbose:bool) -> Vec<&'a str>{
    let mut results = Vec::new();
    if verbose {
        println!("{}", "[*] Debut du scan avec la signature {query}".yellow());
    }
    for line in contents.lines() {
        if line.contains(query) {
            results.push(line);
        }
    }
    results
}


pub fn analyse (args:Arguments)-> Result<(), Box<dyn Error>>{
    
    if args.verbose {
        println!("{}", format!("[*] Étape en cours : Lecture de {}...", args.file).blue());
    }

    let contents = fs::read_to_string(&args.file)?;
    let mut all_alertes = Vec::new();
    
    if let Some(ref custom_query) = args.query {
        // Option A : Recherche sur signature personnalisée
        if args.verbose {
            println!("{}", format!("[*] Scan avec la requête personnalisée : '{}'", custom_query).yellow());
        }
        let alertes = search(custom_query,&contents,args.verbose);
        if alertes.is_empty() {
                println!("{}", format!(" Aucune correspondance trouvée pour le critère : '{}'", custom_query).yellow());
        } else {
            println!("{}", format!("{} alerte(s) détectée(s) pour '{}' :", alertes.len(), custom_query).red().bold());
            for line in alertes {
                println!("{}", line.red());
                all_alertes.push(line.to_string());
            }
        }
    } else {
        // Option B : Recherche automatique par défaut
        if args.verbose {
            println!("{}", "[*] Requête absente. Lancement du scan multi-signatures automatique...".yellow());
        }

        let schemas = [
            AttackSchema::SqlInjection, 
            AttackSchema::DirectoryTraversal, 
            AttackSchema::Xss
        ];

        for schema in &schemas {
            let pattern = schema.as_pattern();
            let alertes = search(pattern, &contents, args.verbose);

            println!("\nRapport pour le critère [{:?}] (Motif: '{}')", schema, pattern);

            if alertes.is_empty() {
                println!("{}", "  └─Sain : Aucune menace détectée pour ce motif.".green());
            } else {
                println!("{}", format!("  └─Attention : {} ligne(s) suspecte(s) détectée(s) !", alertes.len()).red().bold());
                
                for line in alertes {
                    println!("     {}", line.red());
                    // On évite les doublons dans le rapport global
                    if !all_alertes.contains(&line.to_string()) {
                        all_alertes.push(line.to_string());
                    }
                }
            }
            
        }
    }

    if !all_alertes.is_empty() {
        let rapport = AlertReport {
            timestamp : String::from("2026-09-11T13:30:00Z"),
            filepath_audited: args.file.clone(),
            total_alerts:all_alertes.len(),
            lines_detected: all_alertes,
        };

        let json_data = serde_json::to_string_pretty(&rapport)?;

        fs::write(&args.output, json_data)?;

        println!("\n{}", format!("Rapport d'audit global exporté avec succès dans : {}", args.output).green().bold());
    }
    
    Ok(())
}


#[cfg(test)]
mod test{
    use super::*;

    #[test]
    fn test_detection_intrusion(){
        let query = "UNION SELECT";
        let contents = "\
        192.168.1.1 - GET /index.html 200
        10.0.0.99 - GET /login.php?user=admin' UNION SELECT null, password FROM admin-- 404
        192.168.1.2 - GET /style.css 200";

        let result = search(query, contents,true);

        assert_eq!(result.len(),1);
        assert!(result[0].contains("UNION SELECT"));
    }
}