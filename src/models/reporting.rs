use std::sync::Arc;
use serde::Serialize;
use tokio::time::{sleep, Duration};

use crate::models::schema::LEVEL;

#[derive(Serialize, Debug, Clone)]
pub struct AlertReport {
    pub title: String,
    pub priorite:LEVEL,
    pub log_line: String,
    pub local_ip: String,
    pub hostname: String,
    pub type_attaque: String,
}


pub async fn send_alert(
    token: Arc<String>,
    api_url: Arc<reqwest::Url>,
    payload: AlertReport,
    client: Arc<reqwest::Client>,
) {
    let max_retries = 5;
    let mut tentatives = 0;

    while tentatives < max_retries {

        let response = client.post((*api_url).clone())
            .header("X-Agent-Token", &*token)
            .json(&payload)
            .send()
            .await;

        match response {
            Ok(res) if res.status().is_success() => {
                break;
            }
            Ok(res) => {
                eprintln!(" Le serveur a répondu avec une erreur [{}]. Tentative {}/{}", res.status(), tentatives + 1, max_retries);
            }
            Err(err) => {
                eprintln!(" Erreur réseau / Timeout ({}) : Tentative {}/{}", err, tentatives + 1, max_retries);
            }
        }

        tentatives += 1;
        if tentatives < max_retries {
            sleep(Duration::from_secs(2*tentatives)).await;
        }
    }
}