use serde::{Deserialize, Serialize};

#[derive(Serialize, Debug, Clone,Deserialize,PartialEq)]
pub enum LEVEL {
    Low,
    Meduim,
    High,
    Critical
}

#[derive(Debug, Clone,Serialize,Deserialize)]
pub struct MonitorSchema {
    pub title: String,
    pub pattern: String, 
    pub level: LEVEL,
}

impl MonitorSchema {
    pub fn new(nom: &str, pattern: &str,level:LEVEL) -> Self {
        Self {
            title: nom.to_string(),
            pattern: pattern.to_string(),
            level
        }
    }
}
