pub enum LEVEL {
    Low,
    Meduim,
    High,
    Critical
}

#[derive(Debug, Clone)]
pub struct MonitorSchema {
    pub title: String,
    pub pattern: String, 
    pub level: LEVEL,
}

impl MonitorSchema {
    pub fn new(nom: &str, pattern: &str) -> Self {
        Self {
            title: nom.to_string(),
            pattern: pattern.to_string(),
            level
        }
    }
}
