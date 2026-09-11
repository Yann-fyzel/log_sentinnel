use serde::Serialize;

#[derive(Serialize)]
pub struct AlertReport {
    pub timestamp: String,
    pub filepath_audited: String,
    pub total_alerts: usize,
    pub lines_detected: Vec<String>,
}
