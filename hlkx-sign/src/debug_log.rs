//! NDJSON debug logging for agent debug sessions.
#![allow(dead_code)]

use std::fs::OpenOptions;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

const LOG_PATH: &str = "/tmp/debug-f4d2d5.log";
const SESSION_ID: &str = "f4d2d5";

// #region agent log
pub fn log(hypothesis_id: &str, location: &str, message: &str, data_json: &str) {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(LOG_PATH) {
        let _ = writeln!(
            f,
            r#"{{"sessionId":"{SESSION_ID}","hypothesisId":"{hypothesis_id}","location":"{location}","message":"{message}","data":{data_json},"timestamp":{ts}}}"#
        );
    }
}
// #endregion
