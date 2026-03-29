use crate::models::{AlertPayload, AlertThreshold, StatsSnapshot};
use std::collections::HashMap;
use tokio::time::Instant;

pub struct AlertChecker {
    last_alerted: HashMap<String, Instant>,
}

impl AlertChecker {
    pub fn new() -> Self {
        Self {
            last_alerted: HashMap::new(),
        }
    }

    pub fn check(
        &mut self,
        snapshot: &StatsSnapshot,
        thresholds: &[AlertThreshold],
    ) -> Vec<AlertPayload> {
        let mut alerts = Vec::new();
        let now = Instant::now();

        for threshold in thresholds {
            let actual_value = match threshold.metric.as_str() {
                "cpu" => snapshot.cpu_usage_percent as f64,
                "memory" => {
                    if snapshot.memory_total_bytes == 0 {
                        continue;
                    }
                    (snapshot.memory_used_bytes as f64 / snapshot.memory_total_bytes as f64) * 100.0
                }
                "disk" => {
                    if snapshot.disk_total_bytes == 0 {
                        continue;
                    }
                    (snapshot.disk_used_bytes as f64 / snapshot.disk_total_bytes as f64) * 100.0
                }
                "load" => snapshot.load_five,
                _ => continue,
            };

            let exceeded = match threshold.comparison.as_str() {
                "lt" => actual_value < threshold.threshold_value,
                _ => actual_value > threshold.threshold_value, // default "gt"
            };

            if !exceeded {
                continue;
            }

            // Check cooldown
            if let Some(last) = self.last_alerted.get(&threshold.metric) {
                let elapsed_mins = now.duration_since(*last).as_secs() / 60;
                if elapsed_mins < threshold.cooldown_minutes {
                    continue;
                }
            }

            self.last_alerted.insert(threshold.metric.clone(), now);

            let label = match threshold.metric.as_str() {
                "cpu" => "CPU usage",
                "memory" => "Memory usage",
                "disk" => "Disk usage",
                "load" => "Load average (5m)",
                _ => &threshold.metric,
            };

            alerts.push(AlertPayload {
                metric: threshold.metric.clone(),
                threshold_value: threshold.threshold_value,
                actual_value: (actual_value * 10.0).round() / 10.0, // round to 1 decimal
                message: format!(
                    "{} {:.1}% exceeds threshold {:.1}%",
                    label, actual_value, threshold.threshold_value
                ),
            });
        }

        alerts
    }
}
