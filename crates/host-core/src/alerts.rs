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
                "temperature" => {
                    match &snapshot.temperatures {
                        Some(temps) if !temps.is_empty() => {
                            temps.iter().map(|t| t.temp_celsius as f64).fold(f64::NEG_INFINITY, f64::max)
                        }
                        _ => continue,
                    }
                }
                "battery" => {
                    match snapshot.battery_percent {
                        Some(b) => b as f64,
                        None => continue,
                    }
                }
                "swap" => {
                    if snapshot.swap_total_bytes == 0 {
                        continue;
                    }
                    (snapshot.swap_used_bytes as f64 / snapshot.swap_total_bytes as f64) * 100.0
                }
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
                "temperature" => "Temperature",
                "battery" => "Battery",
                "swap" => "Swap usage",
                _ => &threshold.metric,
            };

            let unit = if threshold.metric == "temperature" { "°C" } else { "%" };
            let direction = if threshold.comparison == "lt" { "below" } else { "exceeds" };
            alerts.push(AlertPayload {
                metric: threshold.metric.clone(),
                threshold_value: threshold.threshold_value,
                actual_value: (actual_value * 10.0).round() / 10.0, // round to 1 decimal
                message: format!(
                    "{} {:.1}{} {} threshold {:.1}{}",
                    label, actual_value, unit, direction, threshold.threshold_value, unit
                ),
            });
        }

        alerts
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{AlertThreshold, StatsSnapshot};
    use chrono::Utc;

    fn empty_snapshot() -> StatsSnapshot {
        StatsSnapshot {
            cpu_usage_percent: 0.0,
            memory_total_bytes: 0,
            memory_used_bytes: 0,
            memory_available_bytes: 0,
            memory_free_bytes: 0,
            disk_total_bytes: 0,
            disk_used_bytes: 0,
            swap_total_bytes: 0,
            swap_used_bytes: 0,
            uptime_secs: 0,
            load_one: 0.0,
            load_five: 0.0,
            load_fifteen: 0.0,
            battery_percent: None,
            collected_at: Utc::now(),
            processes: None,
            network_io: None,
            disk_io: None,
            temperatures: None,
            network_connections: None,
            logged_in_users: None,
            os_info: None,
            cpu_per_core: None,
            task_counts: None,
            cpu_times: None,
        }
    }

    fn threshold(metric: &str, value: f64, comparison: &str, cooldown: u64) -> AlertThreshold {
        AlertThreshold {
            metric: metric.to_string(),
            threshold_value: value,
            comparison: comparison.to_string(),
            cooldown_minutes: cooldown,
        }
    }

    #[test]
    fn cpu_threshold_fires_when_exceeded() {
        let mut checker = AlertChecker::new();
        let mut snap = empty_snapshot();
        snap.cpu_usage_percent = 95.0;
        let alerts = checker.check(&snap, &[threshold("cpu", 80.0, "gt", 5)]);
        assert_eq!(alerts.len(), 1);
        let a = &alerts[0];
        assert_eq!(a.metric, "cpu");
        assert_eq!(a.threshold_value, 80.0);
        assert!((a.actual_value - 95.0).abs() < 0.001);
        assert!(a.message.contains("CPU usage"));
        assert!(a.message.contains("exceeds"));
    }

    #[test]
    fn cpu_threshold_does_not_fire_when_under() {
        let mut checker = AlertChecker::new();
        let mut snap = empty_snapshot();
        snap.cpu_usage_percent = 50.0;
        let alerts = checker.check(&snap, &[threshold("cpu", 80.0, "gt", 5)]);
        assert!(alerts.is_empty());
    }

    #[test]
    fn cooldown_suppresses_repeated_alerts() {
        let mut checker = AlertChecker::new();
        let mut snap = empty_snapshot();
        snap.cpu_usage_percent = 95.0;
        let t = threshold("cpu", 80.0, "gt", 5);
        let first = checker.check(&snap, std::slice::from_ref(&t));
        assert_eq!(first.len(), 1);
        let second = checker.check(&snap, std::slice::from_ref(&t));
        assert!(
            second.is_empty(),
            "second call within cooldown window should be silent"
        );
    }

    #[test]
    fn memory_threshold_skipped_when_total_zero() {
        let mut checker = AlertChecker::new();
        let snap = empty_snapshot();
        let alerts = checker.check(&snap, &[threshold("memory", 50.0, "gt", 5)]);
        assert!(alerts.is_empty());
    }

    #[test]
    fn memory_threshold_computes_percentage() {
        let mut checker = AlertChecker::new();
        let mut snap = empty_snapshot();
        snap.memory_total_bytes = 1000;
        snap.memory_used_bytes = 900; // 90%
        let alerts = checker.check(&snap, &[threshold("memory", 80.0, "gt", 5)]);
        assert_eq!(alerts.len(), 1);
        assert!((alerts[0].actual_value - 90.0).abs() < 0.001);
    }

    #[test]
    fn battery_lt_comparison_fires_when_below() {
        let mut checker = AlertChecker::new();
        let mut snap = empty_snapshot();
        snap.battery_percent = Some(15.0);
        let alerts = checker.check(&snap, &[threshold("battery", 20.0, "lt", 5)]);
        assert_eq!(alerts.len(), 1);
        assert!(alerts[0].message.contains("below"));
        assert!(alerts[0].message.contains("Battery"));
    }

    #[test]
    fn battery_skipped_when_absent() {
        let mut checker = AlertChecker::new();
        let snap = empty_snapshot();
        let alerts = checker.check(&snap, &[threshold("battery", 20.0, "lt", 5)]);
        assert!(alerts.is_empty());
    }

    #[test]
    fn unknown_metric_is_skipped() {
        let mut checker = AlertChecker::new();
        let snap = empty_snapshot();
        let alerts = checker.check(&snap, &[threshold("frobnicator", 1.0, "gt", 5)]);
        assert!(alerts.is_empty());
    }

    #[test]
    fn temperature_uses_max_reading() {
        use crate::models::TemperatureReading;
        let mut checker = AlertChecker::new();
        let mut snap = empty_snapshot();
        snap.temperatures = Some(vec![
            TemperatureReading {
                label: "cpu".into(),
                temp_celsius: 40.0,
                max_celsius: None,
            },
            TemperatureReading {
                label: "gpu".into(),
                temp_celsius: 85.0,
                max_celsius: None,
            },
        ]);
        let alerts = checker.check(&snap, &[threshold("temperature", 80.0, "gt", 5)]);
        assert_eq!(alerts.len(), 1);
        assert!((alerts[0].actual_value - 85.0).abs() < 0.001);
        assert!(alerts[0].message.contains("°C"));
    }

    #[test]
    fn disk_and_swap_skipped_when_total_zero() {
        let mut checker = AlertChecker::new();
        let snap = empty_snapshot();
        let alerts = checker.check(
            &snap,
            &[
                threshold("disk", 50.0, "gt", 5),
                threshold("swap", 50.0, "gt", 5),
            ],
        );
        assert!(alerts.is_empty());
    }

    #[test]
    fn load_metric_fires_on_load_five() {
        let mut checker = AlertChecker::new();
        let mut snap = empty_snapshot();
        snap.load_five = 4.5;
        let alerts = checker.check(&snap, &[threshold("load", 2.0, "gt", 5)]);
        assert_eq!(alerts.len(), 1);
        assert!(alerts[0].message.contains("Load average"));
    }
}
