use crate::models::{ProcessInfo, StatsSnapshot};
use chrono::Utc;
use std::collections::HashSet;
use sysinfo::{Disk, Disks, ProcessesToUpdate, System};
use tokio::time::Instant;

/// Disk stats change slowly — cache and refresh at most every 30 seconds.
const DISK_REFRESH_INTERVAL_SECS: u64 = 30;

pub struct StatsCollector {
    system: System,
    cached_disk_total: u64,
    cached_disk_used: u64,
    disk_refreshed_at: Instant,
}

/// Filter disks to only count real, unique physical storage.
/// Deduplicates APFS container siblings and excludes virtual/snapshot mounts.
fn real_disks(disks: &[Disk]) -> Vec<&Disk> {
    let skip_prefixes: &[&str] = &[
        "/System/Volumes/VM",
        "/System/Volumes/Preboot",
        "/System/Volumes/Update",
        "/System/Volumes/xarts",
        "/System/Volumes/iSCPreboot",
        "/System/Volumes/Hardware",
    ];

    let mut seen_devices = HashSet::new();
    let mut result = Vec::new();

    for disk in disks {
        let mount = disk.mount_point().to_string_lossy();

        if skip_prefixes.iter().any(|p| mount.starts_with(p)) {
            continue;
        }

        if mount.contains(".timemachine") || mount.contains(".backup") {
            continue;
        }

        if mount.contains("CoreSimulator") {
            continue;
        }

        // Deduplicate APFS siblings: on macOS, "/" and "/System/Volumes/Data"
        // share the same container — counting both would double-count.
        let device_name = disk.name().to_string_lossy().to_string();
        let key = if mount == "/" || mount == "/System/Volumes/Data" {
            "apfs-root".to_string()
        } else {
            if device_name.is_empty() {
                mount.to_string()
            } else {
                device_name
            }
        };

        if seen_devices.insert(key) {
            result.push(disk);
        }
    }

    result
}

impl StatsCollector {
    pub fn new() -> Self {
        let mut system = System::new_all();
        system.refresh_all();

        let disks = Disks::new_with_refreshed_list();
        let filtered = real_disks(disks.list());
        let disk_total: u64 = filtered.iter().map(|d| d.total_space()).sum();
        let disk_available: u64 = filtered.iter().map(|d| d.available_space()).sum();

        Self {
            system,
            cached_disk_total: disk_total,
            cached_disk_used: disk_total.saturating_sub(disk_available),
            disk_refreshed_at: Instant::now(),
        }
    }

    /// Lightweight snapshot without per-process data (for background/history).
    pub fn snapshot(&mut self) -> StatsSnapshot {
        self.collect(false)
    }

    /// Full snapshot with per-process data (for live WebRTC streaming).
    pub fn snapshot_with_processes(&mut self) -> StatsSnapshot {
        self.collect(true)
    }

    fn refresh_disk_if_stale(&mut self) {
        if self.disk_refreshed_at.elapsed().as_secs() >= DISK_REFRESH_INTERVAL_SECS {
            let disks = Disks::new_with_refreshed_list();
            let filtered = real_disks(disks.list());
            self.cached_disk_total = filtered.iter().map(|d| d.total_space()).sum();
            let available: u64 = filtered.iter().map(|d| d.available_space()).sum();
            self.cached_disk_used = self.cached_disk_total.saturating_sub(available);
            self.disk_refreshed_at = Instant::now();
        }
    }

    fn collect(&mut self, include_processes: bool) -> StatsSnapshot {
        self.system.refresh_cpu_usage();
        self.system.refresh_memory();
        self.refresh_disk_if_stale();

        let load = System::load_average();

        let processes = if include_processes {
            self.system.refresh_processes(ProcessesToUpdate::All, true);
            let mut procs: Vec<ProcessInfo> = self
                .system
                .processes()
                .values()
                .map(|p| ProcessInfo {
                    pid: p.pid().as_u32(),
                    name: p.name().to_string_lossy().to_string(),
                    cpu_percent: p.cpu_usage(),
                    memory_bytes: p.memory(),
                    status: format!("{:?}", p.status()),
                })
                .collect();
            procs.sort_by(|a, b| b.cpu_percent.partial_cmp(&a.cpu_percent).unwrap_or(std::cmp::Ordering::Equal));
            procs.truncate(50);
            Some(procs)
        } else {
            None
        };

        StatsSnapshot {
            cpu_usage_percent: self.system.global_cpu_usage(),
            memory_total_bytes: self.system.total_memory(),
            memory_used_bytes: self.system.used_memory(),
            disk_total_bytes: self.cached_disk_total,
            disk_used_bytes: self.cached_disk_used,
            uptime_secs: System::uptime(),
            load_one: load.one,
            load_five: load.five,
            load_fifteen: load.fifteen,
            battery_percent: None,
            collected_at: Utc::now(),
            processes,
        }
    }
}
