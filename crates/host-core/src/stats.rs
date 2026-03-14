use crate::models::StatsSnapshot;
use chrono::Utc;
use std::collections::HashSet;
use sysinfo::{Disk, Disks, System};

pub struct StatsCollector {
    system: System,
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

        // Skip macOS system/virtual volumes
        if skip_prefixes.iter().any(|p| mount.starts_with(p)) {
            continue;
        }

        // Skip Time Machine snapshot mounts
        if mount.contains(".timemachine") || mount.contains(".backup") {
            continue;
        }

        // Skip iOS simulator volumes
        if mount.contains("CoreSimulator") {
            continue;
        }

        // Deduplicate APFS siblings: on macOS, "/" and "/System/Volumes/Data"
        // share the same container. Prefer "/System/Volumes/Data" (the actual
        // data volume) and skip "/" if Data is present — they report the same
        // total_space so counting both would double-count.
        let device_name = disk.name().to_string_lossy().to_string();
        let key = if mount == "/" || mount == "/System/Volumes/Data" {
            "apfs-root".to_string()
        } else {
            // For external/other volumes, deduplicate by device name
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
        Self { system }
    }

    pub fn snapshot(&mut self) -> StatsSnapshot {
        self.system.refresh_cpu_usage();
        self.system.refresh_memory();

        let disks = Disks::new_with_refreshed_list();
        let filtered = real_disks(disks.list());
        let disk_total_bytes: u64 = filtered.iter().map(|d| d.total_space()).sum();
        let disk_available_bytes: u64 = filtered.iter().map(|d| d.available_space()).sum();

        let load = System::load_average();

        StatsSnapshot {
            cpu_usage_percent: self.system.global_cpu_usage(),
            memory_total_bytes: self.system.total_memory(),
            memory_used_bytes: self.system.used_memory(),
            disk_total_bytes,
            disk_used_bytes: disk_total_bytes.saturating_sub(disk_available_bytes),
            uptime_secs: System::uptime(),
            load_one: load.one,
            load_five: load.five,
            load_fifteen: load.fifteen,
            battery_percent: None,
            collected_at: Utc::now(),
        }
    }
}
