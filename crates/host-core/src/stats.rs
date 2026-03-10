use crate::models::StatsSnapshot;
use chrono::Utc;
use sysinfo::{Disks, System};

pub struct StatsCollector {
    system: System,
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
        let disk_total_bytes: u64 = disks.list().iter().map(|d| d.total_space()).sum();
        let disk_available_bytes: u64 = disks.list().iter().map(|d| d.available_space()).sum();

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
