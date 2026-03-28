use crate::models::{
    DiskIOStats, LoggedInUser, NetworkConnection, NetworkIOStats, OsInfo, ProcessInfo,
    StatsSnapshot, TemperatureReading,
};
use chrono::Utc;
use std::collections::HashSet;
use sysinfo::{Components, Disk, Disks, Networks, ProcessesToUpdate, System};
use tokio::time::Instant;

/// Disk stats change slowly — cache and refresh at most every 30 seconds.
const DISK_REFRESH_INTERVAL_SECS: u64 = 30;

pub struct StatsCollector {
    system: System,
    networks: Networks,
    cached_disk_total: u64,
    cached_disk_used: u64,
    disk_refreshed_at: Instant,
    // Previous sample for rate computation
    prev_net_bytes_sent: u64,
    prev_net_bytes_recv: u64,
    prev_disk_read_bytes: u64,
    prev_disk_write_bytes: u64,
    prev_sample_at: Option<Instant>,
    // OS info is static — cache once
    os_info: OsInfo,
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

/// Collect TCP connection counts by parsing `netstat` output.
fn collect_network_connections() -> Option<NetworkConnection> {
    let output = std::process::Command::new("netstat")
        .args(["-n", "-p", "tcp"])
        .output()
        .ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    let mut established: u32 = 0;
    let mut time_wait: u32 = 0;
    let mut close_wait: u32 = 0;
    let mut listen: u32 = 0;
    let mut total: u32 = 0;

    for line in stdout.lines() {
        let line_upper = line.to_uppercase();
        let trimmed = line.trim_start();
        // Only count lines starting with "tcp" (e.g. "tcp4", "tcp6")
        if !trimmed.to_uppercase().starts_with("TCP") {
            continue;
        }
        total += 1;
        if line_upper.contains("ESTABLISHED") {
            established += 1;
        } else if line_upper.contains("TIME_WAIT") {
            time_wait += 1;
        } else if line_upper.contains("CLOSE_WAIT") {
            close_wait += 1;
        } else if line_upper.contains("LISTEN") {
            listen += 1;
        }
    }

    Some(NetworkConnection {
        tcp_established: established,
        tcp_time_wait: time_wait,
        tcp_close_wait: close_wait,
        tcp_listen: listen,
        tcp_total: total,
    })
}

/// Collect logged-in users via the `who` command.
fn collect_logged_in_users() -> Option<Vec<LoggedInUser>> {
    let output = std::process::Command::new("who").output().ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);

    let users: Vec<LoggedInUser> = stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 2 {
                return None;
            }
            let username = parts[0].to_string();
            let terminal = parts[1].to_string();
            // Remote host is usually in parentheses at the end, e.g. "(192.168.1.1)"
            let remote_host = parts.last().and_then(|p| {
                if p.starts_with('(') && p.ends_with(')') {
                    Some(p.trim_matches(|c| c == '(' || c == ')').to_string())
                } else {
                    None
                }
            });
            Some(LoggedInUser {
                username,
                terminal,
                remote_host,
            })
        })
        .collect();

    Some(users)
}

impl StatsCollector {
    pub fn new() -> Self {
        let mut system = System::new_all();
        system.refresh_all();

        let networks = Networks::new_with_refreshed_list();

        let disks = Disks::new_with_refreshed_list();
        let filtered = real_disks(disks.list());
        let disk_total: u64 = filtered.iter().map(|d| d.total_space()).sum();
        let disk_available: u64 = filtered.iter().map(|d| d.available_space()).sum();

        let os_info = OsInfo {
            os_name: System::name().unwrap_or_default(),
            os_version: System::os_version().unwrap_or_default(),
            kernel_version: System::kernel_version().unwrap_or_default(),
            hostname: System::host_name().unwrap_or_default(),
            arch: System::cpu_arch(),
        };

        Self {
            system,
            networks,
            cached_disk_total: disk_total,
            cached_disk_used: disk_total.saturating_sub(disk_available),
            disk_refreshed_at: Instant::now(),
            prev_net_bytes_sent: 0,
            prev_net_bytes_recv: 0,
            prev_disk_read_bytes: 0,
            prev_disk_write_bytes: 0,
            prev_sample_at: None,
            os_info,
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

    fn collect_network_io(&mut self) -> NetworkIOStats {
        self.networks.refresh(true);

        let mut bytes_sent: u64 = 0;
        let mut bytes_recv: u64 = 0;
        let mut packets_sent: u64 = 0;
        let mut packets_recv: u64 = 0;

        for (_name, net) in &self.networks {
            bytes_sent += net.total_transmitted();
            bytes_recv += net.total_received();
            packets_sent += net.total_packets_transmitted();
            packets_recv += net.total_packets_received();
        }

        let now = Instant::now();
        let (bps_sent, bps_recv) = if let Some(prev_at) = self.prev_sample_at {
            let elapsed = now.duration_since(prev_at).as_secs_f64();
            if elapsed > 0.0 {
                let sent_delta = bytes_sent.saturating_sub(self.prev_net_bytes_sent);
                let recv_delta = bytes_recv.saturating_sub(self.prev_net_bytes_recv);
                (
                    Some((sent_delta as f64 / elapsed) as u64),
                    Some((recv_delta as f64 / elapsed) as u64),
                )
            } else {
                (None, None)
            }
        } else {
            (None, None)
        };

        self.prev_net_bytes_sent = bytes_sent;
        self.prev_net_bytes_recv = bytes_recv;

        NetworkIOStats {
            bytes_sent,
            bytes_recv,
            packets_sent,
            packets_recv,
            bytes_sent_per_sec: bps_sent,
            bytes_recv_per_sec: bps_recv,
        }
    }

    fn collect_disk_io(&mut self) -> DiskIOStats {
        // sysinfo doesn't expose per-disk I/O, so we use process-level I/O as a proxy.
        // On Linux we can read /proc/diskstats; on macOS we use iostat.
        // For simplicity and cross-platform support, use process disk usage from sysinfo.
        let mut read_bytes: u64 = 0;
        let mut write_bytes: u64 = 0;

        for (_pid, proc) in self.system.processes() {
            let du = proc.disk_usage();
            read_bytes += du.total_read_bytes;
            write_bytes += du.total_written_bytes;
        }

        let now = Instant::now();
        let (rps, wps) = if let Some(prev_at) = self.prev_sample_at {
            let elapsed = now.duration_since(prev_at).as_secs_f64();
            if elapsed > 0.0 {
                let r_delta = read_bytes.saturating_sub(self.prev_disk_read_bytes);
                let w_delta = write_bytes.saturating_sub(self.prev_disk_write_bytes);
                (
                    Some((r_delta as f64 / elapsed) as u64),
                    Some((w_delta as f64 / elapsed) as u64),
                )
            } else {
                (None, None)
            }
        } else {
            (None, None)
        };

        self.prev_disk_read_bytes = read_bytes;
        self.prev_disk_write_bytes = write_bytes;

        DiskIOStats {
            read_bytes,
            write_bytes,
            read_bytes_per_sec: rps,
            write_bytes_per_sec: wps,
        }
    }

    fn collect_temperatures(&self) -> Vec<TemperatureReading> {
        let components = Components::new_with_refreshed_list();
        components
            .iter()
            .filter_map(|c| {
                let temp = c.temperature()?;
                Some(TemperatureReading {
                    label: c.label().to_string(),
                    temp_celsius: temp,
                    max_celsius: c.max().filter(|&m| m > 0.0),
                })
            })
            .collect()
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
            procs.sort_by(|a, b| {
                b.cpu_percent
                    .partial_cmp(&a.cpu_percent)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
            procs.truncate(50);
            Some(procs)
        } else {
            None
        };

        let network_io = Some(self.collect_network_io());
        // Disk I/O relies on process data — only collect when processes were refreshed
        let disk_io = if include_processes {
            Some(self.collect_disk_io())
        } else {
            None
        };

        // Update prev_sample_at after both network and disk IO deltas are computed
        self.prev_sample_at = Some(Instant::now());

        let temperatures = {
            let temps = self.collect_temperatures();
            if temps.is_empty() {
                None
            } else {
                Some(temps)
            }
        };

        // These are slightly expensive — only collect for live/full snapshots
        let network_connections = if include_processes {
            collect_network_connections()
        } else {
            None
        };

        let logged_in_users = if include_processes {
            collect_logged_in_users()
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
            network_io,
            disk_io,
            temperatures,
            network_connections,
            logged_in_users,
            os_info: Some(self.os_info.clone()),
        }
    }
}
