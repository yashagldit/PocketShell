#[cfg(target_os = "linux")]
use crate::models::CpuTimes;
use crate::models::{
    CpuCoreInfo, DiskIOStats, LoggedInUser, NetworkConnection, NetworkIOStats, OsInfo, ProcessInfo,
    StatsSnapshot, TaskCounts, TemperatureReading,
};
use chrono::Utc;
use std::collections::HashSet;
use sysinfo::{Components, Disk, Disks, Networks, ProcessStatus, ProcessesToUpdate, System, Users};
use tokio::time::Instant;

/// Disk stats change slowly — cache and refresh at most every 30 seconds.
const DISK_REFRESH_INTERVAL_SECS: u64 = 30;

/// Battery changes slowly — cache with a refresh interval.
const BATTERY_REFRESH_INTERVAL_SECS: u64 = 60;

/// Network connections (netstat) and logged-in users (who) are expensive subprocess
/// calls — cache with a TTL to avoid spawning every 2 seconds.
const NET_CONN_REFRESH_INTERVAL_SECS: u64 = 30;
const USERS_REFRESH_INTERVAL_SECS: u64 = 30;

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
    users: Users,
    // Battery cache
    cached_battery: Option<f32>,
    battery_refreshed_at: Instant,
    // Network connections cache (avoids spawning netstat every 2s)
    cached_net_connections: Option<NetworkConnection>,
    net_conn_refreshed_at: Instant,
    // Logged-in users cache (avoids spawning `who` every 2s)
    cached_logged_in_users: Option<Vec<LoggedInUser>>,
    users_refreshed_at: Instant,
    // Previous CPU times for delta computation (Linux only)
    #[cfg(target_os = "linux")]
    prev_cpu_jiffies: Option<(u64, u64, u64, u64, u64)>, // user, system, idle, iowait, total
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

fn collect_battery() -> Option<f32> {
    #[cfg(target_os = "macos")]
    {
        let output = std::process::Command::new("pmset")
            .args(["-g", "batt"])
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines() {
            if line.contains("InternalBattery") {
                for word in line.split_whitespace() {
                    if word.ends_with("%;") || word.ends_with('%') {
                        let num = word.trim_end_matches(|c| c == '%' || c == ';');
                        return num.parse().ok();
                    }
                }
            }
        }
        None
    }
    #[cfg(target_os = "linux")]
    {
        // Try common battery paths
        for path in &[
            "/sys/class/power_supply/BAT0/capacity",
            "/sys/class/power_supply/BAT1/capacity",
        ] {
            if let Ok(s) = std::fs::read_to_string(path) {
                if let Ok(v) = s.trim().parse::<f32>() {
                    return Some(v);
                }
            }
        }
        None
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        None
    }
}

/// Read /proc/stat and compute CPU time percentages as deltas from the previous sample.
/// Returns (CpuTimes, new_jiffies) so the caller can store jiffies for next delta.
#[cfg(target_os = "linux")]
fn read_cpu_jiffies() -> Option<(u64, u64, u64, u64, u64)> {
    let stat = std::fs::read_to_string("/proc/stat").ok()?;
    let first_line = stat.lines().next()?;
    if !first_line.starts_with("cpu ") {
        return None;
    }
    let parts: Vec<u64> = first_line
        .split_whitespace()
        .skip(1)
        .filter_map(|s| s.parse().ok())
        .collect();
    if parts.len() < 4 {
        return None;
    }
    let user = parts[0] + parts[1]; // user + nice
    let system = parts[2] + parts.get(5).unwrap_or(&0) + parts.get(6).unwrap_or(&0);
    let idle = parts[3];
    let iowait = *parts.get(4).unwrap_or(&0);
    let total = user + system + idle + iowait + parts.get(7).unwrap_or(&0);
    Some((user, system, idle, iowait, total))
}

#[cfg(target_os = "linux")]
fn compute_cpu_times_delta(
    prev: Option<(u64, u64, u64, u64, u64)>,
    curr: (u64, u64, u64, u64, u64),
) -> Option<CpuTimes> {
    let (prev_user, prev_sys, prev_idle, prev_iow, prev_total) = prev?;
    let d_user = curr.0.saturating_sub(prev_user);
    let d_sys = curr.1.saturating_sub(prev_sys);
    let d_idle = curr.2.saturating_sub(prev_idle);
    let d_iow = curr.3.saturating_sub(prev_iow);
    let d_total = curr.4.saturating_sub(prev_total);
    if d_total == 0 {
        return None;
    }
    Some(CpuTimes {
        user_percent: (d_user as f32 / d_total as f32) * 100.0,
        system_percent: (d_sys as f32 / d_total as f32) * 100.0,
        idle_percent: (d_idle as f32 / d_total as f32) * 100.0,
        iowait_percent: (d_iow as f32 / d_total as f32) * 100.0,
    })
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

        let users = Users::new_with_refreshed_list();

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
            users,
            cached_battery: None,
            battery_refreshed_at: Instant::now()
                - std::time::Duration::from_secs(BATTERY_REFRESH_INTERVAL_SECS + 1),
            cached_net_connections: None,
            net_conn_refreshed_at: Instant::now()
                - std::time::Duration::from_secs(NET_CONN_REFRESH_INTERVAL_SECS + 1),
            cached_logged_in_users: None,
            users_refreshed_at: Instant::now()
                - std::time::Duration::from_secs(USERS_REFRESH_INTERVAL_SECS + 1),
            #[cfg(target_os = "linux")]
            prev_cpu_jiffies: None,
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

        // Collect processes and task counts in a single pass
        let (processes, task_counts) = if include_processes {
            self.system.refresh_processes(ProcessesToUpdate::All, true);
            let mut running = 0u32;
            let mut sleeping = 0u32;
            let mut stopped = 0u32;
            let mut zombie = 0u32;
            let mut total = 0u32;
            let mut procs: Vec<ProcessInfo> = self
                .system
                .processes()
                .values()
                .map(|p| {
                    total += 1;
                    match p.status() {
                        ProcessStatus::Run => running += 1,
                        ProcessStatus::Sleep | ProcessStatus::Idle => sleeping += 1,
                        ProcessStatus::Stop => stopped += 1,
                        ProcessStatus::Zombie => zombie += 1,
                        _ => {} // Dead, Unknown, etc. — not counted in any bucket
                    }
                    let user = p.user_id().and_then(|uid| {
                        self.users.get_user_by_id(uid).map(|u| u.name().to_string())
                    });
                    let command = {
                        let cmd = p.cmd();
                        if cmd.is_empty() {
                            None
                        } else {
                            let mut full = cmd
                                .iter()
                                .map(|s| s.to_string_lossy())
                                .collect::<Vec<_>>()
                                .join(" ");
                            if full.len() > 120 {
                                full.truncate(120);
                            }
                            Some(full)
                        }
                    };
                    ProcessInfo {
                        pid: p.pid().as_u32(),
                        name: p.name().to_string_lossy().to_string(),
                        cpu_percent: p.cpu_usage(),
                        memory_bytes: p.memory(),
                        status: format!("{:?}", p.status()),
                        parent_pid: p.parent().map(|pid| pid.as_u32()),
                        user,
                        command,
                        run_time_secs: Some(p.run_time()),
                    }
                })
                .collect();
            procs.sort_by(|a, b| {
                b.cpu_percent
                    .partial_cmp(&a.cpu_percent)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
            procs.truncate(50);
            (
                Some(procs),
                Some(TaskCounts {
                    total,
                    running,
                    sleeping,
                    stopped,
                    zombie,
                }),
            )
        } else {
            (None, None)
        };

        let cpu_per_core = if include_processes {
            Some(
                self.system
                    .cpus()
                    .iter()
                    .map(|c| CpuCoreInfo {
                        name: c.name().to_string(),
                        usage_percent: c.cpu_usage(),
                        frequency_mhz: c.frequency(),
                    })
                    .collect(),
            )
        } else {
            None
        };

        let cpu_times = if include_processes {
            #[cfg(target_os = "linux")]
            {
                let times = if let Some(curr) = read_cpu_jiffies() {
                    let result = compute_cpu_times_delta(self.prev_cpu_jiffies, curr);
                    self.prev_cpu_jiffies = Some(curr);
                    result
                } else {
                    None
                };
                times
            }
            #[cfg(not(target_os = "linux"))]
            {
                None
            }
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

        // These spawn subprocesses — use cached values with TTL
        let network_connections = if include_processes {
            if self.net_conn_refreshed_at.elapsed().as_secs() >= NET_CONN_REFRESH_INTERVAL_SECS {
                self.cached_net_connections = collect_network_connections();
                self.net_conn_refreshed_at = Instant::now();
            }
            self.cached_net_connections.clone()
        } else {
            None
        };

        let logged_in_users = if include_processes {
            if self.users_refreshed_at.elapsed().as_secs() >= USERS_REFRESH_INTERVAL_SECS {
                self.cached_logged_in_users = collect_logged_in_users();
                self.users_refreshed_at = Instant::now();
            }
            self.cached_logged_in_users.clone()
        } else {
            None
        };

        StatsSnapshot {
            cpu_usage_percent: self.system.global_cpu_usage(),
            memory_total_bytes: self.system.total_memory(),
            memory_used_bytes: self.system.used_memory(),
            memory_available_bytes: self.system.available_memory(),
            memory_free_bytes: self.system.free_memory(),
            disk_total_bytes: self.cached_disk_total,
            disk_used_bytes: self.cached_disk_used,
            swap_total_bytes: self.system.total_swap(),
            swap_used_bytes: self.system.used_swap(),
            uptime_secs: System::uptime(),
            load_one: load.one,
            load_five: load.five,
            load_fifteen: load.fifteen,
            battery_percent: if include_processes {
                if self.battery_refreshed_at.elapsed().as_secs() >= BATTERY_REFRESH_INTERVAL_SECS {
                    self.cached_battery = collect_battery();
                    self.battery_refreshed_at = Instant::now();
                }
                self.cached_battery
            } else {
                self.cached_battery
            },
            collected_at: Utc::now(),
            processes,
            network_io,
            disk_io,
            temperatures,
            network_connections,
            logged_in_users,
            os_info: Some(self.os_info.clone()),
            cpu_per_core,
            task_counts,
            cpu_times,
        }
    }
}
