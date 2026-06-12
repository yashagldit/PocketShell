//! Windows Job Object guard for spawned PTY children.
//!
//! # Why this exists
//!
//! On Windows a PTY session is backed by a ConPTY, which spawns a hidden
//! `conhost.exe` that in turn hosts the user's shell (`powershell.exe`). Those
//! processes are connected to the daemon only by pipes — they are NOT killed
//! automatically when the daemon dies.
//!
//! If the daemon exits ungracefully while sessions are live (a crash, an OOM,
//! a power event, or a `taskkill /F`), the graceful PTY teardown never runs and
//! the orphaned `conhost.exe` backends are left behind. Their I/O thread, which
//! used to block on a read of the now-broken owner pipe, stops blocking: the
//! read returns immediately (peer gone) but isn't treated as EOF, so the loop
//! spins — busy-waiting at ~100% of one core, forever, until killed. Several
//! daemon restarts accumulate several spinning orphans and peg the machine.
//!
//! # The fix
//!
//! Create a Job Object at daemon startup with
//! `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` and assign every spawned PTY child to
//! it. When the last handle to the job closes — which the OS does automatically
//! when the owning (daemon) process terminates for ANY reason — Windows kills
//! every process still in the job. Orphaned, spinning conhosts become
//! structurally impossible regardless of how the daemon dies.
//!
//! Crucially, assigning the *shell* child is not enough: the `conhost.exe`
//! ConPTY backend is spawned by `CreatePseudoConsole` (inside `openpty`) as a
//! direct child of the **daemon** — a sibling of the shell, never its
//! descendant — so job membership inherited through the shell never reaches
//! it. The PTY spawn path therefore also diffs the daemon's direct conhost
//! children around `openpty` and assigns the new backend into the job
//! explicitly (see [`direct_conhost_children`] / [`JobObjectGuard::assign_pid`]).
//!
//! As a second layer, [`sweep_orphaned_conpty_backends`] runs once at daemon
//! startup and kills any already-orphaned ConPTY conhost left behind by a
//! previous daemon death (or by builds that predate this guard).
//!
//! # Why hand-rolled FFI
//!
//! The four kernel32 calls and the one limit-info struct used here are stable
//! Win32 with a fixed C ABI. Declaring them directly avoids depending on
//! `windows-sys`, whose Job Object items are split across several features that
//! vary by version (chasing those feature flags proved fragile). `#[repr(C)]`
//! fixes struct layout/padding; we zero the whole struct and set only
//! `LimitFlags`.
//!
//! On non-Windows targets this is a no-op shim so call sites stay portable.

#[cfg(windows)]
mod imp {
    use std::os::raw::c_void;
    use std::os::windows::io::RawHandle;

    type Handle = *mut c_void;
    type Bool = i32;

    // JOBOBJECTINFOCLASS::JobObjectExtendedLimitInformation
    const JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS: i32 = 9;
    // JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: u32 = 0x2000;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct JobObjectBasicLimitInformation {
        per_process_user_time_limit: i64,
        per_job_user_time_limit: i64,
        limit_flags: u32,
        minimum_working_set_size: usize,
        maximum_working_set_size: usize,
        active_process_limit: u32,
        affinity: usize,
        priority_class: u32,
        scheduling_class: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct IoCounters {
        read_operation_count: u64,
        write_operation_count: u64,
        other_operation_count: u64,
        read_transfer_count: u64,
        write_transfer_count: u64,
        other_transfer_count: u64,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct JobObjectExtendedLimitInformation {
        basic_limit_information: JobObjectBasicLimitInformation,
        io_info: IoCounters,
        process_memory_limit: usize,
        job_memory_limit: usize,
        peak_process_memory_used: usize,
        peak_job_memory_used: usize,
    }

    // OpenProcess access rights required by AssignProcessToJobObject.
    const PROCESS_TERMINATE: u32 = 0x0001;
    const PROCESS_SET_QUOTA: u32 = 0x0100;

    #[link(name = "kernel32")]
    extern "system" {
        fn CreateJobObjectW(lp_job_attributes: *mut c_void, lp_name: *const u16) -> Handle;
        fn SetInformationJobObject(
            h_job: Handle,
            job_object_information_class: i32,
            lp_job_object_information: *const c_void,
            cb_job_object_information_length: u32,
        ) -> Bool;
        fn AssignProcessToJobObject(h_job: Handle, h_process: Handle) -> Bool;
        fn OpenProcess(dw_desired_access: u32, b_inherit_handle: Bool, dw_process_id: u32)
            -> Handle;
        fn CloseHandle(h_object: Handle) -> Bool;
    }

    /// Owns a Windows Job Object configured to kill all assigned processes when
    /// the job handle closes (i.e. when this process dies). The daemon holds the
    /// guard for its whole life, so the practical trigger is process
    /// termination, which the OS handles even on a hard kill.
    pub struct JobObjectGuard {
        handle: Handle,
    }

    // The raw HANDLE is just a kernel object identifier; safe to move/share
    // across threads. We only call thread-safe Win32 APIs on it.
    unsafe impl Send for JobObjectGuard {}
    unsafe impl Sync for JobObjectGuard {}

    impl JobObjectGuard {
        /// Create a kill-on-close job object. Returns `None` if any Win32 call
        /// fails — the daemon still runs, just without the orphan guard, so this
        /// is best-effort and never fatal.
        pub fn new() -> Option<Self> {
            unsafe {
                let handle = CreateJobObjectW(std::ptr::null_mut(), std::ptr::null());
                if handle.is_null() {
                    tracing::warn!(
                        "CreateJobObjectW failed; PTY children will not be orphan-guarded"
                    );
                    return None;
                }

                let mut info: JobObjectExtendedLimitInformation = std::mem::zeroed();
                info.basic_limit_information.limit_flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

                let ok = SetInformationJobObject(
                    handle,
                    JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS,
                    &info as *const _ as *const c_void,
                    core::mem::size_of::<JobObjectExtendedLimitInformation>() as u32,
                );
                if ok == 0 {
                    tracing::warn!("SetInformationJobObject failed; closing job, no orphan guard");
                    CloseHandle(handle);
                    return None;
                }

                tracing::debug!("created kill-on-close job object for PTY children");
                Some(Self { handle })
            }
        }

        /// Assign a spawned child process to the job so it is killed when the
        /// daemon dies. `process_handle` is the OS process HANDLE of the child
        /// (from `portable_pty::Child::as_raw_handle`). Best-effort: a failure
        /// is logged but never propagated.
        pub fn assign(&self, process_handle: RawHandle) {
            if process_handle.is_null() {
                return;
            }
            unsafe {
                let ok = AssignProcessToJobObject(self.handle, process_handle as Handle);
                if ok == 0 {
                    tracing::debug!("AssignProcessToJobObject failed for a PTY child (continuing)");
                }
            }
        }

        /// Assign a process by PID. Used for the `conhost.exe` ConPTY backend,
        /// which `CreatePseudoConsole` spawns as a direct child of the daemon —
        /// we never get a handle to it from `portable_pty`, only its PID via
        /// child enumeration. Best-effort: opens the process with the minimal
        /// rights `AssignProcessToJobObject` requires, assigns, closes.
        pub fn assign_pid(&self, pid: u32) {
            unsafe {
                let process = OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, 0, pid);
                if process.is_null() {
                    tracing::debug!("OpenProcess failed for ConPTY backend pid={pid} (continuing)");
                    return;
                }
                let ok = AssignProcessToJobObject(self.handle, process);
                if ok == 0 {
                    // Most common cause: already assigned on a previous call.
                    tracing::debug!(
                        "AssignProcessToJobObject failed for ConPTY backend pid={pid} (continuing)"
                    );
                } else {
                    tracing::debug!("ConPTY backend conhost.exe pid={pid} joined the job object");
                }
                CloseHandle(process);
            }
        }
    }

    /// PIDs of `conhost.exe` processes whose direct parent is this process —
    /// i.e. ConPTY backends created by our `CreatePseudoConsole` calls. Classic
    /// interactive conhosts are children of their console *client* process, so
    /// they never appear here.
    pub fn direct_conhost_children() -> Vec<u32> {
        use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System};

        let mut sys = System::new();
        sys.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::nothing(),
        );
        let me = sysinfo::Pid::from_u32(std::process::id());
        sys.processes()
            .iter()
            .filter(|(_, p)| {
                p.parent() == Some(me) && p.name().eq_ignore_ascii_case("conhost.exe")
            })
            .map(|(pid, _)| pid.as_u32())
            .collect()
    }

    /// Kill `conhost.exe` ConPTY backends orphaned by a previous daemon death.
    ///
    /// Run once at daemon startup. New sessions are protected by the job
    /// object, but orphans left by older builds (or by a failed job
    /// assignment) busy-spin at ~100% CPU forever — nothing else will ever
    /// reap them. Targets are identified conservatively; a process is killed
    /// only if ALL of:
    /// - its image name is `conhost.exe`
    /// - its command line contains `--headless` (the ConPTY marker —
    ///   interactive console hosts never carry it)
    /// - its parent is dead: either the PPID no longer exists, or the process
    ///   now holding that PID started *after* the conhost did (PID reuse)
    ///
    /// Live ConPTY backends (ours or any other app's) always have a live,
    /// older parent and are never touched. Returns the number killed.
    pub fn sweep_orphaned_conpty_backends() -> usize {
        use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

        let mut sys = System::new();
        sys.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::nothing().with_cmd(UpdateKind::Always),
        );

        let procs = sys.processes();
        let mut killed = 0usize;
        for (pid, p) in procs {
            if !p.name().eq_ignore_ascii_case("conhost.exe") {
                continue;
            }
            let headless = p
                .cmd()
                .iter()
                .any(|arg| arg.to_string_lossy().contains("--headless"));
            if !headless {
                continue;
            }
            let Some(ppid) = p.parent() else {
                continue; // can't establish lineage — leave it alone
            };
            let orphaned = match procs.get(&ppid) {
                None => true, // parent is gone
                // The PID was reused: its current holder started after this
                // conhost, so the original parent is dead.
                Some(parent) => parent.start_time() > p.start_time(),
            };
            if !orphaned {
                continue;
            }
            if p.kill() {
                tracing::warn!(
                    "reaped orphaned ConPTY conhost.exe pid={} (parent {} is dead) — \
                     leftover from an ungraceful daemon death",
                    pid.as_u32(),
                    ppid.as_u32()
                );
                killed += 1;
            } else {
                tracing::warn!(
                    "failed to kill orphaned ConPTY conhost.exe pid={}",
                    pid.as_u32()
                );
            }
        }
        killed
    }

    impl Drop for JobObjectGuard {
        fn drop(&mut self) {
            // Closing the handle triggers KILL_ON_JOB_CLOSE for any process
            // still assigned.
            unsafe {
                CloseHandle(self.handle);
            }
        }
    }
}

#[cfg(not(windows))]
mod imp {
    use std::os::raw::c_void;

    /// No-op guard on non-Windows targets (Unix PTY children are reaped via the
    /// process tree / session and don't suffer the ConPTY orphan-spin problem).
    pub struct JobObjectGuard;

    impl JobObjectGuard {
        pub fn new() -> Option<Self> {
            Some(Self)
        }
        #[allow(dead_code)]
        pub fn assign(&self, _process_handle: *mut c_void) {}
        #[allow(dead_code)]
        pub fn assign_pid(&self, _pid: u32) {}
    }

    /// ConPTY backends only exist on Windows; nothing to enumerate elsewhere.
    pub fn direct_conhost_children() -> Vec<u32> {
        Vec::new()
    }

    /// ConPTY backends only exist on Windows; nothing to sweep elsewhere.
    pub fn sweep_orphaned_conpty_backends() -> usize {
        0
    }
}

pub use imp::{direct_conhost_children, sweep_orphaned_conpty_backends, JobObjectGuard};

#[cfg(all(test, windows))]
mod tests {
    use super::{direct_conhost_children, sweep_orphaned_conpty_backends, JobObjectGuard};
    use std::collections::HashSet;
    use std::os::windows::io::AsRawHandle;
    use std::process::Command;
    use std::time::{Duration, Instant};

    /// Serializes the ConPTY-spawning tests. They identify "their" conhost by
    /// diffing this process's conhost children around `openpty`, so two of
    /// them running concurrently can capture each other's backend — and one
    /// test's guard drop would then kill the other test's conhost.
    static CONPTY_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Spawn a real ConPTY with a long-lived child and return everything
    /// needed to reason about its `conhost.exe` backend: the new conhost
    /// PIDs (diffed against a pre-`openpty` snapshot), the PTY pair, and the
    /// shell child.
    fn spawn_conpty() -> (
        Vec<u32>,
        portable_pty::PtyPair,
        Box<dyn portable_pty::Child + Send + Sync>,
    ) {
        use portable_pty::{native_pty_system, CommandBuilder, PtySize};
        use std::io::{Read, Write};

        let before: HashSet<u32> = direct_conhost_children().into_iter().collect();

        let pty = native_pty_system();
        let pair = pty
            .openpty(PtySize {
                rows: 24,
                cols: 80,
                pixel_width: 0,
                pixel_height: 0,
            })
            .expect("openpty");

        // conhost can deadlock `spawn_command` if its output pipe fills with
        // nobody reading, and `--inheritcursor` makes it await a DSR
        // cursor-position reply during startup. Production code always runs a
        // reader thread (pty.rs) and answers device queries (TerminalMirror);
        // stand in for both here: drain the master continuously and pre-seed
        // a cursor-position report.
        let mut reader = pair.master.try_clone_reader().expect("clone reader");
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while matches!(reader.read(&mut buf), Ok(n) if n > 0) {}
        });
        let mut writer = pair.master.take_writer().expect("take writer");
        let _ = writer.write_all(b"\x1b[1;1R");
        let _ = writer.flush();

        let mut cmd = CommandBuilder::new("cmd.exe");
        cmd.args(["/C", "ping -n 60 127.0.0.1 >NUL"]);
        let child = pair.slave.spawn_command(cmd).expect("spawn pty child");

        let new_conhosts: Vec<u32> = direct_conhost_children()
            .into_iter()
            .filter(|pid| !before.contains(pid))
            .collect();
        (new_conhosts, pair, child)
    }

    fn wait_for_pids_to_die(pids: &[u32], timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            let alive: HashSet<u32> = direct_conhost_children().into_iter().collect();
            if pids.iter().all(|pid| !alive.contains(pid)) {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// The actual orphan fix: the `conhost.exe` ConPTY backend — a direct
    /// child of THIS process, not of the shell — must die when the job guard
    /// drops. Assigning only the shell (the pre-fix behavior) left it behind
    /// to busy-spin at 100% CPU.
    #[test]
    fn dropping_guard_kills_conpty_backend_conhost() {
        let _serial = CONPTY_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let guard = JobObjectGuard::new().expect("create job object");
        let (new_conhosts, _pair, mut child) = spawn_conpty();
        assert!(
            !new_conhosts.is_empty(),
            "openpty should have spawned a conhost.exe ConPTY backend as our direct child"
        );

        if let Some(h) = child.as_raw_handle() {
            guard.assign(h);
        }
        for pid in &new_conhosts {
            guard.assign_pid(*pid);
        }

        drop(guard);

        let died = wait_for_pids_to_die(&new_conhosts, Duration::from_secs(5));
        if !died {
            let _ = child.kill(); // don't leak the shell if we're about to fail
            panic!("ConPTY conhost {new_conhosts:?} survived the job-guard drop");
        }
        let _ = child.kill();
    }

    /// Sweep safety: a ConPTY backend whose parent (us) is alive must never
    /// be touched, no matter how many orphans the sweep reaps elsewhere.
    #[test]
    fn sweep_spares_conpty_backend_with_live_parent() {
        let _serial = CONPTY_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (new_conhosts, _pair, mut child) = spawn_conpty();
        assert!(
            !new_conhosts.is_empty(),
            "openpty should have spawned a conhost.exe ConPTY backend as our direct child"
        );

        let _ = sweep_orphaned_conpty_backends();

        let alive: HashSet<u32> = direct_conhost_children().into_iter().collect();
        let _ = child.kill();
        for pid in &new_conhosts {
            assert!(
                alive.contains(pid),
                "sweep killed conhost {pid} even though its parent (this process) is alive"
            );
        }
    }

    /// The core guarantee: a child assigned to the guard's job is killed when
    /// the guard (the sole job handle) is dropped. This is the exact mechanism
    /// that prevents orphaned, CPU-spinning `conhost.exe` when the daemon dies —
    /// here we stand in for the daemon by dropping the guard.
    #[test]
    fn dropping_guard_kills_assigned_child() {
        let guard = JobObjectGuard::new().expect("create job object");

        // A child that would otherwise live ~60s. If kill-on-close works it
        // dies the instant we drop the guard, well before that.
        let mut child = Command::new("cmd")
            .args(["/C", "ping -n 60 127.0.0.1 >NUL"])
            .spawn()
            .expect("spawn child");

        guard.assign(child.as_raw_handle());

        // Sanity: still running right after assignment.
        assert!(
            child.try_wait().expect("try_wait").is_none(),
            "child should still be running before the guard is dropped"
        );

        // Dropping the guard closes the last job handle -> KILL_ON_JOB_CLOSE.
        drop(guard);

        // The OS terminates the child asynchronously; poll briefly.
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut exited = false;
        while Instant::now() < deadline {
            if child.try_wait().expect("try_wait").is_some() {
                exited = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }

        if !exited {
            let _ = child.kill(); // don't leak the child if we're about to fail
            panic!("assigned child was NOT killed when the job guard dropped");
        }
    }
}
