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
    }
}

pub use imp::JobObjectGuard;

#[cfg(all(test, windows))]
mod tests {
    use super::JobObjectGuard;
    use std::os::windows::io::AsRawHandle;
    use std::process::Command;
    use std::time::{Duration, Instant};

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
