#![no_std]

// Constants based on usage in dirt-ebpf/src/main.rs and common practice
pub const FILENAME_LEN_MAX: usize = 256; // A common max filename length
pub const FILEPATH_LEN_MAX: usize = 4096; // A common max filepath length
pub const DNAME_INLINE_LEN: usize = 32;   // From d_iname in struct dentry (often 32 or 36, depends on kernel)
pub const FILEPATH_NODE_MAX: usize = 32; // Max path components to trace back for filepath

pub const MAX_STACK_TRACE_DEPTH: usize = 127; // Max kernel stack trace depth, must be < 128 for some helpers.
pub const DBG_LEN_MAX: usize = 64; // Arbitrary length for debug strings

// Placeholder for process ID of the userspace dirt process
pub static mut PID_SELF: u32 = 0;
// Placeholder for max events to aggregate before sending
pub static mut AGG_EVENTS_MAX: u32 = 0;
// Placeholder for debug filter string
pub static mut DEBUG_FILTER_COMM: [u8; DBG_LEN_MAX] = [0u8; DBG_LEN_MAX];

pub const RECORD_TYPE_FILE: u8 = 1;
pub const RECORD_TYPE_SYSCALL: u8 = 2;


#[repr(C)]
#[derive(Copy, Clone)]
pub struct RecordCommon {
    pub ts: u64,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub type_: u8, // e.g., RECORD_TYPE_FILE, RECORD_TYPE_SYSCALL
    pub comm: [u8; 16], // TASK_COMM_LEN from include/linux/sched.h
    pub padding: [u8; 7], // To make it multiple of 8 bytes, if needed
}

impl RecordCommon {
    pub fn new() -> Self {
        RecordCommon {
            ts: 0,
            pid: 0,
            ppid: 0,
            uid: 0,
            gid: 0,
            type_: 0,
            comm: [0; 16],
            padding: [0; 7],
        }
    }
}


#[repr(C)]
#[derive(Copy, Clone)]
pub struct RecordFs {
    pub rc: RecordCommon,
    pub ino: u32,
    pub imode: u32,
    pub isize: u64,
    pub isize_first: u64,
    pub inlink: u32,
    pub atime_nsec: u64,
    pub mtime_nsec: u64,
    pub ctime_nsec: u64,
    pub events: u32,
    pub event: [u16; 16], // Should match size of INDEX_FS_EVENT enum or similar
    pub filename: [u8; FILENAME_LEN_MAX],
    pub filename_to: [u8; FILENAME_LEN_MAX], // For renames
    pub filepath: [u8; FILEPATH_LEN_MAX],
}

impl RecordFs {
    pub fn new() -> Self {
        RecordFs {
            rc: RecordCommon::new(),
            ino: 0,
            imode: 0,
            isize: 0,
            isize_first: 0,
            inlink: 0,
            atime_nsec: 0,
            mtime_nsec: 0,
            ctime_nsec: 0,
            events: 0,
            event: [0; 16],
            filename: [0; FILENAME_LEN_MAX],
            filename_to: [0; FILENAME_LEN_MAX],
            filepath: [0; FILEPATH_LEN_MAX],
        }
    }
}


#[repr(C)]
#[derive(Copy, Clone)]
pub struct Stats {
    pub fs_events: u64,
    pub fs_records: u64,
    pub fs_records_rb_max: u64,
    pub fs_records_dropped: u64,
    pub fs_records_deleted: u64,
    // Add other stats fields as needed
}

impl Stats {
    pub fn new() -> Self {
        Stats {
            fs_events: 0,
            fs_records: 0,
            fs_records_rb_max: 0,
            fs_records_dropped: 0,
            fs_records_deleted: 0,
        }
    }
}

// This is likely a kernel structure, might need to be defined carefully
// or obtained from bindings if available (e.g. via bpftool gen min_core_btf)
// For now, a placeholder:
#[repr(C)]
#[derive(Copy, Clone)]
pub struct FsEventInfo {
    pub index: u32, // Or some enum like INDEX_FS_EVENT
    pub dentry: *mut core::ffi::c_void, // Placeholder for struct dentry*
    pub dentry_old: *mut core::ffi::c_void, // Placeholder for struct dentry*
    pub func: u64, // Placeholder for function pointer or identifier
}


// Helper function that was missing
#[inline(always)]
pub fn key_pid_ino(pid: u32, ino: u32) -> u64 {
    ((pid as u64) << 32) | (ino as u64)
}

// aya_ebpf::bindings might already provide c_void, Inode, Dentry
// If not, they would need to be defined or aliased here.
// For now, assuming they come from aya_ebpf::bindings.
// pub use aya_ebpf::bindings::c_void; // Example if needed

// Re-export constants defined in dirt-ebpf/src/constants.rs if they are widely used,
// or ensure dirt-ebpf uses its own constants where appropriate.
// For now, dirt-ebpf/src/main.rs uses `use crate::constants::*;` so they are local to it.

// The `bpf_core_read` helper is part of aya_ebpf::helpers if the feature is enabled.
// It seems it's not being found, which might indicate a feature flag issue for aya-ebpf
// or it needs to be explicitly imported.
// For now, this is not a dirt-common issue.

// `s_isreg` and `s_islnk` are defined in dirt-ebpf/src/constants.rs.
// `pid_self`, `agg_events_max`, `debug` (filter) are used as if they are global statics.
// I've added placeholders for PID_SELF and AGG_EVENTS_MAX.
// `debug` seems to be a filter string, added placeholder DEBUG_FILTER_COMM.

// Placeholder for TC_ACT_OK if not coming from bindings directly
// pub const TC_ACT_OK: i32 = 0;
// Actually, TC_ACT_OK is in aya_ebpf::bindings, so no need to redefine usually.

// The `Inode` and `Dentry` types are referenced as pointers.
// These are kernel structures. `aya-ebpf-bindings` should provide them.
// e.g. `aya_ebpf::bindings::inode`, `aya_ebpf::bindings::dentry`.
// The `dirt-ebpf/src/main.rs` uses `use aya_ebpf::bindings::*;` which should bring them in scope.
// The errors `cannot find type Inode/Dentry` suggest they might be named differently or not correctly brought into scope.
// Let's assume for now they are in `aya_ebpf::bindings` and the eBPF code needs to use the correct names.
// For example, `inode` (lowercase) instead of `Inode` (uppercase).
// This will be handled when fixing `dirt-ebpf/src/main.rs`.
