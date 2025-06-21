#![no_std]

// Constants

// Maximum number of nodes in a filepath
pub const FILEPATH_NODE_MAX: usize = 32;
// Maximum length of a filename
pub const FILENAME_LEN_MAX: usize = 255;
// Maximum length of a dname inline
pub const DNAME_INLINE_LEN: usize = 32; // Derived from C, typically PATH_MAX/FILENAME_MAX or similar logic
// Maximum number of filesystem events
pub const FS_EVENT_MAX: usize = 1024;

// Event type constants
pub const I_CREATE: u32 = 0x00000100; // Corresponds to IN_CREATE
pub const I_ACCESS: u32 = 0x00000001; // Corresponds to IN_ACCESS
pub const I_ATTRIB: u32 = 0x00000004; // Corresponds to IN_ATTRIB
pub const I_CLOSE_WRITE: u32 = 0x00000008; // Corresponds to IN_CLOSE_WRITE
pub const I_CLOSE_NOWRITE: u32 = 0x00000010; // Corresponds to IN_CLOSE_NOWRITE
pub const I_DELETE: u32 = 0x00000200; // Corresponds to IN_DELETE
pub const I_MODIFY: u32 = 0x00000002; // Corresponds to IN_MODIFY
pub const I_MOVED_FROM: u32 = 0x00000040; // Corresponds to IN_MOVED_FROM
pub const I_MOVED_TO: u32 = 0x00000080; // Corresponds to IN_MOVED_TO

// Record type constants
pub const RECORD_TYPE_FILE: u32 = 1;

// Monitor flags
pub const MONITOR_NONE: u32 = 0;
pub const MONITOR_FILE: u32 = 1;

// Structs

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct RecordCommon {
    pub record_type: u32,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub comm: [u8; 16], // TASK_COMM_LEN in Linux kernel
    pub tgid: u32,
    pub sessionid: u32,
    pub loginuid: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct RecordFs {
    pub rc: RecordCommon,
    pub filename: [u8; FILENAME_LEN_MAX],
    pub filename_to: [u8; FILENAME_LEN_MAX], // For rename events
    pub filepath: [u8; FILEPATH_NODE_MAX * DNAME_INLINE_LEN], // Assuming this is how filepath is constructed
    pub events: u32,
    pub event: [u32; FS_EVENT_MAX], // Array of event types
    pub atime: u64, // Access time
    pub mtime: u64, // Modification time
    pub ctime: u64, // Change time
    pub ino: u64,   // Inode number
    pub dev: u64,   // Device ID
    pub mode: u32,  // File mode
    pub size: u64,  // File size
    pub nlink: u32, // Number of hard links
    // Timestamps from BPF context
    pub time_ns: u64, // Timestamp in nanoseconds
    pub boot_time_ns: u64, // Boot time in nanoseconds
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct Stats {
    pub events: u64,
    pub errors: u64,
    pub drops: u64,
    pub last_event_ts: u64,
    pub last_error_ts: u64,
    pub last_drop_ts: u64,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct FsEventInfo {
    // Event type index (e.g., I_CREATE, I_MODIFY)
    pub idx: u32, // Changed to u32 to match event constants
    // Name of the kernel function that triggered the event (for debugging/logging)
    pub func: [u8; 32], // Assuming a max function name length of 32

    // Core file information (to be filled by kprobes)
    pub inode_nr: u64,
    pub imode: u32,          // File mode (e.g., S_IFREG, S_IFLNK)
    pub nlink: u32,          // Link count
    pub isize_initial: u64,  // File size when first observed (for new records)
    pub isize_current: u64,  // File size at the time of this event

    // Timestamps from inode
    pub atime_ns: u64,
    pub mtime_ns: u64,
    pub ctime_ns: u64,

    // Filenames and path
    // Primary filename involved in the event
    pub filename: [u8; FILENAME_LEN_MAX],
    // Target filename (for rename/move events, e.g., I_MOVED_TO)
    pub filename_to: [u8; FILENAME_LEN_MAX],
    // Full filepath (potentially truncated if too long)
    pub filepath: [u8; FILEPATH_NODE_MAX * DNAME_INLINE_LEN],

    // Flag to indicate if there was an "old" dentry involved,
    // relevant for I_CREATE to adjust link count if it was a link operation
    // replacing an existing entry (though less common for simple creates).
    // More relevant if a kprobe is on something like `vfs_link` where `old_dentry` is explicit.
    pub dentry_old_is_some: bool,
}
