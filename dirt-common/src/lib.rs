#![no_std]

// Constants
pub const RECORD_TYPE_FILE: u32 = 1;
pub const FS_EVENT_MAX: usize = 15;
pub const FILENAME_LEN_MAX: usize = 32;
pub const FILEPATH_LEN_MAX: usize = 96;

// Struct Record
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct Record {
    pub record_type: u32,
    pub ts: u64,
}

// Struct RecordFs
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct RecordFs {
    pub rc: Record,
    pub events: u32,
    pub event: [u32; FS_EVENT_MAX],
    pub ino: u32,
    pub imode: u32,
    pub inlink: u32,
    pub isize: u64,
    pub atime_nsec: u64,
    pub mtime_nsec: u64,
    pub ctime_nsec: u64,
    pub isize_first: u64,
    pub filepath: [u8; FILEPATH_LEN_MAX],
    pub filename_union: [u8; FILENAME_LEN_MAX],
}

// CRITICAL LINE: Ensure this uses aya_ebpf::Pod
unsafe impl aya_ebpf::Pod for RecordFs {}

// Enum FsEventIndex
#[repr(usize)]
#[derive(Debug, Copy, Clone)]
pub enum FsEventIndex {
    Create = 0,
    Open,
    OpenExec,
    Access,
    Attrib,
    Modify,
    CloseWrite,
    CloseNowrite,
    MovedFrom,
    MovedTo,
    Delete,
    DeleteSelf,
    MoveSelf,
    Unmount,
    QOverflow,
}

// Enum JsonKeyIndex (primarily for user-space reference)
#[derive(Debug, Copy, Clone)]
pub enum JsonKeyIndex {
    InfoTimestamp,
    FilePath,
    File,
    FileMode,
    FileEventCount,
    FileEvents,
    FileInode,
    FileInodeLinkCount,
    FileSize,
    FileSizeChange,
    FileAccessTime,
    FileStatusChangeTime,
    FileModificationTime,
}

// Event type constants (examples)
pub const FS_CREATE_EVENT: u32 = 0x00000100;
pub const FS_MODIFY_EVENT: u32 = 0x00000002;
pub const FS_MOVED_FROM_EVENT: u32 = 0x00000040;
pub const FS_MOVED_TO_EVENT: u32 = 0x00000080;
pub const FS_DELETE_EVENT: u32 = 0x00000200;
pub const FS_ACCESS_EVENT: u32 = 0x00000001;

// Inode mode constants
pub const S_IFMT: u32 = 0o0170000;
pub const S_IFLNK: u32 = 0o0120000;
pub const S_IFREG: u32 = 0o0100000;
pub const S_IFDIR: u32 = 0o0040000;

// Helper functions for file type checking
pub fn is_lnk(mode: u32) -> bool {
    (mode & S_IFMT) == S_IFLNK
}
pub fn is_reg(mode: u32) -> bool {
    (mode & S_IFMT) == S_IFREG
}
pub fn is_dir(mode: u32) -> bool {
    (mode & S_IFMT) == S_IFDIR
}
