#![no_std]

// From dirt.h:
// #define RECORD_TYPE_FILE 1
// #define FS_EVENT_MAX (int)(sizeof(fsevt) / sizeof(struct FS_EVENT))
// (FS_EVENT_MAX is 15 according to the fsevt array in dirt.h)
// #define FILENAME_LEN_MAX 32
// #define FILEPATH_LEN_MAX 96

pub const RECORD_TYPE_FILE: u32 = 1;
pub const FS_EVENT_MAX: usize = 15; // Should match the event array size in RecordFs
pub const FILENAME_LEN_MAX: usize = 32;
pub const FILEPATH_LEN_MAX: usize = 96;

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct Record {
    pub record_type: u32,
    pub ts: u64,
}

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

// This is the critical line that needs to use aya_ebpf::Pod
unsafe impl aya_ebpf::Pod for RecordFs {} // Corrected from aya_bpf::Pod

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

// For JSON output structure, not strictly needed in common for #![no_std]
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

pub const FS_CREATE_EVENT: u32 = 0x00000100;
pub const FS_MODIFY_EVENT: u32 = 0x00000002;
pub const FS_MOVED_FROM_EVENT: u32 = 0x00000040;
pub const FS_MOVED_TO_EVENT: u32 = 0x00000080;
pub const FS_DELETE_EVENT: u32 = 0x00000200;
pub const FS_ACCESS_EVENT: u32 = 0x00000001;

pub const S_IFMT: u32 = 0o0170000;
pub const S_IFLNK: u32 = 0o0120000;
pub const S_IFREG: u32 = 0o0100000;
pub const S_IFDIR: u32 = 0o0040000;

pub fn is_lnk(mode: u32) -> bool {
    (mode & S_IFMT) == S_IFLNK
}
pub fn is_reg(mode: u32) -> bool {
    (mode & S_IFMT) == S_IFREG
}
pub fn is_dir(mode: u32) -> bool {
    (mode & S_IFMT) == S_IFDIR
}
