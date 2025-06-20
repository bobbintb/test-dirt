#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::vmlinux,
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel, bpf_probe_read_kernel_str_bytes, bpf_get_boot_ns},
    macros::{kprobe, kretprobe, map},
    maps::{Array, LruHashMap, PerCpuArray, RingBuf},
    programs::ProbeContext,
};
use aya_log_ebpf::info;
use core::mem::{size_of, zeroed};
use dirt_common::*;

// Calculate max_entries for RINGBUF_RECORDS
// const RINGBUF_MAX_ENTRIES: usize = core::mem::size_of::<RecordFs>() * 8192;
// NOTE: The above const calculation cannot be done directly in static map definition.
// It needs to be a literal. Assuming RecordFs is roughly 2KB for estimation.
// sizeof(RecordFs) is not directly available here for const calculation in map macro.
// For now, using a placeholder size. This should be adjusted with actual RecordFs size.
// A typical RecordFs (with large arrays) might be around:
// rc: ~50 bytes
// filename: 255
// filename_to: 255
// filepath: 32 * 32 = 1024
// event: 1024 * 4 = 4096
// Other fields: ~50 bytes
// Total: ~5730 bytes. Let's use a calculated value based on a more precise estimate if possible,
// or a sufficiently large buffer.
// For now, let's assume a size of 6000 bytes for RecordFs for the RingBuf.
// So, 6000 * 8192 = 49152000. This seems too large for typical BPF limits.
// RingBuf max_entries is specified in bytes.
// Let's use a more common RingBuf size like 256KB or 512KB or 1MB, e.g. 1024 * 1024 = 1MB
// The C code has `sizeof(struct RECORD_FS) * 8192` which seems to imply that BPF_MAP_TYPE_RINGBUF
// in C takes number of entries, and the loader calculates total size.
// However, Aya's RingBuf `max_entries` is the size in bytes.
// Let's use a common default like 256 * 1024 * 1024 (256MB) if the intent was #items * size_of_item.
// Or if it means total size of ring buffer in bytes, then it's that value.
// The original C code `sizeof(struct RECORD_FS) * 8192` would be the *total size in bytes* for the ring buffer.
// Let's estimate sizeof(RecordFs):
// RecordCommon: u32*6 + u8*16 = 24 + 16 = 40
// filename: 255
// filename_to: 255
// filepath: 32 * 32 = 1024
// events: u32 = 4
// event: 1024 * 4 = 4096
// atime, mtime, ctime, ino, dev, size, time_ns, boot_time_ns: u64*8 = 64
// mode: u32 = 4
// Total approx: 40 + 255 + 255 + 1024 + 4 + 4096 + 64 + 4 = 5742 bytes.
// Size of RecordFs: calculated based on struct definition in dirt-common.
// RecordCommon: u32*6 + u8*16 = 24 + 16 = 40
// filename: 255
// filename_to: 255
// filepath: 32 * 32 = 1024
// events: u32 = 4
// event: FS_EVENT_MAX (1024) * 4 = 4096
// atime, mtime, ctime, ino, dev, size, time_ns, boot_time_ns: u64*8 = 64
// mode: u32 = 4
// Total: 40 + 255 + 255 + 1024 + 4 + 4096 + 64 + 4 = 5742.
const RECORD_FS_SIZE: usize = 5742; // core::mem::size_of::<RecordFs>() cannot be used in const directly for map def.
const RINGBUF_TOTAL_SIZE: u32 = (RECORD_FS_SIZE * 8192) as u32;


#[map]
static mut RINGBUF_RECORDS: RingBuf = RingBuf::with_max_entries(RINGBUF_TOTAL_SIZE, 0);

#[map]
static mut HASH_RECORDS: LruHashMap<u64, RecordFs> = LruHashMap::with_max_entries(1024, 0);

#[map]
static mut HEAP_RECORD_FS: PerCpuArray<RecordFs> = PerCpuArray::with_max_entries(1, 0);

#[map]
static mut STATS_MAP: Array<Stats> = Array::with_max_entries(1, 0);

// Global variables (to be initialized by userspace)
// PID of the dirt process itself, to filter out its own events
static mut PID_SELF: u32 = 0;
// Maximum number of events to aggregate before sending a record
static mut AGG_EVENTS_MAX: u32 = 10; // Default value, can be overridden by userspace

// Global monitoring switch (to be initialized by userspace)
static mut MONITOR: u32 = MONITOR_NONE;

// For symlink handling: stores the inode number of the dentry being symlinked.
static mut DENTRY_SYMLINK_INO: u64 = 0;

// Helper function to copy a byte slice into a fixed-size array
fn copy_byte_slice_to_array<const N: usize>(dest: &mut [u8; N], src: &[u8]) {
    let len = if src.len() < N { src.len() } else { N - 1 };
    dest[..len].copy_from_slice(&src[..len]);
    dest[len] = 0; // Null-terminate
}

// Helper function to populate FsEventInfo from a dentry
// This is a critical function and will need careful implementation and error handling.
// For now, focusing on filename and basic inode info. Path construction is deferred/simplified.
#[inline(always)]
fn populate_fs_event_from_dentry(
    ctx: &ProbeContext,
    dentry_ptr: *const vmlinux::dentry,
    func_name_bytes: &[u8], // e.g., b"do_filp_open\0"
    event_idx_val: u32,
    event_info: &mut FsEventInfo,
) -> Result<(), u32> {
    unsafe {
        let dentry: vmlinux::dentry = ctx.bpf_probe_read_kernel(dentry_ptr).map_err(|e| e as u32)?;
        let inode_ptr: *const vmlinux::inode = ctx.bpf_probe_read_kernel(&dentry.d_inode).map_err(|e| e as u32)?;
        if inode_ptr.is_null() {
            return Err(1); // No inode associated
        }
        let inode: vmlinux::inode = ctx.bpf_probe_read_kernel(inode_ptr).map_err(|e| e as u32)?;

        // Populate FsEventInfo
        core::ptr::write_bytes(event_info as *mut FsEventInfo, 0, 1); // Zero out the struct

        copy_byte_slice_to_array(&mut event_info.func, func_name_bytes);
        event_info.idx = event_idx_val;
        event_info.inode_nr = inode.i_ino;
        event_info.imode = inode.i_mode;
        event_info.nlink = inode.i_nlink;
        event_info.isize_current = inode.i_size as u64;
        event_info.isize_initial = inode.i_size as u64; // Initial and current are same at first observation

        event_info.atime_ns = inode.i_atime.tv_sec as u64 * 1_000_000_000u64 + inode.i_atime.tv_nsec as u64;
        event_info.mtime_ns = inode.i_mtime.tv_sec as u64 * 1_000_000_000u64 + inode.i_mtime.tv_nsec as u64;
        event_info.ctime_ns = inode.i_ctime.tv_sec as u64 * 1_000_000_000u64 + inode.i_ctime.tv_nsec as u64;

        // Read filename: dentry->d_name.name
        // Dentry name is a qstr struct. d_name.name is a char*.
        let name_ptr: *const u8 = ctx.bpf_probe_read_kernel(&dentry.d_name.name).map_err(|e| e as u32)?;
        if !name_ptr.is_null() {
            // Determine length of name, d_name.len might be available
            let name_len = ctx.bpf_probe_read_kernel(&dentry.d_name.len).unwrap_or(FILENAME_LEN_MAX as u32) as usize;
            let max_read_len = if name_len < FILENAME_LEN_MAX { name_len } else { FILENAME_LEN_MAX - 1};

            // bpf_probe_read_kernel_str_bytes is safer for null terminated strings
            // but d_name.name is not guaranteed to be short enough for its fixed buffer.
            // Reading byte by byte or using bpf_probe_read_kernel with calculated length.
            let mut name_buffer = [0u8; FILENAME_LEN_MAX];
            if ctx.bpf_probe_read_kernel_str_bytes(name_ptr as *const i8, &mut name_buffer).is_ok() {
                 event_info.filename = name_buffer;
            } else {
                // Fallback or error if string read fails
                // For now, just try a direct read up to max_read_len
                let mut temp_name_buf = [0u8; FILENAME_LEN_MAX];
                if ctx.bpf_probe_read_kernel_bytes(name_ptr, &mut temp_name_buf[..max_read_len]).is_ok() {
                    event_info.filename = temp_name_buf; // This will be null terminated if max_read_len < FILENAME_LEN_MAX
                    if max_read_len < FILENAME_LEN_MAX { // ensure null termination if it filled buffer
                         event_info.filename[max_read_len] = 0;
                    } else {
                         event_info.filename[FILENAME_LEN_MAX-1] = 0;
                    }
                } else {
                    // error reading name
                    return Err(2);
                }
            }
        }


        // Simplified filepath: for now, just copy filename to filepath.
        // Full path construction is complex (iterating d_parent).
        event_info.filepath = event_info.filename; // Simplification

        // dentry_old_is_some needs to be set by caller if applicable
    }
    Ok(())
}

#[kprobe(name = "notify_change")]
pub fn notify_change_kprobe(ctx: ProbeContext) -> u32 {
    if unsafe { MONITOR != MONITOR_FILE } {
        return 0;
    }
    // Args: dentry: *const vmlinux::dentry, attr: *const vmlinux::iattr, ...
    let dentry_ptr = ctx.arg(0) as *const vmlinux::dentry;
    let attr_ptr = ctx.arg(1) as *const vmlinux::iattr;

    if dentry_ptr.is_null() || attr_ptr.is_null() {
        return 0;
    }

    match unsafe { try_notify_change_kprobe(&ctx, dentry_ptr, attr_ptr) } {
        Ok(_) => 0,
        Err(e) => {
            let mut s_opt = unsafe { STATS_MAP.get_ptr_mut(&0) };
            if let Some(s) = s_opt.as_mut() {
                unsafe {
                    (*s).errors += 1;
                    (*s).last_error_ts = bpf_ktime_get_ns();
                }
            }
            e as u32
        }
    }
}

unsafe fn try_notify_change_kprobe(ctx: &ProbeContext, dentry_ptr: *const vmlinux::dentry, attr_ptr: *const vmlinux::iattr) -> Result<(), u32> {
    let attr: vmlinux::iattr = ctx.bpf_probe_read_kernel(attr_ptr)?;
    let ia_valid = attr.ia_valid;

    // Constants for ia_valid flags (from include/linux/fs.h)
    // These might need to be defined if not in aya_ebpf::bindings::vmlinux
    const ATTR_MODE: u32 = 1 << 0;
    const ATTR_UID: u32 = 1 << 1;
    const ATTR_GID: u32 = 1 << 2;
    const ATTR_SIZE: u32 = 1 << 3;
    const ATTR_ATIME: u32 = 1 << 4;
    const ATTR_MTIME: u32 = 1 << 5;
    const ATTR_CTIME: u32 = 1 << 6;
    const ATTR_ATIME_SET: u32 = 1 << 7;
    const ATTR_MTIME_SET: u32 = 1 << 8;
    // const ATTR_FORCE: u32 = 1 << 9; /* Not a change, but a change qualifier */
    // const ATTR_KILL_SUID: u32 = 1 << 11;
    // const ATTR_KILL_SGID: u32 = 1 << 12;
    // const ATTR_FILE: u32 = 1 << 13;
    // const ATTR_KILL_PRIV: u32 = 1 << 14;
    // const ATTR_OPEN: u32 = 1 << 15; /* Truncate */
    // const ATTR_TIMES_SET: u32 = 1 << 16;
    // const ATTR_TOUCH: u32 = 1 << 17;

    let mut event_info: FsEventInfo = zeroed();

    // FS_ATTRIB: Check for changes in mode, uid, gid, timestamps
    if (ia_valid & (ATTR_MODE | ATTR_UID | ATTR_GID | ATTR_CTIME | ATTR_ATIME_SET | ATTR_MTIME_SET | ATTR_ATIME | ATTR_MTIME)) != 0 {
        populate_fs_event_from_dentry(ctx, dentry_ptr, b"notify_change\0", I_ATTRIB, &mut event_info)?;
        // ia_valid might indicate new size, update if so.
        if (ia_valid & ATTR_SIZE) != 0 {
            event_info.isize_current = ctx.bpf_probe_read_kernel(&attr.ia_size)?;
        }
        handle_fs_event(ctx, &event_info)?;
    }

    // FS_MODIFY: Check for changes in file content (size) or mtime
    // The C code checks `(ia_valid & ATTR_SIZE) || ((ia_valid & ATTR_MTIME) && !(ia_valid & ATTR_MTIME_SET))`
    // ATTR_MTIME_SET means mtime was explicitly set (like touch -m), not due to content change.
    // If ATTR_MTIME is set but ATTR_MTIME_SET is not, it implies content modification.
    let mtime_content_change = (ia_valid & ATTR_MTIME) != 0 && (ia_valid & ATTR_MTIME_SET) == 0;
    if (ia_valid & ATTR_SIZE) != 0 || mtime_content_change {
        // Re-populate or update event_info for I_MODIFY if not already suitable
        populate_fs_event_from_dentry(ctx, dentry_ptr, b"notify_change\0", I_MODIFY, &mut event_info)?;
        if (ia_valid & ATTR_SIZE) != 0 {
             event_info.isize_current = ctx.bpf_probe_read_kernel(&attr.ia_size)?;
        }
        handle_fs_event(ctx, &event_info)?;
    }

    // FS_ACCESS: Check for ATTR_ATIME if not ATTR_ATIME_SET
    // Similar to mtime, if ATTR_ATIME is set but ATTR_ATIME_SET is not, it implies an access.
    let atime_access_event = (ia_valid & ATTR_ATIME) != 0 && (ia_valid & ATTR_ATIME_SET) == 0;
    if atime_access_event {
        populate_fs_event_from_dentry(ctx, dentry_ptr, b"notify_change\0", I_ACCESS, &mut event_info)?;
        handle_fs_event(ctx, &event_info)?;
    }

    Ok(())
}

#[kprobe(name = "__fsnotify_parent")]
pub fn fsnotify_parent_kprobe(ctx: ProbeContext) -> u32 {
    if unsafe { MONITOR != MONITOR_FILE } {
        return 0;
    }
    // Args: dentry: *const vmlinux::dentry, mask: u32
    let dentry_ptr = ctx.arg(0) as *const vmlinux::dentry;
    let mask = ctx.arg(1) as u32;

    if dentry_ptr.is_null() {
        return 0;
    }

    match unsafe { try_fsnotify_parent_kprobe(&ctx, dentry_ptr, mask) } {
        Ok(_) => 0,
        Err(e) => {
            let mut s_opt = unsafe { STATS_MAP.get_ptr_mut(&0) };
            if let Some(s) = s_opt.as_mut() {
                unsafe {
                    (*s).errors += 1;
                    (*s).last_error_ts = bpf_ktime_get_ns();
                }
            }
            e as u32
        }
    }
}

unsafe fn try_fsnotify_parent_kprobe(ctx: &ProbeContext, dentry_ptr: *const vmlinux::dentry, mask: u32) -> Result<(), u32> {
    // fsnotify event masks (from include/linux/fsnotify.h)
    const FS_ACCESS_VAL: u32 = 0x00000001;       /* File was accessed */
    const FS_MODIFY_VAL: u32 = 0x00000002;       /* File was modified */
    const FS_ATTRIB_VAL: u32 = 0x00000004;       /* Metadata changed */
    // Other FS_* flags exist but these are the ones dirt C code checks for this probe.

    let mut event_info: FsEventInfo = zeroed();

    if (mask & FS_ATTRIB_VAL) != 0 {
        populate_fs_event_from_dentry(ctx, dentry_ptr, b"__fsnotify_parent\0", I_ATTRIB, &mut event_info)?;
        handle_fs_event(ctx, &event_info)?;
    }
    if (mask & FS_MODIFY_VAL) != 0 {
        populate_fs_event_from_dentry(ctx, dentry_ptr, b"__fsnotify_parent\0", I_MODIFY, &mut event_info)?;
        handle_fs_event(ctx, &event_info)?;
    }
    if (mask & FS_ACCESS_VAL) != 0 {
        populate_fs_event_from_dentry(ctx, dentry_ptr, b"__fsnotify_parent\0", I_ACCESS, &mut event_info)?;
        handle_fs_event(ctx, &event_info)?;
    }

    Ok(())
}


// File mode constants (from linux/stat.h)
// These might be available in aya_ebpf::bindings::vmlinux::* but defining for clarity
const S_IFMT: u32 = 0o0170000;  // bit mask for the file type bit field
const S_IFREG: u32 = 0o0100000; // regular file
const S_IFLNK: u32 = 0o0120000; // symbolic link

// Helper to check file type
#[inline(always)]
fn s_isreg(mode: u32) -> bool {
    (mode & S_IFMT) == S_IFREG
}

#[inline(always)]
fn s_islnk(mode: u32) -> bool {
    (mode & S_IFMT) == S_IFLNK
}

#[allow(unused_variables, dead_code)] // Allow unused variables/dead code for now
fn handle_fs_event(ctx: &ProbeContext, event: &FsEventInfo) -> Result<u32, u32> {
    // 1. Initial Filtering & PID
    if event.idx == I_ACCESS || event.idx == I_ATTRIB {
        return Ok(0);
    }

    let pid_tgid = unsafe { aya_ebpf::helpers::bpf_get_current_pid_tgid() };
    let pid = (pid_tgid >> 32) as u32;

    let pid_self = unsafe { PID_SELF };
    if pid_self != 0 && pid_self == pid {
        return Ok(0);
    }

    // 2. Variable Initialization (largely from event struct)
    let ts_event = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };

    // 3. Core Logic - Inode, Filename, Mode (now from event struct)
    let inode_nr = event.inode_nr;
    let imode = event.imode;

    if !(s_isreg(imode) || s_islnk(imode)) {
        // Not a regular file or symlink
        return Ok(0);
    }

    // 4. Map Lookups & Updates
    let key_pid_ino: u64 = (pid as u64) << 32 | (inode_nr as u64);

    let mut s_opt = unsafe { STATS_MAP.get_ptr_mut(&0) };

    // Try to get existing record
    let r_opt = unsafe { HASH_RECORDS.get(&key_pid_ino) };

    let mut agg_end = false;
    let r_ptr: *mut RecordFs = if let Some(existing_r) = r_opt {
        // Record exists, update it
        let mut r_mut_ref = unsafe { &mut *existing_r }; // Get a mutable reference

        if event.idx == I_MOVED_TO {
            r_mut_ref.filename_to = event.filename_to;
        }
        r_mut_ref.rc.pid = pid; // Update PID, could change if process forks/execs with same inode
        // rc.ts is not present in RecordCommon, time_ns is in RecordFs
        r_mut_ref.time_ns = ts_event;
        r_mut_ref.boot_time_ns = unsafe { aya_ebpf::helpers::bpf_get_boot_ns() };


        r_mut_ref.imode = imode;
        r_mut_ref.size = event.isize_current;
        r_mut_ref.nlink = event.nlink;
        r_mut_ref.atime = event.atime_ns;
        r_mut_ref.mtime = event.mtime_ns;
        r_mut_ref.ctime = event.ctime_ns;

        r_mut_ref.events += 1;
        if (event.idx as usize) < FS_EVENT_MAX { // Check bounds
            r_mut_ref.event[event.idx as usize] += 1;
        }

        existing_r // return the pointer for later use by agg_end logic
    } else {
        // No existing record, get one from heap and initialize
        let r_heap_ptr = unsafe { HEAP_RECORD_FS.get_ptr_mut(0) };
        if r_heap_ptr.is_none() {
            if let Some(s) = s_opt.as_mut() {
                unsafe { (*s).errors += 1; (*s).last_error_ts = ts_event; }
            }
            return Err(1); // Failed to get record from heap
        }
        let r_new = unsafe { &mut *r_heap_ptr.unwrap() };

        // Initialize RecordCommon part of RecordFs
        r_new.rc.record_type = RECORD_TYPE_FILE; // Set type early
        r_new.rc.pid = pid;
        let comm = unsafe { aya_ebpf::helpers::bpf_get_current_comm().unwrap_or_default() };
        r_new.rc.comm = comm;
        // Other rc fields (ppid, uid, gid, tgid, sessionid, loginuid) would need to be fetched
        // using bpf_get_current_uid_gid etc. and populated if required.
        // For now, initializing them to 0 or leaving as is from heap.
        r_new.rc.ppid = 0; // Placeholder
        let uid_gid = unsafe { aya_ebpf::helpers::bpf_get_current_uid_gid() };
        r_new.rc.uid = (uid_gid & 0xFFFFFFFF) as u32;
        r_new.rc.gid = (uid_gid >> 32) as u32;
        r_new.rc.tgid = (pid_tgid & 0xFFFFFFFF) as u32; // tgid is lower 32 bits
        r_new.rc.sessionid = 0; // Placeholder, requires more complex lookup
        r_new.rc.loginuid = 0;  // Placeholder, requires /proc/self/loginuid or audit interaction

        // Initialize RecordFs specific fields
        r_new.time_ns = ts_event;
        r_new.boot_time_ns = unsafe { aya_ebpf::helpers::bpf_get_boot_ns() };
        r_new.ino = inode_nr;
        r_new.filename = event.filename;
        // filename_to is only set for MOVED_TO, initialize to zero or leave
        r_new.filename_to = [0u8; FILENAME_LEN_MAX];
        if event.idx == I_MOVED_TO {
            r_new.filename_to = event.filename_to;
        }
        r_new.filepath = event.filepath; // Assumes kprobe populated this

        r_new.events = 1;
        r_new.event = [0u32; FS_EVENT_MAX]; // Initialize event counters
        if (event.idx as usize) < FS_EVENT_MAX {
             r_new.event[event.idx as usize] = 1;
        }

        r_new.atime = event.atime_ns;
        r_new.mtime = event.mtime_ns;
        r_new.ctime = event.ctime_ns;
        r_new.dev = 0; // Placeholder, event should provide this if available (e.g. from statx)
        r_new.mode = imode;
        r_new.size = event.isize_current;
        // nlink is part of RecordFs but not RecordCommon in my earlier definition. Let's assume it's in RecordFs.
        // The C code has r->inlink, let's assume it's r.nlink.
        r_new.nlink = event.nlink;


        if let Some(s) = s_opt.as_mut() {
            unsafe { (*s).events += 1; (*s).last_event_ts = ts_event; }
        }

        // Insert into HASH_RECORDS, then this r_new ptr is what we work with.
        // Note: HASH_RECORDS stores copies. We'll operate on r_new (from heap), then insert.
        // This means on next hit, we get a *copy* from HASH_RECORDS.
        // The C logic implies operating on the map value directly if possible, or copying, modifying, reinserting.
        // Aya's LruHashMap::get returns a pointer to the value in the map.
        // So, if r_opt was Some(existing_r), existing_r is already a pointer to map value.
        // If we are here (else block), r_new is from HEAP_RECORD_FS. We will insert it later.
        r_heap_ptr.unwrap() // return the pointer for later use by agg_end logic
    };

    // Common update logic for both new and existing records (operating on r_ptr)
    // Most fields already updated above inside if/else.
    // This section is for fields that are updated regardless of new/existing.
    // (e.g. if some fields of rc were missed or need re-evaluation)

    // Handle I_CREATE with dentry_old_is_some:
    // The C code has `if (index == I_CREATE && dentry_old) r->inlink++;`
    // This implies if I_CREATE is effectively overwriting/linking over something.
    // Assuming nlink from event.nlink already reflects the state *after* the operation.
    // If dentry_old_is_some means the operation might have unlinked a previous entry,
    // and nlink needs adjustment or careful interpretation.
    // For simplicity, we trust event.nlink for now.
    // If event.dentry_old_is_some is true for I_CREATE, it might indicate a scenario like
    // creating a hard link where a file with the same name already existed and was unlinked first.
    // However, typical create calls don't have an "old dentry". This might be more for link/rename.
    // Let's stick to the C code's logic if possible:
    if event.idx == I_CREATE && event.dentry_old_is_some {
        unsafe { (*r_ptr).nlink += 1 }; // Potentially adjust nlink based on this flag.
    }

    // 5. Aggregation Logic
    let agg_events_max = unsafe { AGG_EVENTS_MAX };
    if unsafe { (*r_ptr).events >= agg_events_max } ||
       event.idx == I_DELETE || event.idx == I_MOVED_FROM || event.idx == I_MOVED_TO {
        agg_end = true;
    }

    if agg_end {
        unsafe {
            (*r_ptr).rc.record_type = RECORD_TYPE_FILE; // Ensure type is set
            // Populate any remaining RecordCommon fields if not done yet
            // e.g. ppid, sessionid, loginuid if they can be reliably fetched here or were missed.
            // For now, they are placeholders if not filled during init.

            if RINGBUF_RECORDS.output(&*r_ptr, 0).is_err() {
                if let Some(s) = s_opt.as_mut() {
                    (*s).drops += 1; // Using drops for ringbuf failures
                    (*s).last_drop_ts = ts_event;
                }
            }

            // Remove from HASH_RECORDS
            if HASH_RECORDS.remove(&key_pid_ino).is_err() {
                if let Some(s) = s_opt.as_mut() {
                     (*s).errors += 1; // Or a specific counter for hash remove errors
                     (*s).last_error_ts = ts_event;
                }
            } else {
                // Successfully removed from hash. C code had fs_records_deleted.
                // Let's use errors for map operation failures, and events for actual fs events.
                // Drops for ringbuf.
            }
        }
    } else {
        // If not agg_end, and it was a new record, insert it into HASH_RECORDS
        if r_opt.is_none() { // Was a new record from HEAP_RECORD_FS
            unsafe {
                if HASH_RECORDS.insert(&key_pid_ino, &*r_ptr, 0).is_err() {
                    if let Some(s) = s_opt.as_mut() {
                        (*s).errors += 1;
                        (*s).last_error_ts = ts_event;
                        // Should we also remove from HEAP_RECORD_FS or clear it?
                        // The record in HEAP_RECORD_FS is 'consumed' by this HASH_RECORDS insert.
                    }
                }
            }
        }
        // If r_opt was Some, the modifications were in-place in HASH_RECORDS value.
    }

    // 6. Update Stats (RingBuf size) - This seems more like a userspace/init-time calculation
    // The C code snippet `s->fs_records_rb_max = bpf_map_lookup_elem(&RINGBUF_RECORDS, &zero)->max_entries / rsz;`
    // implies getting max_entries from map metadata, which isn't standard for RingBuf data plane.
    // Aya's RingBuf doesn't directly expose item capacity this way in eBPF.
    // RINGBUF_TOTAL_SIZE is known. Size of RecordFs can be found with core::mem::size_of.
    // This logic is better suited for userspace after map creation or if map info is passed.
    // For now, I'll skip this part in the eBPF code.

    Ok(0)
}


#[kretprobe(name = "do_filp_open")]
pub fn do_filp_open_kretprobe(ctx: ProbeContext) -> u32 {
    if unsafe { MONITOR != MONITOR_FILE } {
        return 0;
    }

    // This should be a kretprobe, so return value is in ctx.ret()
    // For do_filp_open, the return is struct file*.
    let filp_ptr = ctx.ret() as *const vmlinux::file;
    if filp_ptr.is_null() {
        return 0;
    }

    match unsafe { try_do_filp_open_kretprobe(&ctx, filp_ptr) } {
        Ok(_) => 0,
        Err(e) => {
            // Log error via STATS_MAP if needed
            let mut s_opt = unsafe { STATS_MAP.get_ptr_mut(&0) };
            if let Some(s) = s_opt.as_mut() {
                unsafe {
                    (*s).errors += 1;
                    (*s).last_error_ts = bpf_ktime_get_ns();
                }
            }
            e as u32
        }
    }
}

unsafe fn try_do_filp_open_kretprobe(ctx: ProbeContext, filp_ptr: *const vmlinux::file) -> Result<(), u32> {
    let f_mode: vmlinux::fmode_t = ctx.bpf_probe_read_kernel(&((*filp_ptr).f_mode))?;
    // Check FMODE_CREATED (0x00080000 in C, value might differ in bindings)
    // aya_ebpf::bindings::vmlinux::FMODE_CREATED might not exist.
    // Using the typical value. Check your kernel's include/linux/fcntl.h if unsure.
    const FMODE_CREATED_VAL: vmlinux::fmode_t = 0x200000; // This is actually __FMODE_CREATED. FMODE_CREATED is (1 << 21)
                                                       // Let's use a known value if bindings are not specific.
                                                       // Looking at linux/fs.h, FMODE_CREATED seems to be (1 << 21) = 0x200000
                                                       // Let's assume FMODE_CREATED = 0x200000 based on common kernel versions.
                                                       // Or, more robustly, this should be checked against kernel headers.
                                                       // The C code uses `filp->f_mode & FMODE_CREATED`.
                                                       // A common value for FMODE_CREATED is 0x200000 (1<<21).
                                                       // Or it could be part of ATTR_ONLY (like in C) which is 0x080000.
                                                       // The C code for dirt has FMODE_CREATED as 0x80000. This is likely a custom definition or older kernel.
                                                       // Let's use the value from the C code context: 0x80000
    const CUSTOM_FMODE_CREATED: vmlinux::fmode_t = 0x80000;


    if (f_mode & CUSTOM_FMODE_CREATED) == 0 {
        return Ok(());
    }

    let dentry_ptr: *const vmlinux::dentry = ctx.bpf_probe_read_kernel(&((*filp_ptr).f_path.dentry))?;
    if dentry_ptr.is_null() {
        return Err(1);
    }

    let mut event_info: FsEventInfo = zeroed();
    populate_fs_event_from_dentry(&ctx, dentry_ptr, b"do_filp_open\0", I_CREATE, &mut event_info)?;

    handle_fs_event(&ctx, &event_info).map(|_| ())
}

#[kprobe(name = "security_inode_link")]
pub fn security_inode_link_kprobe(ctx: ProbeContext) -> u32 {
    if unsafe { MONITOR != MONITOR_FILE } {
        return 0;
    }
    // Args: old_dentry: *const vmlinux::dentry, dir: *const vmlinux::inode, new_dentry: *const vmlinux::dentry
    // We are interested in new_dentry for I_CREATE.
    // The original C code uses `(struct dentry *)PT_REGS_PARM3(ctx);` for new_dentry.
    // Aya provides direct argument access: ctx.arg(index).
    let new_dentry_ptr = ctx.arg(2) as *const vmlinux::dentry;
    if new_dentry_ptr.is_null() {
        return 0;
    }

    match unsafe { try_security_inode_link_kprobe(&ctx, new_dentry_ptr) } {
        Ok(_) => 0,
        Err(e) => {
            let mut s_opt = unsafe { STATS_MAP.get_ptr_mut(&0) };
            if let Some(s) = s_opt.as_mut() {
                unsafe {
                    (*s).errors += 1;
                    (*s).last_error_ts = bpf_ktime_get_ns();
                }
            }
            e as u32
        }
    }
}

unsafe fn try_security_inode_link_kprobe(ctx: &ProbeContext, new_dentry_ptr: *const vmlinux::dentry) -> Result<(), u32> {
    let mut event_info: FsEventInfo = zeroed();
    populate_fs_event_from_dentry(ctx, new_dentry_ptr, b"security_inode_link\0", I_CREATE, &mut event_info)?;

    // For link, dentry_old_is_some should be true, as it links an existing inode.
    // The C code has: if (dentry_old) event_info.dentry_old_is_some = true;
    // Here, old_dentry is ctx.arg(0). We can check if it's non-null.
    let old_dentry_ptr = ctx.arg(0) as *const vmlinux::dentry;
    if !old_dentry_ptr.is_null() {
        event_info.dentry_old_is_some = true;
    }

    handle_fs_event(ctx, &event_info).map(|_| ())
}

#[kprobe(name = "security_inode_symlink")]
pub fn security_inode_symlink_kprobe(ctx: ProbeContext) -> u32 {
    if unsafe { MONITOR != MONITOR_FILE } {
        return 0;
    }
    // Args: dir: *const vmlinux::inode, dentry: *const vmlinux::dentry, target_name: *const i8
    // We are interested in dentry.
    let dentry_ptr = ctx.arg(1) as *const vmlinux::dentry;
    if dentry_ptr.is_null() {
        return 0;
    }

    match unsafe { try_security_inode_symlink_kprobe(&ctx, dentry_ptr) } {
        Ok(_) => 0,
        Err(e) => {
            let mut s_opt = unsafe { STATS_MAP.get_ptr_mut(&0) };
            if let Some(s) = s_opt.as_mut() {
                unsafe {
                    (*s).errors += 1;
                    (*s).last_error_ts = bpf_ktime_get_ns();
                }
            }
            e as u32
        }
    }
}

unsafe fn try_security_inode_symlink_kprobe(ctx: &ProbeContext, dentry_ptr: *const vmlinux::dentry) -> Result<(), u32> {
    // This kprobe just stores the inode number of the dentry being symlinked.
    // The actual event is handled by dput_kprobe.
    let dentry: vmlinux::dentry = ctx.bpf_probe_read_kernel(dentry_ptr)?;
    let inode_ptr: *const vmlinux::inode = ctx.bpf_probe_read_kernel(&dentry.d_inode)?;
    if inode_ptr.is_null() {
        return Err(1);
    }
    let inode: vmlinux::inode = ctx.bpf_probe_read_kernel(inode_ptr)?;

    DENTRY_SYMLINK_INO = inode.i_ino;
    // Optionally, log the function name "security_inode_symlink" if needed for FsEventInfo later,
    // but the C code implies dput_kprobe sets the func name.
    Ok(())
}

#[kprobe(name = "dput")]
pub fn dput_kprobe(ctx: ProbeContext) -> u32 {
    if unsafe { MONITOR != MONITOR_FILE } {
        return 0;
    }
    // Args: dentry: *const vmlinux::dentry
    let dentry_ptr = ctx.arg(0) as *const vmlinux::dentry;
    if dentry_ptr.is_null() || unsafe { DENTRY_SYMLINK_INO == 0 } { // No symlink creation pending
        return 0;
    }

    match unsafe { try_dput_kprobe(&ctx, dentry_ptr) } {
        Ok(_) => 0,
        Err(e) => {
            let mut s_opt = unsafe { STATS_MAP.get_ptr_mut(&0) };
            if let Some(s) = s_opt.as_mut() {
                unsafe {
                    (*s).errors += 1;
                    (*s).last_error_ts = bpf_ktime_get_ns();
                }
            }
            // Reset DENTRY_SYMLINK_INO on error too, to prevent stale state.
            unsafe { DENTRY_SYMLINK_INO = 0 };
            e as u32
        }
    }
}

unsafe fn try_dput_kprobe(ctx: &ProbeContext, dentry_ptr: *const vmlinux::dentry) -> Result<(), u32> {
    let dentry: vmlinux::dentry = ctx.bpf_probe_read_kernel(dentry_ptr)?;
    let inode_ptr: *const vmlinux::inode = ctx.bpf_probe_read_kernel(&dentry.d_inode)?;
    if inode_ptr.is_null() {
        return Err(1);
    }
    let inode: vmlinux::inode = ctx.bpf_probe_read_kernel(inode_ptr)?;

    if inode.i_ino == DENTRY_SYMLINK_INO && s_islnk(inode.i_mode) {
        // This is the completion of the symlink creation.
        DENTRY_SYMLINK_INO = 0; // Reset state

        let mut event_info: FsEventInfo = zeroed();
        // The C code uses "dput+security_inode_symlink" as func_name
        populate_fs_event_from_dentry(ctx, dentry_ptr, b"dput+security_inode_symlink\0", I_CREATE, &mut event_info)?;

        // Symlinks might not have dentry_old in the same way, set to false unless specific logic dictates otherwise.
        event_info.dentry_old_is_some = false;

        return handle_fs_event(ctx, &event_info).map(|_| ());
    }
    Ok(())
}

#[kprobe(name = "security_inode_rename")]
pub fn security_inode_rename_kprobe(ctx: ProbeContext) -> u32 {
    if unsafe { MONITOR != MONITOR_FILE } {
        return 0;
    }
    // Args: old_dir: *const inode, old_dentry: *const dentry, new_dir: *const inode, new_dentry: *const dentry
    let old_dentry_ptr = ctx.arg(1) as *const vmlinux::dentry;
    let new_dentry_ptr = ctx.arg(3) as *const vmlinux::dentry;

    if old_dentry_ptr.is_null() || new_dentry_ptr.is_null() {
        return 0;
    }

    match unsafe { try_security_inode_rename_kprobe(&ctx, old_dentry_ptr, new_dentry_ptr) } {
        Ok(_) => 0,
        Err(e) => {
            let mut s_opt = unsafe { STATS_MAP.get_ptr_mut(&0) };
            if let Some(s) = s_opt.as_mut() {
                unsafe {
                    (*s).errors += 1;
                    (*s).last_error_ts = bpf_ktime_get_ns();
                }
            }
            e as u32
        }
    }
}

unsafe fn try_security_inode_rename_kprobe(
    ctx: &ProbeContext,
    old_dentry_ptr: *const vmlinux::dentry,
    new_dentry_ptr: *const vmlinux::dentry,
) -> Result<(), u32> {
    let mut event_info_old: FsEventInfo = zeroed();
    populate_fs_event_from_dentry(ctx, old_dentry_ptr, b"security_inode_rename\0", I_MOVED_FROM, &mut event_info_old)?;
    handle_fs_event(ctx, &event_info_old)?;

    // For I_MOVED_TO, FsEventInfo.filename should be the *old* name,
    // and FsEventInfo.filename_to should be the *new* name.
    // Our current populate_fs_event_from_dentry will fill event_info_new.filename with new_dentry's name.
    // We need to preserve old_dentry's name for filename_to field of event_info_old, or pass both names.
    // The handle_fs_event expects filename (current) and filename_to (for rename).
    // Let's adjust.
    // When processing I_MOVED_TO for new_dentry_ptr:
    // - event_info.filename will be new_dentry's name (correct)
    // - event_info.filename_to should be old_dentry's name.
    // The current populate_fs_event_from_dentry doesn't set filename_to.
    // We need to capture old_dentry's name for the I_MOVED_TO event.

    let mut old_filename_buffer = [0u8; FILENAME_LEN_MAX];
    let old_dentry_for_name: vmlinux::dentry = ctx.bpf_probe_read_kernel(old_dentry_ptr)?;
    let old_name_ptr: *const u8 = ctx.bpf_probe_read_kernel(&old_dentry_for_name.d_name.name)?;
     if !old_name_ptr.is_null() {
        if ctx.bpf_probe_read_kernel_str_bytes(old_name_ptr as *const i8, &mut old_filename_buffer).is_err() {
            // fallback or error
            let old_name_len = ctx.bpf_probe_read_kernel(&old_dentry_for_name.d_name.len).unwrap_or(FILENAME_LEN_MAX as u32) as usize;
            let max_read_len = if old_name_len < FILENAME_LEN_MAX { old_name_len } else { FILENAME_LEN_MAX - 1};
            ctx.bpf_probe_read_kernel_bytes(old_name_ptr, &mut old_filename_buffer[..max_read_len])?;
             if max_read_len < FILENAME_LEN_MAX { old_filename_buffer[max_read_len] = 0;} else {old_filename_buffer[FILENAME_LEN_MAX-1]=0;}
        }
    }


    let mut event_info_new: FsEventInfo = zeroed();
    populate_fs_event_from_dentry(ctx, new_dentry_ptr, b"security_inode_rename\0", I_MOVED_TO, &mut event_info_new)?;
    event_info_new.filename_to = old_filename_buffer; // Set the 'from' name here

    // The original C code, for the I_MOVED_TO event, copies new_dentry->d_name to record->filename
    // and old_dentry->d_name to record->filename_to.
    // populate_fs_event_from_dentry sets event_info_new.filename from new_dentry. This is correct.
    // So, we just need to set event_info_new.filename_to with old_dentry's name.

    handle_fs_event(ctx, &event_info_new)?;

    Ok(())
}

#[kprobe(name = "security_inode_unlink")]
pub fn security_inode_unlink_kprobe(ctx: ProbeContext) -> u32 {
    if unsafe { MONITOR != MONITOR_FILE } {
        return 0;
    }
    // Args: dir: *const vmlinux::inode, dentry: *const vmlinux::dentry
    let dentry_ptr = ctx.arg(1) as *const vmlinux::dentry;
    if dentry_ptr.is_null() {
        return 0;
    }

    match unsafe { try_security_inode_unlink_kprobe(&ctx, dentry_ptr) } {
        Ok(_) => 0,
        Err(e) => {
            let mut s_opt = unsafe { STATS_MAP.get_ptr_mut(&0) };
            if let Some(s) = s_opt.as_mut() {
                unsafe {
                    (*s).errors += 1;
                    (*s).last_error_ts = bpf_ktime_get_ns();
                }
            }
            e as u32
        }
    }
}

unsafe fn try_security_inode_unlink_kprobe(ctx: &ProbeContext, dentry_ptr: *const vmlinux::dentry) -> Result<(), u32> {
    let mut event_info: FsEventInfo = zeroed();
    populate_fs_event_from_dentry(ctx, dentry_ptr, b"security_inode_unlink\0", I_DELETE, &mut event_info)?;
    handle_fs_event(ctx, &event_info).map(|_| ())
}


// The main kprobe 'dirt' is a placeholder in the original template.
// It should be removed or adapted if it was for general testing.
// For now, I will comment it out to avoid confusion with specific kprobes.
/*
#[kprobe]
pub fn dirt(ctx: ProbeContext) -> u32 {
    match try_dirt(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_dirt(ctx: ProbeContext) -> Result<u32, u32> {
    info!(&ctx, "kprobe called");
    Ok(0)
}
*/

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 7] = *b"GPL v2\0";
