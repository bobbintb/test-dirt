#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::vmlinux,
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel, bpf_probe_read_kernel_str_bytes, bpf_probe_read_kernel_bytes},
    macros::{kprobe, kretprobe, map},
    maps::{Array, LruHashMap, PerCpuArray, RingBuf},
    programs::ProbeContext,
};
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
// Using core::mem::size_of for RecordFs directly.
const RINGBUF_TOTAL_SIZE: u32 = (core::mem::size_of::<RecordFs>() * 8192) as u32;


#[map]
static mut RINGBUF_RECORDS: RingBuf = RingBuf::with_byte_size(RINGBUF_TOTAL_SIZE, 0);

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
        let dentry: vmlinux::dentry = aya_ebpf::helpers::bpf_probe_read_kernel(dentry_ptr).map_err(|e| e as u32)?;
        let inode_ptr: *const vmlinux::inode = aya_ebpf::helpers::bpf_probe_read_kernel(&dentry.d_inode).map_err(|e| e as u32)?;
        if inode_ptr.is_null() {
            return Err(1); // No inode associated
        }
        let inode: vmlinux::inode = aya_ebpf::helpers::bpf_probe_read_kernel(inode_ptr).map_err(|e| e as u32)?;

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
        let name_ptr: *const u8 = aya_ebpf::helpers::bpf_probe_read_kernel(&dentry.d_name.name).map_err(|e| e as u32)?;
        if !name_ptr.is_null() {
            // Determine length of name, d_name.len might be available
            let name_len = aya_ebpf::helpers::bpf_probe_read_kernel(&dentry.d_name.len).unwrap_or(FILENAME_LEN_MAX as u32) as usize;
            let max_read_len = if name_len < FILENAME_LEN_MAX { name_len } else { FILENAME_LEN_MAX - 1};

            // bpf_probe_read_kernel_str_bytes is safer for null terminated strings
            // but d_name.name is not guaranteed to be short enough for its fixed buffer.
            // Reading byte by byte or using bpf_probe_read_kernel with calculated length.
            let mut name_buffer = [0u8; FILENAME_LEN_MAX];
            if aya_ebpf::helpers::bpf_probe_read_kernel_str_bytes(name_ptr as *const i8, &mut name_buffer).is_ok() {
                 event_info.filename = name_buffer;
            } else {
                // Fallback or error if string read fails
                // For now, just try a direct read up to max_read_len
                let mut temp_name_buf = [0u8; FILENAME_LEN_MAX];
                if aya_ebpf::helpers::bpf_probe_read_kernel_bytes(name_ptr, &mut temp_name_buf[..max_read_len]).is_ok() {
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
        // Use copy_byte_slice_to_array for safety, assuming filename is already populated and null-terminated.
        copy_byte_slice_to_array(&mut event_info.filepath, &event_info.filename);


        // dentry_old_is_some needs to be set by caller if applicable
    }
    Ok(())
}

#[kprobe]
pub fn notify_change(ctx: ProbeContext) -> u32 {
    if unsafe { MONITOR != MONITOR_FILE } {
        return 0;
    }
    // Args: dentry: *const vmlinux::dentry, attr: *const vmlinux::iattr, ...
    let dentry_ptr = ctx.arg(0) as *const vmlinux::dentry;
    let attr_ptr = ctx.arg(1) as *const vmlinux::iattr;

    if dentry_ptr.is_null() || attr_ptr.is_null() {
        return 0;
    }

    match unsafe { try_notify_change(&ctx, dentry_ptr, attr_ptr) } {
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

unsafe fn try_notify_change(ctx: &ProbeContext, dentry_ptr: *const vmlinux::dentry, attr_ptr: *const vmlinux::iattr) -> Result<(), u32> {
    let attr: vmlinux::iattr = aya_ebpf::helpers::bpf_probe_read_kernel(attr_ptr)?;
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
            event_info.isize_current = aya_ebpf::helpers::bpf_probe_read_kernel(&attr.ia_size)?;
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
             event_info.isize_current = aya_ebpf::helpers::bpf_probe_read_kernel(&attr.ia_size)?;
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

#[kprobe]
pub fn __fsnotify_parent(ctx: ProbeContext) -> u32 {
    if unsafe { MONITOR != MONITOR_FILE } {
        return 0;
    }
    // Args: dentry: *const vmlinux::dentry, mask: u32
    let dentry_ptr = ctx.arg(0) as *const vmlinux::dentry;
    let mask = ctx.arg(1) as u32;

    if dentry_ptr.is_null() {
        return 0;
    }

    match unsafe { try___fsnotify_parent(&ctx, dentry_ptr, mask) } {
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

unsafe fn try___fsnotify_parent(ctx: &ProbeContext, dentry_ptr: *const vmlinux::dentry, mask: u32) -> Result<(), u32> {
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

    let mut s_opt = unsafe { STATS_MAP.get_ptr_mut(0) }; // Corrected: &0 to 0

    // Get a mutable pointer to a RecordFs from the heap array.
    // This will serve as temporary storage if we create a new record,
    // or as a place to copy an existing record for modification.
    let r_heap_ptr = match unsafe { HEAP_RECORD_FS.get_ptr_mut(0) } {
        Some(ptr) => ptr,
        None => {
            if let Some(s_ref) = s_opt.as_mut() {
                let s = unsafe { &mut **s_ref };
                s.errors += 1;
                s.last_error_ts = ts_event;
            }
            return Err(1); // Cannot get temp storage
        }
    };
    let r_mut_from_heap: &mut RecordFs = unsafe { &mut *r_heap_ptr };

    let mut agg_end = false;

    // Decide if we are updating an existing record or creating a new one.
    // The `current_record_data` will hold the data we operate on.
    // It's either a copy of an existing record, or we use `r_mut_from_heap` directly for a new one.
    let mut current_record_data: RecordFs = match unsafe { HASH_RECORDS.get(&key_pid_ino) } {
        Some(existing_r_ref) => { // existing_r_ref is &RecordFs from HASH_RECORDS
            let mut record_copy = *existing_r_ref; // Make a mutable copy

            // Update the copy
            if event.idx == I_MOVED_TO {
                record_copy.filename_to = event.filename_to;
            }
            record_copy.rc.pid = pid;
            record_copy.time_ns = ts_event;
            // boot_time_ns was removed

            record_copy.mode = event.imode; // event.imode contains the mode
            record_copy.size = event.isize_current;
            record_copy.nlink = event.nlink;
            record_copy.atime = event.atime_ns;
            record_copy.mtime = event.mtime_ns;
            record_copy.ctime = event.ctime_ns;

            record_copy.events += 1;
            if (event.idx as usize) < FS_EVENT_MAX {
                record_copy.event[event.idx as usize] += 1;
            }
            record_copy // This copy will be used
        }
        None => { // No existing record, initialize `r_mut_from_heap`
            // Initialize RecordCommon part of RecordFs
            r_mut_from_heap.rc.record_type = RECORD_TYPE_FILE;
            r_mut_from_heap.rc.pid = pid;
            let comm = unsafe { aya_ebpf::helpers::bpf_get_current_comm().unwrap_or_default() };
            r_mut_from_heap.rc.comm = comm;
            r_mut_from_heap.rc.ppid = 0;
            let uid_gid = unsafe { aya_ebpf::helpers::bpf_get_current_uid_gid() };
            r_mut_from_heap.rc.uid = (uid_gid & 0xFFFFFFFF) as u32;
            r_mut_from_heap.rc.gid = (uid_gid >> 32) as u32;
            r_mut_from_heap.rc.tgid = (pid_tgid & 0xFFFFFFFF) as u32;
            r_mut_from_heap.rc.sessionid = 0;
            r_mut_from_heap.rc.loginuid = 0;

            // Initialize RecordFs specific fields
            r_mut_from_heap.time_ns = ts_event;
            // boot_time_ns was removed
            r_mut_from_heap.ino = inode_nr;
            r_mut_from_heap.filename = event.filename;
            r_mut_from_heap.filename_to = [0u8; FILENAME_LEN_MAX];
            if event.idx == I_MOVED_TO {
                r_mut_from_heap.filename_to = event.filename_to;
            }
            // filepath is populated by populate_fs_event_from_dentry, ensure it's copied
            r_mut_from_heap.filepath = event.filepath;

            r_mut_from_heap.events = 1;
            r_mut_from_heap.event = [0u32; FS_EVENT_MAX];
            if (event.idx as usize) < FS_EVENT_MAX {
                 r_mut_from_heap.event[event.idx as usize] = 1;
            }

            r_mut_from_heap.atime = event.atime_ns;
            r_mut_from_heap.mtime = event.mtime_ns;
            r_mut_from_heap.ctime = event.ctime_ns;
            r_mut_from_heap.dev = 0;
            r_mut_from_heap.mode = event.imode; // event.imode contains the mode
            r_mut_from_heap.size = event.isize_current;
            r_mut_from_heap.nlink = event.nlink;

            if let Some(s_ref) = s_opt.as_mut() {
                 let s = unsafe { &mut **s_ref };
                 s.events += 1;
                 s.last_event_ts = ts_event;
            }
            *r_mut_from_heap // Use the initialized heap record's data
        }
    };

    // `current_record_data` holds the state of the record we are processing.
    // It's either a copy of an existing one (that was updated) or a new one (initialized from heap).

    if event.idx == I_CREATE && event.dentry_old_is_some {
        current_record_data.nlink += 1;
    }

    // 5. Aggregation Logic
    let agg_events_max = unsafe { AGG_EVENTS_MAX };
    if current_record_data.events >= agg_events_max ||
       event.idx == I_DELETE || event.idx == I_MOVED_FROM || event.idx == I_MOVED_TO {
        agg_end = true;
    }

    if agg_end {
        current_record_data.rc.record_type = RECORD_TYPE_FILE;

        if unsafe { RINGBUF_RECORDS.output(&current_record_data, 0) }.is_err() {
            if let Some(s_ref) = s_opt.as_mut() {
                let s = unsafe { &mut **s_ref };
                s.drops += 1;
                s.last_drop_ts = ts_event;
            }
        }

        // Remove from HASH_RECORDS whether it was an existing entry or a new one that became agg_end immediately
        if unsafe { HASH_RECORDS.remove(&key_pid_ino) }.is_err() {
            // This error might occur if the entry was new and never inserted, then agg_end=true.
            // Or if it was an existing entry.
            // Consider if this error should be logged only if an entry was *expected* to be there.
            // For now, log all remove errors.
            if let Some(s_ref) = s_opt.as_mut() {
                 let s = unsafe { &mut **s_ref };
                 s.errors += 1;
                 s.last_error_ts = ts_event;
            }
        }
    } else {
        // If not agg_end, insert/re-insert the current_record_data into HASH_RECORDS
        if unsafe { HASH_RECORDS.insert(&key_pid_ino, &current_record_data, 0) }.is_err() {
            if let Some(s_ref) = s_opt.as_mut() {
                let s = unsafe { &mut **s_ref };
                s.errors += 1;
                s.last_error_ts = ts_event;
            }
        }
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


#[kretprobe]
pub fn do_filp_open(ctx: ProbeContext) -> u32 {
    if unsafe { MONITOR != MONITOR_FILE } {
        return 0;
    }

    // This should be a kretprobe, so return value is in ctx.ret()
    // For do_filp_open, the return is struct file*.
    let filp_ptr = ctx.ret() as *const vmlinux::file;
    if filp_ptr.is_null() {
        return 0;
    }

    match unsafe { try_do_filp_open(&ctx, filp_ptr) } {
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

unsafe fn try_do_filp_open(ctx: ProbeContext, filp_ptr: *const vmlinux::file) -> Result<(), u32> {
    let f_mode: vmlinux::fmode_t = aya_ebpf::helpers::bpf_probe_read_kernel(&((*filp_ptr).f_mode))?;
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

    let dentry_ptr: *const vmlinux::dentry = aya_ebpf::helpers::bpf_probe_read_kernel(&((*filp_ptr).f_path.dentry))?;
    if dentry_ptr.is_null() {
        return Err(1);
    }

    let mut event_info: FsEventInfo = zeroed();
    populate_fs_event_from_dentry(&ctx, dentry_ptr, b"do_filp_open\0", I_CREATE, &mut event_info)?;

    handle_fs_event(&ctx, &event_info).map(|_| ())
}

#[kprobe]
pub fn security_inode_link(ctx: ProbeContext) -> u32 {
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

    match unsafe { try_security_inode_link(&ctx, new_dentry_ptr) } {
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

unsafe fn try_security_inode_link(ctx: &ProbeContext, new_dentry_ptr: *const vmlinux::dentry) -> Result<(), u32> {
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

#[kprobe]
pub fn security_inode_symlink(ctx: ProbeContext) -> u32 {
    if unsafe { MONITOR != MONITOR_FILE } {
        return 0;
    }
    // Args: dir: *const vmlinux::inode, dentry: *const vmlinux::dentry, target_name: *const i8
    // We are interested in dentry.
    let dentry_ptr = ctx.arg(1) as *const vmlinux::dentry;
    if dentry_ptr.is_null() {
        return 0;
    }

    match unsafe { try_security_inode_symlink(&ctx, dentry_ptr) } {
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

unsafe fn try_security_inode_symlink(ctx: &ProbeContext, dentry_ptr: *const vmlinux::dentry) -> Result<(), u32> {
    // This kprobe just stores the inode number of the dentry being symlinked.
    // The actual event is handled by dput_kprobe.
    let dentry: vmlinux::dentry = aya_ebpf::helpers::bpf_probe_read_kernel(dentry_ptr)?;
    let inode_ptr: *const vmlinux::inode = aya_ebpf::helpers::bpf_probe_read_kernel(&dentry.d_inode)?;
    if inode_ptr.is_null() {
        return Err(1);
    }
    let inode: vmlinux::inode = aya_ebpf::helpers::bpf_probe_read_kernel(inode_ptr)?;

    DENTRY_SYMLINK_INO = inode.i_ino;
    // Optionally, log the function name "security_inode_symlink" if needed for FsEventInfo later,
    // but the C code implies dput_kprobe sets the func name.
    Ok(())
}

#[kprobe]
pub fn dput(ctx: ProbeContext) -> u32 {
    if unsafe { MONITOR != MONITOR_FILE } {
        return 0;
    }
    // Args: dentry: *const vmlinux::dentry
    let dentry_ptr = ctx.arg(0) as *const vmlinux::dentry;
    if dentry_ptr.is_null() || unsafe { DENTRY_SYMLINK_INO == 0 } { // No symlink creation pending
        return 0;
    }

    match unsafe { try_dput(&ctx, dentry_ptr) } {
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

unsafe fn try_dput(ctx: &ProbeContext, dentry_ptr: *const vmlinux::dentry) -> Result<(), u32> {
    let dentry: vmlinux::dentry = aya_ebpf::helpers::bpf_probe_read_kernel(dentry_ptr)?;
    let inode_ptr: *const vmlinux::inode = aya_ebpf::helpers::bpf_probe_read_kernel(&dentry.d_inode)?;
    if inode_ptr.is_null() {
        return Err(1);
    }
    let inode: vmlinux::inode = aya_ebpf::helpers::bpf_probe_read_kernel(inode_ptr)?;

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

#[kprobe]
pub fn security_inode_rename(ctx: ProbeContext) -> u32 {
    if unsafe { MONITOR != MONITOR_FILE } {
        return 0;
    }
    // Args: old_dir: *const inode, old_dentry: *const dentry, new_dir: *const inode, new_dentry: *const dentry
    let old_dentry_ptr = ctx.arg(1) as *const vmlinux::dentry;
    let new_dentry_ptr = ctx.arg(3) as *const vmlinux::dentry;

    if old_dentry_ptr.is_null() || new_dentry_ptr.is_null() {
        return 0;
    }

    match unsafe { try_security_inode_rename(&ctx, old_dentry_ptr, new_dentry_ptr) } {
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

unsafe fn try_security_inode_rename(
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
    let old_dentry_for_name: vmlinux::dentry = aya_ebpf::helpers::bpf_probe_read_kernel(old_dentry_ptr)?;
    let old_name_ptr: *const u8 = aya_ebpf::helpers::bpf_probe_read_kernel(&old_dentry_for_name.d_name.name)?;
     if !old_name_ptr.is_null() {
        if aya_ebpf::helpers::bpf_probe_read_kernel_str_bytes(old_name_ptr as *const i8, &mut old_filename_buffer).is_err() {
            // fallback or error
            let old_name_len = aya_ebpf::helpers::bpf_probe_read_kernel(&old_dentry_for_name.d_name.len).unwrap_or(FILENAME_LEN_MAX as u32) as usize;
            let max_read_len = if old_name_len < FILENAME_LEN_MAX { old_name_len } else { FILENAME_LEN_MAX - 1};
            aya_ebpf::helpers::bpf_probe_read_kernel_bytes(old_name_ptr, &mut old_filename_buffer[..max_read_len])?;
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

#[kprobe]
pub fn security_inode_unlink(ctx: ProbeContext) -> u32 {
    if unsafe { MONITOR != MONITOR_FILE } {
        return 0;
    }
    // Args: dir: *const vmlinux::inode, dentry: *const vmlinux::dentry
    let dentry_ptr = ctx.arg(1) as *const vmlinux::dentry;
    if dentry_ptr.is_null() {
        return 0;
    }

    match unsafe { try_security_inode_unlink(&ctx, dentry_ptr) } {
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

unsafe fn try_security_inode_unlink(ctx: &ProbeContext, dentry_ptr: *const vmlinux::dentry) -> Result<(), u32> {
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
