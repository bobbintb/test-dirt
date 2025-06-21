#![no_std]
#![no_main]

use core::mem;
use aya_ebpf::{
    macros::{kprobe, map},
    programs::ProbeContext,
    maps::{HashMap, Array, RingBuf},
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns},
    btf::helpers::bpf_core_read,
    BpfContext, AyaEbpfError,
};
use aya_log_ebpf::info;
use dirt_common::{
    Record, RecordFs, RECORD_TYPE_FILE, FILEPATH_LEN_MAX, FILENAME_LEN_MAX, FS_EVENT_MAX,
    FsEventIndex, S_IFREG, S_IFLNK, S_IFDIR, S_IFMT, // Ensure these are pub in dirt_common
};

// Constants for f_mode in struct file (values might vary based on kernel version)
// These are illustrative. Actual values should be verified from kernel sources (e.g., include/linux/fcntl.h)
// FMODE_READ and FMODE_WRITE are typically defined as 1 and 2 respectively.
const FMODE_READ: u32 = 0x1;
const FMODE_WRITE: u32 = 0x2;

#[map]
static mut EVENTS: RingBuf = RingBuf::with_byte_size(1_048_576, 0); // 1MB
#[map]
static mut AGG_RECORDS: HashMap<u64, RecordFs> = HashMap::with_max_entries(10240, 0);
#[map]
static mut AGG_EVENTS_MAX_MAP: Array<u32> = Array::with_max_entries(1, 0);


fn get_agg_events_max(ctx: &ProbeContext) -> u32 {
    // Reading from Array map. This map should be initialized by userspace.
    // Index 0 is used to store the agg_events_max value.
    let agg_max_ptr = unsafe { AGG_EVENTS_MAX_MAP.get_ptr(0) };
    if let Some(ptr) = agg_max_ptr {
        let value = unsafe { core::ptr::read_volatile(ptr) };
        if value == 0 { 1 } else { value } // Treat 0 as 1 (effectively no aggregation beyond single event)
    } else {
        info!(ctx, "Failed to read AGG_EVENTS_MAX_MAP, defaulting to 1");
        1 // Default to 1 (no aggregation) if map read fails
    }
}

fn populate_inode_data(ctx: &ProbeContext, inode_ptr: u64, record_fs: &mut RecordFs) -> Result<(), u32> {
    if inode_ptr == 0 {
        info!(ctx, "populate_inode_data: inode_ptr is null");
        return Ok(());
    }
    // Read basic inode fields
    record_fs.ino = unsafe { bpf_core_read!(ctx, inode_ptr as *const core::ffi::c_void, "i_ino").map_err(|e| e as u32)? };
    let i_mode_val: u16 = unsafe { bpf_core_read!(ctx, inode_ptr as *const core::ffi::c_void, "i_mode").map_err(|e| e as u32)? };
    record_fs.imode = i_mode_val as u32;
    record_fs.inlink = unsafe { bpf_core_read!(ctx, inode_ptr as *const core::ffi::c_void, "i_nlink").map_err(|e| e as u32)? };
    record_fs.isize = unsafe { bpf_core_read!(ctx, inode_ptr as *const core::ffi::c_void, "i_size").map_err(|e| e as u32)? };

    // Read timespec fields for atime, mtime, ctime
    // Example: record_fs.atime_nsec = read_timespec_nsec(ctx, inode_ptr, "i_atime")?;
    // For brevity, direct core_read for tv_sec and tv_nsec.
    record_fs.atime_nsec = unsafe { bpf_core_read!(ctx, inode_ptr as *const core::ffi::c_void, "i_atime.tv_sec").map_err(|e| e as u32)? } * 1_000_000_000 +
                           unsafe { bpf_core_read!(ctx, inode_ptr as *const core::ffi::c_void, "i_atime.tv_nsec").map_err(|e| e as u32)? };
    record_fs.mtime_nsec = unsafe { bpf_core_read!(ctx, inode_ptr as *const core::ffi::c_void, "i_mtime.tv_sec").map_err(|e| e as u32)? } * 1_000_000_000 +
                           unsafe { bpf_core_read!(ctx, inode_ptr as *const core::ffi::c_void, "i_mtime.tv_nsec").map_err(|e| e as u32)? };
    record_fs.ctime_nsec = unsafe { bpf_core_read!(ctx, inode_ptr as *const core::ffi::c_void, "i_ctime.tv_sec").map_err(|e| e as u32)? } * 1_000_000_000 +
                           unsafe { bpf_core_read!(ctx, inode_ptr as *const core::ffi::c_void, "i_ctime.tv_nsec").map_err(|e| e as u32)? };
    Ok(())
}

fn get_file_name_from_dentry(ctx: &ProbeContext, dentry_ptr: u64) -> Result<[u8; FILENAME_LEN_MAX], u32> {
    let mut file_name_buf = [0u8; FILENAME_LEN_MAX];
    if dentry_ptr == 0 { return Err(1); }

    let name_ptr_val = unsafe { bpf_core_read!(ctx, dentry_ptr as *const core::ffi::c_void, "d_name.name") };
    let name_ptr: u64 = name_ptr_val.map_err(|e| e as u32)?;

    let name_len_val = unsafe { bpf_core_read!(ctx, dentry_ptr as *const core::ffi::c_void, "d_name.len") };
    let name_len: u32 = name_len_val.map_err(|e| e as u32)?;

    if name_ptr == 0 || name_len == 0 {
        info!(ctx, "get_file_name: name_ptr or name_len is zero.");
        return Ok(file_name_buf); // Return empty if no name
    }

    let len_to_copy = core::cmp::min(name_len as usize, FILENAME_LEN_MAX - 1);

    // Using ctx.read_kernel_str_bytes for potentially safer/more optimized string reading.
    // This helper expects a null-terminated string or will read up to the buffer limit.
    // Since d_name.name is not necessarily null-terminated in the qstr struct (it has d_name.len),
    // a byte-by-byte copy up to len_to_copy is more accurate.
    for i in 0..len_to_copy {
        let byte_val = unsafe { ctx.read_kernel::<u8>(name_ptr + i as u64).map_err(|e| e as u32)? };
        file_name_buf[i] = byte_val;
    }
    Ok(file_name_buf)
}

fn handle_event_aggregation(ctx: &ProbeContext, mut current_event_record: RecordFs, event_type: FsEventIndex, flush_immediately: bool) -> Result<(), u32> {
    let agg_max = get_agg_events_max(ctx);
    let key = current_event_record.ino;

    if key == 0 { // Cannot aggregate if inode is 0 (e.g. error condition)
        info!(ctx, "handle_event_aggregation: key (inode) is 0, outputting directly.");
        current_event_record.event[event_type as usize] += 1;
        current_event_record.events +=1;
        unsafe { EVENTS.output(&current_event_record, 0).map_err(|e| e as u32)?; }
        return Ok(());
    }

    if agg_max <= 1 && !flush_immediately {
        current_event_record.event[event_type as usize] += 1;
        current_event_record.events +=1;
        current_event_record.isize_first = current_event_record.isize; // Set for non-aggregated too
        unsafe { EVENTS.output(&current_event_record, 0).map_err(|e| e as u32)?; }
        return Ok(());
    }

    let existing_record_ptr = unsafe { AGG_RECORDS.get_ptr_mut(&key) };
    if let Some(ptr) = existing_record_ptr {
        let existing_record = unsafe { &mut *ptr };
        existing_record.event[event_type as usize] += 1;
        existing_record.events += 1;
        existing_record.isize = current_event_record.isize;
        existing_record.mtime_nsec = current_event_record.mtime_nsec;
        existing_record.ctime_nsec = current_event_record.ctime_nsec;
        existing_record.atime_nsec = current_event_record.atime_nsec;
        // imode can change, update it
        existing_record.imode = current_event_record.imode;
        // inlink can change
        existing_record.inlink = current_event_record.inlink;


        if flush_immediately || existing_record.events >= agg_max {
            unsafe { EVENTS.output(existing_record, 0).map_err(|e| e as u32)?; }
            unsafe { AGG_RECORDS.delete(&key).map_err(|e| e as u32)?; }
        }
    } else {
        current_event_record.event[event_type as usize] = 1;
        current_event_record.events = 1;
        current_event_record.isize_first = current_event_record.isize;

        if flush_immediately && agg_max > 1 { // only flush if truly aggregated, else it was sent above
             unsafe { EVENTS.output(&current_event_record, 0).map_err(|e| e as u32)?; }
        } else if agg_max > 1 { // Not flushing immediately, and aggregation is enabled
            unsafe { AGG_RECORDS.insert(&key, &current_event_record).map_err(|e| e as u32)?; }
        } else { // Not flushing and no aggregation (agg_max <=1), already sent.
            // This case should be covered by the (agg_max <=1 && !flush_immediately) block earlier.
            // If flush_immediately is true here, and agg_max <=1, it means it should be sent,
            // but that specific combo is not handled cleanly above.
            // For safety, if it reaches here and agg_max <=1 (meaning no aggregation), send it.
             unsafe { EVENTS.output(&current_event_record, 0).map_err(|e| e as u32)?; }
        }
    }
    Ok(())
}

// Common function to extract dentry and inode from file pointer
fn get_dentry_inode_from_file(ctx: &ProbeContext, file_ptr: u64) -> Result<(u64, u64), u32> {
    if file_ptr == 0 { return Err(1); }
    // struct file { struct path f_path; ... }
    let f_path_ptr: u64 = unsafe { bpf_core_read!(ctx, file_ptr as *const core::ffi::c_void, "f_path").map_err(|e| e as u32)? };
    if f_path_ptr == 0 { return Err(2); }
    // struct path { struct dentry *dentry; ... }
    let dentry_ptr: u64 = unsafe { bpf_core_read!(ctx, f_path_ptr as *const core::ffi::c_void, "dentry").map_err(|e| e as u32)? };
    if dentry_ptr == 0 { return Err(3); }
    // struct dentry { struct inode *d_inode; ... }
    let d_inode_ptr: u64 = unsafe { bpf_core_read!(ctx, dentry_ptr as *const core::ffi::c_void, "d_inode").map_err(|e| e as u32)? };
    if d_inode_ptr == 0 { return Err(4); }
    Ok((dentry_ptr, d_inode_ptr))
}


#[kprobe]
pub fn security_inode_create(ctx: ProbeContext) -> u32 {
    match try_security_inode_create(ctx) {
        Ok(ret) => ret,
        Err(ret) => { info!(&ctx, "create: Error {}", ret); ret }
    }
}

fn try_security_inode_create(ctx: ProbeContext) -> Result<u32, u32> {
    info!(&ctx, "kprobe security_inode_create called");
    let mut record_fs = unsafe { mem::zeroed::<RecordFs>() };
    record_fs.rc.record_type = RECORD_TYPE_FILE;
    record_fs.rc.ts = unsafe { bpf_ktime_get_ns() };

    let dentry_ptr: u64 = ctx.arg(1).ok_or(1u32)?;
    let mode: u32 = ctx.arg(2).ok_or(1u32)?;
    if dentry_ptr == 0 { info!(&ctx, "create: dentry_ptr is null"); return Err(2); }

    record_fs.imode = mode & 0xFFFF; // umode_t

    let d_inode_ptr_res = unsafe { bpf_core_read!(ctx, dentry_ptr as *const core::ffi::c_void, "d_inode") };
    match d_inode_ptr_res {
        Ok(d_inode_ptr) if d_inode_ptr != 0 => {
            populate_inode_data(&ctx, d_inode_ptr, &mut record_fs).map_err(|e| {
                info!(&ctx, "create: populate_inode_data failed: {}", e); e
            })?;
        }
        _ => {
            info!(&ctx, "create: d_inode is null or read error. ino set to 0.");
            record_fs.ino = 0;
        }
    }

    get_file_name_from_dentry(&ctx, dentry_ptr).and_then(|name_buf| { record_fs.filename_union = name_buf; Ok(()) }).unwrap_or_else(|e| {
        info!(&ctx, "create: get_file_name_from_dentry failed: {}", e);
    });

    let p_path = b"/placeholder/create"; // Path placeholder
    for i in 0..core::cmp::min(p_path.len(), FILEPATH_LEN_MAX) { record_fs.filepath[i] = p_path[i]; }

    handle_event_aggregation(&ctx, record_fs, FsEventIndex::Create, false)?;
    Ok(0)
}


#[kprobe]
pub fn security_inode_unlink(ctx: ProbeContext) -> u32 {
    match try_security_inode_unlink(ctx) {
        Ok(ret) => ret,
        Err(ret) => { info!(&ctx, "unlink: Error {}", ret); ret }
    }
}

fn try_security_inode_unlink(ctx: ProbeContext) -> Result<u32, u32> {
    info!(&ctx, "kprobe security_inode_unlink called");
    let mut record_fs = unsafe { mem::zeroed::<RecordFs>() };
    record_fs.rc.record_type = RECORD_TYPE_FILE;
    record_fs.rc.ts = unsafe { bpf_ktime_get_ns() };

    let dentry_ptr: u64 = ctx.arg(1).ok_or(1u32)?;
    if dentry_ptr == 0 { info!(&ctx, "unlink: dentry_ptr is null"); return Err(2); }

    let d_inode_ptr_res = unsafe { bpf_core_read!(ctx, dentry_ptr as *const core::ffi::c_void, "d_inode") };
     match d_inode_ptr_res {
        Ok(d_inode_ptr) if d_inode_ptr != 0 => {
            populate_inode_data(&ctx, d_inode_ptr, &mut record_fs).map_err(|e| {
                info!(&ctx, "unlink: populate_inode_data failed: {}", e); e
            })?;
        }
        _ => {
            info!(&ctx, "unlink: d_inode is null or read error. ino set to 0.");
            record_fs.ino = 0; // Should not happen for unlink normally
        }
    }

    get_file_name_from_dentry(&ctx, dentry_ptr).and_then(|name_buf| { record_fs.filename_union = name_buf; Ok(()) }).unwrap_or_else(|e| {
        info!(&ctx, "unlink: get_file_name_from_dentry failed: {}", e);
    });

    let p_path = b"/placeholder/unlink";
    for i in 0..core::cmp::min(p_path.len(), FILEPATH_LEN_MAX) { record_fs.filepath[i] = p_path[i]; }

    handle_event_aggregation(&ctx, record_fs, FsEventIndex::Delete, true)?;
    Ok(0)
}

#[kprobe]
pub fn security_inode_rename(ctx: ProbeContext) -> u32 {
    info!(&ctx, "kprobe security_inode_rename called");
    // Args: old_dir (inode), old_dentry, new_dir (inode), new_dentry
    let old_dentry_ptr: u64 = ctx.arg(1).unwrap_or(0);
    let new_dentry_ptr: u64 = ctx.arg(3).unwrap_or(0);
    let current_ts = unsafe { bpf_ktime_get_ns() };

    if old_dentry_ptr != 0 {
        let mut record_fs_from = unsafe { mem::zeroed::<RecordFs>() };
        record_fs_from.rc.record_type = RECORD_TYPE_FILE;
        record_fs_from.rc.ts = current_ts;

        let d_inode_ptr_res = unsafe { bpf_core_read!(ctx, old_dentry_ptr as *const core::ffi::c_void, "d_inode") };
        match d_inode_ptr_res {
            Ok(d_inode_ptr) if d_inode_ptr != 0 => {
                populate_inode_data(&ctx, d_inode_ptr, &mut record_fs_from).unwrap_or_else(|e|{
                    info!(&ctx, "rename(from): populate_inode_data failed: {}", e);
                });
            }
            _ => { record_fs_from.ino = 0; }
        }
        get_file_name_from_dentry(&ctx, old_dentry_ptr).and_then(|name_buf| { record_fs_from.filename_union = name_buf; Ok(()) }).unwrap_or_else(|e|{
            info!(&ctx, "rename(from): get_file_name_from_dentry failed: {}", e);
        });
        let p_path = b"/placeholder/mv_from";
        for i in 0..core::cmp::min(p_path.len(), FILEPATH_LEN_MAX) { record_fs_from.filepath[i] = p_path[i]; }

        handle_event_aggregation(&ctx, record_fs_from, FsEventIndex::MovedFrom, true).unwrap_or_else(|e|{
             info!(&ctx, "rename(from): aggregation failed: {}", e);
        });
    }

    if new_dentry_ptr != 0 {
        let mut record_fs_to = unsafe { mem::zeroed::<RecordFs>() };
        record_fs_to.rc.record_type = RECORD_TYPE_FILE;
        record_fs_to.rc.ts = current_ts; // Could be slightly later if desired: unsafe { bpf_ktime_get_ns() };

        let d_inode_ptr_res = unsafe { bpf_core_read!(ctx, new_dentry_ptr as *const core::ffi::c_void, "d_inode") };
        match d_inode_ptr_res {
            Ok(d_inode_ptr) if d_inode_ptr != 0 => {
                populate_inode_data(&ctx, d_inode_ptr, &mut record_fs_to).unwrap_or_else(|e|{
                    info!(&ctx, "rename(to): populate_inode_data failed: {}", e);
                });
            }
             _ => { record_fs_to.ino = 0; }
        }
        get_file_name_from_dentry(&ctx, new_dentry_ptr).and_then(|name_buf| { record_fs_to.filename_union = name_buf; Ok(()) }).unwrap_or_else(|e|{
             info!(&ctx, "rename(to): get_file_name_from_dentry failed: {}", e);
        });
        let p_path = b"/placeholder/mv_to";
        for i in 0..core::cmp::min(p_path.len(), FILEPATH_LEN_MAX) { record_fs_to.filepath[i] = p_path[i]; }

        handle_event_aggregation(&ctx, record_fs_to, FsEventIndex::MovedTo, false).unwrap_or_else(|e|{
            info!(&ctx, "rename(to): aggregation failed: {}", e);
        });
    }
    Ok(0)
}

#[kprobe]
pub fn security_file_open(ctx: ProbeContext) -> u32 {
    // Args: struct file *file (typically arg0 for older kernels)
    // Or struct path *path (arg0), struct file *file (arg1) for newer
    // Let's assume file is arg(0) for now, adjust if needed based on target kernel / LSM hook
    // Or check BTF for security_file_open signature.
    // For many modern kernels, it's (struct file *file).
    let file_ptr: u64 = ctx.arg(0).unwrap_or(0);
    if file_ptr == 0 { return 0; }

    info!(&ctx, "kprobe security_file_open called");
    let mut record_fs = unsafe { mem::zeroed::<RecordFs>() };
    record_fs.rc.record_type = RECORD_TYPE_FILE;
    record_fs.rc.ts = unsafe { bpf_ktime_get_ns() };

    match get_dentry_inode_from_file(&ctx, file_ptr) {
        Ok((dentry_ptr, d_inode_ptr)) => {
            populate_inode_data(&ctx, d_inode_ptr, &mut record_fs).unwrap_or_else(|e|{
                info!(&ctx, "file_open: populate_inode_data failed: {}", e);
            });
            get_file_name_from_dentry(&ctx, dentry_ptr).and_then(|name_buf| { record_fs.filename_union = name_buf; Ok(()) }).unwrap_or_else(|e|{
                info!(&ctx, "file_open: get_file_name_from_dentry failed: {}", e);
            });
        }
        Err(e) => {
            info!(&ctx, "file_open: get_dentry_inode_from_file failed: {}, ino set to 0", e);
            record_fs.ino = 0; // Mark as invalid
        }
    }

    let p_path = b"/placeholder/open";
    for i in 0..core::cmp::min(p_path.len(), FILEPATH_LEN_MAX) { record_fs.filepath[i] = p_path[i]; }

    // Determine event type based on file->f_mode
    let f_mode: u32 = unsafe { bpf_core_read!(ctx, file_ptr as *const core::ffi::c_void, "f_mode").unwrap_or(0) };
    let mut event_type = FsEventIndex::Access; // Default to Access
    if (f_mode & FMODE_WRITE) != 0 {
        event_type = FsEventIndex::Modify; // Or OpenWrite if we want to distinguish
    } else if (f_mode & FMODE_READ) != 0 {
        event_type = FsEventIndex::Access; // Or OpenRead
    }
    // Other modes like FMODE_EXEC could be OpenExec

    handle_event_aggregation(&ctx, record_fs, event_type, false).unwrap_or_else(|e|{
        info!(&ctx, "file_open: aggregation failed: {}", e);
    });
    Ok(0)
}


// vfs_write is often a good candidate for write monitoring.
// ssize_t vfs_write(struct file *file, const char __user *buf, size_t count, loff_t *pos);
#[kprobe]
pub fn vfs_write_kprobe(ctx: ProbeContext) -> u32 {
    let file_ptr: u64 = ctx.arg(0).unwrap_or(0);
    // let write_count: u64 = ctx.arg(2).unwrap_or(0); // size_t can be u32 or u64
    if file_ptr == 0 { return 0; }

    info!(&ctx, "kprobe vfs_write called");
    let mut record_fs = unsafe { mem::zeroed::<RecordFs>() };
    record_fs.rc.record_type = RECORD_TYPE_FILE;
    record_fs.rc.ts = unsafe { bpf_ktime_get_ns() };

    match get_dentry_inode_from_file(&ctx, file_ptr) {
        Ok((dentry_ptr, d_inode_ptr)) => {
            populate_inode_data(&ctx, d_inode_ptr, &mut record_fs).unwrap_or_else(|e|{
                info!(&ctx, "vfs_write: populate_inode_data failed: {}", e);
            });
            // The size in record_fs.isize is now the size *before* this write completes.
            // The actual size *after* this write will be reflected on next inode read.
            // We could add 'write_count' to isize for an estimate if needed, but that's not what original dirt does.
            get_file_name_from_dentry(&ctx, dentry_ptr).and_then(|name_buf| { record_fs.filename_union = name_buf; Ok(()) }).unwrap_or_else(|e|{
                 info!(&ctx, "vfs_write: get_file_name_from_dentry failed: {}", e);
            });
        }
        Err(e) => {
            info!(&ctx, "vfs_write: get_dentry_inode_from_file failed: {}, ino set to 0", e);
            record_fs.ino = 0;
        }
    }

    let p_path = b"/placeholder/write";
    for i in 0..core::cmp::min(p_path.len(), FILEPATH_LEN_MAX) { record_fs.filepath[i] = p_path[i]; }

    handle_event_aggregation(&ctx, record_fs, FsEventIndex::Modify, false).unwrap_or_else(|e|{
        info!(&ctx, "vfs_write: aggregation failed: {}", e);
    });
    Ok(0)
}


#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\x00";
