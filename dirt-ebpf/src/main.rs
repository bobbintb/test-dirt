#![no_std]
#![no_main]

use core::ffi::c_void;
// use core::{mem, ptr, slice}; // Removed unused core imports
// use core::mem::offset_of; // Removed offset_of import

use dirt_common::constants::{
    RecordFs, Stats, FsEventInfo,
    FILENAME_LEN_MAX, FILEPATH_NODE_MAX, DNAME_INLINE_LEN, RECORD_TYPE_FILE,
    MAX_STACK_TRACE_DEPTH, DBG_LEN_MAX,
    FS_MOVED_TO, INDEX_FS_EVENT,
    s_isreg, s_islnk, key_pid_ino,
};

// Placeholder for missing constants - these should be defined or passed in correctly
const PID_SELF: u64 = 0; // Example: replace with actual logic if available
const AGG_EVENTS_MAX: u32 = 10; // Example: replace with actual logic
const DEBUG_ENABLED: [u8; DBG_LEN_MAX] = [0; DBG_LEN_MAX]; // Example: replace

// Placeholder for FSEVT - this should be properly initialized or passed
// For now, using a simplified version based on dirt_common::constants::FSEVT
// This might need adjustment based on actual usage.
struct FsEvent {
    value: i16,
}
const FSEVT: [FsEvent; 1] = [FsEvent { value: FS_MOVED_TO as i16 }];


use aya_ebpf::{
    macros::{map, kprobe, kretprobe},
    maps::{Array, PerCpuArray, LruHashMap, RingBuf},
    programs::{ProbeContext, RetProbeContext},
    bindings::{self, inode}, // dentry removed, will use c_void
    helpers::{
        bpf_get_stack,
        bpf_ktime_get_ns,
        bpf_map_lookup_elem,
        bpf_map_update_elem,
        bpf_map_delete_elem,
        bpf_probe_read_kernel_str_bytes,
        bpf_ringbuf_output,
        bpf_ringbuf_query,
        bpf_printk,
        // Re-adding aya_ebpf::bpf_core_read_* helpers
        // These might be in aya_ebpf::programs::bpf_core_read or aya_ebpf::btf::BtfExt
        // For now, assuming they might be in helpers or globally accessible via aya_ebpf::bpf_core_read::*
        // If not, will use bpf_probe_read_kernel with string paths if possible.
        // For now, let's assume direct import path from aya_ebpf::helpers if they exist there for CO-RE
        // This is a bit of a guess based on common eBPF library patterns.
        // Actual Aya might require `ctx.read_btf_field` or similar.
        // Given previous errors, these specific helpers are likely NOT in aya_ebpf::helpers.
        // Will proceed by using bpf_probe_read_kernel and bpf_probe_read_kernel_str_bytes
        // for field access by constructing pointers to fields manually if ctx.field_ptr fails.
        // For now, let's rely on bpf_probe_read_kernel for primitives and bpf_probe_read_kernel_str_bytes for strings.
        // And for pointers, bpf_probe_read_kernel to get the address.
        bpf_probe_read_kernel, // Re-adding for reading primitives/pointers
    },
    EbpfContext,
};

// use aya_log_ebpf::info;




#[map(name = "ringbuf_records")]
static mut RINGBUF_RECORDS: RingBuf = RingBuf::with_byte_size(8192 * 1024, 0); // 8MB, flags = 0

#[map(name = "hash_records")]
static mut HASH_RECORDS: LruHashMap<u64, RecordFs> = LruHashMap::<u64, RecordFs>::with_max_entries(8192, 0);

#[map(name = "heap_record_fs")]
static mut HEAP_RECORD_FS: PerCpuArray<RecordFs> = PerCpuArray::<RecordFs>::with_max_entries(1, 0);

#[map(name = "stats")]
static mut STATS: Array<Stats> = Array::<Stats>::with_max_entries(1, 0);



#[inline(always)]
fn handle_fs_event_impl(ctx: ProbeContext) -> Result<i32, i32> {
    let event_ptr = ctx.arg::<*const FsEventInfo>(1).ok_or(1i32)?;
    let event = unsafe { &*event_ptr };

    if event.index == INDEX_FS_EVENT::I_ACCESS as i32 || event.index == INDEX_FS_EVENT::I_ATTRIB as i32 {
        return Ok(0);
    }

    let pid = ctx.pid();
    if PID_SELF == pid as u64 {
        return Ok(0);
    }

    let index = event.index;
    let index = event.index;
    let index = event.index;
    let index = event.index;
    let dentry_c_ptr = event.dentry as *const c_void;
    let dentry_old_c_ptr = event.dentry_old as *const c_void;

    let index = event.index;
    let dentry_c_ptr = event.dentry as *const c_void;
    let dentry_old_c_ptr = event.dentry_old as *const c_void;

    // Placeholder offsets - these need to be accurate for the target kernel
    // Or use CO-RE helpers if they can be made to work.
    const OFFSET_DENTRY_D_INODE: isize = 0; // FIXME: Placeholder
    const OFFSET_DENTRY_D_NAME_NAME: isize = 16; // FIXME: Placeholder, assuming d_name is a pointer at offset 16, and name is first field of qstr
    const OFFSET_DENTRY_D_PARENT: isize = 8; // FIXME: Placeholder
    const OFFSET_INODE_I_INO: isize = 8; // FIXME: Placeholder
    const OFFSET_INODE_I_MODE: isize = 24; // FIXME: Placeholder
    const OFFSET_INODE_I_SIZE: isize = 32; // FIXME: Placeholder
    const OFFSET_INODE_I_NLINK: isize = 28; // FIXME: Placeholder
    const OFFSET_INODE_I_ATIME_TV_SEC: isize = 40; // FIXME: Placeholder
    const OFFSET_INODE_I_ATIME_TV_NSEC: isize = 48; // FIXME: Placeholder
    const OFFSET_INODE_I_MTIME_TV_SEC: isize = 56; // FIXME: Placeholder
    const OFFSET_INODE_I_MTIME_TV_NSEC: isize = 64; // FIXME: Placeholder
    const OFFSET_INODE_I_CTIME_TV_SEC: isize = 72; // FIXME: Placeholder
    const OFFSET_INODE_I_CTIME_TV_NSEC: isize = 80; // FIXME: Placeholder


    let d_inode_ptr_val: u64 = unsafe {
        aya_ebpf::helpers::bpf_probe_read_kernel(
            (if !dentry_old_c_ptr.is_null() { dentry_old_c_ptr } else { dentry_c_ptr } as *const u8)
                .offset(OFFSET_DENTRY_D_INODE) as *const _
        ).map_err(|e| e as i32)?
    };
    if d_inode_ptr_val == 0 { return Err(2); }
    let current_inode_ptr = d_inode_ptr_val as *const inode;

    let mut filename = [0u8; FILENAME_LEN_MAX];
    let name_ptr_val: u64 = unsafe { // Assuming d_name points to a qstr-like struct where 'name' is the first field (char*)
        let d_name_ptr: u64 = aya_ebpf::helpers::bpf_probe_read_kernel((dentry_c_ptr as *const u8).offset(OFFSET_DENTRY_D_NAME_NAME) as *const _).map_err(|e|e as i32)?;
        aya_ebpf::helpers::bpf_probe_read_kernel(d_name_ptr as *const _).map_err(|e| e as i32)?
    };
    unsafe {
        bpf_probe_read_kernel_str_bytes(name_ptr_val as *const u8, &mut filename)
            .map_err(|e| e as i32)?;
    }

    if filename[0] == 0 { return Ok(0); }

    let ino = unsafe { aya_ebpf::helpers::bpf_probe_read_kernel((current_inode_ptr as *const u8).offset(OFFSET_INODE_I_INO) as *const u32).map_err(|e| e as i32)? };
    let imode = unsafe { aya_ebpf::helpers::bpf_probe_read_kernel((current_inode_ptr as *const u8).offset(OFFSET_INODE_I_MODE) as *const u32).map_err(|e| e as i32)? };

    if !(s_isreg(imode) || s_islnk(imode)) { return Ok(0); }

    let key = key_pid_ino(pid as u64, ino as u64);
    let r_ptr = unsafe { bpf_map_lookup_elem(&mut HASH_RECORDS as *mut _ as *mut c_void, &key as *const _ as *const c_void) as *mut RecordFs };
    let s_ptr = unsafe { bpf_map_lookup_elem(&mut STATS as *mut _ as *mut c_void, &0u32 as *const _ as *const c_void) as *mut Stats };

    if !r_ptr.is_null() {
        let r = unsafe { &mut *r_ptr };
        if FSEVT[0].value == FS_MOVED_TO as i16 {
            core::ptr::write_bytes(r.filename.full.as_mut_ptr(), 0, r.filename.full.len());
            let name_ptr_move_val: u64 = unsafe {
                let d_name_ptr: u64 = aya_ebpf::helpers::bpf_probe_read_kernel((dentry_c_ptr as *const u8).offset(OFFSET_DENTRY_D_NAME_NAME) as *const _).map_err(|e|e as i32)?;
                aya_ebpf::helpers::bpf_probe_read_kernel(d_name_ptr as *const _).map_err(|e| e as i32)?
            };
            unsafe {
                bpf_probe_read_kernel_str_bytes(name_ptr_move_val as *const u8, &mut r.filename.full)
                    .map_err(|e| e as i32)?;
            }
        }
        r.rc.ts = unsafe { bpf_ktime_get_ns() };
    } else {
        let r_heap_ptr = unsafe { bpf_map_lookup_elem(&mut HEAP_RECORD_FS as *mut _ as *mut c_void, &0u32 as *const _ as *const c_void) as *mut RecordFs };
        if r_heap_ptr.is_null() { return Err(3); }
        let r = unsafe { &mut *r_heap_ptr };

        r.rc.ts = unsafe { bpf_ktime_get_ns() };
        r.ino = ino;
        core::ptr::write_bytes(r.filename.full.as_mut_ptr(), 0, r.filename.full.len());
        let name_ptr_new_val: u64 = unsafe {
            let d_name_ptr: u64 = aya_ebpf::helpers::bpf_probe_read_kernel((dentry_c_ptr as *const u8).offset(OFFSET_DENTRY_D_NAME_NAME) as *const _).map_err(|e|e as i32)?;
            aya_ebpf::helpers::bpf_probe_read_kernel(d_name_ptr as *const _).map_err(|e| e as i32)?
        };
        unsafe {
            bpf_probe_read_kernel_str_bytes(name_ptr_new_val as *const u8, &mut r.filename.full)
                .map_err(|e| e as i32)?;
        }
        r.isize_first = unsafe { aya_ebpf::helpers::bpf_probe_read_kernel((current_inode_ptr as *const u8).offset(OFFSET_INODE_I_SIZE) as *const u64).map_err(|e| e as i32)? };

        let mut pathnode: [*const u8; FILEPATH_NODE_MAX] = unsafe { core::mem::zeroed() };
        let mut current_dentry_build_path = dentry_c_ptr;
        let mut cnt = 0;
        while cnt < FILEPATH_NODE_MAX {
            let dname_qstr_ptr_path: u64 = unsafe { aya_ebpf::helpers::bpf_probe_read_kernel((current_dentry_build_path as *const u8).offset(OFFSET_DENTRY_D_NAME_NAME) as *const _).map_err(|e| e as i32)? };
            let dname_path_ptr: u64 = unsafe { aya_ebpf::helpers::bpf_probe_read_kernel(dname_qstr_ptr_path as *const _).map_err(|e| e as i32)? };
            let dparent_path_ptr_val: u64 = unsafe { aya_ebpf::helpers::bpf_probe_read_kernel((current_dentry_build_path as *const u8).offset(OFFSET_DENTRY_D_PARENT) as *const _).map_err(|e| e as i32)? };
            pathnode[cnt] = dname_path_ptr as *const u8;

            let d_inode_addr_val: u64 = unsafe{ aya_ebpf::helpers::bpf_probe_read_kernel((current_dentry_build_path as *const u8).offset(OFFSET_DENTRY_D_INODE) as *const _).map_err(|e| e as i32)? };
            let dp_inode_addr_val: u64 = unsafe{ aya_ebpf::helpers::bpf_probe_read_kernel((dparent_path_ptr_val as *const u8).offset(OFFSET_DENTRY_D_INODE) as *const _).map_err(|e| e as i32)? };

            let d_inode_ino = unsafe{ aya_ebpf::helpers::bpf_probe_read_kernel((d_inode_addr_val as *const u8).offset(OFFSET_INODE_I_INO) as *const u32).map_err(|e| e as i32)? };
            let dp_inode_ino = unsafe{ aya_ebpf::helpers::bpf_probe_read_kernel((dp_inode_addr_val as *const u8).offset(OFFSET_INODE_I_INO) as *const u32).map_err(|e| e as i32)? };

            if d_inode_ino == dp_inode_ino { break; }
            current_dentry_build_path = dparent_path_ptr_val as *const c_void;
            cnt += 1;
        }

        let num_nodes = if cnt < FILEPATH_NODE_MAX { cnt } else { 0 };
        core::ptr::write_bytes(r.filepath.as_mut_ptr(), 0, r.filepath.len());

        let mut offset = 0;
        for i in (1..=num_nodes).rev() {
            let node = pathnode[i];
            if !node.is_null() && offset < (r.filepath.len() - DNAME_INLINE_LEN) {
                let mut temp_node_buf = [0u8; DNAME_INLINE_LEN];
                let len_val = match unsafe { bpf_probe_read_kernel_str_bytes(node, &mut temp_node_buf) } {
                    Ok(read_bytes_count) => read_bytes_count,
                    Err(e) => return Err(e as i32),
                };

                if offset + len_val <= r.filepath.len() {
                    r.filepath[offset..(offset + len_val)].copy_from_slice(&temp_node_buf[..len_val]);
                    offset += len_val;
                    if i != num_nodes && offset < r.filepath.len() {
                        r.filepath[offset] = b'/';
                        offset += 1;
                    }
                } else { break; }
            }
        }
        r.events = 0;
        for e_ref in r.event.iter_mut() { *e_ref = 0; }
        r.inlink = 0;
        if !s_ptr.is_null() { unsafe { (*s_ptr).fs_records += 1 }; }
    }
    let r = unsafe { &mut *r_ptr };
    let s_opt = if s_ptr.is_null() { None } else { Some(unsafe { &mut *s_ptr }) };

    if let Some(stats) = s_opt.as_mut() { stats.fs_events += 1; }

    r.imode = imode;
    r.isize = unsafe { aya_ebpf::helpers::bpf_probe_read_kernel((current_inode_ptr as *const u8).offset(OFFSET_INODE_I_SIZE) as *const u64).map_err(|e| e as i32)? };
    r.inlink = unsafe { aya_ebpf::helpers::bpf_probe_read_kernel((current_inode_ptr as *const u8).offset(OFFSET_INODE_I_NLINK) as *const u32).map_err(|e| e as i32)? };

    if index == INDEX_FS_EVENT::I_CREATE as i32 && dentry_old_c_ptr != core::ptr::null() { r.inlink += 1; }
    r.atime_nsec = (unsafe { aya_ebpf::helpers::bpf_probe_read_kernel((current_inode_ptr as *const u8).offset(OFFSET_INODE_I_ATIME_TV_SEC) as *const u64).map_err(|e| e as i32)? }) * 1_000_000_000
        + (unsafe { aya_ebpf::helpers::bpf_probe_read_kernel((current_inode_ptr as *const u8).offset(OFFSET_INODE_I_ATIME_TV_NSEC) as *const u64).map_err(|e| e as i32)? });
    r.mtime_nsec = (unsafe { aya_ebpf::helpers::bpf_probe_read_kernel((current_inode_ptr as *const u8).offset(OFFSET_INODE_I_MTIME_TV_SEC) as *const u64).map_err(|e| e as i32)? }) * 1_000_000_000
        + (unsafe { aya_ebpf::helpers::bpf_probe_read_kernel((current_inode_ptr as *const u8).offset(OFFSET_INODE_I_MTIME_TV_NSEC) as *const u64).map_err(|e| e as i32)? });
    r.ctime_nsec = (unsafe { aya_ebpf::helpers::bpf_probe_read_kernel((current_inode_ptr as *const u8).offset(OFFSET_INODE_I_CTIME_TV_SEC) as *const u64).map_err(|e| e as i32)? }) * 1_000_000_000
        + (unsafe { aya_ebpf::helpers::bpf_probe_read_kernel((current_inode_ptr as *const u8).offset(OFFSET_INODE_I_CTIME_TV_NSEC) as *const u64).map_err(|e| e as i32)? });

    r.events += 1;
    r.event[index as usize] += 1;

    if unsafe { bpf_map_update_elem(&mut HASH_RECORDS as *mut _ as *mut c_void, &key as *const _ as *const c_void, r as *const RecordFs as *const c_void, bindings::BPF_ANY.into()) } < 0 { // Added .into()
        return Err(4);
    }

    let mut agg_end = false;
    if index == INDEX_FS_EVENT::I_CLOSE_WRITE as i32 || index == INDEX_FS_EVENT::I_CLOSE_NOWRITE as i32 || index == INDEX_FS_EVENT::I_DELETE as i32 || index == INDEX_FS_EVENT::I_MOVED_TO as i32
        || (index == INDEX_FS_EVENT::I_CREATE as i32 && (s_islnk(imode) || r.inlink > 1)) {
        agg_end = true;
    }

    if !agg_end && AGG_EVENTS_MAX != 0 && r.events >= AGG_EVENTS_MAX { agg_end = true; }

    if agg_end {
        r.rc.r#type = RECORD_TYPE_FILE;
        let output_len = core::mem::size_of_val(&*r) as u64;
        if unsafe { bpf_ringbuf_output(&mut RINGBUF_RECORDS as *mut _ as *mut c_void, r as *const RecordFs as *const c_void, output_len, 0) } != 0 {
            if let Some(stats) = s_opt.as_mut() { stats.fs_records_dropped += 1; }
        }
        if unsafe { bpf_map_delete_elem(&mut HASH_RECORDS as *mut _ as *mut c_void, &key as *const _ as *const c_void) } != 0 {
            return Err(5);
        }
        if let Some(stats) = s_opt.as_mut() { stats.fs_records_deleted += 1; }
    }

    if let Some(stats) = s_opt {
        let mut rsz = core::mem::size_of_val(&*r) as u64;
        rsz += 8 - (rsz % 8);
        if stats.fs_records == 1 {
            stats.fs_records_rb_max = unsafe { bpf_ringbuf_query(&mut RINGBUF_RECORDS as *mut _ as *mut c_void, bindings::BPF_RB_RING_SIZE.into()) } / rsz;
        }
    }
    Ok(0)
}

fn handle_fs_event_wrapper(ctx: ProbeContext) -> u32 { // Return u32
    match handle_fs_event_impl(ctx) {
        Ok(ret) => ret as u32, // Cast to u32
        Err(ret) => ret as u32,  // Cast to u32
    }
}





#[kretprobe]
pub fn do_filp_open(ctx: RetProbeContext) -> u32 {
    try_dirt1(ctx).unwrap_or(0)
}

#[kprobe]
pub fn security_inode_link(ctx: ProbeContext) -> u32 {
    handle_fs_event_wrapper(ctx)
}

#[kprobe]
pub fn security_inode_symlink(ctx: ProbeContext) -> u32 {
    handle_fs_event_wrapper(ctx)
}

#[kprobe]
pub fn dput(ctx: ProbeContext) -> u32 {
    handle_fs_event_wrapper(ctx)
}

#[kprobe]
pub fn notify_change(ctx: ProbeContext) -> u32 {
    handle_fs_event_wrapper(ctx)
}

#[kprobe]
pub fn __fsnotify_parent(ctx: ProbeContext) -> u32 {
    handle_fs_event_wrapper(ctx)
}

#[kprobe]
pub fn security_inode_rename(ctx: ProbeContext) -> u32 {
    handle_fs_event_wrapper(ctx)
}

#[kprobe]
pub fn security_inode_unlink(ctx: ProbeContext) -> u32 {
    handle_fs_event_wrapper(ctx)
}

fn try_dirt(_ctx: ProbeContext) -> Result<u32, u32> {
    Ok(0)
}

fn try_dirt1(_ctx: RetProbeContext) -> Result<u32, u32> {
    Ok(0)
}



static mut DEBUG_STACK: [i64; MAX_STACK_TRACE_DEPTH] = [0; MAX_STACK_TRACE_DEPTH];

#[inline(always)]
fn debug_dump_stack(ctx: ProbeContext, func: *const u8) {
    unsafe {
        let kstacklen = bpf_get_stack(
            ctx.as_ptr(),
            DEBUG_STACK.as_mut_ptr() as *mut _,
            (MAX_STACK_TRACE_DEPTH * core::mem::size_of::<i64>()) as u32,
            0,
        );

        if kstacklen > 0 {
            bpf_printk!(
                b"KERNEL STACK (%u): %s\0",
                (kstacklen as i64 / core::mem::size_of::<i64>() as i64) as u32,
                func,
            );

            for i in 0..MAX_STACK_TRACE_DEPTH {
                if kstacklen > (i as i64 * core::mem::size_of::<i64>() as i64) {
                    bpf_printk!(b"  %pB\0", DEBUG_STACK[i as usize] as *const c_void);
                }
            }
        }
    }
}

fn debug_file_is_tp(filename: *const u8) -> bool {
    let tp = b"trace_pipe";
    unsafe {
        if !filename.is_null() {
            for cnt in 0..DBG_LEN_MAX {
                let fc = *filename.add(cnt);
                let tc = *tp.get(cnt).unwrap_or(&0);
                if fc != tc {
                    break;
                } else if cnt == tp.len() - 1 {
                    return true;
                }
            }
        }
    }
    false
}

fn debug_proc(comm: *const u8, filename: *const u8) -> bool {
    unsafe {
        if comm.is_null() {
            return DEBUG_ENABLED[0] == b'q' && DEBUG_ENABLED[1] == 0; // Replaced debug
        }

        if DEBUG_ENABLED[0] != b'*' { // Replaced debug
            for cnt in 0..DBG_LEN_MAX {
                if *comm.add(0) == 0 || *comm.add(cnt) != DEBUG_ENABLED[cnt] { // Replaced debug
                    return false;
                }
            }
        }

        if debug_file_is_tp(filename) {
            return false;
        }

        true
    }
}




#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
