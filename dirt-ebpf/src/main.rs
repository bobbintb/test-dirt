#![no_std]
#![no_main]

// use aya_ebpf::alloc::AllocGlobal; // Ensure this is commented out
use dirt_common::*;

// #[global_allocator]
// static ALLOC: AllocGlobal = AllocGlobal; // Ensure this is commented out

use core::ffi::c_void; // Added for c_void
use core::{mem, ptr, slice};

// use aya_ebpf_bindings::{inode, dentry, BPF_ANY, BPF_NOEXIST, BPF_RB_RING_SIZE}; // Removed direct bindings import

use aya_ebpf::{
    bindings::{inode, dentry, BPF_ANY, BPF_NOEXIST, BPF_RB_RING_SIZE}, // Using aya_ebpf::bindings again
    macros::{map, kprobe, kretprobe},
    maps::{Array, PerCpuArray, LruHashMap, RingBuf},
    programs::{ProbeContext, RetProbeContext},
    helpers::{
        bpf_get_current_pid_tgid,
        bpf_get_stack,
        bpf_ktime_get_ns,
        bpf_map_lookup_elem,
        bpf_map_update_elem,
        bpf_map_delete_elem,
        // bpf_probe_read_kernel_str_bytes, // Not in aya-ebpf 0.1.1
        bpf_probe_read_str, // Use this instead
        bpf_ringbuf_output,
        bpf_ringbuf_query,
        bpf_printk,
    },
};

use aya_log_ebpf::info;


// RingBuf stores raw bytes. The type is handled during output and parsing.
// Max entries was 8192. RecordFs is approx 260 bytes.
// So, 8192 * 260 bytes is roughly 2MB.
const RINGBUF_BYTE_SIZE: u32 = 2 * 1024 * 1024;
#[map(name = "ringbuf_records")]
static mut RINGBUF_RECORDS: RingBuf = RingBuf::with_byte_size(RINGBUF_BYTE_SIZE, 0);

#[map(name = "hash_records")]
static mut HASH_RECORDS: LruHashMap<u64, RecordFs> = LruHashMap::<u64, RecordFs>::with_max_entries(8192, 0);

#[map(name = "heap_record_fs")]
static mut HEAP_RECORD_FS: PerCpuArray<RecordFs> = PerCpuArray::<RecordFs>::with_max_entries(1, 0);

#[map(name = "stats")]
static mut STATS: Array<Stats> = Array::<Stats>::with_max_entries(1, 0);

static mut PID_SELF: u64 = 0;
static mut AGG_EVENTS_MAX: u32 = 0;
static mut AGG_END: bool = false;
static mut TEST_VAR: u32 = 123; // For testing static mut visibility

#[inline(always)]
fn handle_fs_event(ctx: *mut c_void, event: *const FsEventInfo) -> i32 {
    unsafe {
        if (*event).index == INDEX_FS_EVENT::I_ACCESS as i32 || (*event).index == INDEX_FS_EVENT::I_ATTRIB as i32 {
            return 0;
        }

        let pid = bpf_get_current_pid_tgid() >> 32;
        // if PID_SELF == pid { // Temporarily commented for diagnostics
        //     return 0;
        // }

        let index = (*event).index;
        let mut dentry = (*event).dentry;
        let dentry_old = (*event).dentry_old;
        // let func = (*event).func; // func is unused

        let inode = bpf_core_read( // This will error (bpf_core_read not found)
            if !dentry_old.is_null() { dentry_old } else { dentry },
            b"__d_inode\0",
        ) as *const inode; // Uses imported inode

        let mut filename = [0u8; dirt_common::FILENAME_LEN_MAX];
        let d_name_ptr = bpf_core_read(dentry, b"d_name.name\0") as *const u8; // This will error (bpf_core_read not found)
        let _ = bpf_probe_read_str(d_name_ptr, &mut filename); // Swapped args, ignoring result for now

        if inode.is_null() || filename[0] == 0 {
            return 0;
        }

        let ino = bpf_core_read(inode, b"i_ino\0") as u32; // This will error
        let imode = bpf_core_read(inode, b"i_mode\0") as u32; // This will error
        if !(dirt_common::s_isreg(imode) || dirt_common::s_islnk(imode)) {
            return 0;
        }

        let key = dirt_common::key_pid_ino(pid, ino);
        let r = bpf_map_lookup_elem(&mut HASH_RECORDS as *mut _ as *mut core::ffi::c_void, &key as *const u64 as *const core::ffi::c_void) as *mut RecordFs;
        let s = bpf_map_lookup_elem(&mut STATS as *mut _ as *mut core::ffi::c_void, &0u32 as *const u32 as *const core::ffi::c_void) as *mut Stats;

        if !r.is_null() {
            if dirt_common::FSEVT[index as usize].value == dirt_common::FS_MOVED_TO as i16 {
                core::ptr::write_bytes((*r).filename.split.filename_to.as_mut_ptr(), 0, (*r).filename.split.filename_to.len());
                let src_ptr_moved = bpf_core_read(dentry, b"d_name.name\0") as *const u8; // This will error
                let _ = bpf_probe_read_str(src_ptr_moved, &mut (*r).filename.split.filename_to); // Swapped args
            }
            (*r).rc.ts = bpf_ktime_get_ns();
        } else {
            let r_opt = bpf_map_lookup_elem(&mut HEAP_RECORD_FS as *mut _ as *mut core::ffi::c_void, &0u32 as *const u32 as *const core::ffi::c_void);
            if r_opt.is_null() {
                return 0;
            }
            let r = r_opt as *mut RecordFs;


            (*r).rc.ts = bpf_ktime_get_ns();
            (*r).ino = ino;
            core::ptr::write_bytes((*r).filename.full.as_mut_ptr(), 0, (*r).filename.full.len());
            let src_ptr_full = bpf_core_read(dentry, b"d_name.name\0") as *const u8; // This will error
            let _ = bpf_probe_read_str(src_ptr_full, &mut (*r).filename.full); // Swapped args
            (*r).isize_first = bpf_core_read(inode, b"i_size\0") as u64; // This will error

            let mut pathnode: [*const u8; dirt_common::FILEPATH_NODE_MAX] = core::mem::zeroed();
            let mut cnt = 0;
            while cnt < dirt_common::FILEPATH_NODE_MAX {
                let dname = bpf_core_read(dentry, b"d_name.name\0") as *const u8; // This will error
                let dparent = bpf_core_read(dentry, b"d_parent\0") as *const dentry; // This will error
                pathnode[cnt] = dname;
                if bpf_core_read(dentry, b"d_inode.i_ino\0") == bpf_core_read(dparent, b"d_inode.i_ino\0") { // This will error
                    break;
                }
                dentry = dparent as *mut core::ffi::c_void; // Cast needed if dparent is *const dentry
                cnt += 1;
            }

            let num_nodes = if cnt < dirt_common::FILEPATH_NODE_MAX { cnt } else { 0 };
            core::ptr::write_bytes((*r).filepath.as_mut_ptr(), 0, (*r).filepath.len());

            let mut offset = 0;
            for current_node_idx in (1..=num_nodes).rev() { // Changed loop variable name
                let node = pathnode[current_node_idx]; // Use current_node_idx
                if !node.is_null() {
                    let max_len_for_component = (*r).filepath.len() - offset;
                    if max_len_for_component == 0 { break; }

                    let read_res = bpf_probe_read_str(
                        node, // src argument first
                        &mut (*r).filepath[offset..offset + max_len_for_component] // dest argument second
                    );

                    match read_res {
                        Ok(bytes_copied_including_null) => {
                            if bytes_copied_including_null == 0 { // Nothing useful copied (e.g. src was empty or immediate error represented as Ok(0))
                                break;
                            }

                            let component_len = bytes_copied_including_null.saturating_sub(1); // Length of string without NUL

                            if component_len == 0 { // Only a NUL byte was read, or non-NUL terminated string filled buffer.
                                                    // Treat as empty component, stop further path assembly for this segment.
                                break;
                            }

                            offset += component_len;

                            if current_node_idx != num_nodes && offset < (*r).filepath.len() {
                                (*r).filepath[offset] = b'/';
                                offset += 1;
                            } else if offset >= (*r).filepath.len() { // Buffer full or exactly filled
                                offset = (*r).filepath.len(); // Cap offset
                                break;
                            }
                        }
                        Err(_) => {
                            // Error from bpf_probe_read_str
                            break;
                        }
                    }
                } else {
                    break;
                }
            }

            (*r).events = 0;
            for e_val in (*r).event.iter_mut() { // Changed loop var name
                *e_val = 0;
            }
            (*r).inlink = 0;

            if !s.is_null() {
                (*s).fs_records += 1;
            }
        }

        if !s.is_null() {
            (*s).fs_events += 1;
        }

        (*r).imode = imode;
        (*r).isize = bpf_core_read(inode, b"i_size\0") as u64; // This will error
        (*r).inlink = bpf_core_read(inode, b"i_nlink\0") as u32; // This will error
        if index == INDEX_FS_EVENT::I_CREATE as i32 && !dentry_old.is_null() {
            (*r).inlink += 1;
        }
        (*r).atime_nsec = (bpf_core_read(inode, b"i_atime_sec\0") as u64) * 1_000_000_000 // This will error
            + (bpf_core_read(inode, b"i_atime_nsec\0") as u64); // This will error
        (*r).mtime_nsec = (bpf_core_read(inode, b"i_mtime_sec\0") as u64) * 1_000_000_000 // This will error
            + (bpf_core_read(inode, b"i_mtime_nsec\0") as u64); // This will error
        (*r).ctime_nsec = (bpf_core_read(inode, b"i_ctime_sec\0") as u64) * 1_000_000_000 // This will error
            + (bpf_core_read(inode, b"i_ctime_nsec\0") as u64); // This will error

        (*r).events += 1;
        (*r).event[index as usize] += 1;

        if bpf_map_update_elem(&mut HASH_RECORDS as *mut _ as *mut core::ffi::c_void, &key as *const u64 as *const core::ffi::c_void, r as *const RecordFs as *const core::ffi::c_void, BPF_ANY as u64) < 0 {
            return 0;
        }

        let mut agg_end_flag = false; // Renamed to avoid conflict with static
        if index == INDEX_FS_EVENT::I_CLOSE_WRITE as i32 || index == INDEX_FS_EVENT::I_CLOSE_NOWRITE as i32 || index == INDEX_FS_EVENT::I_DELETE as i32 || index == INDEX_FS_EVENT::I_MOVED_TO as i32
            || (index == INDEX_FS_EVENT::I_CREATE as i32 && (dirt_common::s_islnk(imode) || (*r).inlink > 1)) {
            agg_end_flag = true;
        }

        // if !agg_end_flag && AGG_EVENTS_MAX != 0 && (*r).events >= AGG_EVENTS_MAX { // Temporarily commented for diagnostics
        //     agg_end_flag = true;
        // }

        if agg_end_flag {
            (*r).rc.r#type = dirt_common::RECORD_TYPE_FILE;
            let output_len = core::mem::size_of_val(&*r) as u32;
            if bpf_ringbuf_output(&mut RINGBUF_RECORDS as *mut _ as *mut core::ffi::c_void, r as *const RecordFs as *const core::ffi::c_void, output_len as u64, 0 as u64) != 0 {
                if !s.is_null() {
                    (*s).fs_records_dropped += 1;
                }
            }
            if bpf_map_delete_elem(&mut HASH_RECORDS as *mut _ as *mut core::ffi::c_void, &key as *const u64 as *const core::ffi::c_void) != 0 {
                return 0;
            }
            if !s.is_null() {
                (*s).fs_records_deleted += 1;
            }
        }

        let stats_key_val: u32 = 0; // Renamed
        if let Some(s_ptr) = bpf_map_lookup_elem(&mut STATS as *mut _ as *mut core::ffi::c_void, &stats_key_val as *const u32 as *const core::ffi::c_void) {
            let s_stats = s_ptr as *mut Stats; // Renamed
            let mut rsz = core::mem::size_of_val(&*r) as u64;
            rsz += 8 - (rsz % 8); // Ensure 8-byte alignment for ringbuf
            if (*s_stats).fs_records == 1 { // Use s_stats
                (*s_stats).fs_records_rb_max = bpf_ringbuf_query(&mut RINGBUF_RECORDS as *mut _ as *mut core::ffi::c_void, BPF_RB_RING_SIZE as u64) / rsz;
            }
        }
        0
    }
}





#[kretprobe]
pub fn do_filp_open(ctx: RetProbeContext) -> u32 {
    try_dirt1(ctx).unwrap_or(0)
}

#[kprobe]
pub fn security_inode_link(ctx: ProbeContext) -> u32 {
    try_dirt(ctx).unwrap_or(0)
}

#[kprobe]
pub fn security_inode_symlink(ctx: ProbeContext) -> u32 {
    try_dirt(ctx).unwrap_or(0)
}

#[kprobe]
pub fn dput(ctx: ProbeContext) -> u32 {
    try_dirt(ctx).unwrap_or(0)
}

#[kprobe]
pub fn notify_change(ctx: ProbeContext) -> u32 {
    try_dirt(ctx).unwrap_or(0)
}

#[kprobe]
pub fn __fsnotify_parent(ctx: ProbeContext) -> u32 {
    try_dirt(ctx).unwrap_or(0)
}

#[kprobe]
pub fn security_inode_rename(ctx: ProbeContext) -> u32 {
    try_dirt(ctx).unwrap_or(0)
}

#[kprobe]
pub fn security_inode_unlink(ctx: ProbeContext) -> u32 {
    try_dirt(ctx).unwrap_or(0)
}

fn try_dirt(ctx: ProbeContext) -> Result<u32, u32> {
    unsafe { info!(&ctx, "kprobe called, TEST_VAR: {}", TEST_VAR); }
    Ok(0)
}

fn try_dirt1(ctx: RetProbeContext) -> Result<u32, u32> {
    info!(&ctx, "kretprobe called");
    Ok(0)
}

// Qualified MAX_STACK_TRACE_DEPTH and DBG_LEN_MAX

static mut DEBUG_STACK: [i64; dirt_common::MAX_STACK_TRACE_DEPTH] = [0; dirt_common::MAX_STACK_TRACE_DEPTH];
static mut DEBUG_FILTER: [u8; dirt_common::DBG_LEN_MAX] = [0; dirt_common::DBG_LEN_MAX]; // Added DEBUG_FILTER
// static mut _TEST_CONST_VISIBILITY: [u8; dirt_common::CACHE_ENTRIES_MAX] = [0; dirt_common::CACHE_ENTRIES_MAX]; // Test

#[inline(always)]
fn debug_dump_stack(ctx: *mut core::ffi::c_void, func: *const u8) {
    unsafe {
        let buf_size_bytes = dirt_common::MAX_STACK_TRACE_DEPTH * core::mem::size_of::<i64>();
        let kstacklen = bpf_get_stack( // kstacklen is i64 (bytes read)
            ctx,
            DEBUG_STACK.as_mut_ptr() as *mut _,
            buf_size_bytes as u32, // Cast to u32 for bpf_get_stack
            0,
        );

        if kstacklen > 0 {
            let bytes_per_entry = core::mem::size_of::<i64>() as i64;
            let num_stack_entries_read = if bytes_per_entry > 0 { kstacklen / bytes_per_entry } else { 0 };

            bpf_printk!(
                b"KERNEL STACK (%u): %s\0",
                num_stack_entries_read as u32,
                func,
            );

            for cnt in 0..dirt_common::MAX_STACK_TRACE_DEPTH { // cnt is usize
                if (cnt as i64) < num_stack_entries_read {
                    bpf_printk!(b"  %pB\0", &DEBUG_STACK[cnt] as *const i64);
                } else {
                    break;
                }
            }
        }
    }
}

fn debug_file_is_tp(filename: *const u8) -> bool {
    let tp = b"trace_pipe";
    unsafe {
        if !filename.is_null() {
            for cnt in 0..dirt_common::DBG_LEN_MAX { // Qualified
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
            return DEBUG_FILTER[0] == b'q' && DEBUG_FILTER[1] == 0; // Use DEBUG_FILTER
        }

        if DEBUG_FILTER[0] != b'*' { // Use DEBUG_FILTER
            for cnt in 0..dirt_common::DBG_LEN_MAX { // Qualified
                if *comm.add(0) == 0 || *comm.add(cnt) != DEBUG_FILTER[cnt] { // Use DEBUG_FILTER
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
