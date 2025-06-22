#![no_std]
#![no_main]

mod constants;
use crate::constants::*;
use dirt_common::*;
use core::ffi::c_void;

use core::{mem, ptr, slice, cmp};

use aya_ebpf::{
    macros::{map, kprobe, kretprobe, bpf_printk},
    maps::{Array, PerCpuArray, LruHashMap, RingBuf},
    programs::{ProbeContext, RetProbeContext},
    bindings::{dentry, inode, BPF_ANY, BPF_RB_RING_SIZE, TC_ACT_OK},
    helpers::{
        bpf_get_current_pid_tgid,
        bpf_get_stack,
        bpf_ktime_get_ns,
        bpf_map_lookup_elem,
        bpf_map_update_elem,
        bpf_map_delete_elem,
        bpf_probe_read_kernel_str_bytes,
        bpf_ringbuf_output,
        bpf_ringbuf_query,
        bpf_core_read,
    },
};

// use aya_log_ebpf::info; // info! macro requires a program context.

// Map definitions
#[map(name = "ringbuf_records")]
static mut RINGBUF_RECORDS: RingBuf = RingBuf::new(); // Needs const initializer, but this is private.
                                                      // The #[map] macro handles the actual map definition.
                                                      // For static declaration, it just needs to be a type.
                                                      // Let's try without `::new()` if loader handles it.
// static mut RINGBUF_RECORDS: RingBuf; // This is what it should be if #[map] handles it fully.

#[map(name = "hash_records")]
static mut HASH_RECORDS: LruHashMap<u64, RecordFs> = LruHashMap::<u64, RecordFs>::with_max_entries(8192, 0);

#[map(name = "heap_record_fs")]
static mut HEAP_RECORD_FS: PerCpuArray<RecordFs> = PerCpuArray::<RecordFs>::with_max_entries(1, 0);

#[map(name = "stats")]
static mut STATS: Array<Stats> = Array::<Stats>::with_max_entries(1, 0);

#[inline(always)]
fn handle_fs_event(_ctx: *mut c_void, event_ptr: *const FsEventInfo) -> i32 {
    unsafe {
        let event = match (*event_ptr).as_ref() { // Original code had this, FsEventInfo is Copy
            Some(e) => e,
            None => return TC_ACT_OK,
        };

        if event.index == INDEX_FS_EVENT::I_ACCESS as u32 || event.index == INDEX_FS_EVENT::I_ATTRIB as u32 {
            return TC_ACT_OK;
        }

        let pid_tgid = bpf_get_current_pid_tgid();
        let pid = (pid_tgid >> 32) as u32;
        if PID_SELF > 0 && PID_SELF == pid {
            return TC_ACT_OK;
        }

        let index = event.index;
        let dentry_ptr = event.dentry as *const dentry;
        let dentry_old_ptr = event.dentry_old as *const dentry;

        let current_dentry_ptr = if !dentry_old_ptr.is_null() { dentry_old_ptr } else { dentry_ptr };
        if current_dentry_ptr.is_null() { return TC_ACT_OK; }

        let inode_ptr = bpf_core_read::<*const inode>(current_dentry_ptr as *const _, &b"d_inode\0"[0] as *const _).unwrap_or(ptr::null());
        if inode_ptr.is_null() { return TC_ACT_OK; }

        let mut filename_buffer = [0u8; FILENAME_LEN_MAX];
        let d_name_ptr = bpf_core_read::<*const u8>(dentry_ptr as *const _, &b"d_name.name\0"[0] as *const _).unwrap_or(ptr::null());
        if d_name_ptr.is_null() { return TC_ACT_OK; }

        match bpf_probe_read_kernel_str_bytes(d_name_ptr, &mut filename_buffer) {
            Ok(len) if len > 0 => {},
            _ => return TC_ACT_OK,
        }

        let ino = bpf_core_read::<u32>(inode_ptr as *const _, &b"i_ino\0"[0] as *const _).unwrap_or(0);
        let imode = bpf_core_read::<u32>(inode_ptr as *const _, &b"i_mode\0"[0] as *const _).unwrap_or(0);
        if ino == 0 || imode == 0 { return TC_ACT_OK; }

        if !(S_ISREG(imode) || S_ISLNK(imode)) {
            return TC_ACT_OK;
        }

        let key = key_pid_ino(pid, ino);
        let mut s_ptr_option = (bpf_map_lookup_elem(&STATS as *const _ as *mut _, &0u32 as *const _ as *const _) as *mut Stats).as_mut();

        let r_mut_ptr: &mut RecordFs = match (bpf_map_lookup_elem(&HASH_RECORDS as *const _ as *mut _, &key as *const _ as *const _) as *mut RecordFs).as_mut() {
            Some(r_existing) => {
                if FSEVT[index as usize].value == FS_MOVED_TO as i16 {
                    core::ptr::write_bytes(r_existing.filename_to.as_mut_ptr(), 0, r_existing.filename_to.len());
                    let d_name_ptr_move = bpf_core_read::<*const u8>(dentry_ptr as *const _, &b"d_name.name\0"[0] as *const _).unwrap_or(ptr::null());
                    bpf_probe_read_kernel_str_bytes(d_name_ptr_move, &mut r_existing.filename_to).unwrap_or(0);
                }
                r_existing.rc.ts = bpf_ktime_get_ns();
                r_existing
            }
            None => {
                let r_heap = match (bpf_map_lookup_elem(&HEAP_RECORD_FS as *const _ as *mut _, &0u32 as *const _ as *const _) as *mut RecordFs).as_mut() {
                    Some(rh) => rh,
                    None => return TC_ACT_OK,
                };

                r_heap.rc.ts = bpf_ktime_get_ns();
                r_heap.rc.pid = pid;
                r_heap.ino = ino;
                core::ptr::write_bytes(r_heap.filename.as_mut_ptr(), 0, r_heap.filename.len());
                let len_to_copy = filename_buffer.iter().position(|&x| x == 0).unwrap_or(FILENAME_LEN_MAX);
                r_heap.filename[..len_to_copy].copy_from_slice(&filename_buffer[..len_to_copy]);

                r_heap.isize_first = bpf_core_read::<u64>(inode_ptr as *const _, &b"i_size\0"[0] as *const _).unwrap_or(0);

                let mut current_path_dentry = dentry_ptr;
                let mut path_offset = FILEPATH_LEN_MAX;
                core::ptr::write_bytes(r_heap.filepath.as_mut_ptr(), 0, FILEPATH_LEN_MAX);

                for _idx_path in 0..FILEPATH_NODE_MAX {
                    if current_path_dentry.is_null() { break; }
                    let name_ptr = bpf_core_read::<*const u8>(current_path_dentry as *const _, &b"d_name.name\0"[0] as *const _).unwrap_or(ptr::null());
                    if name_ptr.is_null() { break; }

                    let mut component_buf = [0u8; DNAME_INLINE_LEN];
                    let len_res = bpf_probe_read_kernel_str_bytes(name_ptr, &mut component_buf);

                    if let Ok(len_val) = len_res {
                        if len_val == 0 { break; }
                        let actual_len = cmp::min(len_val, DNAME_INLINE_LEN);
                        if path_offset < actual_len { break; }

                        path_offset -= actual_len;
                        r_heap.filepath[path_offset..path_offset + actual_len].copy_from_slice(&component_buf[..actual_len]);

                        let parent_dentry = bpf_core_read::<*const dentry>(current_path_dentry as *const _, &b"d_parent\0"[0] as *const _).unwrap_or(ptr::null());
                        if parent_dentry == current_path_dentry || parent_dentry.is_null() { break; }

                        if path_offset > 0 {
                           path_offset -= 1;
                           r_heap.filepath[path_offset] = b'/';
                        } else { break; }
                        current_path_dentry = parent_dentry;
                    } else { break; }
                }

                if path_offset < FILEPATH_LEN_MAX {
                    let final_path_len = FILEPATH_LEN_MAX - path_offset;
                    r_heap.filepath.copy_within(path_offset.., 0);
                    if final_path_len < FILEPATH_LEN_MAX {
                        r_heap.filepath[final_path_len] = 0;
                    }
                } else {
                    r_heap.filepath[0] = 0;
                }

                r_heap.events = 0;
                for e_val in r_heap.event.iter_mut() { *e_val = 0; }
                r_heap.inlink = 0;

                if let Some(s) = s_ptr_option.as_mut() { s.fs_records = s.fs_records.saturating_add(1); }
                r_heap
            }
        };

        if let Some(s) = s_ptr_option.as_mut() { s.fs_events = s.fs_events.saturating_add(1); }

        r_mut_ptr.imode = imode;
        r_mut_ptr.isize = bpf_core_read::<u64>(inode_ptr as *const _, &b"i_size\0"[0] as *const _).unwrap_or(0);
        r_mut_ptr.inlink = bpf_core_read::<u32>(inode_ptr as *const _, &b"i_nlink\0"[0] as *const _).unwrap_or(0);

        if index == INDEX_FS_EVENT::I_CREATE as u32 && !dentry_old_ptr.is_null() {
            r_mut_ptr.inlink = r_mut_ptr.inlink.saturating_add(1);
        }

        let i_atime_sec = bpf_core_read::<i64>(inode_ptr as *const _, &b"i_atime.tv_sec\0"[0] as *const _).unwrap_or(0);
        let i_atime_nsec_val = bpf_core_read::<i64>(inode_ptr as *const _, &b"i_atime.tv_nsec\0"[0] as *const _).unwrap_or(0);
        r_mut_ptr.atime_nsec = (i_atime_sec as u64).wrapping_mul(1_000_000_000).wrapping_add(i_atime_nsec_val as u64);

        let i_mtime_sec = bpf_core_read::<i64>(inode_ptr as *const _, &b"i_mtime.tv_sec\0"[0] as *const _).unwrap_or(0);
        let i_mtime_nsec_val = bpf_core_read::<i64>(inode_ptr as *const _, &b"i_mtime.tv_nsec\0"[0] as *const _).unwrap_or(0);
        r_mut_ptr.mtime_nsec = (i_mtime_sec as u64).wrapping_mul(1_000_000_000).wrapping_add(i_mtime_nsec_val as u64);

        let i_ctime_sec = bpf_core_read::<i64>(inode_ptr as *const _, &b"i_ctime.tv_sec\0"[0] as *const _).unwrap_or(0);
        let i_ctime_nsec_val = bpf_core_read::<i64>(inode_ptr as *const _, &b"i_ctime.tv_nsec\0"[0] as *const _).unwrap_or(0);
        r_mut_ptr.ctime_nsec = (i_ctime_sec as u64).wrapping_mul(1_000_000_000).wrapping_add(i_ctime_nsec_val as u64);

        r_mut_ptr.events = r_mut_ptr.events.saturating_add(1);
        if (index as usize) < r_mut_ptr.event.len() {
             r_mut_ptr.event[index as usize] = r_mut_ptr.event[index as usize].saturating_add(1);
        }

        if bpf_map_update_elem(&HASH_RECORDS as *const _ as *mut _, &key as *const _ as *const _, r_mut_ptr as *const RecordFs as *const _, BPF_ANY as u64) < 0 {
            return TC_ACT_OK;
        }

        let mut agg_end = false;
        if index == INDEX_FS_EVENT::I_CLOSE_WRITE as u32 || index == INDEX_FS_EVENT::I_CLOSE_NOWRITE as u32 || index == INDEX_FS_EVENT::I_DELETE as u32 || index == INDEX_FS_EVENT::I_MOVED_TO as u32
            || (index == INDEX_FS_EVENT::I_CREATE as u32 && (S_ISLNK(imode) || r_mut_ptr.inlink > 1)) {
            agg_end = true;
        }

        if !agg_end && AGG_EVENTS_MAX != 0 && r_mut_ptr.events >= AGG_EVENTS_MAX {
            agg_end = true;
        }

        if agg_end {
            r_mut_ptr.rc.type_ = RECORD_TYPE_FILE;
            let output_len = core::mem::size_of_val(&*r_mut_ptr) as u32;
            if bpf_ringbuf_output(&RINGBUF_RECORDS as *const _ as *mut _, r_mut_ptr as *const RecordFs as *const _, output_len as u64, 0) != 0 {
                if let Some(s) = s_ptr_option.as_mut() {
                    s.fs_records_dropped = s.fs_records_dropped.saturating_add(1);
                }
            }
            let _ = bpf_map_delete_elem(&HASH_RECORDS as *const _ as *mut _, &key as *const _ as *const _);
            if let Some(s) = s_ptr_option.as_mut() {
                s.fs_records_deleted = s.fs_records_deleted.saturating_add(1);
            }
        }

        if let Some(s_val) = s_ptr_option {
            let mut rsz = core::mem::size_of_val(&*r_mut_ptr) as u64;
            rsz = rsz.wrapping_add(7) & !7u64;
            if s_val.fs_records == 1 {
                let ringbuf_size = bpf_ringbuf_query(&RINGBUF_RECORDS as *const _ as *mut _, BPF_RB_RING_SIZE as u64);
                if rsz > 0 {
                    s_val.fs_records_rb_max = ringbuf_size / rsz;
                } else {
                    s_val.fs_records_rb_max = 0;
                }
            }
        }
        TC_ACT_OK
    }
}

#[kretprobe]
pub fn do_filp_open(ctx: RetProbeContext) -> u32 {
    // Placeholder: Actual FsEventInfo construction is complex.
    // info!( & RetProbeContext::from(ctx), "kretprobe do_filp_open called, ret: {}", ctx.ret());
    TC_ACT_OK as u32
}

#[kprobe]
pub fn security_inode_link(ctx: ProbeContext) -> u32 {
    // info!(&ctx, "kprobe security_inode_link called");
    TC_ACT_OK as u32
}

#[kprobe]
pub fn security_inode_symlink(ctx: ProbeContext) -> u32 {
    // info!(&ctx, "kprobe security_inode_symlink called");
    TC_ACT_OK as u32
}

#[kprobe]
pub fn dput(ctx: ProbeContext) -> u32 {
    // info!(&ctx, "kprobe dput called");
    TC_ACT_OK as u32
}

#[kprobe]
pub fn notify_change(ctx: ProbeContext) -> u32 {
    // info!(&ctx, "kprobe notify_change called");
    TC_ACT_OK as u32
}

#[kprobe]
pub fn __fsnotify_parent(ctx: ProbeContext) -> u32 {
    // info!(&ctx, "kprobe __fsnotify_parent called");
    TC_ACT_OK as u32
}

#[kprobe]
pub fn security_inode_rename(ctx: ProbeContext) -> u32 {
    // info!(&ctx, "kprobe security_inode_rename called");
    TC_ACT_OK as u32
}

#[kprobe]
pub fn security_inode_unlink(ctx: ProbeContext) -> u32 {
    // info!(&ctx, "kprobe security_inode_unlink called");
    TC_ACT_OK as u32
}

static mut DEBUG_STACK: [i64; MAX_STACK_TRACE_DEPTH] = [0; MAX_STACK_TRACE_DEPTH];

#[inline(always)]
fn debug_dump_stack(ctx: *mut core::ffi::c_void, func_name_ptr: *const u8) {
    unsafe {
        let kstacklen = bpf_get_stack(
            ctx,
            DEBUG_STACK.as_mut_ptr() as *mut _,
            (MAX_STACK_TRACE_DEPTH * core::mem::size_of::<i64>()) as u32,
            0,
        );

        if kstacklen > 0 {
            bpf_printk!(
                b"KERNEL STACK (%u): %s\0".as_ptr() as *const i8,
                (kstacklen as u32 / (core::mem::size_of::<i64>() as u32)),
                func_name_ptr as *const i8
            );

            let num_frames = kstacklen / (core::mem::size_of::<i64>() as i64);
            for cnt in 0..cmp::min(num_frames as usize, MAX_STACK_TRACE_DEPTH) {
                 bpf_printk!(b"  %pB\0".as_ptr() as *const i8, DEBUG_STACK[cnt] as *const c_void);
            }
        }
    }
}

fn debug_file_is_tp(filename: *const u8) -> bool {
    let tp = b"trace_pipe\0";
    unsafe {
        if filename.is_null() { return false; }
        for i in 0..tp.len() {
            let fc = *filename.add(i);
            let tc = tp[i];
            if fc != tc { return false; }
            if tc == 0 { return true; }
        }
        return *filename.add(tp.len() -1) == 0;
    }
}

fn debug_proc(comm: *const u8, filename: *const u8) -> bool {
    unsafe {
        if comm.is_null() {
            return DEBUG_FILTER_COMM[0] == b'q' && DEBUG_FILTER_COMM[1] == 0;
        }

        if DEBUG_FILTER_COMM[0] != b'*' {
            let mut match_filter = true;
            for cnt in 0..DBG_LEN_MAX {
                let filter_char = DEBUG_FILTER_COMM[cnt];
                let comm_char = *comm.add(cnt);

                if filter_char == 0 { break; }
                if comm_char == 0 || comm_char != filter_char {
                    match_filter = false;
                    break;
                }
            }
            if !match_filter { return false; }
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
    unsafe { core::hint::unreachable_unchecked() }
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
