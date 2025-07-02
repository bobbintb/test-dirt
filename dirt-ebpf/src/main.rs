#![no_std]
#![no_main]
mod vmlinux;
use vmlinux::*;
use core::{ptr, mem};
use core::mem::size_of;
use core::panic::PanicInfo;
use dirt_common::kprobe_switch;
use dirt_common::constants::*;
use dirt_common::constants::key_pid_ino;
use dirt_common::constants::IndexFsEvent::*;
use aya_ebpf::{
    helpers::{bpf_get_stack, bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_printk, bpf_probe_read_kernel_str_bytes},
    macros::{kprobe, kretprobe, map},
    maps::{Array, LruHashMap, PerCpuArray, RingBuf},
    programs::{ProbeContext, RetProbeContext},
};
use aya_ebpf::EbpfContext; // Used for ctx.as_ptr()

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

/* bpf maps */

#[map(name = "ringbuf_records")]
static mut RINGBUF_RECORDS: RingBuf = RingBuf::with_byte_size(
    (core::mem::size_of::<RECORD_FS>() * 8192) as u32,
    0,
);

#[map(name = "hash_records")]
static mut HASH_RECORDS: LruHashMap<u64, RECORD_FS> = LruHashMap::with_max_entries(
    MAP_RECORDS_MAX as u32,
    0,
);

#[map(name = "heap_record_fs")]
static mut HEAP_RECORD_FS: PerCpuArray<RECORD_FS> = PerCpuArray::with_max_entries(1, 0);

#[map(name = "stats")]
static mut STATS_MAP: Array<STATS> = Array::with_max_entries(1, 0);

/* global variables shared with userspace */
type PidT = u32;
#[no_mangle]
pub static mut ts_start: u64 = 0;
#[no_mangle]
pub static mut agg_events_max: u32 = 0;
#[no_mangle]
pub static mut pid_self: PidT = 0;
#[no_mangle]
pub static mut pid_shell: PidT = 0;
#[no_mangle]
pub static mut monitor: u32 = MONITOR_NONE;
/* debug */
#[no_mangle]
pub static mut debug: [u8; DBG_LEN_MAX] = [0; DBG_LEN_MAX];

#[repr(C)]
pub struct FsEventInfo {
    pub index: IndexFsEvent,
    pub dentry: *mut dentry,
    pub dentry_old: *mut dentry,
    pub func: *const i8,
}

unsafe fn handle_fs_event(_ctx: *mut core::ffi::c_void, event: &FsEventInfo) -> i32 {
    let dentry_ptr: *mut dentry = event.dentry;
    let dentry_old_ptr: *mut dentry = event.dentry_old;

    let inode_ptr_val: *mut inode;
    let mut local_filename_buffer = [0u8; FILENAME_LEN_MAX];
    let imode_val: umode_t;
    let ts_event_val: u64 = bpf_ktime_get_ns();
    let mut current_path_offset: u32 = 0;
    let key_val: u64;
    let current_event_idx: IndexFsEvent = event.index;
    let ino_val: u64;

    if current_event_idx == IAccess || current_event_idx == IAttrib {
        return 0;
    }

    let pid_val = (bpf_get_current_pid_tgid() >> 32) as PidT;
    if pid_val == pid_self {
        return 0;
    }

    if dentry_ptr.is_null() { return 0; }

    inode_ptr_val = if !dentry_old_ptr.is_null() {
        (*dentry_old_ptr).d_inode
    } else {
        (*dentry_ptr).d_inode
    };

    if inode_ptr_val.is_null() { return 0; }

    let name_ptr_char = (*dentry_ptr).d_name.name;
    if name_ptr_char.is_null() { return 0; }
    let read_res_alt = bpf_probe_read_kernel_str_bytes(name_ptr_char as *const u8, &mut local_filename_buffer);
    // Assuming compiler is correct about Result<&[u8], i64> for now & trying workaround.
    if read_res_alt.is_err() || read_res_alt.map(|s| s.len()).unwrap_or(0) == 0 {
        return 0;
    }

    ino_val = (*inode_ptr_val).i_ino;
	imode_val = (*inode_ptr_val).i_mode;
    if ino_val == 0 { return 0; } // Check after reading ino_val

    if !(s_isreg(imode_val as u32) || s_islnk(imode_val as u32)) {
        return 0;
    }

    key_val = key_pid_ino(pid_val, ino_val);

    let r_opt = HASH_RECORDS.get_ptr_mut(&key_val);
    let s_ptr_mut_opt = STATS_MAP.get_ptr_mut(0); // s_ptr_mut_opt is Option<*mut STATS>

    if let Some(rec_raw_ptr) = r_opt {
        let rec = &mut *rec_raw_ptr;
        if FSEVT[current_event_idx as usize].value == FS_MOVED_TO {
            (*rec.filename_union.filenames).filename_to = [0i8; FILENAME_LEN_MAX / 2];
        }
        rec.rc.ts = ts_event_val;
    } else {
        let rec_ptr_heap_opt = HEAP_RECORD_FS.get_ptr_mut(0);
        if rec_ptr_heap_opt.is_none() { // This check is for Option<*mut T>
            return 0;
        }
        let r_mut_ref: &mut RECORD_FS = &mut *(rec_ptr_heap_opt.unwrap()); // Unwrap Option<*mut T> to *mut T then deref to &mut T

        r_mut_ref.rc.ts = ts_event_val;
        r_mut_ref.ino = ino_val as u32;
        r_mut_ref.filename_union.filename = [0i8; FILENAME_LEN_MAX];

        let name_to_read_ptr = (*dentry_ptr).d_name.name as *const u8;
        let dest_filename_u8_slice: &mut [u8] =
            core::slice::from_raw_parts_mut((&mut r_mut_ref.filename_union.filename) as *mut _ as *mut u8, FILENAME_LEN_MAX);
        // Assuming compiler is correct about Result<&[u8], i64> for now.
        // Result is assigned to _, so specific handling of its value might not be immediately necessary here,
        // but the type inference must match what the compiler expects.
        let _ = bpf_probe_read_kernel_str_bytes(name_to_read_ptr, dest_filename_u8_slice);

        r_mut_ref.isize_first = (*inode_ptr_val).i_size as u64;

        let mut current_dentry_traversal = dentry_ptr;
        let mut path_nodes_count: u32 = 0;
        let mut pathnode_temp_buffer: [*const u8; FILEPATH_NODE_MAX] = [ptr::null(); FILEPATH_NODE_MAX];

        while path_nodes_count < FILEPATH_NODE_MAX as u32 {
            if (*current_dentry_traversal).d_name.name.is_null() ||
               (*current_dentry_traversal).d_parent.is_null() ||
               (*(*current_dentry_traversal).d_inode).i_ino == 0 { break; }

            pathnode_temp_buffer[path_nodes_count as usize] = (*current_dentry_traversal).d_name.name as *const u8;

            let parent_dentry = (*current_dentry_traversal).d_parent;
            if parent_dentry == current_dentry_traversal { break; }
            if (*parent_dentry).d_inode.is_null() { break; }

            current_dentry_traversal = parent_dentry;
            path_nodes_count += 1;
        }

        r_mut_ref.filepath = [0i8; FILEPATH_LEN_MAX];
        current_path_offset = 0;

        for i_idx in (0..path_nodes_count).rev() {
            let current_offset_usize = current_path_offset as usize;
            let node_idx = i_idx as usize;

            if !pathnode_temp_buffer[node_idx].is_null() && current_offset_usize < FILEPATH_LEN_MAX {
                let src_name_ptr = pathnode_temp_buffer[node_idx];
                let filepath_base_ptr: *mut i8 = (&mut r_mut_ref.filepath) as *mut _ as *mut i8;
                let max_len_to_copy = FILEPATH_LEN_MAX - current_offset_usize;

                if max_len_to_copy > 0 {
                    let dest_slice_u8: &mut [u8] =
                        core::slice::from_raw_parts_mut(filepath_base_ptr.add(current_offset_usize) as *mut u8, max_len_to_copy);

                    let bytes_copied_res_alt = bpf_probe_read_kernel_str_bytes(src_name_ptr, dest_slice_u8);
                    // Assuming compiler is correct about Result<&[u8], i64> for now & trying workaround.
                    let len_copied: usize = bytes_copied_res_alt.map(|s| s.len()).unwrap_or(0);

                    if len_copied > 0 {
                        current_path_offset += len_copied as u32;
                        if i_idx != 0 && (current_path_offset as usize) < FILEPATH_LEN_MAX {
                            r_mut_ref.filepath[current_path_offset as usize] = b'/' as i8;
                            current_path_offset += 1;
                        }
                    } else { break; }
                } else { break; }
            } else { break; }
        }

        r_mut_ref.events = 0;
        r_mut_ref.event = [0; FS_EVENT_MAX];
        r_mut_ref.inlink = 0;

        if let Some(s_ptr) = s_ptr_mut_opt { // s_ptr is *mut STATS
            (*s_ptr).fs_records += 1;
        }
    }

    if let Some(s_ptr) = s_ptr_mut_opt { // s_ptr is *mut STATS
        (*s_ptr).fs_events += 1;
    }

    let r_rec_ref = &mut *HASH_RECORDS.get_ptr_mut(&key_val).unwrap();
    r_rec_ref.imode = imode_val as u32;
    r_rec_ref.isize = (*inode_ptr_val).i_size as u64;
    r_rec_ref.inlink = (*inode_ptr_val).__bindgen_anon_1.i_nlink;
    if current_event_idx == ICreate && !dentry_old_ptr.is_null() {
        r_rec_ref.inlink += 1;
    }

    // Time fields commented out
    // r_rec_ref.atime_nsec = ...
    // r_rec_ref.mtime_nsec = ...
    // r_rec_ref.ctime_nsec = ...

    r_rec_ref.events += 1;
    r_rec_ref.event[current_event_idx as usize] += 1;

    if HASH_RECORDS.insert(&key_val, r_rec_ref, 0).is_err() {
        return 0;
    }

    let mut agg_end_flag = false;
	if current_event_idx == ICloseWrite
		|| current_event_idx == ICloseNowrite
		|| current_event_idx == IDelete
		|| current_event_idx == IMovedTo
		|| (current_event_idx == ICreate && (s_islnk(imode_val as u32) || r_rec_ref.inlink > 1))
	{
		agg_end_flag = true;
	}

    if !agg_end_flag && agg_events_max > 0 && r_rec_ref.events >= agg_events_max {
        agg_end_flag = true;
    }

    if agg_end_flag {
        r_rec_ref.rc.type_ = RECORD_TYPE_FILE as u32;
        let record_to_output = *r_rec_ref;
        if RINGBUF_RECORDS
            .output(&record_to_output, 0)
            .is_err()
        {
            if let Some(s_ptr) = s_ptr_mut_opt { // s_ptr is *mut STATS
                (*s_ptr).fs_records_dropped += 1;
            }
        }

        if HASH_RECORDS.remove(&key_val).is_err() {
            // Log or handle
        }

        if let Some(s_ptr) = s_ptr_mut_opt { // s_ptr is *mut STATS
            (*s_ptr).fs_records_deleted += 1;
        }
    }

    if let Some(s_ptr) = s_ptr_mut_opt { // s_ptr is *mut STATS
        let s_ref = &mut *s_ptr; // s_ref is &mut STATS
        let mut rsz = mem::size_of::<RECORD_FS>();
        rsz += 8 - rsz % 8;
        if s_ref.fs_records == 1 {
            const RINGBUF_SIZE: u64 = (core::mem::size_of::<RECORD_FS>() * 8192) as u64;
            s_ref.fs_records_rb_max = RINGBUF_SIZE / rsz as u64;
        }
    }

    0
}
#[kretprobe]
pub fn do_filp_open(ctx: RetProbeContext) -> i32 {
    unsafe {
        kprobe_switch!(MONITOR_FILE);
        let filp: *mut file = ctx.ret().unwrap_or(ptr::null_mut());
        if filp.is_null() { return 0; }
        let f_mode = core::ptr::read_unaligned(&(*filp).f_mode);
        if f_mode & FMODE_CREATED != 0 {
            if (*filp).f_path.dentry.is_null() { return 0; }
            let dentry_val = core::ptr::read_unaligned(&(*filp).f_path.dentry);
            if dentry_val.is_null() { return 0; }
            let event = FsEventInfo {
                index: ICreate,
                dentry: dentry_val,
                dentry_old: core::ptr::null_mut(),
                func: b"do_filp_open\0".as_ptr() as *const i8,
            };
            handle_fs_event(ctx.as_ptr() as *mut core::ffi::c_void, &event)
        } else {
            0
        }
    }
}
#[kprobe]
pub fn security_inode_link(ctx: ProbeContext) -> i32 {
    unsafe {
        kprobe_switch!(MONITOR_FILE);
        let old_dentry_opt = ctx.arg::<*mut dentry>(0);
        let new_dentry_opt = ctx.arg::<*mut dentry>(2);
        let event = FsEventInfo {
            index: ICreate,
            dentry: new_dentry_opt.unwrap_or(ptr::null_mut()),
            dentry_old: old_dentry_opt.unwrap_or(ptr::null_mut()),
            func: b"security_inode_link\0".as_ptr() as *const i8,
        };
        handle_fs_event(ctx.as_ptr() as *mut core::ffi::c_void, &event)
    }
}

static mut DENTRY_SYMLINK: *mut dentry = core::ptr::null_mut();
#[kprobe]
pub fn security_inode_symlink(ctx: ProbeContext) -> i32 {
    unsafe {
        kprobe_switch!(MONITOR_FILE);
        DENTRY_SYMLINK = ctx.arg::<*mut dentry>(1).unwrap_or(ptr::null_mut());
        0
    }
}

#[kprobe]
pub fn dput(ctx: ProbeContext) -> i32 {
    unsafe {
        kprobe_switch!(MONITOR_FILE);
        let dentry_ptr = match ctx.arg::<*mut dentry>(0) {
            Some(p) if !p.is_null() => p,
            _ => return 0,
        };
        if (*dentry_ptr).d_inode.is_null() { return 0; }
        let imode_val = ptr::read_unaligned(&(*(*dentry_ptr).d_inode).i_mode);
        let ino_val   = ptr::read_unaligned(&(*(*dentry_ptr).d_inode).i_ino);
        if !(s_islnk(imode_val as u32) && ino_val != 0 && DENTRY_SYMLINK == dentry_ptr) {
            return 0;
        }
        DENTRY_SYMLINK = ptr::null_mut();
        let event = FsEventInfo {
            index: IndexFsEvent::ICreate,
            dentry:      dentry_ptr,
            dentry_old:  ptr::null_mut(),
            func:        b"dput+security_inode_symlink\0".as_ptr() as *const i8,
        };
        handle_fs_event(ctx.as_ptr() as *mut core::ffi::c_void, &event)
    }
}


#[kprobe]
pub fn __fsnotify_parent(ctx: ProbeContext) -> i32 {
    unsafe {
        kprobe_switch!(MONITOR_FILE);
        let dentry_ptr = match ctx.arg::<*mut dentry>(0) {
            Some(p) if !p.is_null() => p,
            _ => return 0,
        };
        let mask_val = ctx.arg::<u32>(1).unwrap_or(0);

        if mask_val & FS_ATTRIB != 0 {
            let event = FsEventInfo {
                index: IAttrib,
                dentry: dentry_ptr,
                dentry_old: ptr::null_mut(),
                func: b"__fsnotify_parent\0".as_ptr() as *const i8,
            };
            handle_fs_event(ctx.as_ptr() as *mut core::ffi::c_void, &event);
        }
        if mask_val & FS_MODIFY != 0 {
            let event = FsEventInfo {
                index: IModify,
                dentry: dentry_ptr,
                dentry_old: ptr::null_mut(),
                func: b"__fsnotify_parent\0".as_ptr() as *const i8,
            };
            handle_fs_event(ctx.as_ptr() as *mut core::ffi::c_void, &event);
        }
        if mask_val & FS_ACCESS != 0 {
            let event = FsEventInfo {
                index: IAccess,
                dentry: dentry_ptr,
                dentry_old: ptr::null_mut(),
                func: b"__fsnotify_parent\0".as_ptr() as *const i8,
            };
            handle_fs_event(ctx.as_ptr() as *mut core::ffi::c_void, &event);
        }
        0
    }
}
#[kprobe]
pub fn security_inode_rename(ctx: ProbeContext) -> i32 {
    unsafe {
        kprobe_switch!(MONITOR_FILE);
		let old_dentry_ptr = match ctx.arg::<*mut dentry>(1) {
            Some(p) if !p.is_null() => p,
            _ => return 0,
        };

		let flags = core::ptr::read_unaligned(&(*old_dentry_ptr).d_flags);
		if (flags & DCACHE_ENTRY_TYPE) == DCACHE_DIRECTORY_TYPE
			|| (flags & DCACHE_ENTRY_TYPE) == DCACHE_AUTODIR_TYPE
		{
			return 0;
		}

        let new_dentry_opt = ctx.arg::<*mut dentry>(3);
        let event_from = FsEventInfo {
            index: IMovedFrom,
            dentry: old_dentry_ptr,
            dentry_old: ptr::null_mut(),
            func: b"security_inode_rename\0".as_ptr() as *const i8,
        };
        handle_fs_event(ctx.as_ptr() as *mut core::ffi::c_void, &event_from);
        let event_to = FsEventInfo {
            index: IMovedTo,
            dentry: new_dentry_opt.unwrap_or(ptr::null_mut()),
            dentry_old: old_dentry_ptr,
            func: b"security_inode_rename\0".as_ptr() as *const i8,
        };
        handle_fs_event(ctx.as_ptr() as *mut core::ffi::c_void, &event_to);
        0
    }
}
#[kprobe]
pub fn security_inode_unlink(ctx: ProbeContext) -> i32 {
    unsafe {
        kprobe_switch!(MONITOR_FILE);
        let dentry_opt = ctx.arg::<*mut dentry>(1);
        let event = FsEventInfo {
            index: IDelete,
            dentry: dentry_opt.unwrap_or(ptr::null_mut()),
            dentry_old: ptr::null_mut(),
            func: b"security_inode_unlink\0".as_ptr() as *const i8,
        };
        handle_fs_event(ctx.as_ptr() as *mut core::ffi::c_void, &event)
    }
}
#[no_mangle]
static mut DEBUG_STACK: [i64; MAX_STACK_TRACE_DEPTH] = [0; MAX_STACK_TRACE_DEPTH];

#[inline(always)]
pub fn debug_dump_stack(ctx: &ProbeContext, func: &str) {
    let stack_size = MAX_STACK_TRACE_DEPTH * size_of::<i64>();
    let kstacklen : i64 = unsafe {
        bpf_get_stack(
            ctx.as_ptr() as *mut core::ffi::c_void,
            DEBUG_STACK.as_mut_ptr() as *mut _,
            stack_size as u32,
            0,
        )
    };

    if kstacklen > 0 {
        unsafe {
            bpf_printk!(
                b"KERNEL STACK (%u): %s\0",
                kstacklen as usize / size_of::<i64>(),
                func.as_ptr(),
            );
        }

        for i in 0..MAX_STACK_TRACE_DEPTH {
            if (kstacklen as usize) > i * size_of::<i64>() {
                let addr = unsafe { DEBUG_STACK[i] };
                unsafe {
                    bpf_printk!(b"  %pB\0", addr as *const core::ffi::c_void);
                }
            }
        }
    }
}
#[inline(always)]
unsafe fn debug_file_is_tp(filename: *const i8) -> bool {
    let tp = b"trace_pipe\0";
    if filename.is_null() {
        return false;
    }
    for i in 0..tp.len() {
        if *filename.add(i) != tp[i] as i8 {
            return false;
        }
    }
    true
}

#[inline(always)]
unsafe fn debug_proc(comm: *const i8, filename: *const i8) -> bool {
    if comm.is_null() {
        return debug[0] == b'q' && debug[1] == 0;
    }
    if debug[0] != b'*' {
        for i in 0..DBG_LEN_MAX {
            if *comm.add(i) == 0 || *comm.add(i) != debug[i] as i8 {
                return false;
            }
        }
    }
    !debug_file_is_tp(filename)
}
