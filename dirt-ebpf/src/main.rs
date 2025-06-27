#![no_std]
#![no_main]
mod vmlinux;
use vmlinux::*;
use core::{ptr, mem};
use core::mem::size_of;
use core::panic::PanicInfo;
use dirt_common::kprobe_switch;
use dirt_common::constants::*;
use dirt_common::constants::IndexFsEvent::*;
use aya_ebpf::{
    helpers::{bpf_get_stack, bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_printk, bpf_probe_read_kernel_str_bytes},
    macros::{kprobe, kretprobe, map},
    maps::{Array, LruHashMap, PerCpuArray, RingBuf},
    programs::{ProbeContext, RetProbeContext},
};

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
static mut HEAP_RECORD_FS: PerCpuArray<RECORD_FS> = PerCpuArray::with_max_entries(1);

#[map(name = "stats")]
static mut STATS_MAP: Array<STATS> = Array::with_max_entries(1);
/* global variables shared with userspace */
type pid_t = i32;
#[no_mangle]
pub static mut ts_start: u64 = 0;
#[no_mangle]
pub static mut agg_events_max: u32 = 0;
#[no_mangle]
pub static mut pid_self: pid_t = 0;
#[no_mangle]
pub static mut pid_shell: pid_t = 0;
#[no_mangle]
pub static mut monitor: u32 = MONITOR_NONE;
/* debug */
#[no_mangle]
pub static mut debug: [u8; DBG_LEN_MAX] = [0; DBG_LEN_MAX];

#[repr(C)]
pub struct FsEventInfo {
    pub index: i32,
    pub dentry: *mut dentry,
    pub dentry_old: *mut dentry,
    pub func: *mut i8,
}
unsafe fn handle_fs_event(ctx: *mut core::ffi::c_void, event: &FsEventInfo) -> i32 {
    if event.index == IAccess || event.index == IAttrib {
        return 0;
    }

    let pid = (bpf_get_current_pid_tgid() >> 32) as i32;
    if pid == pid_self {
        return 0;
    }
	
	let index = event.index;
    let dentry = event.dentry;
    let dentry_old = event.dentry_old;
    let func = event.func;
    let inode_ptr = if !dentry_old.is_null() {
        dentry_old
    } else {
        dentry
    };
    let inode = unsafe { core::ptr::read_unaligned(&(*inode_ptr).d_inode) };
    let mut filename = [0u8; FILENAME_LEN_MAX];
    let name_ptr = unsafe { core::ptr::read_unaligned(&(*dentry).d_name.name) };
    let _ = unsafe { bpf_probe_read_kernel_str_bytes(&mut filename, name_ptr) };

    if inode.is_null() || filename[0] == 0 {
        return 0;
    }

    let ino = unsafe { core::ptr::read_unaligned(&(*inode).i_ino) };
    let imode = unsafe { core::ptr::read_unaligned(&(*inode).i_mode) };
    if !(S_ISREG(imode) || S_ISLNK(imode)) {
        return 0;
    }

    let key = KEY_PID_INO(pid, ino);
    let zero: u32 = 0;
    let ts_event = bpf_ktime_get_ns();
    let mut offset = 0;

    let r = HASH_RECORDS.get_mut(&key);
    let s = STATS_MAP.get_ptr_mut(0).as_mut();

    if let Some(rec) = r {
        if FSEVT[event.index as usize].value == crate::FS_MOVED_TO {
            rec.filename_to = [0; FILENAME_LEN_MAX];
            let name_ptr = unsafe { core::ptr::read_unaligned(&(*dentry).d_name.name) };
            let _ = unsafe { bpf_probe_read_kernel_str_bytes(&mut rec.filename_to, name_ptr) };
        }
        rec.rc.ts = ts_event;
    } else {
        let rec_ptr = HEAP_RECORD_FS.get_ptr_mut(0).as_mut();
        if rec_ptr.is_none() {
            return 0;
        }

        let r = rec_ptr.unwrap();
        r.rc.ts = ts_event;
        r.ino = ino;
        r.filename = [0; FILENAME_LEN_MAX];
        let name_ptr = unsafe { core::ptr::read_unaligned(&(*dentry).d_name.name) };
        let _ = unsafe { bpf_probe_read_kernel_str_bytes(&mut r.filename, name_ptr) };
        r.isize_first = unsafe { core::ptr::read_unaligned(&(*inode).i_size) };

        let mut d = dentry;
        let mut cnt = 0;
        let mut pathnode = [ptr::null(); FILEPATH_NODE_MAX];

        while cnt < FILEPATH_NODE_MAX {
            let dname = unsafe { core::ptr::read_unaligned(&(*d).d_name.name) };
            let dparent = unsafe { core::ptr::read_unaligned(&(*d).d_parent) };
            pathnode[cnt] = dname;

            let d_ino = unsafe { core::ptr::read_unaligned(&(*(*d).d_inode).i_ino) };
            let dparent_ino = unsafe { core::ptr::read_unaligned(&(*(*dparent).d_inode).i_ino) };
            if d_ino == dparent_ino {
                break;
            }

            d = dparent;
            cnt += 1;
        }

        let num_nodes = if cnt < FILEPATH_NODE_MAX { cnt } else { 0 };
        r.filepath = [0; FILENAME_LEN_MAX];

        for i in (1..=num_nodes).rev() {
            if !pathnode[i].is_null() && offset < FILENAME_LEN_MAX - DNAME_INLINE_LEN {
                let len =
                    bpf_probe_read_kernel_str_bytes(&mut r.filepath[offset..], pathnode[i] as *const u8)
                        .unwrap_or(0);

                if len > 0 && offset + len < FILENAME_LEN_MAX {
                    offset += len - 1;
                    if i != num_nodes {
                        r.filepath[offset] = b'/' as u8;
                        offset += 1;
                    }
                }
            }
        }

        r.events = 0;
        r.event = [0; crate::FS_EVENT_MAX];
        r.inlink = 0;

        if let Some(s) = s {
            s.fs_records += 1;
        }
    }

    if let Some(s) = s {
        s.fs_events += 1;
    }

    let r = HASH_RECORDS.get_mut(&key).unwrap();
    r.imode = imode;
    r.isize = unsafe { core::ptr::read_unaligned(&(*inode).i_size) };
    r.inlink = unsafe { core::ptr::read_unaligned(&(*inode).i_nlink) };
    if event.index == ICreate && !dentry_old.is_null() {
        r.inlink += 1;
    }

    r.atime_nsec = unsafe {
        core::ptr::read_unaligned(&(*inode).i_atime_sec) as u64 * 1_000_000_000
            + core::ptr::read_unaligned(&(*inode).i_atime_nsec) as u64
    };
    r.mtime_nsec = unsafe {
        core::ptr::read_unaligned(&(*inode).i_mtime_sec) as u64 * 1_000_000_000
            + core::ptr::read_unaligned(&(*inode).i_mtime_nsec) as u64
    };
    r.ctime_nsec = unsafe {
        core::ptr::read_unaligned(&(*inode).i_ctime_sec) as u64 * 1_000_000_000
            + core::ptr::read_unaligned(&(*inode).i_ctime_nsec) as u64
    };

    r.events += 1;
    r.event[event.index as usize] += 1;

    if HASH_RECORDS.insert(&key, r, 0).is_err() {
        return 0;
    }

    let mut agg_end = false;
	if index == ICloseWrite
		|| index == ICloseNowrite
		|| index == IDelete
		|| index == IMovedTo
		|| (index == ICreate && (S_ISLNK(imode) || r.inlink > 1))
	{
		agg_end = true;
	}

    if !agg_end && agg_events_max > 0 && r.events >= agg_events_max {
        agg_end = true;
    }

    if agg_end {
        r.rc.r#type = RECORD_TYPE_FILE;
        let output_len = mem::size_of::<RECORD_FS>();
        if RINGBUF_RECORDS
            .output(r as *const _ as *const u8, output_len, 0)
            .is_err()
        {
            if let Some(s) = s {
                s.fs_records_dropped += 1;
            }
        }

        if HASH_RECORDS.remove(&key).is_err() {
            return 0;
        }

        if let Some(s) = s {
            s.fs_records_deleted += 1;
        }
    }

    if let Some(s) = STATS_MAP.get_ptr_mut(0).as_mut() {
        let mut rsz = mem::size_of::<RECORD_FS>();
        rsz += 8 - rsz % 8;
        if s.fs_records == 1 {
            s.fs_records_rb_max = RINGBUF_RECORDS.ring_size() / rsz as u64;
        }
    }

    0
}
#[kretprobe]
pub fn do_filp_open(ctx: RetProbeContext) -> i32 {
    unsafe {
        kprobe_switch!(MONITOR_FILE);
        let filp: *mut file = ctx.ret() as *mut file;
        let f_mode = unsafe { core::ptr::read_unaligned(&(*filp).f_mode) };
        if f_mode & FMODE_CREATED != 0 {
            let dentry = unsafe { core::ptr::read_unaligned(&(*filp).f_path.dentry) };
            let event = FsEventInfo {
                index: ICreate,
                dentry,
                dentry_old: core::ptr::null_mut(),
                func: b"do_filp_open\0".as_ptr() as *mut i8,
            };
            handle_fs_event(ctx.as_ptr(), &event)
        } else {
            0
        }
    }
}
#[kprobe]
pub fn security_inode_link(ctx: ProbeContext) -> i32 {
    unsafe {
        kprobe_switch!(MONITOR_FILE);
        let old_dentry = ctx.arg::<*mut dentry>(0);
        let new_dentry = ctx.arg::<*mut dentry>(2);
        let event = FsEventInfo {
            index: ICreate,
            dentry: new_dentry,
            dentry_old: old_dentry,
            func: b"security_inode_link\0".as_ptr() as *mut i8,
        };
        handle_fs_event(ctx.as_ptr(), &event)
    }
}

static mut DENTRY_SYMLINK: *mut dentry = core::ptr::null_mut();
#[kprobe]
pub fn security_inode_symlink(ctx: ProbeContext) -> i32 {
    unsafe {
        kprobe_switch!(MONITOR_FILE);
        DENTRY_SYMLINK = ctx.arg::<*mut dentry>(1);
        0
    }
}

#[kprobe]
pub fn dput(ctx: ProbeContext) -> i32 {
    unsafe {
        kprobe_switch!(MONITOR_FILE);
        let dentry = ctx.arg::<*mut dentry>(0);
        let imode = unsafe { core::ptr::read_unaligned(&(*(*dentry).d_inode).i_mode) };
        let ino = unsafe { core::ptr::read_unaligned(&(*(*dentry).d_inode).i_ino) };
        if !(S_ISLNK(imode) && ino != 0 && DENTRY_SYMLINK == dentry) {
            return 0;
        }
        DENTRY_SYMLINK = ptr::null_mut();
        let event = FsEventInfo {
            index: ICreate,
            dentry,
            dentry_old: ptr::null_mut(),
            func: b"dput+security_inode_symlink\0".as_ptr() as *mut i8,
        };
        handle_fs_event(ctx.as_ptr(), &event)
    }
}

#[kprobe]
pub fn __fsnotify_parent(ctx: ProbeContext) -> i32 {
    unsafe {
        kprobe_switch!(MONITOR_FILE);
        let dentry = ctx.arg::<*mut dentry>(0);
        let mask = ctx.arg::<u32>(1);
        if mask & FS_ATTRIB != 0 {
            let event = FsEventInfo {
                index: IAttrib,
                dentry,
                dentry_old: ptr::null_mut(),
                func: b"__fsnotify_parent\0".as_ptr() as *mut i8,
            };
            handle_fs_event(ctx.as_ptr(), &event);
        }
        if mask & FS_MODIFY != 0 {
            let event = FsEventInfo {
                index: IModify,
                dentry,
                dentry_old: ptr::null_mut(),
                func: b"__fsnotify_parent\0".as_ptr() as *mut i8,
            };
            handle_fs_event(ctx.as_ptr(), &event);
        }
        if mask & FS_ACCESS != 0 {
            let event = FsEventInfo {
                index: IAccess,
                dentry,
                dentry_old: ptr::null_mut(),
                func: b"__fsnotify_parent\0".as_ptr() as *mut i8,
            };
            handle_fs_event(ctx.as_ptr(), &event);
        }
        0
    }
}
#[kprobe]
pub fn security_inode_rename(ctx: ProbeContext) -> i32 {
    unsafe {
        kprobe_switch!(MONITOR_FILE);
        let old_dentry = ctx.arg::<*mut dentry>(1);
        if {
            let flags = unsafe { core::ptr::read_unaligned(&(*old_dentry).d_flags) };
            (flags & DCACHE_ENTRY_TYPE) == DCACHE_DIRECTORY_TYPE
                || (flags & DCACHE_ENTRY_TYPE) == DCACHE_AUTODIR_TYPE
        } {
            return 0;
        }
        let new_dentry = ctx.arg::<*mut dentry>(3);
        let event_from = FsEventInfo {
            index: IMovedFrom,
            dentry: old_dentry,
            dentry_old: ptr::null_mut(),
            func: b"security_inode_rename\0".as_ptr() as *mut i8,
        };
        handle_fs_event(ctx.as_ptr(), &event_from);
        let event_to = FsEventInfo {
            index: IMovedTo,
            dentry: new_dentry,
            dentry_old: old_dentry,
            func: b"security_inode_rename\0".as_ptr() as *mut i8,
        };
        handle_fs_event(ctx.as_ptr(), &event_to);
        0
    }
}
#[kprobe]
pub fn security_inode_unlink(ctx: ProbeContext) -> i32 {
    unsafe {
        kprobe_switch!(MONITOR_FILE);
        let dentry = ctx.arg::<*mut dentry>(1);
        let event = FsEventInfo {
            index: IDelete,
            dentry,
            dentry_old: ptr::null_mut(),
            func: b"security_inode_unlink\0".as_ptr() as *mut i8,
        };
        handle_fs_event(ctx.as_ptr(), &event)
    }
}
#[no_mangle]
static mut DEBUG_STACK: [i64; MAX_STACK_TRACE_DEPTH] = [0; MAX_STACK_TRACE_DEPTH];

#[inline(always)]
pub fn debug_dump_stack(ctx: &ProbeContext, func: &str) {
    let stack_size = MAX_STACK_TRACE_DEPTH * size_of::<i64>();
    let kstacklen = unsafe {
        bpf_get_stack(
            ctx.as_ptr(),
            DEBUG_STACK.as_mut_ptr() as *mut _,
            stack_size as u32,
            0,
        )
    };

    if kstacklen > 0 {
        unsafe {
            bpf_printk!(
                b"KERNEL STACK (%u): %s\0",
                kstacklen / size_of::<i64>(),
                func.as_ptr(),
            );
        }

        for i in 0..MAX_STACK_TRACE_DEPTH {
            if (kstacklen as usize) > i * size_of::<i64>() {
                let addr = unsafe { DEBUG_STACK[i] };
                unsafe {
                    bpf_printk!(b"  %pB\0", addr as *const _);
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
