use aya::{Ebpf, maps::{Array, RingBuf}, programs::KProbe, util::online_cpus};
use aya_log::EbpfLogger;
use chrono::{DateTime, Utc, TimeZone};
use clap::Parser;
use daemonize::Daemonize;
use dirt_common::{
    RecordFs, FsEventIndex,
    FILENAME_LEN_MAX, FILEPATH_LEN_MAX, FS_EVENT_MAX, S_IFLNK, S_IFREG, S_IFDIR, S_IFMT
};
use log::{debug, info, warn, error};
use serde::Serialize;
use serde_json::json;
use std::collections::HashMap as StdHashMap;
use std::fs::File;
use std::path::PathBuf; // Not strictly used in final version but often useful
use std::process::exit;
use std::sync::Arc;
use tokio::{net::UnixDatagram, signal, task};

/// eBPF-based process monitoring tool for file system events
#[derive(Parser, Debug, Clone)]
#[clap(author, version, about = "Monitors file system events using eBPF.", long_about = None)]
struct CliArgs {
    /// Max number of filesystem events per aggregated record until export
    #[clap(short, long, value_parser, default_value_t = 1)]
    agg_events: u32,

    /// Output format: "json" (pretty, default) or "json-min" (compact)
    #[clap(short = 'o', long, value_parser, default_value = "json")]
    json_output: String,

    /// Unix domain socket path to send json output to
    #[clap(short = 'x', long)]
    socket_path: Option<String>,

    /// Token specified on host to be included in json output
    #[clap(short = 'T', long)]
    token: Option<String>,

    /// Quiet mode to suppress output to stdout console
    #[clap(short, long, action = clap::ArgAction::SetTrue)]
    quiet: bool,

    /// Daemonize program to run in background
    #[clap(short, long, action = clap::ArgAction::SetTrue)]
    daemonize: bool,

    /// PID file path for daemon mode
    #[clap(long, default_value = "/var/run/dirt.pid")]
    pid_file: String,

    /// Working directory for daemon mode
    #[clap(long, default_value = "/")]
    working_directory: String,

    /// User to switch to in daemon mode
    #[clap(long)]
    user: Option<String>,

    /// Group to switch to in daemon mode
    #[clap(long)]
    group: Option<String>,

    /// Show legend of JSON output fields and exit
    #[clap(long, action = clap::ArgAction::SetTrue)]
    legend: bool,
}

#[derive(Serialize, Debug)]
struct OutputRecord {
    #[serde(rename = "InfoTimestamp")]
    info_timestamp: String,
    #[serde(rename = "FilePath")]
    file_path: String,
    #[serde(rename = "File")]
    file: String,
    #[serde(rename = "FileMode")]
    file_mode: String,
    #[serde(rename = "FileEventCount")]
    file_event_count: u32,
    #[serde(rename = "FileEvents")]
    file_events: serde_json::Value,
    #[serde(rename = "FileInode")]
    file_inode: u32,
    #[serde(rename = "FileInodeLinkCount")]
    file_inode_link_count: u32,
    #[serde(rename = "FileSize")]
    file_size: u64,
    #[serde(rename = "FileSizeChange")]
    file_size_change: i64,
    #[serde(rename = "FileAccessTime")]
    file_access_time: String,
    #[serde(rename = "FileStatusChangeTime")]
    file_status_change_time: String,
    #[serde(rename = "FileModificationTime")]
    file_modification_time: String,
    #[serde(rename = "Token", skip_serializing_if = "Option::is_none")]
    token: Option<String>,
}

fn c_array_to_string(arr: &[u8]) -> String {
    arr.iter().take_while(|&&c| c != 0).map(|&c| c as char).collect()
}

fn format_nsecs_to_iso(nsecs: u64) -> String {
    if nsecs == 0 { return String::from("N/A"); }
    let secs = nsecs / 1_000_000_000;
    let nanos = (nsecs % 1_000_000_000) as u32;
    Utc.timestamp_opt(secs as i64, nanos).unwrap_or_else(|| Utc::now()).to_rfc3339_opts(chrono::SecondsFormat::Nanos, true)
}

fn fs_event_index_to_name(index: usize) -> Option<&'static str> {
    match index {
        idx if idx == FsEventIndex::Create as usize => Some("CREATE"),
        idx if idx == FsEventIndex::Modify as usize => Some("MODIFY"),
        idx if idx == FsEventIndex::MovedFrom as usize => Some("MOVED_FROM"),
        idx if idx == FsEventIndex::MovedTo as usize => Some("MOVED_TO"),
        idx if idx == FsEventIndex::Delete as usize => Some("DELETE"),
        idx if idx == FsEventIndex::Access as usize => Some("ACCESS"),
        idx if idx == FsEventIndex::Open as usize => Some("OPEN"),
        idx if idx == FsEventIndex::OpenExec as usize => Some("OPEN_EXEC"),
        idx if idx == FsEventIndex::Attrib as usize => Some("ATTRIB"),
        idx if idx == FsEventIndex::CloseWrite as usize => Some("CLOSE_WRITE"),
        idx if idx == FsEventIndex::CloseNowrite as usize => Some("CLOSE_NOWRITE"),
        idx if idx == FsEventIndex::DeleteSelf as usize => Some("DELETE_SELF"),
        idx if idx == FsEventIndex::MoveSelf as usize => Some("MOVE_SELF"),
        idx if idx == FsEventIndex::Unmount as usize => Some("UNMOUNT"),
        idx if idx == FsEventIndex::QOverflow as usize => Some("Q_OVERFLOW"),
        _ => None,
    }
}

fn print_legend() {
    println!("dirt JSON Output Legend:");
    println!("{:<28} {}", "Field Name", "Description");
    println!("{:-<70}", ""); // Separator
    println!("{:<28} {}", "InfoTimestamp", "Message timestamp in UTC datetime format with nanoseconds");
    println!("{:<28} {}", "FilePath", "Directory path name of file (placeholder in eBPF)");
    println!("{:<28} {}", "File", "File name");
    println!("{:<28} {}", "FileMode", "Type of file: regular, symlink, hardlink, directory, other");
    println!("{:<28} {}", "FileEventCount", "Total number of aggregated file events in this record");
    println!("{:<28} {}", "FileEvents", "JSON object detailing types and counts of specific file events:");
    for i in 0..FS_EVENT_MAX { // Iterate up to FS_EVENT_MAX to show all possible events
        if let Some(name) = fs_event_index_to_name(i) {
            println!("  {:<26} {}", format!("└─ {}", name), format!("File event: {}", name));
        }
    }
    println!("{:<28} {}", "FileInode", "Inode number of the file");
    println!("{:<28} {}", "FileInodeLinkCount", "Number of hard links to the inode");
    println!("{:<28} {}", "FileSize", "File size in bytes at the time of the event");
    println!("{:<28} {}", "FileSizeChange", "Change in file size in bytes (current - initial at first event aggregation)");
    println!("{:<28} {}", "FileAccessTime", "Last access timestamp in UTC (from inode)");
    println!("{:<28} {}", "FileStatusChangeTime", "Last status change (metadata) timestamp in UTC (from inode)");
    println!("{:<28} {}", "FileModificationTime", "Last modification timestamp in UTC (from inode)");
    println!("{:<28} {}", "Token", "Optional user-provided token string");
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = CliArgs::parse();

    if args.legend {
        print_legend();
        exit(0);
    }

    // Initialize logger. For daemon, this might need adjustment to log to syslog or file.
    env_logger::init();

    if args.daemonize {
        if args.socket_path.is_none() && !args.quiet {
             warn!("Daemon mode typically used with -x (socket output) or -q (quiet stdout).");
        }

        let mut daemonize = Daemonize::new()
            .pid_file(args.pid_file.clone())
            .chown_pid_file(true)
            .working_directory(args.working_directory.clone())
            .umask(0o027);

        if let Some(user_name) = &args.user {
            daemonize = daemonize.user(user_name.as_str());
        }
        if let Some(group_name) = &args.group {
            daemonize = daemonize.group(group_name.as_str());
        }

        // In daemon mode, redirect stdout/stderr to /dev/null if not quiet.
        // If quiet, stdout is already suppressed later. stderr might still be useful for critical errors.
        // For robust daemon logging, consider using the 'syslog' crate or similar after daemonization.
        if !args.quiet { // If not quiet, daemon's stdout will be /dev/null. Stderr might still go somewhere or also /dev/null.
            let stdout = File::create("/dev/null")?;
            let stderr = File::create("/dev/null")?; // Or keep stderr for critical daemon errors
            daemonize = daemonize.stdout(stdout).stderr(stderr);
        }

        match daemonize.start() {
            Ok(_) => info!("Successfully daemonized dirt process."),
            Err(e) => {
                error!("Error daemonizing: {}", e);
                return Err(e.into());
            }
        }
    }

    // Bump the memlock rlimit.
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) } != 0 {
        // Log only if not in daemon mode or if logging is specifically configured for daemon
        if !args.daemonize {
            debug!("Failed to increase rlimit memlock (this might be okay if not root or already high).");
        }
    }

    // Prefer env!("OUT_DIR") for locating the eBPF object file.
    // Fallback to relative path if OUT_DIR is not set (e.g. not using build.rs properly for dirt-ebpf as build-dep)
    // For now, using the previously determined relative path as it was modified by a subtask.
    // The most robust solution involves dirt-ebpf being a proper build-dependency that sets OUT_DIR.
    let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/dirt-ebpf-probe"
    )))?;

    if let Err(e) = EbpfLogger::init(&mut ebpf) {
        if !args.daemonize { warn!("Failed to initialize eBPF logger: {}", e); }
    }

    let mut agg_events_max_map: Array<_, u32> =
        Array::try_from(ebpf.map_mut("AGG_EVENTS_MAX_MAP")?)?;
    let agg_val = if args.agg_events == 0 { 1 } else { args.agg_events }; // Treat CLI 0 as 1
    agg_events_max_map.set(0, agg_val, 0)?;
    if !args.daemonize { info!("Set AGG_EVENTS_MAX to {}", agg_val); }

    let kprobes_to_attach: &[(&str, &str)] = &[
        ("security_inode_create", "security_inode_create"),
        ("security_inode_unlink", "security_inode_unlink"),
        ("security_inode_rename", "security_inode_rename"),
        ("security_file_open", "security_file_open"),
        ("vfs_write_kprobe", "vfs_write"),
    ];

    for (prog_name, attach_to) in kprobes_to_attach {
        let prog: &mut KProbe = ebpf.program_mut(prog_name).unwrap().try_into()?;
        prog.load()?;
        prog.attach(attach_to, 0)?;
        if !args.daemonize { info!("Attached kprobe {} to {}", prog_name, attach_to); }
    }

    let uds_socket_and_path: Arc<Option<(UnixDatagram, String)>> = {
        if let Some(socket_path_str) = args.socket_path.as_ref() {
            match UnixDatagram::unbound() {
                Ok(socket) => {
                    if !args.daemonize { info!("Will send events to Unix socket: {}", socket_path_str); }
                    Arc::new(Some((socket, socket_path_str.clone())))
                }
                Err(e) => {
                    error!("Failed to create UnixDatagram socket: {}. Will not send to socket.", e);
                    Arc::new(None)
                }
            }
        } else {
            Arc::new(None)
        }
    };

    let mut events_rb = RingBuf::from_map(ebpf.map_mut("EVENTS")?)?;
    if !args.daemonize { info!("Waiting for events (Ctrl-C to exit)..."); }

    for cpu_id in online_cpus()? {
        let mut buf_reader = events_rb.open(cpu_id, None)?;
        let task_args = args.clone();
        let task_uds_socket_and_path = Arc::clone(&uds_socket_and_path);

        task::spawn(async move {
            let mut item_buffers = (0..10)
                .map(|_| vec![0u8; std::mem::size_of::<RecordFs>() + std::mem::size_of::<u64>()]) // Max possible size
                .collect::<Vec<_>>();

            loop {
                match buf_reader.read_blocking(&mut item_buffers) {
                    Ok(num_items_read) => {
                        for i in 0..num_items_read {
                            let raw_data = &item_buffers[i];
                            if raw_data.len() >= std::mem::size_of::<RecordFs>() {
                                let record_fs: &RecordFs = unsafe { &*(raw_data.as_ptr() as *const RecordFs) };

                                let file_events_map = {
                                    let mut map = StdHashMap::new();
                                    for (idx, &count) in record_fs.event.iter().enumerate().take(FS_EVENT_MAX) {
                                        if count > 0 {
                                            if let Some(name) = fs_event_index_to_name(idx) {
                                                map.insert(name, count);
                                            }
                                        }
                                    }
                                    json!(map)
                                };

                                let file_mode_str = if (record_fs.imode & S_IFMT) == S_IFLNK { "symlink" }
                                    else if (record_fs.imode & S_IFMT) == S_IFREG { if record_fs.inlink > 1 { "hardlink" } else { "regular" } }
                                    else if (record_fs.imode & S_IFMT) == S_IFDIR { "directory" }
                                    else { "other" };

                                let output_rec = OutputRecord {
                                    info_timestamp: format_nsecs_to_iso(record_fs.rc.ts),
                                    file_path: c_array_to_string(&record_fs.filepath),
                                    file: c_array_to_string(&record_fs.filename_union),
                                    file_mode: file_mode_str.to_string(),
                                    file_event_count: record_fs.events,
                                    file_events: file_events_map,
                                    file_inode: record_fs.ino,
                                    file_inode_link_count: record_fs.inlink,
                                    file_size: record_fs.isize,
                                    file_size_change: record_fs.isize as i64 - record_fs.isize_first as i64,
                                    file_access_time: format_nsecs_to_iso(record_fs.atime_nsec),
                                    file_status_change_time: format_nsecs_to_iso(record_fs.ctime_nsec),
                                    file_modification_time: format_nsecs_to_iso(record_fs.mtime_nsec),
                                    token: task_args.token.clone(),
                                };

                                let json_result = if task_args.json_output == "json-min" {
                                    serde_json::to_string(&output_rec)
                                } else {
                                    serde_json::to_string_pretty(&output_rec)
                                };

                                if let Ok(json_string) = json_result {
                                    if let Some((socket, path_str)) = task_uds_socket_and_path.as_ref() {
                                        if let Err(e) = socket.send_to(json_string.as_bytes(), path_str).await {
                                            if !task_args.daemonize { warn!("Failed to send to socket {}: {}", path_str, e); }
                                        }
                                    }
                                    if !task_args.quiet && !task_args.daemonize {
                                        println!("{}
", json_string); //  is RS (Record Separator)
                                    }
                                } else if let Err(e) = json_result {
                                     if !task_args.daemonize { warn!("CPU {}: Failed to serialize to JSON: {}", cpu_id, e); }
                                }
                            } else {
                                 if !task_args.daemonize { warn!("CPU {}: Undersized event data ({} bytes)", cpu_id, raw_data.len()); }
                            }
                        }
                    }
                    Err(e) => {
                         if !matches!(e, aya::maps::ring_buf::RingBufReaderError::RingBufNoSpace) {
                             if !task_args.daemonize { warn!("CPU {}: Error reading ring buffer: {:?}", cpu_id, e); }
                        }
                    }
                }
            }
        });
    }

    signal::ctrl_c().await?;
    if !args.daemonize { info!("Exiting..."); }
    Ok(())
}
