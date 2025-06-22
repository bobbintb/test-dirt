#![no_std]
#![no_main]

use aya_ebpf::{macros::kretprobe, programs::RetProbeContext};
use aya_log_ebpf::info;

#[kretprobe]
pub fn dirt1(ctx: RetProbeContext) -> u32 {
    match try_dirt1(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_dirt1(ctx: RetProbeContext) -> Result<u32, u32> {
    info!(&ctx, "kretprobe called");
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
