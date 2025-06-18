#![no_std]
#![no_main]

use aya_ebpf::{
    macros::kprobe,
    programs::ProbeContext, // Keep for now, might be needed by macro, or change to PtRegs if directly usable
    bindings::pt_regs,     // Import PtRegs
};
// use aya_log_ebpf::info; // Commenting out info for now

#[kprobe]
// pub fn dirt_test_clone(ctx: ProbeContext) -> u32 { // Old signature
pub fn dirt_test_clone(ctx: *const pt_regs) -> u32 { // New signature using raw pt_regs pointer
    match try_dirt_test_clone(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

// fn try_dirt_test_clone(_ctx: ProbeContext) -> Result<u32, u32> { // Old signature
fn try_dirt_test_clone(_ctx: *const pt_regs) -> Result<u32, u32> { // New signature
    // If we were to use ctx, it would be via unsafe dereference:
    // let pc = unsafe { (*ctx).pc };
    // info!(&ctx, "kprobe CLONE called at pc: {}", pc); // This would require info! and careful context wrapping for logging
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
