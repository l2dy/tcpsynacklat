#![no_std]

// https://github.com/geobeau/ebpf-histogram/blob/21f59e08256d8465b0b9d30e110032215e3bb766/ebpf-histogram-ebpf/src/lib.rs
// SPDX-License-Identifier: Apache-2.0

#[inline(always)]
fn bpf_log2(mut v: u32) -> u32 {
    let mut r: u32;
    let mut shift: u32;
    r = ((v > 0xFFFF) as u32) << 4;
    v >>= r;
    shift = ((v > 0xFF) as u32) << 3;
    v >>= shift;
    r |= shift;
    shift = ((v > 0xF) as u32) << 2;
    v >>= shift;
    r |= shift;
    shift = ((v > 0x3) as u32) << 1;
    v >>= shift;
    r |= shift;
    r |= v >> 1;
    r
}

/// Return the log2(v) ceiled
/// It should match the equivalent function in BCC
pub fn bpf_log2l(v: u64) -> u32 {
    let lo: u32 = (v & 0xFFFFFFFF) as u32;
    let hi: u32 = (v >> 32) as u32;

    if hi != 0 {
        bpf_log2(hi) + 32 + 1
    } else {
        bpf_log2(lo) + 1
    }
}
