#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{xdp_action, BPF_NOEXIST, BPF_SOCK_OPS_TIMEOUT_INIT, BPF_TCP_SYN_SENT},
    helpers::bpf_ktime_get_ns,
    macros::{map, sock_ops, xdp},
    maps::{LruHashMap, PerCpuArray},
    programs::{SockOpsContext, XdpContext},
};
use aya_log_ebpf::{error, warn};
use tcpsynacklat_common::{PacketDirection, TcpHandshakeEvent, TcpHandshakeKey, DIST_BUCKET_SIZE};
use tcpsynacklat_ebpf::bpf_log2l;

use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
};

// value: timestamp in nanoseconds
#[map]
static START: LruHashMap<TcpHandshakeKey, u64> = LruHashMap::with_max_entries(1 << 14, 0);

#[map]
static DIST: PerCpuArray<u64> = PerCpuArray::with_max_entries(DIST_BUCKET_SIZE, 0);

#[xdp]
pub fn probe_tcp_synack(ctx: XdpContext) -> u32 {
    match try_probe_tcp_synack(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_probe_tcp_synack(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?;
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    let source_addr = u32::from_be(unsafe { (*ipv4hdr).src_addr });
    let destination_addr = u32::from_be(unsafe { (*ipv4hdr).dst_addr });

    let (source_port, destination_port, ack_seq) = match unsafe { (*ipv4hdr).proto } {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;

            unsafe {
                if (*tcphdr).syn() == 0 || (*tcphdr).ack() == 0 {
                    return Ok(xdp_action::XDP_PASS);
                }
            }

            (
                u16::from_be(unsafe { (*tcphdr).source }),
                u16::from_be(unsafe { (*tcphdr).dest }),
                u32::from_be(unsafe { (*tcphdr).ack_seq }),
            )
        }
        _ => return Ok(xdp_action::XDP_PASS),
    };

    let ts = unsafe { bpf_ktime_get_ns() };

    let event = TcpHandshakeEvent {
        key: TcpHandshakeKey {
            peer_addr: source_addr,
            local_addr: destination_addr,
            peer_port: source_port,
            local_port: destination_port,
            syn_seq: ack_seq - 1,
        },
        direction: PacketDirection::RX,
    };

    // Match SYN packet with 4-tuple and ack number.
    if let Some(start_ts) = unsafe { START.get(&event.key) } {
        let latency = ts - start_ts;

        if let Err(errno) = START.remove(&event.key) {
            error!(&ctx, "Unable to remove key from hash map, error {}", errno)
        }

        // If SYN packet is older than 2*MSL, ignore it.
        if latency > 60 * 1_000_000_000 {
            return Ok(xdp_action::XDP_PASS);
        }

        let bucket_index = bpf_log2l(latency / 1_000_000); // to milliseconds
        if let Some(bucket) = DIST.get_ptr_mut(bucket_index) {
            unsafe {
                *bucket += 1;
            }
        } else {
            error!(&ctx, "DIST.get_ptr_mut failed!");
            // fallthrough
        }
    }

    Ok(xdp_action::XDP_PASS)
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

// TCP connect

#[sock_ops]
pub fn probe_tcp_connect(ctx: SockOpsContext) -> u32 {
    // BPF_SOCK_OPS_TCP_CONNECT_CB does not expose `write_seq` yet.
    if ctx.op() == BPF_SOCK_OPS_TIMEOUT_INIT {
        let _ = try_probe_tcp_connect(ctx);
    }

    0 // <=0 to use default RTO
}

const AF_INET: u32 = 2;

fn try_probe_tcp_connect(ctx: SockOpsContext) -> Result<u32, u32> {
    if unsafe { (*ctx.ops).state } != BPF_TCP_SYN_SENT {
        return Ok(0);
    }
    if ctx.family() != AF_INET {
        return Ok(0);
    }

    // TODO: implement group by comm
    //match ctx.command() {
    //    Ok(comm) => {
    //        let _comm = unsafe { core::str::from_utf8_unchecked(&comm) };
    //    }
    //    Err(errno) => debug!(&ctx, "could not get comm, code:{}", errno),
    //}

    let source_addr = u32::from_be(ctx.local_ip4());
    let source_port = ctx.local_port() as u16; // local_port is stored in host byte order.
    let destination_addr = u32::from_be(ctx.remote_ip4());
    let destination_port = u32::from_be(ctx.remote_port()) as u16;
    let seq = unsafe { (*ctx.ops).snd_nxt };

    let event = TcpHandshakeEvent {
        key: TcpHandshakeKey {
            peer_addr: destination_addr,
            local_addr: source_addr,
            peer_port: destination_port,
            local_port: source_port,
            syn_seq: seq,
        },
        direction: PacketDirection::TX,
    };

    let ts = unsafe { bpf_ktime_get_ns() };
    if let Err(ret) = START.insert(&event.key, &ts, BPF_NOEXIST as u64) {
        if let Some(start_ts) = unsafe { START.get(&event.key) } {
            let latency = ts - start_ts;
            // If SYN packet is older than 2*MSL, replace it.
            if latency > 60 * 1_000_000_000 {
                if let Ok(_) = START.insert(&event.key, &ts, 0) {
                    return Ok(0);
                }
            }
        }
        warn!(&ctx, "insert to hash failed {}", ret)
    }

    Ok(0)
}
