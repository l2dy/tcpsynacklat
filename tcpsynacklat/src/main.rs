use anyhow::Context;
use aya::maps::{PerCpuArray, PerCpuValues};
use aya::programs::{SockOps, Xdp, XdpFlags};
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use clap::Parser;
use log::{debug, info, warn};
use tcpsynacklat::print_log2_hist;
use tcpsynacklat_common::DIST_BUCKET_SIZE;
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
    #[clap(short, long, default_value = "/sys/fs/cgroup/unified")]
    cgroup_path: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/tcpsynacklat"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/tcpsynacklat"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let xdp_program: &mut Xdp = bpf.program_mut("probe_tcp_synack").unwrap().try_into()?;
    xdp_program.load()?;
    let xdp_link = xdp_program.attach(&opt.iface, XdpFlags::default())
           .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    let sockops_program: &mut SockOps = bpf.program_mut("probe_tcp_connect").unwrap().try_into()?;
    let cgroup = std::fs::File::open(opt.cgroup_path)?;
    sockops_program.load()?;
    let sockops_link = sockops_program.attach(cgroup)?;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;

    // detach programs
    let sockops_program: &mut SockOps = bpf.program_mut("probe_tcp_connect").unwrap().try_into()?;
    sockops_program.detach(sockops_link)?;
    let xdp_program: &mut Xdp = bpf.program_mut("probe_tcp_synack").unwrap().try_into()?;
    xdp_program.detach(xdp_link)?;

    const DIST_BUCKET_USIZE: usize = DIST_BUCKET_SIZE as usize;

    // print histogram
    let mut histogram_values: [u64; DIST_BUCKET_USIZE] = [0; DIST_BUCKET_USIZE];
    let array = PerCpuArray::try_from(bpf.map_mut("DIST").unwrap())?;
    for bucket_id in 0..DIST_BUCKET_SIZE {
        let values: PerCpuValues<u64> = array.get(&bucket_id, 0)?;

        let mut val = 0;
        for cpu_val in values.iter() {
            val += cpu_val;
        }

        histogram_values[bucket_id as usize] = val;
    }

    let mut out_buf = String::default();
    print_log2_hist(&histogram_values, "latency", &mut out_buf);
    println!("{}", out_buf);

    Ok(())
}
