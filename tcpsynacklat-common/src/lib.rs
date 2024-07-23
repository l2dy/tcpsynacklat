#![no_std]

pub const TASK_COMM_LEN: usize = 16;

#[derive(Clone, Copy)]
#[repr(C)]
pub enum PacketDirection {
    TX,
    RX,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct TcpHandshakeKey {
    pub peer_addr: u32,
    pub local_addr: u32,
    pub peer_port: u16,
    pub local_port: u16,
    pub syn_seq: u32,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct TcpHandshakeEvent {
    pub key: TcpHandshakeKey,
    pub direction: PacketDirection,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct Config {
    pub milliseconds_precision: bool,
    pub port: u16,
    pub comm: [u8; TASK_COMM_LEN],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Config {}

pub const DIST_BUCKET_SIZE: u32 = 64;
