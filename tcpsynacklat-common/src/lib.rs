#![no_std]

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
