pub mod crypto;
pub mod lora;
pub mod packet;

pub const PACKET_BUFFER_SIZE: usize = 256;
pub const MESHCORE_SYNCWORD: u8 = 0x12;

// pub const MAX_PACKET_PAYLOAD: usize = 184;
// pub const MAX_PATH_SIZE: usize = 64;
pub const SIGNATURE_SIZE: usize = 64;
