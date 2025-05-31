use thiserror::Error;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
	#[error("Lora radio error: {0:?}")]
	RadioError(lora_phy::mod_params::RadioError),
	#[error("Zerocopy conversion error")]
	ZeroCopy,
	#[error("Packet parsing error")]
	PacketParse,
	#[error("Protobuf decode error: {0:?}")]
	ProtobufDecode(femtopb::error::DecodeError),
	#[error("Protobuf enccode error: {0:?}")]
	ProtobufEncode(femtopb::error::EncodeError),
	#[error("Invalid MAC")]
	InvalidMAC,
}
