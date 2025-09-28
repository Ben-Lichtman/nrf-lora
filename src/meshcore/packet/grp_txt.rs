use defmt::Format;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

#[derive(Clone, FromBytes, IntoBytes, KnownLayout, Immutable, Format)]
#[repr(C)]
pub struct GrpTextHeader {
	pub channel_hash: u8,
	pub mac: [u8; 2],
}
