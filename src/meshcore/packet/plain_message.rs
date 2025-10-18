use crate::meshcore::packet::U32;
use defmt::{Format, write, *};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

#[derive(Clone, FromBytes, IntoBytes, KnownLayout, Immutable, Format)]
#[repr(C)]
pub struct PlainMessageHeader {
	pub timestamp: U32,
	pub flags: MessageFlags,
}

#[derive(Clone, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(transparent)]
pub struct MessageFlags(u8);

impl MessageFlags {
	pub fn as_raw(&self) -> u8 { self.0 }
}

impl Format for MessageFlags {
	fn format(&self, fmt: Formatter) {
		write!(fmt, "{:x}", self.0);
	}
}
