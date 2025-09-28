use crate::meshcore::packet::U32;
use defmt::{Format, write, *};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

#[derive(Clone, FromBytes, IntoBytes, KnownLayout, Immutable, Format)]
#[repr(C)]
pub struct PlainMessageHeader {
	timestamp: U32,
	flags: MessageFlags,
}

#[derive(Clone, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct MessageFlags(u8);

impl Format for MessageFlags {
	fn format(&self, fmt: Formatter) {
		write!(fmt, "{:x}", self.0);
	}
}
