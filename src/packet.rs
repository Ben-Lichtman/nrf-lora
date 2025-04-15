use core::ops::BitOr;
use defmt::Format;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

#[derive(Clone, FromBytes, IntoBytes, KnownLayout, Immutable, Format)]
#[repr(C)]
pub struct NodeID(u32);

impl NodeID {
	pub const BROADCAST: Self = Self(0xffffffff);

	pub const fn id(&self) -> u32 { self.0 }

	pub const fn from_id(id: u32) -> Self { Self(id) }
}

#[derive(Clone, FromBytes, IntoBytes, KnownLayout, Immutable, Format, Default)]
#[repr(C)]
pub struct Flags(u8);

impl BitOr for Flags {
	type Output = Self;

	fn bitor(self, rhs: Self) -> Self::Output { Self(self.0 | rhs.0) }
}

impl Flags {
	pub fn hop_limit(limit: u8) -> Self {
		debug_assert!(limit < 8);
		Self((limit & 0b111) << 5)
	}

	pub fn get_hop_limit(&self) -> u8 { (self.0 >> 5) & 0b111 }

	pub fn want_ack(ack: bool) -> Self { Self((ack as u8) << 4) }

	pub fn get_want_ack(&self) -> bool { (self.0 >> 4) & 1 != 0 }

	pub fn via_mqtt(mqtt: bool) -> Self { Self((mqtt as u8) << 3) }

	pub fn get_via_mqtt(&self) -> bool { (self.0 >> 3) & 1 != 0 }

	pub fn hop_start(start: u8) -> Self {
		debug_assert!(start < 8);
		Self(start & 0b111)
	}

	pub fn get_hop_start(&self) -> u8 { self.0 & 0b111 }
}

#[derive(Clone, FromBytes, IntoBytes, KnownLayout, Immutable, Format)]
#[repr(C)]
pub struct PacketHeader {
	pub dest: NodeID,
	pub sender: NodeID,
	pub packet_id: u32,
	pub flags: Flags,
	pub channel_hash: u8,
	pub next_hop: u8,
	pub relay_node: u8,
}

impl PacketHeader {
	pub const SIZE: usize = size_of::<Self>();
}
