use crate::{
	error::{Error, Result},
	meshcore::SIGNATURE_SIZE,
};
use core::ops::BitOr;
use defmt::*;
use zerocopy::{
	FromBytes, Immutable, IntoBytes, KnownLayout,
	little_endian::{U16, U32},
};

#[derive(Clone, Format)]
#[repr(u8)]
pub enum AdvType {
	None = 0b00,
	Chat = 0b01,
	Repeater = 0b10,
	Room = 0b11,
}

#[derive(Clone, FromBytes, IntoBytes, KnownLayout, Immutable, Debug, Format)]
#[repr(C)]
pub struct AdvertFlags(u8);

impl BitOr for AdvertFlags {
	type Output = Self;

	fn bitor(self, rhs: Self) -> Self::Output { Self(self.0 | rhs.0) }
}

impl AdvertFlags {
	pub const LATLONG: Self = Self(0x10);

	pub const BATTERY: Self = Self(0x20);

	pub const TEMPERATURE: Self = Self(0x40);

	pub const NAME: Self = Self(0x80);

	pub fn from(byte: u8) -> Self { Self(byte) }

	pub fn from_adv_type(ty: AdvType) -> Self { Self(ty as u8) }

	pub fn contains(&self, flags: AdvertFlags) -> bool { self.0 & flags.0 != 0 }

	pub fn as_raw(&self) -> u8 { self.0 }
}

#[derive(Clone, FromBytes, IntoBytes, KnownLayout, Immutable, Debug)]
#[repr(C)]
pub struct AdvertHeader {
	pub pub_key: [u8; 32],
	pub timestamp: U32,
	pub signature: [u8; SIGNATURE_SIZE],
	pub flags: AdvertFlags,
}

#[derive(Clone, FromBytes, IntoBytes, KnownLayout, Immutable, Debug)]
#[repr(C)]
pub struct LatLong {
	pub lat: U32,
	pub long: U32,
}

#[derive(Clone, FromBytes, IntoBytes, KnownLayout, Immutable, Debug)]
#[repr(C)]
pub struct Battery(pub U16);

#[derive(Clone, FromBytes, IntoBytes, KnownLayout, Immutable, Debug)]
#[repr(C)]
pub struct Temperature(pub U16);

#[derive(Clone, Debug)]
pub struct Advert<'a> {
	pub header: AdvertHeader,
	pub lat_long: Option<LatLong>,
	pub battery: Option<Battery>,
	pub temperature: Option<Temperature>,
	pub name: Option<&'a [u8]>,
}

impl<'a> Advert<'a> {
	pub fn from_bytes(payload: &'a [u8]) -> Result<(Self, &'a [u8])> {
		let (header, mut body) =
			AdvertHeader::ref_from_prefix(payload).map_err(|_| Error::ZeroCopy)?;

		let mut lat_long = None;
		let mut battery = None;
		let mut temperature = None;
		let mut name = None;

		let flags = header.flags.clone();
		if flags.contains(AdvertFlags::LATLONG) {
			let (x, tail) = LatLong::ref_from_prefix(body).unwrap();
			lat_long = Some(x.clone());
			body = tail;
		}
		if flags.contains(AdvertFlags::BATTERY) {
			let (x, tail) = Battery::ref_from_prefix(body).unwrap();
			battery = Some(x.clone());
			body = tail;
		}
		if flags.contains(AdvertFlags::TEMPERATURE) {
			let (x, tail) = Temperature::ref_from_prefix(body).unwrap();
			temperature = Some(x.clone());
			body = tail;
		}
		if flags.contains(AdvertFlags::NAME) {
			name = Some(body);
			body = &[];
		}

		let advert = Self {
			header: header.clone(),
			lat_long,
			battery,
			temperature,
			name,
		};

		info!("Got advert: {}", Debug2Format(&advert));

		Ok((advert, body))
	}
}
