use crate::error::{Error, Result};
use defmt::*;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

pub mod advert;

fn try_split_at<T>(slice: &[T], index: usize) -> Option<(&[T], &[T])> {
	(slice.len() >= index).then(|| slice.split_at(index))
}

#[derive(Clone, Format)]
#[repr(u8)]
pub enum RouteType {
	Reserved1 = 0b00,
	Flood = 0b01,
	Direct = 0b10,
	Reserved2 = 0b11,
}

#[derive(Clone, Format)]
#[repr(u8)]
pub enum PayloadType {
	Req = 0x0,
	Resp = 0x1,
	Txt = 0x2,
	Ack = 0x3,
	Advert = 0x4,
	GrpText = 0x5,
	GrpData = 0x6,
	AnonReq = 0x7,
	Path = 0x8,
	RawCustom = 0xf,
}

#[derive(Clone, Format)]
#[repr(u8)]
pub enum PayloadVersion {
	Ver1 = 0b00,
	Ver2 = 0b01,
	Ver3 = 0b10,
	Ver4 = 0b11,
}

#[derive(Clone, FromBytes, IntoBytes, KnownLayout, Immutable, Debug, Format)]
#[repr(C)]
pub struct PacketFlags(pub u8);

impl PacketFlags {
	pub fn new(
		route_type: RouteType,
		payload_type: PayloadType,
		payload_version: PayloadVersion,
	) -> Self {
		let header =
			((payload_version as u8) << 6) | ((payload_type as u8) << 2) | (route_type as u8);
		Self(header)
	}

	pub fn route_type(&self) -> RouteType {
		match self.0 & 0b11 {
			0b00 => RouteType::Reserved1,
			0b01 => RouteType::Flood,
			0b10 => RouteType::Direct,
			0b11 => RouteType::Reserved2,
			_ => defmt::unreachable!(),
		}
	}

	pub fn payload_type(&self) -> Result<PayloadType> {
		let payload_type = match (self.0 >> 2) & 0xf {
			0x0 => PayloadType::Req,
			0x1 => PayloadType::Resp,
			0x2 => PayloadType::Txt,
			0x3 => PayloadType::Ack,
			0x4 => PayloadType::Advert,
			0x5 => PayloadType::GrpText,
			0x6 => PayloadType::GrpData,
			0x7 => PayloadType::AnonReq,
			0x8 => PayloadType::Path,
			0xf => PayloadType::RawCustom,
			_ => return Err(Error::PacketParse),
		};
		Ok(payload_type)
	}

	pub fn payload_version(&self) -> PayloadVersion {
		match (self.0 >> 6) & 0b11 {
			0b00 => PayloadVersion::Ver1,
			0b01 => PayloadVersion::Ver2,
			0b10 => PayloadVersion::Ver3,
			0b11 => PayloadVersion::Ver4,
			_ => defmt::unreachable!(),
		}
	}
}

#[derive(Clone, FromBytes, IntoBytes, KnownLayout, Immutable, Debug, Format)]
#[repr(C)]
pub struct PacketHeader {
	pub flags: PacketFlags,
	pub path_len: u8,
}

#[derive(Clone, Debug)]
pub struct Packet<'a> {
	pub header: PacketHeader,
	pub path: &'a [u8],
	pub payload: &'a [u8],
}

impl<'a> Packet<'a> {
	pub fn from_bytes(bytes: &'a [u8]) -> Result<Self> {
		let (header, tail) = PacketHeader::ref_from_prefix(bytes).map_err(|_| Error::ZeroCopy)?;
		let (path, payload) = try_split_at(tail, header.path_len as _).ok_or(Error::PacketParse)?;

		info!("header: {:02x}", header);
		info!("path: {:02x}", path);
		info!("payload: {:02x}", payload);

		let packet = Self {
			header: header.clone(),
			path,
			payload,
		};

		Ok(packet)
	}
}
