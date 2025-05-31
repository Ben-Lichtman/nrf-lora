use crate::error::{Error, Result};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use x25519_dalek::SharedSecret;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, FromBytes, IntoBytes, KnownLayout, Immutable, Debug)]
#[repr(C)]
pub struct TxtMsgHeader {
	pub dest_hash: u8,
	pub src_hash: u8,
	pub mac: [u8; 2],
}

impl TxtMsgHeader {
	pub fn check_mac(&self, shared: &SharedSecret, payload: &[u8]) -> Result<()> {
		let mut mac = <HmacSha256 as Mac>::new_from_slice(shared.as_bytes()).unwrap();
		mac.update(payload);
		let finished = mac.finalize().into_bytes();

		// This protocol only checks the first few bytes of the macs
		if finished.as_bytes()[..2] != self.mac {
			return Err(Error::InvalidMAC);
		}

		Ok(())
	}
}
