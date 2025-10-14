use crate::error::Result;
use aes::{
	Aes128Dec, Aes256Dec,
	cipher::{BlockDecryptMut, KeyInit},
};
use ed25519_dalek::{SigningKey, VerifyingKey, ed25519::signature::Signer};
use hmac::Mac;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};

const ED25519_PRIVATE_KEY_HARDCODED: [u8; 32] = [
	0x5b, 0x24, 0x9a, 0x29, 0xe3, 0x69, 0x7d, 0x05, 0x52, 0x8d, 0x76, 0xa1, 0x07, 0x58, 0x77, 0x19,
	0xc7, 0x05, 0x2b, 0x2b, 0xaa, 0x0e, 0x0f, 0xa2, 0xb4, 0xa2, 0xed, 0x1f, 0x81, 0x2a, 0x78, 0x33,
];

const OTHER_DEVICE_PUBLIC_KEY_HARDCODED: [u8; 32] = [
	0xc5, 0xef, 0xbf, 0xf4, 0x93, 0xee, 0x9e, 0xf3, 0x44, 0xd, 0x72, 0x15, 0x61, 0xed, 0x1c, 0x6a,
	0x9b, 0xac, 0xec, 0x43, 0xce, 0xf8, 0xbc, 0x0, 0x2, 0x90, 0x98, 0xab, 0x6b, 0x9, 0x3f, 0x26,
];

pub const PUBLIC_GROUP_PSK: [u8; 16] = [
	0x8b, 0x33, 0x87, 0xe9, 0xc5, 0xcd, 0xea, 0x6a, 0xc9, 0xe5, 0xed, 0xba, 0xa1, 0x15, 0xcd, 0x72,
];

type HmacSha256 = hmac::Hmac<Sha256>;

pub fn hardcoded_pub_key() -> VerifyingKey {
	VerifyingKey::from_bytes(&OTHER_DEVICE_PUBLIC_KEY_HARDCODED).unwrap()
}

pub struct SigningKeys {
	keys: SigningKey,
}

impl SigningKeys {
	pub fn hardcoded() -> Self {
		let keys = SigningKey::from_bytes(&ED25519_PRIVATE_KEY_HARDCODED);
		Self { keys }
	}

	pub fn public_key(&self) -> [u8; 32] { self.keys.verifying_key().to_bytes() }

	pub fn sign_message(&self, msg: &[u8]) -> [u8; 64] { self.keys.sign(msg).to_bytes() }

	pub fn calc_shared_secret(&self, other: &VerifyingKey) -> SharedSecret {
		let sk = StaticSecret::from(self.keys.to_scalar().to_bytes());
		let pk = PublicKey::from(other.to_montgomery().0);
		sk.diffie_hellman(&pk)
	}
}

pub fn msg_mac_16(payload: &[u8], shared: &[u8; 16]) -> Result<[u8; 32]> {
	let mut mac = <HmacSha256 as Mac>::new_from_slice(shared).unwrap();
	mac.update(payload);
	let finished = mac.finalize().into_bytes();
	let mac = <[u8; 32]>::from(finished);
	Ok(mac)
}

pub fn msg_mac_32(payload: &[u8], shared: &[u8; 32]) -> Result<[u8; 32]> {
	let mut mac = <HmacSha256 as Mac>::new_from_slice(shared).unwrap();
	mac.update(payload);
	let finished = mac.finalize().into_bytes();
	let mac = <[u8; 32]>::from(finished);
	Ok(mac)
}

pub fn calculate_channel_hash(secret: &[u8; 16]) -> u8 {
	let sha = Sha256::new().chain_update(secret).finalize();
	let out = <[u8; 32]>::from(sha);
	out[0]
}

pub fn decrypt_message_16<'a>(
	key: &'a [u8; 16],
	message: &'a mut [u8; 256],
	len: usize,
) -> &'a [u8] {
	let mut aes = Aes128Dec::new(key.into());
	for block in message.chunks_exact_mut(16) {
		aes.decrypt_block_mut(block.into());
	}
	&message[..len]
}

pub fn decrypt_message_32<'a>(
	key: &'a [u8; 32],
	message: &'a mut [u8; 256],
	len: usize,
) -> &'a [u8] {
	let mut aes = Aes256Dec::new(key.into());
	for block in message.chunks_exact_mut(32) {
		aes.decrypt_block_mut(block.into());
	}
	&message[..len]
}
