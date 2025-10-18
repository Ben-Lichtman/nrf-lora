use crate::{
	error::Result,
	meshcore::{PACKET_BUFFER_SIZE, packet::plain_message::PlainMessageHeader},
};
use aes::{
	Aes128Dec,
	cipher::{BlockDecryptMut, KeyInit},
};
use ed25519_dalek::{SigningKey, VerifyingKey, ed25519::signature::Signer};
use hmac::Mac;
use sha2::{Digest, Sha256};

const ED25519_PRIVATE_KEY_HARDCODED: [u8; 32] = [
	0x5b, 0x24, 0x9a, 0x29, 0xe3, 0x69, 0x7d, 0x05, 0x52, 0x8d, 0x76, 0xa1, 0x07, 0x58, 0x77, 0x19,
	0xc7, 0x05, 0x2b, 0x2b, 0xaa, 0x0e, 0x0f, 0xa2, 0xb4, 0xa2, 0xed, 0x1f, 0x81, 0x2a, 0x78, 0x33,
];

// B3NNY

pub const OTHER_DEVICE_PUBLIC_KEY_HARDCODED: [u8; 32] = [
	0x2, 0xaa, 0x76, 0xfd, 0x80, 0xff, 0xa9, 0xc9, 0x94, 0x2a, 0xb, 0xfd, 0x53, 0x1b, 0xf6, 0x22,
	0xc9, 0x9c, 0x46, 0x72, 0x6e, 0xed, 0x22, 0x4a, 0x11, 0xdc, 0x65, 0x81, 0x34, 0xe4, 0xde, 0xb0,
];

// B3NNY-H

// pub const OTHER_DEVICE_PUBLIC_KEY_HARDCODED: [u8; 32] = [
// 	0xdd, 0x2, 0x15, 0x55, 0xbd, 0x9, 0x8d, 0x69, 0xb1, 0x60, 0x6b, 0xae, 0xb5, 0xd4, 0xda, 0xdf,
// 	0x2e, 0x81, 0xab, 0xae, 0x2f, 0xc6, 0xb9, 0xcb, 0xbe, 0xf9, 0xf0, 0x78, 0x14, 0x7a, 0x1d, 0x8,
// ];

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

	pub fn calc_shared_secret(&self, other: &VerifyingKey) -> [u8; 32] {
		// let sk = StaticSecret::from(self.keys.to_scalar().to_bytes());
		// let pk = PublicKey::from(other.to_montgomery().0);
		// sk.diffie_hellman(&pk)
		(self.keys.to_scalar() * other.to_montgomery()).to_bytes()
	}
}

pub fn msg_ack_hash(
	header: &PlainMessageHeader,
	message: &[u8],
	sender_pubkey: &[u8; 32],
) -> [u8; 4] {
	let trunc_message = message.split(|x| *x == 0).next().unwrap();
	let trunc_message_len = trunc_message.len();

	let mut intermediate = [0u8; 256];
	intermediate[..4].copy_from_slice(&header.timestamp.0.to_bytes());
	intermediate[4] = header.flags.as_raw();
	intermediate[5..5 + trunc_message_len].copy_from_slice(trunc_message);

	let sha = Sha256::new()
		.chain_update(header.timestamp.0.to_bytes())
		.chain_update([header.flags.as_raw()])
		.chain_update(trunc_message)
		.chain_update(sender_pubkey)
		.finalize();
	let out = <[u8; 32]>::from(sha);

	out[..4].try_into().unwrap()
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

pub fn decrypt_message<'a>(
	key: &[u8; 16],
	message: &'a mut [u8; PACKET_BUFFER_SIZE],
	len: usize,
) -> &'a [u8] {
	let mut aes = Aes128Dec::new(key.into());
	for block in message.chunks_exact_mut(16) {
		aes.decrypt_block_mut(block.into());
	}
	&message[..len]
}
