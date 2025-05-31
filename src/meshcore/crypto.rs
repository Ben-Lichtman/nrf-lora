use ed25519_dalek::{SigningKey, VerifyingKey, ed25519::signature::Signer};
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};

const ED25519_PRIVATE_KEY_HARDCODED: [u8; 32] = [
	0x5b, 0x24, 0x9a, 0x29, 0xe3, 0x69, 0x7d, 0x05, 0x52, 0x8d, 0x76, 0xa1, 0x07, 0x58, 0x77, 0x19,
	0xc7, 0x05, 0x2b, 0x2b, 0xaa, 0x0e, 0x0f, 0xa2, 0xb4, 0xa2, 0xed, 0x1f, 0x81, 0x2a, 0x78, 0x33,
];

const OTHER_DEVICE_PUBLIC_KEY_HARDCODED: [u8; 32] = [
	0x73, 0xb6, 0xdb, 0xf2, 0xf4, 0x42, 0xba, 0x35, 0x9e, 0x4a, 0x47, 0x8e, 0xb5, 0xfe, 0x0c, 0x07,
	0x46, 0x41, 0xad, 0xd5, 0x53, 0x01, 0x3d, 0x0d, 0x1f, 0xb6, 0x7a, 0x9c, 0x53, 0xc4, 0x2d, 0xf7,
];

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
		let secret = StaticSecret::from(self.keys.to_bytes());
		let public = PublicKey::from(other.to_bytes());
		secret.diffie_hellman(&public)
	}
}
