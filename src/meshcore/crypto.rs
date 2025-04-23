use ed25519_dalek::{SigningKey, ed25519::signature::Signer};

const ED25519_PRIVATE_KEY_HARDCODED: [u8; 32] = [
	0x5b, 0x24, 0x9a, 0x29, 0xe3, 0x69, 0x7d, 0x05, 0x52, 0x8d, 0x76, 0xa1, 0x07, 0x58, 0x77, 0x19,
	0xc7, 0x05, 0x2b, 0x2b, 0xaa, 0x0e, 0x0f, 0xa2, 0xb4, 0xa2, 0xed, 0x1f, 0x81, 0x2a, 0x78, 0x33,
];

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
}
