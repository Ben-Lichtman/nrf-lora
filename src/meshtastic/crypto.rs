use aes::{
	Aes128,
	cipher::{KeyIvInit, StreamCipher},
};
use ctr::Ctr32BE;

pub fn generate_nonce(packet_id: u32, sender_id: u32) -> [u8; 16] {
	let mut nonce = [0u8; 16];
	*nonce[0..4].as_mut_array::<4>().unwrap() = packet_id.to_le_bytes();
	*nonce[8..12].as_mut_array::<4>().unwrap() = sender_id.to_le_bytes();
	nonce
}

pub fn crypt_data_128(data: &mut [u8], key: [u8; 16], nonce: [u8; 16]) {
	let mut aes = Ctr32BE::<Aes128>::new(&key.into(), &nonce.into());
	aes.apply_keystream(data);
}
