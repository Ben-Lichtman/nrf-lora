pub enum TxMessage {
	Text { len: u8, bytes: [u8; 256] },
}

pub enum RxMessage {
	Text { len: u8, bytes: [u8; 256] },
}
