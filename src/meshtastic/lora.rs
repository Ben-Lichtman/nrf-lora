use crate::{
	error::{Error, Result},
	meshtastic::{
		LONGFAST_KEY, PACKET_BUFFER_SIZE,
		crypto::{crypt_data_128, generate_nonce},
		packet::{Flags, NodeID, PacketHeader},
	},
	protobuf::{Data, PortNum},
};
use defmt::*;
use embassy_time::Timer;
use femtopb::{EnumValue, Message, UnknownFields};
use lora_phy::{
	DelayNs, LoRa, RxMode,
	mod_params::{Bandwidth, CodingRate, ModulationParams, SpreadingFactor},
	mod_traits::RadioKind,
};
use rand_core::RngCore;
use zerocopy::FromBytes;

async fn rx_packet<'a, RK: RadioKind, DLY: DelayNs>(
	lora: &mut LoRa<RK, DLY>,
	mod_params: &ModulationParams,
	buffer: &'a mut [u8; PACKET_BUFFER_SIZE as usize],
	timeout: u16,
) -> Result<(PacketHeader, Data<'a>)> {
	let rx_pkt_params = lora
		.create_rx_packet_params(16, false, buffer.len() as u8, true, false, mod_params)
		.map_err(Error::RadioError)?;

	lora.prepare_for_rx(RxMode::Single(timeout), mod_params, &rx_pkt_params)
		.await
		.map_err(Error::RadioError)?;

	info!("Ready for rx");

	let (received_len, _packet_status) = lora
		.rx(&rx_pkt_params, buffer)
		.await
		.map_err(Error::RadioError)?;

	info!("Rx complete");

	let received_len = received_len as usize;
	let (header, body) =
		PacketHeader::mut_from_prefix(&mut buffer[..received_len]).map_err(|_| Error::ZeroCopy)?;

	let nonce = generate_nonce(header.packet_id, header.sender.id());
	crypt_data_128(body, LONGFAST_KEY, nonce);

	info!("Received packet data: {:02x}", body);

	let data = Data::decode(&*body).map_err(Error::ProtobufDecode)?;

	Ok((header.clone(), data))
}

async fn tx_packet<'a, RK: RadioKind, DLY: DelayNs>(
	lora: &mut LoRa<RK, DLY>,
	mod_params: &ModulationParams,
	buffer: &'a mut [u8; PACKET_BUFFER_SIZE as usize],
	header: PacketHeader,
	data: &Data<'a>,
) -> Result<()> {
	let (packet_header, body_buffer) =
		PacketHeader::mut_from_prefix(&mut *buffer).map_err(|_| Error::ZeroCopy)?;
	*packet_header = header;

	let mut cursor = &mut *body_buffer;
	data.encode(&mut cursor).map_err(Error::ProtobufEncode)?;
	let remaining_len = cursor.len();
	let body = &mut body_buffer[..PACKET_BUFFER_SIZE as usize - remaining_len];

	let nonce = generate_nonce(packet_header.packet_id, packet_header.sender.id());
	crypt_data_128(body, LONGFAST_KEY, nonce);

	let full_packet = &mut buffer[..PACKET_BUFFER_SIZE as usize - remaining_len];

	let mut tx_pkt_params = lora
		.create_tx_packet_params(16, false, true, false, mod_params)
		.map_err(Error::RadioError)?;

	lora.prepare_for_tx(mod_params, &mut tx_pkt_params, 20, full_packet)
		.await
		.map_err(Error::RadioError)?;

	info!("Ready for tx");

	lora.tx().await.map_err(Error::RadioError)?;

	info!("Tx complete");

	Ok(())
}

pub async fn lora_loop<RK: RadioKind, DLY: DelayNs, R: RngCore>(
	mut lora: LoRa<RK, DLY>,
	mut rng: R,
) -> ! {
	let mod_params = lora
		.create_modulation_params(
			SpreadingFactor::_11,
			Bandwidth::_250KHz,
			CodingRate::_4_7,
			906_875_000,
		)
		.unwrap();

	loop {
		let mut packet_buffer: [u8; PACKET_BUFFER_SIZE as usize] = [0; PACKET_BUFFER_SIZE as usize];

		let Ok((mut header, data)) = rx_packet(&mut lora, &mod_params, &mut packet_buffer, 0).await
		else {
			info!("Invalid message");
			continue;
		};

		info!("Header: {:02x}", header);
		info!(
			"Hop limit: {}, hop start: {}",
			header.flags.get_hop_limit(),
			header.flags.get_hop_start(),
		);
		info!("Data payload: {=[u8]:a}", data.payload);

		Timer::after_millis(10).await;

		if header.relay_node > 0 {
			// Rebroadcast the message
			let mut packet_buffer_2: [u8; PACKET_BUFFER_SIZE as usize] =
				[0; PACKET_BUFFER_SIZE as usize];
			header.relay_node -= 1;
			tx_packet(&mut lora, &mod_params, &mut packet_buffer_2, header, &data)
				.await
				.unwrap();

			Timer::after_millis(10).await;
		}

		let msg_id = rng.next_u32();
		let msg_header = PacketHeader {
			dest: NodeID::BROADCAST,
			sender: NodeID::from_id(0x1337),
			packet_id: msg_id,
			flags: Flags::hop_limit(0) | Flags::hop_start(0),
			channel_hash: 0x08,
			next_hop: 0,
			relay_node: 1,
		};
		let msg_payload = b"Hello world!";
		let msg = Data {
			portnum: EnumValue::Known(PortNum::TextMessageApp),
			payload: msg_payload,
			want_response: false,
			dest: NodeID::BROADCAST.id(),
			source: msg_header.sender.id(),
			request_id: msg_header.packet_id,
			reply_id: 0,
			emoji: 0,
			bitfield: None,
			unknown_fields: UnknownFields::empty(),
		};

		tx_packet(&mut lora, &mod_params, &mut packet_buffer, msg_header, &msg)
			.await
			.unwrap();
	}
}
