use crate::{
	error::{Error, Result},
	meshcore::{
		PACKET_BUFFER_SIZE,
		crypto::{
			OTHER_DEVICE_PUBLIC_KEY_HARDCODED, PUBLIC_GROUP_PSK, SigningKeys,
			calculate_channel_hash, decrypt_message, hardcoded_pub_key, msg_ack_hash, msg_mac_16,
			msg_mac_32,
		},
		packet::{
			Packet, PacketFlags, PacketHeader, PayloadType, PayloadVersion, RouteType, U32,
			advert::{AdvType, Advert, AdvertFlags, AdvertHeader},
			direct_packets::DirectHeader,
			group_packets::GroupHeader,
			plain_message::PlainMessageHeader,
			try_split_at_mut,
		},
	},
};
use defmt::*;
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
	buffer: &'a mut [u8; PACKET_BUFFER_SIZE],
	timeout: u16,
) -> Result<&'a [u8]> {
	let rx_pkt_params = lora
		.create_rx_packet_params(8, false, buffer.len() as u8, true, false, mod_params)
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

	Ok(&buffer[..received_len])
}

async fn tx_packet<RK: RadioKind, DLY: DelayNs>(
	lora: &mut LoRa<RK, DLY>,
	mod_params: &ModulationParams,
	buffer: &[u8],
) -> Result<()> {
	let mut tx_pkt_params = lora
		.create_tx_packet_params(8, false, false, false, mod_params)
		.map_err(Error::RadioError)?;

	lora.prepare_for_tx(mod_params, &mut tx_pkt_params, 20, buffer)
		.await
		.map_err(Error::RadioError)?;

	info!("Ready for tx");

	lora.tx().await.map_err(Error::RadioError)?;

	info!("Tx complete");

	Ok(())
}

fn decrypt_direct_message<'a>(
	identity: &SigningKeys,
	header: &DirectHeader,
	payload: &[u8],
	decryption_buffer: &'a mut [u8; PACKET_BUFFER_SIZE],
) -> Result<&'a [u8]> {
	let shared_secret = identity.calc_shared_secret(&hardcoded_pub_key());
	// info!("=> shared_secret : {:02x}", shared_secret);

	let mac = msg_mac_32(payload, &shared_secret).unwrap();
	// info!("=> msg_mac : {:02x}", header.mac);
	// info!("=> calc_mac : {:02x}", mac);

	if mac[..2] != header.mac {
		warn!("MACs don't match");
		return Err(Error::InvalidMAC);
	}

	let payload_len = payload.len();
	decryption_buffer[..payload_len].copy_from_slice(payload);

	let key_trunc = <[u8; 16]>::try_from(&shared_secret[..16]).unwrap();

	let decrypted = decrypt_message(&key_trunc, decryption_buffer, payload_len);

	Ok(decrypted)
}

pub async fn lora_loop<RK: RadioKind, DLY: DelayNs, R: RngCore>(
	mut lora: LoRa<RK, DLY>,
	mut _rng: R,
) -> ! {
	let mod_params = lora
		.create_modulation_params(
			SpreadingFactor::_7,
			Bandwidth::_62KHz,
			CodingRate::_4_5,
			910_525_000,
		)
		.unwrap();

	let identity = SigningKeys::hardcoded();
	info!("=> My public key: {:02x}", identity.public_key());

	let mut packet_buffer: [u8; PACKET_BUFFER_SIZE] = [0; PACKET_BUFFER_SIZE];
	let mut crypto_buffer: [u8; PACKET_BUFFER_SIZE] = [0; PACKET_BUFFER_SIZE];
	let mut resp_buffer: [u8; PACKET_BUFFER_SIZE] = [0; PACKET_BUFFER_SIZE];

	let (packet, payload) = PacketHeader::mut_from_prefix(&mut packet_buffer).unwrap();
	packet.flags = PacketFlags::new(RouteType::Direct, PayloadType::Advert, PayloadVersion::Ver1);
	let path_len = 0;
	let (_path, payload) = try_split_at_mut(payload, path_len).unwrap();

	let (advert_header, body) = AdvertHeader::mut_from_prefix(payload).unwrap();
	advert_header.timestamp = U32::from(0x1);
	advert_header.flags = AdvertFlags::NAME | AdvertFlags::from_adv_type(AdvType::Chat);

	let message = "ROBOT";
	let message_len = message.len();
	body[..message_len].copy_from_slice(message.as_bytes());

	advert_header.fill_key_and_signature(&body[..message_len], &identity);

	let packet_length =
		size_of::<PacketHeader>() + path_len + size_of::<AdvertHeader>() + message_len;

	tx_packet(&mut lora, &mod_params, &packet_buffer[..packet_length])
		.await
		.unwrap();

	loop {
		let Ok(packet) = rx_packet(&mut lora, &mod_params, &mut packet_buffer, 0).await
		else {
			info!("Invalid message");
			continue;
		};

		// info!("Got data: {:02x}", packet);

		let Ok(packet) = Packet::from_bytes(packet)
		else {
			warn!("Parsing packet failed");
			continue;
		};

		info!("Packet Header: {:02x}", packet.header);

		let Ok(payload_type) = packet.header.flags.payload_type()
		else {
			info!("Invalid payload type");
			continue;
		};
		info!("==> Payload type <{}>", payload_type);
		match payload_type {
			PayloadType::Req => {
				let (direct_header, payload) =
					DirectHeader::ref_from_prefix(packet.payload).unwrap();
				if direct_header.dest_hash != identity.public_key()[0] {
					continue;
				}
				info!("Direct text to this device");
				info!("{:02x}", &direct_header);
				let Ok(decrypted) =
					decrypt_direct_message(&identity, direct_header, payload, &mut crypto_buffer)
				else {
					warn!("Failed to decrypt message");
					continue;
				};
			}
			PayloadType::Resp => {
				let (direct_header, payload) =
					DirectHeader::ref_from_prefix(packet.payload).unwrap();
				if direct_header.dest_hash != identity.public_key()[0] {
					continue;
				}
				info!("Direct text to this device");
				info!("{:02x}", &direct_header);
				let Ok(decrypted) =
					decrypt_direct_message(&identity, direct_header, payload, &mut crypto_buffer)
				else {
					warn!("Failed to decrypt message");
					continue;
				};
			}
			PayloadType::Txt => {
				let (direct_header, payload) =
					DirectHeader::ref_from_prefix(packet.payload).unwrap();
				if direct_header.dest_hash != identity.public_key()[0] {
					continue;
				}
				info!("Direct text to this device");
				info!("{:02x}", &direct_header);
				let Ok(decrypted) =
					decrypt_direct_message(&identity, direct_header, payload, &mut crypto_buffer)
				else {
					warn!("Failed to decrypt message");
					continue;
				};

				let (plain_header, message) =
					PlainMessageHeader::ref_from_prefix(decrypted).unwrap();

				info!(
					"Header: {}, Msg: \"{}\", Bytes: \"{:02x}\"",
					plain_header,
					unsafe { str::from_utf8_unchecked(message) },
					message
				);
				// Send Ack response
				let ack = msg_ack_hash(plain_header, message, &OTHER_DEVICE_PUBLIC_KEY_HARDCODED);

				let (packet, payload) = PacketHeader::mut_from_prefix(&mut packet_buffer).unwrap();
				packet.flags =
					PacketFlags::new(RouteType::Direct, PayloadType::Ack, PayloadVersion::Ver1);
				let path_len = 0;
				let (_path, payload) = try_split_at_mut(payload, path_len).unwrap();

				payload[..4].copy_from_slice(&ack);

				let packet_length = size_of::<PacketHeader>() + path_len + 4;

				tx_packet(&mut lora, &mod_params, &packet_buffer[..packet_length])
					.await
					.unwrap();
			}
			// PayloadType::Ack => {}
			PayloadType::Advert => {
				let (advert, _) = Advert::from_bytes(packet.payload).unwrap();
				info!("{:02x}", &advert);

				info!("pub key: {:#02x}", &advert.header.pub_key);
			}
			PayloadType::GrpText => {
				let (group_header, payload) = GroupHeader::ref_from_prefix(packet.payload).unwrap();

				info!("{:02x}", &group_header);

				if group_header.channel_hash == calculate_channel_hash(&PUBLIC_GROUP_PSK) {
					// Sent on public group
					info!("Public group text");

					let mac = msg_mac_16(payload, &PUBLIC_GROUP_PSK).unwrap();
					if mac[..2] != group_header.mac {
						warn!("MACs don't match");
						continue;
					}

					let mut decryption_buffer = [0u8; 256];
					let payload_len = payload.len();
					decryption_buffer[..payload_len].copy_from_slice(payload);

					let decrypted =
						decrypt_message(&PUBLIC_GROUP_PSK, &mut decryption_buffer, payload_len);

					let (plain_header, message) =
						PlainMessageHeader::ref_from_prefix(decrypted).unwrap();

					info!("Header: {}, Msg: \"{}\"", plain_header, unsafe {
						str::from_utf8_unchecked(message)
					});
				}
			}
			PayloadType::GrpData => {
				let (group_header, payload) = GroupHeader::ref_from_prefix(packet.payload).unwrap();

				info!("{:02x}", &group_header);
			}
			// PayloadType::AnonReq => {}
			PayloadType::Path => {
				let (direct_header, payload) =
					DirectHeader::ref_from_prefix(packet.payload).unwrap();
				if direct_header.dest_hash != identity.public_key()[0] {
					continue;
				}
				info!("Direct text to this device");
				info!("{:02x}", &direct_header);
				let Ok(decrypted) =
					decrypt_direct_message(&identity, direct_header, payload, &mut crypto_buffer)
				else {
					warn!("Failed to decrypt message");
					continue;
				};
			}
			// PayloadType::RawCustom => {}
			_ => {
				info!("Unable to process payload type");
			}
		}
	}
}
