use crate::{
	error::{Error, Result},
	meshcore::{
		PACKET_BUFFER_SIZE,
		crypto::SigningKeys,
		packet::{
			Packet, PacketFlags, PacketHeader, PayloadType, PayloadVersion, RouteType,
			advert::{AdvType, Advert, AdvertFlags, AdvertHeader},
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
use zerocopy::{FromBytes, IntoBytes};

async fn rx_packet<'a, RK: RadioKind, DLY: DelayNs>(
	lora: &mut LoRa<RK, DLY>,
	mod_params: &ModulationParams,
	buffer: &'a mut [u8; PACKET_BUFFER_SIZE as usize],
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
		.create_tx_packet_params(8, false, true, false, mod_params)
		.map_err(Error::RadioError)?;

	lora.prepare_for_tx(mod_params, &mut tx_pkt_params, 20, buffer)
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
			CodingRate::_4_5,
			910_525_000,
		)
		.unwrap();

	let identity = SigningKeys::hardcoded();

	let mut packet_buffer: [u8; PACKET_BUFFER_SIZE as usize] = [0; PACKET_BUFFER_SIZE as usize];

	loop {
		let Ok(packet) = rx_packet(&mut lora, &mod_params, &mut packet_buffer, 0).await
		else {
			info!("Invalid message");
			continue;
		};

		info!("Got data: {:02x}", packet);

		let packet = Packet::from_bytes(packet).unwrap();

		let advert = Advert::from_bytes(packet.payload).unwrap();

		// Send packet

		let rest = PacketHeader::mut_from_prefix(&mut packet_buffer)
			.map(|(x, rest)| {
				*x = PacketHeader {
					flags: PacketFlags::new(
						RouteType::Direct,
						PayloadType::Advert,
						PayloadVersion::Ver1,
					),
					path_len: 0,
				};
				rest
			})
			.unwrap();

		let timestamp = 1672534719u32;
		let flags = AdvertFlags::from_adv_type(AdvType::Chat) | AdvertFlags::NAME;

		let name = *b"BOT";

		let mut signed_message = [0u8; 40];
		*signed_message[0..32].as_mut_array().unwrap() = identity.public_key();
		*signed_message[32..36].as_mut_array().unwrap() = timestamp.to_le_bytes();
		signed_message[36] = flags.as_raw();
		*signed_message[37..40].as_mut_array().unwrap() = name;

		let advert_header = AdvertHeader {
			pub_key: identity.public_key(),
			timestamp: timestamp.into(),
			signature: identity.sign_message(&signed_message),
			flags,
		};

		let rest = AdvertHeader::mut_from_prefix(rest)
			.map(|(x, rest)| {
				*x = advert_header;
				rest
			})
			.unwrap();

		name.write_to_prefix(rest).unwrap();
		tx_packet(
			&mut lora,
			&mod_params,
			&packet_buffer
				[..size_of::<PacketHeader>() + size_of::<AdvertHeader>() + size_of_val(&name)],
		)
		.await
		.unwrap();
	}
}
