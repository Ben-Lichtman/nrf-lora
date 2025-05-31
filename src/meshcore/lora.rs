use crate::{
	error::{Error, Result},
	meshcore::{
		PACKET_BUFFER_SIZE,
		crypto::SigningKeys,
		packet::{Packet, PayloadType, advert::Advert, txt_msg::TxtMsgHeader},
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

		match packet.header.flags.payload_type().unwrap() {
			PayloadType::Advert => {
				let (advert, _) = Advert::from_bytes(packet.payload).unwrap();
				info!("advert: {}", Debug2Format(&advert));
			}
			PayloadType::Txt => {
				let (advert, payload) = TxtMsgHeader::ref_from_prefix(packet.payload).unwrap();
				info!("advert: {}", Debug2Format(&advert));
			}
			unknown => {
				info!("unknown payload type: {}", unknown);
			}
		}
	}
}
