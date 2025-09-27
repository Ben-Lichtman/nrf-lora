use crate::{
	error::{Error, Result},
	meshcore::{
		PACKET_BUFFER_SIZE, PUBLIC_GROUP_HASH,
		crypto::{PUBLIC_GROUP_PSK, SigningKeys, msg_mac},
		packet::{
			Packet, PayloadType, advert::Advert, grp_txt::GrpTextHeader, txt_msg::TxtMsgHeader,
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
	mut _rng: R,
) -> ! {
	let mod_params = lora
		.create_modulation_params(
			SpreadingFactor::_10,
			Bandwidth::_250KHz,
			CodingRate::_4_5,
			915_000_000,
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

		println!("{:?}", packet.header);

		match packet.header.flags.payload_type().unwrap() {
			PayloadType::Advert => {
				let (advert, _) = Advert::from_bytes(packet.payload).unwrap();
				info!("advert: {:?}", &advert);
			}
			PayloadType::Txt => {
				let (txt, payload) = TxtMsgHeader::ref_from_prefix(packet.payload).unwrap();
				info!("txt: {:02x}", &txt);
			}
			PayloadType::GrpText => {
				let (grp_txt, payload) = GrpTextHeader::ref_from_prefix(packet.payload).unwrap();

				info!("grp_txt: {:02x}", &grp_txt);

				if grp_txt.channel_hash == PUBLIC_GROUP_HASH {
					// Sent on public group
					info!("Public group text");

					let mac = msg_mac(payload, &PUBLIC_GROUP_PSK).unwrap();
					if mac[..2] != grp_txt.mac {
						error!("MACs don't match");
						continue;
					}

					// TODO: decrypt the message (AES-128-ECB)
				}
			}
			unknown => {
				info!("unknown payload type: {:02x}", unknown);
			}
		}
	}
}
