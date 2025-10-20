#![feature(impl_trait_in_assoc_type)]
#![feature(slice_as_array)]
#![no_std]
#![no_main]

pub mod bluetooth;
pub mod error;
pub mod meshcore;
pub mod meshtastic;
pub mod protobuf;

use crate::{bluetooth::Server, meshcore::MESHCORE_SYNCWORD, meshtastic::MESHTASTIC_SYNCWORD};
use defmt::*;
use defmt_rtt as _;
use embassy_executor::Spawner;
use embassy_nrf::{
	bind_interrupts,
	gpio::{Input, Level, Output, OutputDrive, Pull},
	interrupt::{self, InterruptExt, Priority},
	peripherals, spim,
};
use embassy_time::Delay;
use embedded_hal_bus::spi::ExclusiveDevice;
use lora_phy::{
	LoRa,
	iv::GenericSx126xInterfaceVariant,
	sx126x::{self, Sx126x, Sx1262, TcxoCtrlVoltage},
};
use nrf_softdevice::{self as _, Softdevice, random_bytes, raw};
use panic_probe as _;
use rand::{SeedableRng, rngs::StdRng};

type LoraRadio = LoRa<
	Sx126x<
		ExclusiveDevice<spim::Spim<'static, peripherals::TWISPI1>, Output<'static>, Delay>,
		GenericSx126xInterfaceVariant<Output<'static>, Input<'static>>,
		Sx1262,
	>,
	Delay,
>;

bind_interrupts!(struct Irqs {
	TWISPI1 => spim::InterruptHandler<peripherals::TWISPI1>;
});

#[embassy_executor::task]
async fn softdevice_task(sd: &'static Softdevice) -> ! { sd.run().await }

#[embassy_executor::task]
async fn lora_loop(lora: LoraRadio) -> ! { meshcore::lora::lora_loop(lora).await }

#[embassy_executor::task]
async fn bluetooth_loop(sd: &'static Softdevice, server: Server) -> ! {
	bluetooth::bluetooth_loop(sd, server).await
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
	// Reconfigure interrupt priorities to not clash with softdevice
	let mut config = embassy_nrf::config::Config::default();
	config.gpiote_interrupt_priority = Priority::P2;
	config.time_interrupt_priority = Priority::P2;
	let p = embassy_nrf::init(config);
	interrupt::TWISPI1.set_priority(Priority::P2);

	// Configure softdevice
	let config = nrf_softdevice::Config {
		clock: Some(raw::nrf_clock_lf_cfg_t {
			source: raw::NRF_CLOCK_LF_SRC_RC as u8,
			rc_ctiv: 16,
			rc_temp_ctiv: 2,
			accuracy: raw::NRF_CLOCK_LF_ACCURACY_500_PPM as u8,
		}),
		conn_gap: Some(raw::ble_gap_conn_cfg_t {
			conn_count: 6,
			event_length: 24,
		}),
		conn_gatt: Some(raw::ble_gatt_conn_cfg_t { att_mtu: 256 }),
		gatts_attr_tab_size: Some(raw::ble_gatts_cfg_attr_tab_size_t {
			attr_tab_size: raw::BLE_GATTS_ATTR_TAB_SIZE_DEFAULT,
		}),
		gap_role_count: Some(raw::ble_gap_cfg_role_count_t {
			adv_set_count: 1,
			periph_role_count: 3,
		}),
		gap_device_name: Some(raw::ble_gap_cfg_device_name_t {
			p_value: b"HelloRust" as *const u8 as _,
			current_len: 9,
			max_len: 9,
			write_perm: unsafe { core::mem::zeroed() },
			_bitfield_1: raw::ble_gap_cfg_device_name_t::new_bitfield_1(
				raw::BLE_GATTS_VLOC_STACK as u8,
			),
		}),
		..Default::default()
	};

	let sd = Softdevice::enable(&config);

	// Configure LORA radio
	let nss = Output::new(p.P1_10, Level::High, OutputDrive::Standard);
	let reset = Output::new(p.P1_06, Level::High, OutputDrive::Standard);
	let dio1 = Input::new(p.P1_15, Pull::Down);
	let busy = Input::new(p.P1_14, Pull::None);
	let rf_switch_rx = Output::new(p.P1_05, Level::Low, OutputDrive::Standard);
	let rf_switch_tx = Output::new(p.P1_07, Level::Low, OutputDrive::Standard);

	let mut spi_config = spim::Config::default();
	spi_config.frequency = spim::Frequency::M16;
	let spim = spim::Spim::new(p.TWISPI1, Irqs, p.P1_11, p.P1_13, p.P1_12, spi_config);
	let spi = ExclusiveDevice::new(spim, nss, Delay).unwrap();

	let config = sx126x::Config {
		chip: Sx1262,
		tcxo_ctrl: Some(TcxoCtrlVoltage::Ctrl1V7),
		use_dcdc: true,
		rx_boost: false,
	};
	let iv = GenericSx126xInterfaceVariant::new(
		reset,
		dio1,
		busy,
		Some(rf_switch_rx),
		Some(rf_switch_tx),
	)
	.unwrap();

	let lora = LoRa::with_syncword(Sx126x::new(spi, iv, config), MESHCORE_SYNCWORD, Delay)
		.await
		.unwrap();

	// Configure bluetooth
	let server = Server::new(sd).unwrap();

	// // Configure RNG
	// let mut buf = [0u8; 32];
	// random_bytes(sd, &mut buf).unwrap();
	// let mut rng_device = StdRng::from_seed(buf);

	info!("Setup complete");

	spawner.must_spawn(softdevice_task(sd));
	spawner.must_spawn(lora_loop(lora));
	spawner.must_spawn(bluetooth_loop(sd, server));
}
