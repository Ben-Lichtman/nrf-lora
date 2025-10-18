#![feature(impl_trait_in_assoc_type)]
#![feature(slice_as_array)]
#![no_std]
#![no_main]

pub mod error;
pub mod meshcore;
pub mod meshtastic;
pub mod protobuf;

use defmt::*;
use defmt_rtt as _;
use embassy_executor::Spawner;
use embassy_nrf::{
	bind_interrupts,
	gpio::{Input, Level, Output, OutputDrive, Pull},
	peripherals, rng, spim,
};
use embassy_time::Delay;
use embedded_hal_bus::spi::ExclusiveDevice;
use lora_phy::{
	LoRa,
	iv::GenericSx126xInterfaceVariant,
	sx126x::{self, Sx126x, Sx1262, TcxoCtrlVoltage},
};
use panic_probe as _;
use rand::{Rng, SeedableRng, rngs::StdRng};

use crate::{meshcore::MESHCORE_SYNCWORD, meshtastic::MESHTASTIC_SYNCWORD};

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
	RNG => rng::InterruptHandler<peripherals::RNG>;
});

#[embassy_executor::task]
async fn lora_loop(lora: LoraRadio, rng: StdRng) -> ! { meshcore::lora::lora_loop(lora, rng).await }

#[embassy_executor::main]
async fn main(spawner: Spawner) {
	let p = embassy_nrf::init(Default::default());

	// Configure RNG
	let mut rng_device = rng::Rng::new(p.RNG, Irqs);

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

	info!("Setup complete");

	let rng = StdRng::from_seed(rng_device.random());
	spawner.must_spawn(lora_loop(lora, rng));
}
