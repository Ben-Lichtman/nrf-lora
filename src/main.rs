#![feature(impl_trait_in_assoc_type)]
#![feature(slice_as_array)]
#![feature(array_chunks)]
#![no_std]
#![no_main]

extern crate alloc;

pub mod commands;
pub mod crypto;
pub mod error;
pub mod packet;
pub mod protobuf;
pub mod radio;

use defmt::*;
use defmt_rtt as _;
use embassy_executor::Spawner;
use embassy_nrf::{
	bind_interrupts,
	gpio::{Input, Level, Output, OutputDrive, Pin, Pull},
	peripherals,
	rng::{self, Rng},
	spim,
};
use embassy_sync::{
	blocking_mutex::raw::CriticalSectionRawMutex,
	channel::{Channel, Receiver, Sender},
};
use embassy_time::Delay;
use embedded_alloc::LlffHeap;
use embedded_hal_bus::spi::ExclusiveDevice;
use lora_phy::{
	LoRa,
	iv::GenericSx126xInterfaceVariant,
	sx126x::{self, Sx126x, Sx1262, TcxoCtrlVoltage},
};
use panic_probe as _;

use crate::commands::{RxMessage, TxMessage};

const PACKET_BUFFER_SIZE: usize = 2048;
const CHANNEL_SIZE: usize = 10;

const LONGFAST_KEY: [u8; 16] = [
	0xd4, 0xf1, 0xbb, 0x3a, 0x20, 0x29, 0x07, 0x59, 0xf0, 0xbc, 0xff, 0xab, 0xcf, 0x4e, 0x69, 0x01,
];

#[global_allocator]
static HEAP: LlffHeap = LlffHeap::empty();

static TX_CHANNEL: Channel<CriticalSectionRawMutex, TxMessage, CHANNEL_SIZE> = Channel::new();
static RX_CHANNEL: Channel<CriticalSectionRawMutex, RxMessage, CHANNEL_SIZE> = Channel::new();

bind_interrupts!(struct Irqs {
	TWISPI1 => spim::InterruptHandler<peripherals::TWISPI1>;
	RNG => rng::InterruptHandler<peripherals::RNG>;
});

unsafe fn init_heap() {
	// Initialize the allocator BEFORE you use it

	use core::mem::MaybeUninit;
	const HEAP_SIZE: usize = 4096;
	static mut HEAP_MEM: [MaybeUninit<u8>; HEAP_SIZE] = [MaybeUninit::uninit(); HEAP_SIZE];
	#[allow(static_mut_refs)]
	unsafe {
		HEAP.init(HEAP_MEM.as_ptr() as usize, HEAP_SIZE)
	}
}

type LoraRadio = LoRa<
	Sx126x<
		ExclusiveDevice<spim::Spim<'static, peripherals::TWISPI1>, Output<'static>, Delay>,
		GenericSx126xInterfaceVariant<Output<'static>, Input<'static>>,
		Sx1262,
	>,
	Delay,
>;

#[embassy_executor::task]
async fn radio_loop(
	lora: LoraRadio,
	rng: Rng<'static, peripherals::RNG>,
	tx_channel: Receiver<'static, CriticalSectionRawMutex, TxMessage, CHANNEL_SIZE>,
	rx_channel: Sender<'static, CriticalSectionRawMutex, RxMessage, CHANNEL_SIZE>,
) -> ! {
	radio::radio_loop(lora, rng, tx_channel, rx_channel).await
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
	unsafe { init_heap() };

	let p = embassy_nrf::init(Default::default());

	let rng = rng::Rng::new(p.RNG, Irqs);

	let nss = Output::new(p.P1_10.degrade(), Level::High, OutputDrive::Standard);
	let reset = Output::new(p.P1_06.degrade(), Level::High, OutputDrive::Standard);
	let dio1 = Input::new(p.P1_15.degrade(), Pull::Down);
	let busy = Input::new(p.P1_14.degrade(), Pull::None);
	let rf_switch_rx = Output::new(p.P1_05.degrade(), Level::Low, OutputDrive::Standard);
	let rf_switch_tx = Output::new(p.P1_07.degrade(), Level::Low, OutputDrive::Standard);

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

	let lora = LoRa::with_syncword(Sx126x::new(spi, iv, config), 0x2b, Delay)
		.await
		.unwrap();

	info!("Setup complete");

	spawner.must_spawn(radio_loop(
		lora,
		rng,
		TX_CHANNEL.receiver(),
		RX_CHANNEL.sender(),
	));
}
