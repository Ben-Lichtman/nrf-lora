use defmt::*;
use nrf_softdevice::{
	Softdevice,
	ble::{
		advertisement_builder::{
			Flag, LegacyAdvertisementBuilder, LegacyAdvertisementPayload, ServiceList,
		},
		gatt_server, peripheral,
	},
};

#[nrf_softdevice::gatt_service(uuid = "9e7312e0-2354-11eb-9f10-fbc30a62cf38")]
pub struct FooService {
	#[characteristic(
		uuid = "9e7312e0-2354-11eb-9f10-fbc30a63cf38",
		read,
		write,
		notify,
		indicate
	)]
	foo: u16,
}

#[nrf_softdevice::gatt_server]
pub struct Server {
	foo: FooService,
}

pub async fn bluetooth_loop(sd: &'static Softdevice, server: Server) -> ! {
	static ADV_DATA: LegacyAdvertisementPayload = LegacyAdvertisementBuilder::new()
		.flags(&[Flag::GeneralDiscovery, Flag::LE_Only])
		.full_name("HelloRust")
		.build();

	static SCAN_DATA: LegacyAdvertisementPayload = LegacyAdvertisementBuilder::new()
		.services_128(
			ServiceList::Complete,
			&[0x9e7312e0_2354_11eb_9f10_fbc30a62cf38_u128.to_le_bytes()],
		)
		.build();

	loop {
		let config = peripheral::Config::default();
		let adv = peripheral::ConnectableAdvertisement::ScannableUndirected {
			adv_data: &ADV_DATA,
			scan_data: &SCAN_DATA,
		};
		let conn = peripheral::advertise_connectable(sd, adv, &config)
			.await
			.unwrap();

		info!("advertising done!");

		let e = gatt_server::run(&conn, &server, |e| match e {
			ServerEvent::Foo(e) => match e {
				FooServiceEvent::FooWrite(val) => {
					info!("wrote foo: {}", val);
					if let Err(e) = server.foo.foo_notify(&conn, &(val + 1)) {
						info!("send notification error: {:?}", e);
					}
				}
				FooServiceEvent::FooCccdWrite {
					indications,
					notifications,
				} => {
					info!(
						"foo indications: {}, notifications: {}",
						indications, notifications
					)
				}
			},
		})
		.await;

		info!("gatt_server run exited with error: {:?}", e);
	}
}
