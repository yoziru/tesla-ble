"""Tests for module-level helpers: VIN names, state text, polling policy."""

import tesla_ble

from conftest import VIN, make_vehicle, pump


def test_vin_advertisement_name_roundtrip():
    # Value documented in vin_utils.h
    assert tesla_ble.get_vin_advertisement_name("5YJS0000000000000") == "S1a87a5a75f3df858C"
    name = tesla_ble.get_vin_advertisement_name(VIN)
    assert name.startswith("S") and name.endswith("C")
    assert tesla_ble.is_tesla_vehicle_name(name)
    assert tesla_ble.matches_vin(name, VIN)
    assert not tesla_ble.matches_vin(name, "5YJ30123456789XXX")


def test_state_text_helpers():
    tag = tesla_ble.charging_state_tag("Charging")
    assert tag != 0
    assert tesla_ble.charging_state_text(tag) == "Charging"
    assert tesla_ble.is_charging_tag(tag)
    assert tesla_ble.iec61851_state_text(tag) == "C"
    assert tesla_ble.charging_state_tag("Nope") == 0

    shift = tesla_ble.shift_state_tag("P")
    assert shift != 0
    assert tesla_ble.shift_state_text(shift) == "P"
    assert tesla_ble.is_parked_tag(shift)

    # Software update status re-exported from the package (1 = no update pending,
    # 4 = Available).
    assert tesla_ble.software_update_status_text(1) == "Up to date"
    assert tesla_ble.software_update_status_text(4) == "Available"
    assert tesla_ble.software_update_status_text(0) == "Unknown"


def test_polling_policy():
    policy = tesla_ble.InfotainmentPollPolicy()
    policy.set_awake_interval_ms(30000)
    policy.set_active_interval_ms(10000)
    policy.set_sleep_timeout_ms(660000)

    # Idle car right after connect: gentle, wake-enabled polling.
    decision = policy.update(1000, False, False, False)
    assert decision["interval_ms"] == 30000
    assert decision["wake_policy"] == tesla_ble.WakePolicy.WAKE_IF_NEEDED

    # Charging keeps the fast cadence.
    decision = policy.update(2000, False, True, False)
    assert decision["interval_ms"] == 10000

    # Long idle: back off so the car can sleep. The idle window restarted at
    # t=2000 when charging stopped, so the timeout expires at 2000+660000.
    decision = policy.update(2000 + 660000, False, False, False)
    assert decision["wake_policy"] == tesla_ble.WakePolicy.NO_WAKE_SKIP
    assert decision["interval_ms"] == 660000

    # Observed asleep: never wake.
    decision = policy.update(1, True, False, False)
    assert decision["wake_policy"] == tesla_ble.WakePolicy.NO_WAKE_SKIP

    policy.on_poll(100000)
    assert not policy.should_poll(100000 + 29999, 30000)
    assert policy.should_poll(100000 + 30000, 30000)


def test_tire_pressure_state_callback():
    sim = tesla_ble.SimulatedVehicle(VIN)
    sim.set_tpms(0, 2.9)
    sim.set_tpms(3, 2.7)

    ble, _, vehicle = make_vehicle()
    states = []
    vehicle.set_tire_pressure_state_callback(states.append)

    vehicle.set_connected(True)
    vehicle.set_awake(True)
    vehicle.tire_pressure_poll()
    pump(vehicle, ble, sim)

    assert states
    assert abs(states[-1]["tpms_pressure_fl"] - 2.9) < 0.01
    assert abs(states[-1]["tpms_pressure_rr"] - 2.7) < 0.01


def test_parse_frame_info():
    info = tesla_ble.parse_frame_info(b"\x00\x01garbage")
    assert info["valid"] is False
