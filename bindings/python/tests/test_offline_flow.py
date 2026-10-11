"""Offline end-to-end tests: Python Vehicle <-> SimulatedVehicle over fake BLE."""

import tesla_ble
import pytest

from conftest import VIN, FakeStorage, collect_callbacks, make_vehicle, pump


def test_vcsec_poll_reports_vehicle_status():
    sim = tesla_ble.SimulatedVehicle(VIN)
    sim.set_locked(False)
    sim.set_sleeping(False)

    ble, _, vehicle = make_vehicle()
    states = []
    vehicle.set_vehicle_status_callback(states.append)

    vehicle.set_connected(True)
    vehicle.vcsec_poll()
    pump(vehicle, ble, sim)

    assert states, "vehicle status callback must fire"
    status = states[-1]
    assert status["locked"] is False
    assert status["asleep"] is False
    assert status["closures"]["front_driver_door"] == "closed"


def test_seat_cabin_and_sunroof_commands_report_protocol_state():
    sim = tesla_ble.SimulatedVehicle(VIN)
    ble, _, vehicle = make_vehicle()
    climate, closures, results = [], [], []
    vehicle.set_climate_state_callback(climate.append)
    vehicle.set_closures_state_callback(closures.append)
    vehicle.set_connected(True)
    vehicle.set_awake(True)
    seats = [
        (tesla_ble.SeatPosition.FRONT_LEFT, "seat_heater_left"),
        (tesla_ble.SeatPosition.FRONT_RIGHT, "seat_heater_right"),
        (tesla_ble.SeatPosition.REAR_LEFT, "seat_heater_rear_left"),
        (tesla_ble.SeatPosition.REAR_LEFT_BACK, "seat_heater_rear_left_back"),
        (tesla_ble.SeatPosition.REAR_CENTER, "seat_heater_rear_center"),
        (tesla_ble.SeatPosition.REAR_RIGHT, "seat_heater_rear_right"),
        (tesla_ble.SeatPosition.REAR_RIGHT_BACK, "seat_heater_rear_right_back"),
        (tesla_ble.SeatPosition.THIRD_ROW_LEFT, "seat_heater_third_row_left"),
        (tesla_ble.SeatPosition.THIRD_ROW_RIGHT, "seat_heater_third_row_right"),
    ]
    for index, (seat, field) in enumerate(seats):
        level = index % 4
        vehicle.set_seat_heater(seat, level, results.append)
        vehicle.climate_state_poll()
        pump(vehicle, ble, sim)
        assert results[-1].success
        assert climate[-1][field] == level
    for seat, side in ((tesla_ble.SeatPosition.FRONT_LEFT, "left"), (tesla_ble.SeatPosition.FRONT_RIGHT, "right")):
        for level in range(4):
            vehicle.set_seat_cooler(seat, level, results.append)
            vehicle.climate_state_poll()
            pump(vehicle, ble, sim)
            assert results[-1].success
            assert climate[-1][f"seat_fan_front_{side}"] == level
        for enabled in (True, False):
            vehicle.set_auto_seat_climate(seat, enabled, results.append)
            vehicle.climate_state_poll()
            pump(vehicle, ble, sim)
            assert results[-1].success
            assert climate[-1][f"auto_seat_climate_{side}"] is enabled
    for mode in range(3):
        vehicle.set_cabin_overheat_protection(mode, results.append)
        vehicle.climate_state_poll()
        pump(vehicle, ble, sim)
        assert results[-1].success
        assert climate[-1]["cabin_overheat_protection"] == mode
    for level in (1, 2, 3):
        vehicle.set_cabin_overheat_protection_temp(level, results.append)
        vehicle.climate_state_poll()
        pump(vehicle, ble, sim)
        assert results[-1].success
        assert climate[-1]["cop_activation_temperature"] == level
    for position in (0, 42, 100):
        vehicle.set_sunroof_position(position, results.append)
        vehicle.closures_state_poll()
        pump(vehicle, ble, sim)
        assert results[-1].success
        assert closures[-1]["sun_roof_percent_open"] == position
    for method, args in (
        (vehicle.set_seat_heater, (tesla_ble.SeatPosition.FRONT_LEFT, -1)),
        (vehicle.set_seat_heater, (tesla_ble.SeatPosition.REAR_RIGHT, 4)),
        (vehicle.set_seat_cooler, (tesla_ble.SeatPosition.REAR_RIGHT, 2)),
        (vehicle.set_seat_cooler, (tesla_ble.SeatPosition.FRONT_RIGHT, 4)),
        (vehicle.set_auto_seat_climate, (tesla_ble.SeatPosition.REAR_RIGHT, True)),
        (vehicle.set_cabin_overheat_protection, (3,)),
        (vehicle.set_cabin_overheat_protection_temp, (0,)),
        (vehicle.set_sunroof_position, (-1,)),
        (vehicle.set_sunroof_position, (101,)),
        (vehicle.set_seat_climate, (tesla_ble.SeatPosition.FRONT_LEFT, -1, False, True)),
        (vehicle.set_seat_climate, (tesla_ble.SeatPosition.FRONT_LEFT, 4, False, True)),
        (vehicle.set_seat_climate, (tesla_ble.SeatPosition.FRONT_LEFT, 2, True, False)),
        (vehicle.set_seat_climate, (tesla_ble.SeatPosition.REAR_RIGHT, 2, False, True)),
    ):
        before = sim.frames_received
        method(*args, results.append)
        pump(vehicle, ble, sim)
        assert not results[-1].success
        assert sim.frames_received == before


@pytest.mark.parametrize("failed_step", [0, 1])
def test_seat_off_stops_at_failed_step(failed_step):
    sim = tesla_ble.SimulatedVehicle(VIN)
    seat = tesla_ble.SeatPosition.FRONT_LEFT
    sim.set_seat_heater(seat, 2)
    sim.set_seat_cooler(seat, 2)
    sim.set_auto_seat_climate(seat, True)
    ble, _, vehicle = make_vehicle()
    states, results = [], []
    vehicle.set_climate_state_callback(states.append)
    vehicle.set_connected(True)
    vehicle.set_awake(True)
    vehicle.climate_state_poll()
    pump(vehicle, ble, sim)
    write = ble.write
    attempts = []

    def fail_step(data):
        attempts.append(bytes(data))
        return False if len(attempts) == failed_step + 1 else write(data)

    ble.write = fail_step
    vehicle.set_seat_climate(seat, 0, False, True, results.append)
    pump(vehicle, ble, sim)
    assert len(results) == 1 and results[0].failure
    ble.write = write
    vehicle.climate_state_poll()
    pump(vehicle, ble, sim)
    assert states[-1]["seat_heater_left"] == 2
    assert states[-1]["seat_fan_front_left"] == (0 if failed_step == 1 else 2)


def test_seat_operations_are_serialized_and_cancel_on_departure():
    sim = tesla_ble.SimulatedVehicle(VIN)
    ble, _, vehicle = make_vehicle()
    seat = tesla_ble.SeatPosition.FRONT_LEFT
    sim.set_auto_seat_climate(seat, True)
    states, results = [], []
    vehicle.set_climate_state_callback(states.append)
    vehicle.set_connected(True)
    vehicle.set_awake(True)
    vehicle.climate_state_poll()
    pump(vehicle, ble, sim)
    before = sim.frames_received
    vehicle.set_seat_climate(seat, 2, True, True, lambda r: results.append(("cool", r)))
    vehicle.set_seat_climate(seat, 3, False, True, lambda r: results.append(("heat", r)))
    pump(vehicle, ble, sim)
    assert sim.frames_received - before == 3, "Two manual requests and one coalesced state poll"
    assert [name for name, _ in results] == ["cool", "heat"]
    assert all(result.success for _, result in results)
    assert states[-1]["seat_heater_left"] == 3
    assert states[-1]["seat_fan_front_left"] == 0
    assert states[-1]["auto_seat_climate_left"] is False
    results.clear()
    vehicle.set_seat_climate(seat, 0, False, True, lambda r: results.append(("departed", r)))
    for _ in range(20):
        vehicle.loop()
        if ble.sent:
            break
    assert len(ble.sent) == 1
    for response in sim.on_client_frame(ble.sent.pop(0)):
        vehicle.on_rx_data(response)
    vehicle.set_connected(False)
    assert len(results) == 1 and results[0][1].failure
    vehicle.set_connected(True)
    before = sim.frames_received
    pump(vehicle, ble, sim)
    assert sim.frames_received == before
    assert len(results) == 1
    vehicle.set_seat_climate(seat, 0, False, True, lambda r: results.append(("off", r)))
    pump(vehicle, ble, sim)
    assert results[-1][1].success
    assert states[-1]["seat_heater_left"] == 0
    assert states[-1]["seat_fan_front_left"] == 0


def test_charge_state_poll_reports_state():
    sim = tesla_ble.SimulatedVehicle(VIN)
    sim.set_battery_level(42)
    sim.set_battery_range(123.5)
    sim.set_charging_state(tesla_ble.charging_state_tag("Charging"))
    sim.set_scheduled_charging_mode(2)
    sim.set_charge_limit(70)
    sim.set_charging_amps(12)
    sim.set_charger_power(7)
    sim.set_charge_port_door_open(True)

    ble, _, vehicle = make_vehicle()
    charge_states = []
    unrelated_states = []
    vehicle.set_charge_state_callback(charge_states.append)
    vehicle.set_climate_state_callback(unrelated_states.append)
    vehicle.set_closures_state_callback(unrelated_states.append)

    vehicle.set_connected(True)
    vehicle.set_awake(True)
    vehicle.charge_state_poll()
    pump(vehicle, ble, sim)

    assert charge_states, "charge state callback must fire"
    assert not unrelated_states, "a charge poll must not supply unrelated snapshots"
    state = charge_states[-1]
    assert state["battery_level"] == 42
    assert abs(state["battery_range"] - 123.5) < 0.01
    assert state["charging_state"] == "Charging"
    assert state["charging_state_raw"] == tesla_ble.charging_state_tag("Charging")
    assert state["scheduled_charging_mode"] == 2
    assert state["charge_limit_soc"] == 70
    assert state["charging_amps"] == 12
    assert state["charger_power"] == 7
    assert state["charge_port_door_open"] is True


def test_software_update_poll_reports_state():
    sim = tesla_ble.SimulatedVehicle(VIN)
    sim.set_software_update_state(4)  # CarServer_SoftwareUpdateState_SoftwareUpdateStatus_Available_tag

    ble, _, vehicle = make_vehicle()
    states = []
    vehicle.set_software_update_state_callback(states.append)

    vehicle.set_connected(True)
    vehicle.set_awake(True)
    vehicle.software_update_poll()
    pump(vehicle, ble, sim)

    assert states, "software update callback must fire"
    assert states[-1]["status"] == 4

    states.clear()
    for cycle in range(1, 6):
        vehicle.infotainment_poll(tesla_ble.WakePolicy.NO_WAKE_SKIP)
        pump(vehicle, ble, sim)
        assert len(states) == (1 if cycle == 5 else 0)


def test_software_update_schedule_and_cancel_commands():
    sim = tesla_ble.SimulatedVehicle(VIN)
    sim.set_software_update_state(4)  # Available

    ble, _, vehicle = make_vehicle()
    results, callback = collect_callbacks()
    states = []
    vehicle.set_software_update_state_callback(states.append)

    vehicle.set_connected(True)
    vehicle.set_awake(True)

    vehicle.schedule_software_update(0, callback)
    pump(vehicle, ble, sim)
    assert results and results[-1].success, results[-1]

    assert states[-1]["status"] == 3, "scheduling must report Scheduled"

    vehicle.cancel_software_update(callback)
    pump(vehicle, ble, sim)
    assert results[-1].success, results[-1]

    assert states[-1]["status"] == 4, "cancel must report Available"

    # Negative offsets are rejected before hitting the wire.
    vehicle.schedule_software_update(-1, callback)
    assert not results[-1].success


def test_climate_and_closures_and_drive_state_callbacks():
    sim = tesla_ble.SimulatedVehicle(VIN)
    sim.set_inside_temp(21.5)
    sim.set_outside_temp(9.0)
    sim.set_climate_on(True)
    sim.set_cabin_overheat_protection(1)
    sim.set_shift_state(tesla_ble.shift_state_tag("P"))
    sim.set_odometer_miles(1234.5)
    sim.set_door_open("driver_front", True)

    ble, _, vehicle = make_vehicle()
    climate, drive, closures = [], [], []
    vehicle.set_climate_state_callback(climate.append)
    vehicle.set_drive_state_callback(drive.append)
    vehicle.set_closures_state_callback(closures.append)

    vehicle.set_connected(True)
    vehicle.set_awake(True)
    vehicle.infotainment_poll()
    pump(vehicle, ble, sim)

    assert climate and abs(climate[-1]["inside_temp_celsius"] - 21.5) < 0.01
    assert climate[-1]["is_climate_on"] is True
    assert climate[-1]["cabin_overheat_protection"] == 1
    assert drive and drive[-1]["odometer_in_hundredths_of_a_mile"] == 123450
    assert closures and closures[-1]["door_open_driver_front"] is True
    assert closures[-1]["locked"] is True


def test_lock_command_completes_with_success():
    sim = tesla_ble.SimulatedVehicle(VIN)
    sim.set_locked(False)

    ble, _, vehicle = make_vehicle()
    results, callback = collect_callbacks()
    states = []
    vehicle.set_vehicle_status_callback(states.append)

    vehicle.set_connected(True)
    vehicle.lock(callback)
    pump(vehicle, ble, sim)

    assert results, "lock callback must fire"
    assert results[-1].success, results[-1]
    assert results[-1].outcome == "success"
    assert states[-1]["locked"] is True


def test_charging_command_completes_with_success():
    sim = tesla_ble.SimulatedVehicle(VIN)

    ble, _, vehicle = make_vehicle()
    results, callback = collect_callbacks()
    states = []
    vehicle.set_charge_state_callback(states.append)

    vehicle.set_connected(True)
    vehicle.set_awake(True)
    vehicle.set_charging_state(True, callback)
    pump(vehicle, ble, sim)

    assert results, "charging callback must fire"
    assert results[-1].success, results[-1]
    assert states[-1]["charging_state"] == "Charging"


@pytest.mark.parametrize(
    ("action", "argument", "callback", "field", "expected"),
    [
        ("set_charging_amps", 11, "set_charge_state_callback", "charging_amps", 11),
        ("set_charging_limit", 67, "set_charge_state_callback", "charge_limit_soc", 67),
        ("set_climate_temp", 22.5, "set_climate_state_callback", "driver_temp_setting", 22.5),
        ("set_sentry_mode", True, "set_closures_state_callback", "sentry_mode_state", 3),
    ],
)
def test_encrypted_action_changes_reported_state(action, argument, callback, field, expected):
    sim = tesla_ble.SimulatedVehicle(VIN)
    ble, _, vehicle = make_vehicle()
    states, results = [], []
    getattr(vehicle, callback)(states.append)
    vehicle.set_connected(True)
    vehicle.set_awake(True)
    getattr(vehicle, action)(argument, results.append)
    pump(vehicle, ble, sim)
    assert len(results) == 1 and results[0].success
    assert states[-1][field] == expected


def test_pairing_persists_private_key():
    sim = tesla_ble.SimulatedVehicle(VIN)

    ble, storage, vehicle = make_vehicle(with_key=False)
    results, callback = collect_callbacks()

    vehicle.set_connected(True)
    vehicle.pair(tesla_ble.KeysRole.OWNER, callback)
    pump(vehicle, ble, sim)

    assert results and results[-1].success, results
    assert "private_key" in storage.data
    assert storage.data["private_key"].startswith(b"-----BEGIN EC PRIVATE KEY-----")


def test_session_is_persisted_after_auth():
    sim = tesla_ble.SimulatedVehicle(VIN)

    ble, storage, vehicle = make_vehicle()
    vehicle.set_connected(True)
    vehicle.vcsec_poll()
    pump(vehicle, ble, sim)

    assert "session_vcsec" in storage.data
    # A second Vehicle can be constructed from the same storage (HA restart).
    _, _, reloaded = make_vehicle(storage=storage)
    assert reloaded.is_connected is False


def test_invalid_parameter_reports_build_failure():
    ble, _, vehicle = make_vehicle()
    results, callback = collect_callbacks()

    vehicle.set_connected(True)
    vehicle.set_charging_amps(200, callback)

    assert results and results[-1].failure
    assert "Failed to build" in results[-1].error_message
    assert results[-1].error_severity == "permanent"


def test_disconnected_command_reports_failure():
    _, _, vehicle = make_vehicle()
    results, callback = collect_callbacks()

    vehicle.lock(callback)

    assert results and results[-1].failure
    assert "Connection lost" in results[-1].error_message
    # A command that never left the device definitely did not run, but the
    # library reports connection loss as "may have succeeded" conservatively.
    assert results[-1].error_severity == "temporary"


def test_disconnect_fails_queued_command():
    sim = tesla_ble.SimulatedVehicle(VIN)
    ble, _, vehicle = make_vehicle()
    results, callback = collect_callbacks()

    vehicle.set_connected(True)
    vehicle.set_awake(True)
    vehicle.set_charging_state(True, callback)
    vehicle.set_connected(False)

    assert results and results[-1].failure


def test_unpaired_vehicle_reports_key_not_on_whitelist():
    sim = tesla_ble.SimulatedVehicle(VIN)
    sim.set_paired(False)

    ble, _, vehicle = make_vehicle()
    results, callback = collect_callbacks()

    vehicle.set_connected(True)
    vehicle.lock(callback)
    pump(vehicle, ble, sim)

    assert results and results[-1].failure
    assert "whitelist" in results[-1].error_message


def test_skip_wake_when_already_awake():
    sim = tesla_ble.SimulatedVehicle(VIN)

    _, _, vehicle = make_vehicle()
    results, callback = collect_callbacks()

    vehicle.set_connected(True)
    vehicle.set_awake(True)
    vehicle.wake(callback)

    assert results and results[-1].skipped
    assert results[-1].terminal_reason == "none"


def test_raw_message_and_log_callbacks():
    sim = tesla_ble.SimulatedVehicle(VIN)
    ble, _, vehicle = make_vehicle()

    raw_frames = []
    vehicle.set_raw_message_callback(raw_frames.append)

    log_lines = []
    tesla_ble.set_log_callback(lambda level, message, tag, line: log_lines.append((level, message)))

    try:
        vehicle.set_connected(True)
        vehicle.vcsec_poll()
        pump(vehicle, ble, sim)
    finally:
        tesla_ble.set_log_callback(None)

    assert raw_frames, "raw message callback must fire"
    assert all(isinstance(frame, bytes) for frame in raw_frames)
    assert log_lines, "log callback must receive messages"
    assert any("VCSEC" in message or "vehicle" in message.lower() for _, message in log_lines)
    assert not any("Session key:" in message or "Session key (first" in message for _, message in log_lines)


def test_simulated_vehicle_counts_frames():
    sim = tesla_ble.SimulatedVehicle(VIN)
    assert sim.frames_received == 0
    assert sim.vin == VIN


def test_pairing_state_and_pending_count():
    sim = tesla_ble.SimulatedVehicle(VIN)

    ble, storage, vehicle = make_vehicle(with_key=False)
    assert vehicle.has_private_key is False
    assert vehicle.pending_command_count == 0

    vehicle.set_connected(True)
    vehicle.set_awake(True)
    vehicle.lock()
    assert vehicle.pending_command_count == 1

    pump(vehicle, ble, sim)
    assert vehicle.pending_command_count == 0
    assert vehicle.has_private_key is False  # pairing is what creates the key


def test_successful_command_triggers_follow_up_poll():
    sim = tesla_ble.SimulatedVehicle(VIN)

    ble, _, vehicle = make_vehicle()
    vehicle.set_connected(True)
    vehicle.set_awake(True)

    vehicle.lock()
    pump(vehicle, ble, sim)

    # Traffic: VCSEC session info request, the lock command, and the
    # follow-up VCSEC poll the library queues after a successful action.
    assert sim.frames_received >= 3
    assert vehicle.pending_command_count == 0


def test_closure_helpers():
    assert tesla_ble.closure_state_text(1) == "open"  # CLOSURESTATE_OPEN
    assert tesla_ble.closure_state_text(0) == "closed"
    assert tesla_ble.closure_is_open(1) is True
    assert tesla_ble.closure_is_open(0) is False
