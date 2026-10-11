import gc
import subprocess
import sys
import weakref

import pytest
import tesla_ble

from conftest import FakeBleAdapter, FakeStorage, VIN, make_vehicle, pump


def test_vehicle_retains_temporary_python_adapters():
    ble, storage = FakeBleAdapter(), FakeStorage()
    ble_ref, storage_ref = weakref.ref(ble), weakref.ref(storage)
    vehicle = tesla_ble.Vehicle(ble, storage)
    vehicle.set_vin(VIN)
    del ble, storage
    gc.collect()
    assert ble_ref() is not None and storage_ref() is not None
    results = []
    vehicle.set_connected(True)
    vehicle.pair(on_complete=results.append)
    pump(vehicle, ble_ref(), tesla_ble.SimulatedVehicle(VIN))
    assert results[0].success
    del vehicle
    gc.collect()
    assert ble_ref() is None and storage_ref() is None


@pytest.mark.parametrize("missing", ["ble", "storage"])
def test_null_adapter_is_rejected(missing):
    with pytest.raises(ValueError, match="must not be None"):
        tesla_ble.Vehicle(None if missing == "ble" else FakeBleAdapter(),
                          None if missing == "storage" else FakeStorage())


def test_installed_log_callback_is_safe_at_interpreter_exit():
    completed = subprocess.run(
        [sys.executable, "-c", "import tesla_ble; tesla_ble.set_log_callback(lambda *args: None)"],
        capture_output=True, text=True, timeout=10,
    )
    assert completed.returncode == 0, completed.stderr


def test_storage_load_exception_propagates_from_constructor():
    class BrokenStorage(FakeStorage):
        def load(self, key):
            raise OSError("cannot read credentials")

    with pytest.raises(OSError, match="cannot read credentials"):
        tesla_ble.Vehicle(FakeBleAdapter(), BrokenStorage())


def test_media_callback_validation_and_clearing():
    _, _, vehicle = make_vehicle()
    states = []
    vehicle.set_media_state_callback(states.append)
    frame = bytes.fromhex("000b3a02080352051203a20100")
    vehicle.on_rx_data(frame)
    vehicle.loop()
    assert states == [{}]
    with pytest.raises(TypeError):
        vehicle.set_media_state_callback(123)
    vehicle.set_media_state_callback(None)
    payload = frame[2:] + b"\x60\x01"
    vehicle.on_rx_data(len(payload).to_bytes(2, "big") + payload)
    vehicle.loop()
    assert states == [{}]


def test_raw_callback_can_disconnect():
    completed = subprocess.run(
        [sys.executable, "-c", '''
import sys
sys.path.insert(0, "bindings/python/tests")
from conftest import make_vehicle
_, _, vehicle = make_vehicle()
vehicle.set_connected(True)
vehicle.set_raw_message_callback(lambda _: vehicle.set_connected(False))
vehicle.on_rx_data(bytes.fromhex("000b3a02080352051203a20100"))
assert not vehicle.is_connected
'''], capture_output=True, text=True, timeout=10,
    )
    assert completed.returncode == 0, completed.stderr


def test_identical_consecutive_fragments_preserve_media_response():
    _, _, vehicle = make_vehicle()
    states = []
    vehicle.set_media_state_callback(states.append)
    media = b"\x1a\x50" + b"a" * 80
    data = bytes.fromhex("a201") + bytes([len(media)]) + media
    response = b"\x12" + bytes([len(data)]) + data
    message = bytes.fromhex("3a02080352") + bytes([len(response)]) + response
    frame = len(message).to_bytes(2, "big") + message
    first = len(frame) - 80
    vehicle.on_rx_data(frame[:first])
    for offset in range(first, len(frame), 20):
        vehicle.on_rx_data(frame[offset:offset + 20])
    vehicle.loop()
    assert states[-1]["now_playing_artist"] == "a" * 80


def test_raising_state_callback_is_reported_without_breaking_command(monkeypatch):
    errors = []
    monkeypatch.setattr(sys, "unraisablehook", errors.append)
    ble, _, vehicle = make_vehicle()

    def state(_):
        vehicle.clear_callbacks()
        raise RuntimeError("host callback failed")

    vehicle.set_vehicle_status_callback(state)
    vehicle.set_connected(True)
    vehicle.vcsec_poll()
    pump(vehicle, ble, tesla_ble.SimulatedVehicle(VIN))
    assert vehicle.pending_command_count == 0
    assert len(errors) == 1 and str(errors[0].exc_value) == "host callback failed"


def test_explicit_callback_teardown_releases_python_owner():
    class Owner:
        def __init__(self):
            self.ble, self.storage, self.vehicle = make_vehicle()
            self.vehicle.set_charge_state_callback(self.state)
            self.vehicle.set_media_state_callback(self.state)

        def state(self, state):
            pass

    owner = Owner()
    ref = weakref.ref(owner)
    owner.vehicle.set_connected(False)
    owner.vehicle.clear_callbacks()
    del owner
    gc.collect()
    assert ref() is None


def test_storage_save_exception_preserves_auth_progress_but_fails_pairing(monkeypatch):
    errors = []
    monkeypatch.setattr(sys, "unraisablehook", errors.append)

    class BrokenStorage(FakeStorage):
        def save(self, key, data):
            raise OSError("disk unavailable")

        def remove(self, key):
            raise OSError("disk unavailable")

    ble, _, vehicle = make_vehicle(storage=BrokenStorage())
    results = []
    vehicle.set_connected(True)
    vehicle.lock(results.append)
    pump(vehicle, ble, tesla_ble.SimulatedVehicle(VIN))
    assert len(results) == 1 and results[0].success
    assert vehicle.pending_command_count == 0
    results.clear()
    sent = len(ble.sent)
    vehicle.pair(on_complete=results.append)
    assert len(results) == 1 and results[0].failure
    assert vehicle.pending_command_count == 0 and len(ble.sent) == sent
    results.clear()
    vehicle.regenerate_key(results.append)
    assert len(results) == 1 and results[0].failure
    assert len(errors) >= 2 and all(isinstance(error.exc_value, OSError) for error in errors)


def test_closure_raw_keys_match_text_keys():
    ble, _, vehicle = make_vehicle()
    states = []
    vehicle.set_vehicle_status_callback(states.append)
    vehicle.set_connected(True)
    vehicle.vcsec_poll()
    pump(vehicle, ble, tesla_ble.SimulatedVehicle(VIN))
    assert states[-1]["closures"].keys() == states[-1]["closures_raw"].keys()


def test_simulator_rejects_unsigned_non_status_payloads():
    sim = tesla_ble.SimulatedVehicle(VIN)
    # Unsigned infotainment payload; VCSEC RKE action; non-status VCSEC oneof.
    for frame in ["0009320208035203626164", "00083202080252021063", "00083202080252021801"]:
        assert sim.on_client_frame(bytes.fromhex(frame)) == []


def test_simulator_authenticates_encrypted_command_before_applying_it():
    sim = tesla_ble.SimulatedVehicle(VIN)
    sim.set_locked(False)
    ble, _, vehicle = make_vehicle()
    vehicle.set_connected(True)
    vehicle.vcsec_poll()
    pump(vehicle, ble, sim)
    vehicle.lock()
    for _ in range(10):
        vehicle.loop()
        if ble.sent:
            break
    assert ble.sent
    frame = ble.sent.pop(0)
    # Client serialization places to/from destinations before payload field 10.
    offset = 2
    while frame[offset] != 0x52:
        assert frame[offset] in (0x32, 0x3A)
        offset += 2 + frame[offset + 1]
    damaged = bytearray(frame)
    damaged[offset + 2] ^= 1
    assert sim.on_client_frame(bytes(damaged)) == []
    replies = sim.on_client_frame(frame)
    assert replies
    states = []
    vehicle.set_vehicle_status_callback(states.append)
    for reply in replies:
        vehicle.on_rx_data(reply)
    pump(vehicle, ble, sim)
    assert states[-1]["locked"] is True
