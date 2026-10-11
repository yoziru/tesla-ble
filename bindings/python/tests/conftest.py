"""Shared fixtures and helpers for the tesla_ble binding tests."""

import tesla_ble
import time

VIN = "5YJ30123456789ABC"

# Protocol-spec test key (same as tests/test_constants.h; never use for real cars)
TEST_PRIVATE_KEY_PEM = (
    "-----BEGIN EC PRIVATE KEY-----\n"
    "MHcCAQEEICU4zcKal8GcHpmmN9bPT4yXDBGLVu3h5jI+bRYsSzDboAoGCCqGSM49\n"
    "AwEHoUQDQgAEsra8aMLaBmXOZWgVWUmWxiOU7di+qQX+eBp1T+aoRacUMwkC8iXp\n"
    "Jp1GbgWzSZgf2p2FzCPG+0RKpztikQXcbg==\n"
    "-----END EC PRIVATE KEY-----"
)


class FakeBleAdapter(tesla_ble.BleAdapter):
    """Captures outgoing frames instead of sending them over the air."""

    def __init__(self):
        super().__init__()
        self.sent = []
        self.connected = False
        self.connect_calls = []
        self.disconnect_calls = 0

    def connect(self, address):
        self.connected = True
        self.connect_calls.append(address)

    def disconnect(self):
        self.connected = False
        self.disconnect_calls += 1

    def write(self, data):
        self.sent.append(bytes(data))
        return True


class FakeStorage(tesla_ble.StorageAdapter):
    """In-memory StorageAdapter."""

    def __init__(self):
        super().__init__()
        self.data = {}
        self.save_calls = []

    def load(self, key):
        return self.data.get(key)

    def save(self, key, data):
        self.data[key] = bytes(data)
        self.save_calls.append(key)
        return True

    def remove(self, key):
        return self.data.pop(key, None) is not None


def make_vehicle(storage=None, vin=VIN, with_key=True):
    ble = FakeBleAdapter()
    storage = storage if storage is not None else FakeStorage()
    if with_key and "private_key" not in storage.data:
        storage.data["private_key"] = TEST_PRIVATE_KEY_PEM.encode() + b"\x00"
    vehicle = tesla_ble.Vehicle(ble, storage)
    vehicle.set_vin(vin)
    return ble, storage, vehicle


def pump(vehicle, ble, sim, max_iterations=500):
    """Drive the vehicle state machine against the simulated car.

    Alternates between Vehicle.loop() and handing captured frames to the
    SimulatedVehicle, feeding its replies back, until two consecutive
    iterations produce no traffic at all.
    """
    idle = 0
    for _ in range(max_iterations):
        before = len(ble.sent)
        vehicle.loop()
        produced = len(ble.sent) > before
        fed = False
        while ble.sent:
            frame = ble.sent.pop(0)
            fed = True
            for response in sim.on_client_frame(frame):
                vehicle.on_rx_data(response)
        if not produced and not fed:
            idle += 1
            if idle >= 2 and vehicle.pending_command_count == 0:
                return
            if vehicle.pending_command_count:
                time.sleep(0.01)
        else:
            idle = 0
    raise AssertionError("state machine did not settle")


def collect_callbacks():
    """Returns (results, callback) collecting CommandResults in a list."""
    results = []
    return results, results.append
