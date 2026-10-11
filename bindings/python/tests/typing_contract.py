from typing import Any, assert_type

from tesla_ble import (
    BleAdapter,
    CommandResult,
    SimulatedVehicle,
    SleepState,
    StorageAdapter,
    Vehicle,
    WakePolicy,
)


class Ble(BleAdapter):
    def write(self, data: bytes) -> bool:
        return bool(data)


def check_types(storage: StorageAdapter) -> None:
    vehicle = Vehicle(Ble(), storage)
    assert_type(storage.load("private_key"), bytes | None)
    assert_type(vehicle.sleep_state, SleepState)

    def complete(result: CommandResult) -> None:
        assert_type(result.success, bool)
        assert_type(result.error_message, str | None)

    def state(data: dict[str, Any]) -> None:
        assert_type(data, dict[str, Any])

    vehicle.lock(complete)
    vehicle.set_charge_state_callback(state)
    vehicle.set_charge_state_callback(None)
    vehicle.vcsec_poll(WakePolicy.NO_WAKE_SKIP)
    assert_type(SimulatedVehicle().on_client_frame(b""), list[bytes])
    vehicle.lock(123)  # type: ignore[arg-type]
    vehicle.vcsec_poll("no_wake")  # type: ignore[arg-type]
    CommandResult()  # type: ignore[call-arg]
