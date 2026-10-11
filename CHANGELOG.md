# Changelog

## 6.0.0

This release moves the shared host logic into the library and cleans up the
public API. It is a breaking release; see "Breaking changes" below.

### Added

- Python bindings (`bindings/python`, PyPI package `tesla-ble`): the full
  `Vehicle` state machine with subclassable `BleAdapter`/`StorageAdapter`,
  state callbacks delivered as plain dicts, a log bridge and a
  `SimulatedVehicle` test double. Used by the Home Assistant integration
  [yoziru/ha-tesla-ble](https://github.com/yoziru/ha-tesla-ble).
- `state_text`: enum/tag -> text and flag conversions (moved from
  esphome-tesla-ble), including closure state helpers.
- `InfotainmentPollPolicy` (moved from esphome-tesla-ble): decides the
  infotainment polling cadence and wake policy from vehicle state.
- `Vehicle::has_private_key()`: pairing state for hosts.
- `Vehicle::pending_command_count()`: queued + in-flight commands, so hosts
  can avoid disconnecting while work is pending.
- All high-level actions accept an `OperationResultCallback` and report
  success / skipped / failure with a rich `CommandError`.
- Successful actions queue a follow-up poll for the state they changed
  (VCSEC / charge / climate / closures, `NO_WAKE_SKIP`), so hosts converge
  without their own refresh bookkeeping.
- `Vehicle::vcsec_poll(WakePolicy)`; `wake()` takes a result callback.
- `BleAdapter::connect`/`disconnect` are now optional (default no-ops); the
  library never calls them, hosts own the connection lifecycle.
- VIN helpers recognize all advertised name schemes: `S<16 hex>C/R/D/P`
  and the 2023+ `Tesla <last 6 of VIN>`.

### Breaking changes

- Removed the legacy `Vehicle::send_command` and `send_command_bool`
  overloads. Use `send_command_result` (or a high-level action method).
- `Client` is no longer movable (moving left its peers aliasing the
  moved-from crypto context).
- `Vehicle::rx_buffer_` is private; tests use `rx_buffer_for_testing()`.
- `Vehicle::get_command_queue_for_testing()` returns a mutable reference.

### Changed

- `vehicle.h` includes `polling_policy.h`, which now defines `WakePolicy`
  (the enum moved there from `vehicle.h`).
