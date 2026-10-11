# tesla-ble (Python bindings)

Python bindings for the [TeslaBLE](../../README.md) C++ library: control Tesla
vehicles over BLE from Python.

```python
import tesla_ble


class MyBle(tesla_ble.BleAdapter):
    def connect(self, address): ...
    def disconnect(self): ...
    def write(self, data: bytes) -> bool: ...


class MyStorage(tesla_ble.StorageAdapter):
    def load(self, key): ...
    def save(self, key, data): ...
    def remove(self, key): ...


vehicle = tesla_ble.Vehicle(MyBle(), MyStorage())
vehicle.set_vin("5YJ...")
vehicle.set_connected(True)
vehicle.set_charge_state_callback(lambda state: print(state["battery_level"]))
vehicle.loop()  # drive the state machine from your event loop
vehicle.on_rx_data(...)  # feed BLE notifications
```

## Development

The Python packaging lives at the repository root (`pyproject.toml`); the
extension sources are under `bindings/python/`.

```sh
uv sync                    # creates .venv, builds and installs tesla-ble + pytest
uv run pytest bindings/python/tests -q
uv run ruff check bindings/python scripts
uv run ruff format --check bindings/python scripts
uv run mypy
```

`uv build` produces wheels/sdists; sdists contain the whole C++ library and
build standalone, fetching the pinned nanopb and Mbed TLS dependencies.
Run `python3 scripts/check_dist.py dist` to check archive contents and licenses.

Ruff covers the Python package, tools and tests. Mypy strictly checks the
standalone Python tools; checking the compiled API requires `.pyi` stubs,
which are not shipped yet. Use `uv run ruff format bindings/python scripts`
to apply formatting.

## Wheels

CI builds wheels for CPython 3.13, 3.14 and 3.15 (see `[tool.cibuildwheel]` in
`pyproject.toml`):

| Platform | Architectures | Typical Home Assistant setup |
| --- | --- | --- |
| Linux (manylinux/glibc) | x86_64, aarch64 | Python virtual environments on glibc distributions |
| Linux (musllinux/Alpine) | x86_64, aarch64 | HA OS, HA Container, Alpine Linux |
| macOS | arm64, x86_64 (cross-compiled) | Native macOS Python; Docker uses Linux wheels |

Local builds:

```sh
# Linux (any host with Docker; aarch64 runs under emulation)
uvx cibuildwheel --platform linux .

# macOS: cibuildwheel requires the python.org framework CPythons.
# Install the 3.13/3.14/3.15 installers from python.org (admin prompt), then:
uvx cibuildwheel --platform macos .
```

The macOS runners in CI install the required Pythons automatically, so release
wheels are produced without local setup.
Linux cross-architecture builds require Docker emulation/binfmt support; CI
sets up QEMU explicitly. Every testable wheel runs the offline bindings suite.

## Notes

- Requires Python ≥ 3.13 (matching Home Assistant) and a C++23 compiler.
- `Vehicle` is **not thread-safe**: call `loop()`, `on_rx_data()` and actions
  from a single thread (the Home Assistant integration uses the event loop).
- Python infotainment polls default to `WakePolicy.WAKE_IF_NEEDED` and may
  wake the vehicle. Pass `WakePolicy.NO_WAKE_SKIP` explicitly for background
  telemetry polling; unlike Python, native C++ polls default to no wake.
- `Vehicle` retains its Python BLE/storage adapters. Adapters must be non-null.
- Storage `load()` exceptions propagate, including during construction. Exceptions
  from `save()` and `remove()` are reported through `sys.unraisablehook` and
  converted to `False`. Session persistence is optional; private-key save failures
  fail pairing without sending a pairing request.
- Storage `save()`/`remove()` may stage changes for a host-managed flush. Async
  hosts must durably flush a newly generated private key before transmitting
  pairing and flush staged state on shutdown; ESPHome commits NVS synchronously.
- `CommandResult.success` is protocol completion, not an observed postcondition.
  `may_have_succeeded` signals an uncertain result: do not replay a control after
  reconnect merely because its reply was lost. `BleAdapter.write()` returning
  `True` only accepts a frame for transmission.
- `set_seat_climate(seat, level, cooling, cooling_supported, cb)` sends one
  heat/cool request. Level 0 clears supported cooling, then heating; the car
  disables Auto. Cooling support refers to observed hardware, not current levels.
  Invalid levels are rejected; a failure stops later steps without rollback.
  Climate/preconditioning or Climate Keeper must be on; it is not enabled implicitly.
- Callback exceptions are reported through `sys.unraisablehook`. Pass `None` to
  any state/raw callback setter to remove it. Bound methods may retain their
  owner through a C++ callback cycle: explicitly tear down callbacks on unload.
  Stop polling and detach BLE notifications first, then:

  ```python
  vehicle.set_connected(False)  # finish/fail pending action callbacks
  vehicle.clear_callbacks()  # release state and raw-message callbacks
  ```

  Release any adapter-to-owner references too. `set_log_callback(None)` removes
  the process-wide log sink; only its installer should remove it. Installed log
  callbacks are also safe during normal interpreter shutdown. Use the main
  interpreter only; this module does not support subinterpreters or native-thread
  calls into the shared library while a Python log callback is installed.
- `SimulatedVehicle` validates AES-GCM request authentication and parses actions.
  It supports status/polls, pairing, lock/unlock/wake, basic closures, charging,
  climate, sentry, lights and horn; malformed and unsupported requests receive
  no response. Setters affect reported telemetry, and supported actions change it.
  Responses remain plaintext and pairing auto-approves keys: this is an offline
  binding/host test helper, not an emulator of vehicle security or timing.
- The wheel version tracks the C++ library version (`VERSION` at the repo root).
- The package follows the repository's AGPL-3.0 license, not the old MIT metadata.
  Wheels include dependency license texts and notices without development headers
  or static libraries.
