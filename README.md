# TeslaBLE - A C++ library for communicating with Tesla vehicles over BLE

This library is designed to communicate with Tesla vehicles locally via the BLE API. It follows the same principles as the official Tesla [vehicle-command](https://github.com/teslamotors/vehicle-command) library (Golang), and is intended for use in embedded systems.

It exists to:

1. Provide a local and offline alternative to the official Tesla API.
2. Avoid the rate limits of the official Tesla API.

The main purpose of this library is to locally manage charging of the vehicle to enable use cases such as charging during off-peak hours, or to manage charging based on solar production. It is not intended to replace the official Tesla API for all use cases.

## Usage

This project is intended to be used as a library in your own project. It is not a standalone application.

Hosts built on this library:

- [yoziru/esphome-tesla-ble](https://github.com/yoziru/esphome-tesla-ble) - ESPHome component (ESP32 talks to the car directly).
- [yoziru/ha-tesla-ble](https://github.com/yoziru/ha-tesla-ble) - Home Assistant integration via the [Python bindings](bindings/python), working over local adapters or ESPHome Bluetooth proxies.

Several examples are included for your convenience.

```sh
cd examples/simple/
cmake .
make
```

The host contract is small: implement `BleAdapter` (write frames) and
`StorageAdapter` (persist keys/sessions), construct the `Vehicle` **after**
storage is loaded, then call `loop()` periodically, feed notifications to
`on_rx_data()` and connection state to `set_connected()`. Successful actions
queue their own follow-up state polls; `has_private_key()` and
`pending_command_count()` cover pairing state and in-flight work.

Disconnect cancels unfinished commands, decoded replies, partial frames and
delayed refreshes; do not replay controls automatically on reconnection. Keep
vehicle credentials, pairing evidence and host-owned last-known telemetry.
`BleAdapter::write()` means queue acceptance, not delivery. A successful result
means the protocol completion condition was received, not that refreshed
telemetry proves the requested state. A lost reply can leave an unknown outcome
even after retries; retries reuse the encoded request within the same session.
Command names are diagnostic labels, not authentication or refresh policy.

`set_seat_climate()` sends one heat/cool request; the car handles exclusivity.
Off clears cooling when supported, then heating, with one completion callback.
Cooling support describes observed hardware, not current levels. Failure stops
later steps without rollback. Climate/preconditioning or Climate Keeper must be
on for seat commands; the library does not turn climate on implicitly. Optional UI exposure
and retention/freshness remain host-native, best effort rather than parity.

State callbacks are observations: absent optional fields are unknown, not zero,
Off or proof that hardware was removed. The library does not merge telemetry.
HA replaces each reported state group, keeps capability evidence separately and
retains sleeping-car values while VCSEC remains reachable. ESPHome retains
individual sensor values and uses last-known charging/sentry state for its native
poll cadence; those retained values are not new observations or per-field
freshness guarantees. Neither host should optimistically publish a commanded
state as observed merely because the command completed.

`set_poll_result_callback(callback)` reports each telemetry poll's diagnostic
name and terminal `OperationResult` (`CommandResult` in Python), including
sleep skips and failures. It covers individual, bulk and follow-up polls;
completion does not imply a state observation. Python `clear_callbacks()` removes
this callback too. Disconnect before clearing callbacks to finish pending work.

`InfotainmentPollPolicy::on_poll()` records cadence, not activity. Its idle timer
continues across absence; neither an awake report nor reconnect should reset it.
Hosts own bounded arrival probes, genuine-activity detection and freshness.

### Charging power

`Vehicle::charging_power()` returns watts, inferred phases, the power multiplier,
AC/DC classification and source. Python charge-state callbacks add
`charger_power_w`, `charger_effective_phases`, `charger_power_multiplier`,
`charger_is_ac` and `charger_power_source`; original protobuf fields stay unchanged.

AC estimates use voltage × current × a multiplier, assuming power factor ≈ 1
and equally loaded inputs:

- **1:** single-phase, including US 240 V split-phase.
- **2:** two line-to-neutral inputs.
- **3 or sqrt(3):** three-phase with
  [line-to-neutral or line-to-line voltage](https://www.engineeringtoolbox.com/three-phase-electrical-d_888.html), respectively.

Detection requires three stable readings with one plausible multiplier matching
reported power. Raw phases alone cannot determine it. Uncertain, incomplete or DC
readings use reported power; absent or invalid power stays unknown. Voltage and
current are never carried between readings. Unplugging resets detection and
reports zero; BLE reconnects retain detection but revalidate each reading.

Inferred phases are estimates, not a wiring diagnosis. Integrate AC energy only
when `is_ac` is true; DC reported power is battery-side power.

## Building and Testing

### Quick Start

```bash
# Clone the repository
git clone https://github.com/yoziru/tesla-ble.git
cd tesla-ble

# Setup development environment (optional but recommended)
./scripts/setup_dev_environment.sh

# Build the project
cmake -B build
cmake --build build

# Run tests
./scripts/run_tests.sh
```

### Manual Build

```bash
# Configure with CMake
cmake -B build -DCMAKE_BUILD_TYPE=Release

# Build the library and tests
cmake --build build --config Release

# Run tests with CTest
cd build
ctest --build-config Release --output-on-failure
```

### Running Tests

#### Using the Test Runner Script

The repository includes a comprehensive test runner script with various options:

```bash
# Run tests in Debug mode (default)
./scripts/run_tests.sh

# Run tests in Release mode
./scripts/run_tests.sh --release

# Run tests with coverage analysis
./scripts/run_tests.sh --coverage

# Run tests with Valgrind (Linux only)
./scripts/run_tests.sh --valgrind

# Clean build and run tests
./scripts/run_tests.sh --clean

# Get help on available options
./scripts/run_tests.sh --help
```

#### Manual Test Execution

```bash
# Build and run all Tesla BLE tests (excludes dependency tests)
cd build
ctest --output-on-failure --verbose

# Run specific test suites
./tests/test_client
./tests/test_key_generation
./tests/test_message_building
./tests/test_message_parsing
./tests/test_session_management
./tests/test_protocol_compliance
./tests/test_error_handling
```

### Test Coverage

To generate a coverage report:

```bash
# Install coverage tools (Ubuntu/Debian)
sudo apt-get install lcov

# Run tests with coverage
./scripts/run_tests.sh --coverage

# Coverage report will be generated in build/coverage_html/
```

### Static Analysis

The project includes static analysis via cppcheck:

```bash
# Install cppcheck
sudo apt-get install cppcheck  # Ubuntu/Debian
brew install cppcheck          # macOS

# Run static analysis
cppcheck --enable=all --inconclusive \
    --suppress=missingIncludeSystem \
    --suppress=unusedFunction \
    src/ include/ examples/
```

### Code Formatting and Linting

The project uses clang-format for code formatting and clang-tidy for static analysis:

```bash
# Install clang tools
sudo apt-get install clang-format clang-tidy  # Ubuntu/Debian
brew install clang-format clang-tidy          # macOS

# Run formatting and linting checks (will configure CMake if needed)
./scripts/clang-format.sh --check
./scripts/clang-tidy.sh --check

# Or run individually:
# Format code
find src include tests examples -name "*.cpp" -o -name "*.h" | xargs clang-format -i

# Check formatting
find src include tests examples -name "*.cpp" -o -name "*.h" | xargs clang-format --dry-run --Werror --style=file

# Run clang-tidy on source files (requires compile_commands.json)
find src -name "*.cpp" | xargs clang-tidy
```

### Development Environment Setup

Use the provided script to set up your development environment:

```bash
./scripts/setup_dev_environment.sh
```

This script will:

- Detect your operating system
- Install required dependencies (cmake, compiler, etc.)
- Install optional development tools (lcov, cppcheck, valgrind)
- Set up git hooks for automatic testing

### Continuous Integration

The project uses GitHub Actions for CI/CD with the following features:

- **C++ build, tests, examples and clang checks**: Ubuntu
- **Python bindings and sdist-to-wheel builds**: CPython 3.13 and 3.14 on Ubuntu
- **Release wheels and offline wheel tests**: Linux x86_64/aarch64 and macOS arm64/x86_64
- **Memory testing**: Valgrind is available locally via `./scripts/run_tests.sh --valgrind` (not run in CI)
- **Coverage**: Coverage analysis is available locally via `./scripts/run_tests.sh --coverage` (not run in CI)

### Test Structure

The test suite is organized into several categories:

- **`test_client.cpp`**: Core client functionality and initialization
- **`test_key_generation.cpp`**: Private key generation and loading
- **`test_message_building.cpp`**: Message construction for various commands
- **`test_message_parsing.cpp`**: Parsing of received messages
- **`test_session_management.cpp`**: Session handling and peer management
- **`test_tb_utils.cpp`**: Utility functions and helper methods
- **`test_vehicle.cpp`**: Vehicle state management and command processing
- **`test_session_recovery.cpp`**: Session recovery after session errors

Each test file contains comprehensive unit tests covering both success and failure scenarios, edge cases, and parameter validation.

### State Architecture

The library uses a unified state pattern for command processing with the following states:

- **`IDLE`**: Initial state for new commands
- **`AUTHENTICATING`**: Unified authentication initiation (replaces legacy domain-specific states)
- **`AUTH_RESPONSE_WAITING`**: Unified authentication response waiting
- **`READY`**: Command ready to be sent
- **`WAITING_FOR_RESPONSE`**: Waiting for command response
- **`COMPLETED`**: Command completed successfully
- **`FAILED`**: Command failed

This architecture provides a clean, maintainable approach to command lifecycle management with exponential backoff for retries.

### Dependencies

- [nanopb](https://github.com/nanopb/nanopb)
- [mbedtls 3.x](https://github.com/Mbed-TLS/mbedtls)
  - NOTE: ESP-IDF <=4.4 includes [mbedtls 2.x](https://github.com/espressif/mbedtls/wiki#mbed-tls-support-in-esp-idf), and is not compatible with this library. You will need to use at least ESP-IDF 5.0.

## Features

- [x] Implements Tesla's BLE [protocol](https://github.com/teslamotors/vehicle-command/blob/main/pkg/protocol/protocol.md)
- [x] AES-GCM key generation
- [x] [Metadata serialization](https://github.com/teslamotors/vehicle-command/blob/main/pkg/protocol/protocol.md#metadata-serialization)
- [x] Supports `UniversalMessage.RoutableMessage` encoding and decoding
  - [x] Supports Vehicle Security (VSSEC) payload
  - [x] Supports Infotainment payload

# Credits

This fork builds on the original version by [pmdroid](https://github.com/pmdroid/tesla-ble/tree/main).

# IMPORTANT

Please take note that this library does not have official backing from Tesla, and its operational capabilities may be discontinued without prior notice. It's essential to recognize that this library retains private keys and other sensitive data on your device without encryption. I would like to stress that I assume no liability for any possible (although highly unlikely) harm that may befall your vehicle.
