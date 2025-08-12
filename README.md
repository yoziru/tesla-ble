# TeslaBLE - A C++ library for communicating with Tesla vehicles over BLE

This library is designed to communicate with Tesla vehicles locally via the BLE API. It follows the same principles as the official Tesla [vehicle-command](https://github.com/teslamotors/vehicle-command) library (Golang), and is intended for use in embedded systems.

It exists to:

1. Provide a local and offline alternative to the official Tesla API.
2. Avoid the rate limits of the official Tesla API.

The main purpose of this library is to locally manage charging of the vehicle to enable use cases such as charging during off-peak hours, or to manage charging based on solar production. It is not intended to replace the official Tesla API for all use cases.

## Usage

This project is intended to be used as a library in your own project. It is not a standalone application.

[yoziru/esphome-tesla-ble](https://github.com/yoziru/esphome-tesla-ble) is an ESPHome project that uses this library to control your Tesla vehicle charging.

Several examples are included for your convenience.

```sh
cd examples/simple/
cmake .
make
```

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
ctest --output-on-failure --verbose -R "Tesla|Client|Key|Message|Session|Utils"

# Run specific test suites
./tests/test_client
./tests/test_key_generation
./tests/test_message_building
./tests/test_message_parsing
./tests/test_session_management
./tests/test_utils

# Run the complete test suite
./tests/tesla_ble_tests
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

- **Cross-platform testing**: Ubuntu, Windows, macOS
- **Multiple build types**: Debug and Release
- **Code coverage**: Automatic coverage reporting to Codecov
- **Static analysis**: cppcheck integration
- **Memory testing**: Valgrind and AddressSanitizer
- **Performance testing**: Various sanitizers (address, undefined, thread)

### Test Structure

The test suite is organized into several categories:

- **`test_client.cpp`**: Core client functionality and initialization
- **`test_key_generation.cpp`**: Private key generation and loading
- **`test_message_building.cpp`**: Message construction for various commands
- **`test_message_parsing.cpp`**: Parsing of received messages
- **`test_session_management.cpp`**: Session handling and peer management
- **`test_utils.cpp`**: Utility functions and helper methods

Each test file contains comprehensive unit tests covering both success and failure scenarios, edge cases, and parameter validation.

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
