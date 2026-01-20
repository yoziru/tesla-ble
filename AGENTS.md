# AGENTS.md - TeslaBLE Development Guide

## Build Commands
```bash
cmake -B build -DCMAKE_MESSAGE_LOG_LEVEL=ERROR && cmake --build build -j 2>&1 | grep -E "error:|Error:|Built target|failed" | head -20 || true
cd build && ctest -j 2>&1 | grep -E "(FAILED.*\]|^[0-9]+% tests|expected equality|Which is:|tests/.*:.*:.*Failure|Failed to)"
```

## Lint and Format Commands
```bash
# Run all linting and formatting checks
./scripts/lint.sh

# Format code with clang-format
find src include tests examples -name "*.cpp" -o -name "*.h" | xargs clang-format -i

# Run clang-tidy on source files
find src -name "*.cpp" | xargs clang-tidy
```

## Architecture
- **Library**: C++23 library for Tesla vehicle BLE communication
- **Core Classes**: `Client` (main API), `CryptoContext` (keys/EC), `Peer` (sessions per domain)
- **Domains**: VEHICLE_SECURITY, INFOTAINMENT (via `UniversalMessage_Domain`)
- **Protocol**: Protobuf messages (nanopb), AES-GCM encryption (mbedtls)
- **Dependencies**: nanopb, mbedtls, googletest
- **Generated Code**: `generated/src/*.pb.c`, `generated/include/*.pb.h`

## Code Style
- **Namespace**: `TeslaBLE`
- **Naming**: `PascalCase` classes, `snake_case` functions, `_` suffix for members (`crypto_context_`)
- **Types**: Use `pb_byte_t`, `pb_size_t` for protobuf; `std::array`, `std::unique_ptr`
- **Error Handling**: Return `TeslaBLE_Status_E` enum (0=OK); use `LOG_ERROR`/`LOG_DEBUG` macros
- **Formatting**: No comments unless requested; 4-space indent; braces on same line
- **Protobuf**: Use `*_init_default`/`*_init_zero`; encode with `pb_encode_fields`, decode with `pb_decode`
