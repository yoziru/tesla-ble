# Tesla BLE Build Dependency Resolution Progress

## End Goal
Eliminate the dependency on `protoc` (Protocol Buffers compiler) entirely from the build process. The build should work without `protoc` being installed, leveraging PlatformIO's built-in nanopb support. Investigate if `protoc` is only needed for the Google timestamp.proto file and find a way to handle it without requiring `protoc` system-wide.

## Approach
1. Analyze why `protoc` is required in the current CMakeLists.txt
2. Determine if nanopb can handle all proto files without `protoc`
3. Check if the Google timestamp.proto dependency can be avoided or handled differently
4. Modify the build system to remove `protoc` dependency while maintaining functionality
5. Update CI workflows accordingly

## Steps Completed So Far
1. **Identified CI Failure**: ESPHome Tesla BLE CI was failing because `protoc` was not installed in the Ubuntu runners.
2. **Updated esphome-tesla-ble CI Workflow**: Added `sudo apt-get install -y protobuf-compiler` to the CI steps in `.github/workflows/ci.yml` to install `protoc` before building.
3. **Added protoc Check to CMakeLists.txt**: In `tesla-ble/CMakeLists.txt`, added `find_program(PROTOC protoc REQUIRED)` in the ESP-IDF component mode to ensure `protoc` is available and fail early if not found.
4. **Local Installation**: Installed `protoc` locally using `brew install protobuf` to resolve local build failures.
5. **Attempted Pre-generation**: Tried to pre-generate protobuf files to eliminate `protoc` dependency, but discovered that nanopb's generator itself requires `protoc` to generate `nanopb_pb2.py`.
6. **Constraint Applied**: User constrained to only keep `timestamp.pb.h` as a pre-generated file, deleting all other generated files.
7. **Added grpcio-tools fallback & PlatformIO bootstrap script**: Updated `CMakeLists.txt` to attempt to use `grpcio-tools` (Python) when `protoc` is not available and added `scripts/platformio_bootstrap.py` to ensure PlatformIO's penv has `pip`, `protobuf`, and `grpcio-tools` installed.

## Current Status
Under the constraint of only keeping `timestamp.pb.h` as a pre-generated file and not modifying the source `.proto` files, it is not possible to build without `protoc` installed. The nanopb generator requires `protoc` to process any protobuf files, including those that import `google/protobuf/timestamp.proto`. Pre-generating only the header file for timestamp does not eliminate the need for `protoc` since the corresponding `.pb.c` file and all other protobuf files still need to be generated at build time.

## Conclusion
To achieve the goal of building without `protoc`, we would need to either:
- Allow pre-generation and commitment of all `.pb.c` and `.pb.h` files to the repository
- Modify the source `.proto` files to avoid Google protobuf dependencies (not allowed)
- Switch to a different protobuf library that doesn't require `protoc` at build time
- Accept that `protoc` must be installed for the build to work

Since the current constraint prevents the viable solutions, the build will continue to require `protoc` to be installed.