cmake_minimum_required(VERSION 3.22)

include(FetchContent)
project(TeslaBLE
        VERSION 3.2.1
        DESCRIPTION "CPP Tesla BLE Library"
        LANGUAGES CXX C
)
set(CMAKE_CXX_STANDARD 23)


# Ensure mbedtls tests and programs are disabled
set(MBEDTLS_AS_SUBPROJECT ON)
set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(MBEDTLS_INSTALL OFF CACHE BOOL "" FORCE)

FetchContent_Declare(
        nanopb
        GIT_REPOSITORY https://github.com/nanopb/nanopb.git
        GIT_TAG 0.4.9.1
        GIT_SHALLOW    TRUE
)
FetchContent_Declare(
        mbedtls
        GIT_REPOSITORY https://github.com/espressif/mbedtls.git
        GIT_TAG mbedtls-3.6.2-idf
        GIT_SHALLOW    TRUE
)
FetchContent_MakeAvailable(nanopb mbedtls)

set(CMAKE_MODULE_PATH ${nanopb_SOURCE_DIR}/extra)
find_package(Nanopb REQUIRED)

# Generate nanopb sources from proto files
# Files are generated in ${CMAKE_CURRENT_BINARY_DIR} which is build/
file(GLOB_RECURSE PROTO_FILES "${CMAKE_CURRENT_SOURCE_DIR}/proto/*.proto")
nanopb_generate_cpp(TARGET tesla_ble_proto RELPATH proto ${PROTO_FILES})

add_library(TeslaBLE
        STATIC
        src/client.cpp
        src/errors.cpp
        src/peer.cpp
        src/tb_utils.cpp
        src/crypto_context.cpp
        src/message_builders.cpp
)

# Link the generated protobuf library (PUBLIC so consumers get the headers too)
target_link_libraries(TeslaBLE PUBLIC tesla_ble_proto mbedcrypto mbedtls mbedx509)

target_include_directories(
        TeslaBLE
        PRIVATE
        src/
        PUBLIC
        include/
)

# Removed separate mbedtls linking since it's now in target_link_libraries above
set_target_properties(TeslaBLE PROPERTIES PUBLIC_HEADER include/client.h)
set_target_properties(TeslaBLE PROPERTIES PUBLIC_HEADER include/errors.h)
set_target_properties(TeslaBLE PROPERTIES PUBLIC_HEADER include/peer.h)
set_target_properties(TeslaBLE PROPERTIES PUBLIC_HEADER include/tb_utils.h)
set_target_properties(TeslaBLE PROPERTIES PUBLIC_HEADER include/car_server.pb.h)
set_target_properties(TeslaBLE PROPERTIES PUBLIC_HEADER include/common.pb.h)
set_target_properties(TeslaBLE PROPERTIES PUBLIC_HEADER include/errors.pb.h)
set_target_properties(TeslaBLE PROPERTIES PUBLIC_HEADER include/keys.pb.h)
set_target_properties(TeslaBLE PROPERTIES PUBLIC_HEADER include/signatures.pb.h)
set_target_properties(TeslaBLE PROPERTIES PUBLIC_HEADER include/universal_message.pb.h)
set_target_properties(TeslaBLE PROPERTIES PUBLIC_HEADER include/vcsec.pb.h)
set_target_properties(TeslaBLE PROPERTIES PUBLIC_HEADER include/vehicle.pb.h)

# Only build tests if this is the main project
if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
    # Enable testing
    enable_testing()
    
    # Add tests subdirectory
    add_subdirectory(tests)
endif()
