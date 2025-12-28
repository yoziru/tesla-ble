# Detect if we're being used as an ESP-IDF component
# ESP-IDF sets IDF_PATH and includes component.cmake before processing CMakeLists.txt
if(DEFINED ENV{IDF_PATH} AND COMMAND idf_component_register)
    # ============================================================================
    # ESP-IDF Component Mode
    # ============================================================================
    
    # ESP-IDF runs CMakeLists.txt twice:
    # 1. In script mode to extract requirements (CMAKE_SCRIPT_MODE_FILE is set)
    # 2. In normal mode during actual build
    # We need to skip FetchContent and proto generation during script mode
    
    if(CMAKE_SCRIPT_MODE_FILE)
        # Script mode: just register with minimal info for dependency resolution
        # The actual sources will be populated during normal build
        idf_component_register(
            SRCS
                "src/client.cpp"
                "src/errors.cpp"
                "src/peer.cpp"
                "src/tb_utils.cpp"
                "src/crypto_context.cpp"
                "src/message_builders.cpp"
            INCLUDE_DIRS
                "include"
            REQUIRES
                mbedtls
        )
    else()
        # Normal build mode: do the full setup
        include(FetchContent)
        
        # Set policy to suppress FetchContent_Populate deprecation
        # We intentionally use Populate instead of MakeAvailable to avoid
        # adding nanopb's build targets which conflict with ESP-IDF's build system
        if(POLICY CMP0169)
            cmake_policy(SET CMP0169 OLD)
        endif()
        
        # Fetch nanopb for runtime only (no generation)
        FetchContent_Declare(
            nanopb
            GIT_REPOSITORY https://github.com/nanopb/nanopb.git
            GIT_TAG 0.4.9.1
            GIT_SHALLOW TRUE
        )
        # Download without calling add_subdirectory to avoid target conflicts
        FetchContent_GetProperties(nanopb)
        if(NOT nanopb_POPULATED)
            FetchContent_Populate(nanopb)
        endif()
        
        # Register as ESP-IDF component with prebuilt protobuf sources
        idf_component_register(
            SRCS
                "src/client.cpp"
                "src/errors.cpp"
                "src/peer.cpp"
                "src/tb_utils.cpp"
                "src/crypto_context.cpp"
                "src/message_builders.cpp"
                "src/car_server.pb.c"
                "src/common.pb.c"
                "src/errors.pb.c"
                "src/keys.pb.c"
                "src/managed_charging.pb.c"
                "src/signatures.pb.c"
                "src/universal_message.pb.c"
                "src/vcsec.pb.c"
                "src/vehicle.pb.c"
                "${nanopb_SOURCE_DIR}/pb_common.c"
                "${nanopb_SOURCE_DIR}/pb_encode.c"
                "${nanopb_SOURCE_DIR}/pb_decode.c"
            INCLUDE_DIRS
                "include"
                "${nanopb_SOURCE_DIR}"
            REQUIRES
                mbedtls
        )
    endif()

else()
    # ============================================================================
    # Standalone CMake Build Mode
    # ============================================================================
    
    cmake_minimum_required(VERSION 3.22)
    
    include(FetchContent)
    project(TeslaBLE
            VERSION 3.3.0
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
            GIT_TAG mbedtls-3.6.5-idf
            GIT_SHALLOW    TRUE
    )
    FetchContent_MakeAvailable(nanopb mbedtls)
    
    set(CMAKE_MODULE_PATH ${nanopb_SOURCE_DIR}/extra)
    find_package(Nanopb REQUIRED)
    
    add_library(TeslaBLE
            STATIC
            src/client.cpp
            src/errors.cpp
            src/peer.cpp
            src/tb_utils.cpp
            src/crypto_context.cpp
            src/message_builders.cpp
            generated/src/car_server.pb.c
            generated/src/common.pb.c
            generated/src/errors.pb.c
            generated/src/keys.pb.c
            generated/src/managed_charging.pb.c
            generated/src/signatures.pb.c
            generated/src/universal_message.pb.c
            generated/src/vcsec.pb.c
            generated/src/vehicle.pb.c
            generated/src/google/protobuf/timestamp.pb.c
            ${nanopb_SOURCE_DIR}/pb_decode.c
            ${nanopb_SOURCE_DIR}/pb_encode.c
            ${nanopb_SOURCE_DIR}/pb_common.c
    )
    
    target_include_directories(
            TeslaBLE
            PRIVATE
            src/
            generated/include/
            generated/src/
            ${NANOPB_INCLUDE_DIRS}
            PUBLIC
            include/
            generated/include/
            ${NANOPB_INCLUDE_DIRS}
    )
    
    target_link_libraries(TeslaBLE PUBLIC mbedcrypto mbedtls mbedx509)
    
    # Removed separate mbedtls linking since it's now in target_link_libraries above
    set_target_properties(TeslaBLE PROPERTIES PUBLIC_HEADER include/client.h)
    set_target_properties(TeslaBLE PROPERTIES PUBLIC_HEADER include/errors.h)
    set_target_properties(TeslaBLE PROPERTIES PUBLIC_HEADER include/peer.h)
    set_target_properties(TeslaBLE PROPERTIES PUBLIC_HEADER include/tb_utils.h)
    set_target_properties(TeslaBLE PROPERTIES PUBLIC_HEADER generated/include/protobuf/car_server.pb.h)
    set_target_properties(TeslaBLE PROPERTIES PUBLIC_HEADER generated/include/protobuf/common.pb.h)
    set_target_properties(TeslaBLE PROPERTIES PUBLIC_HEADER generated/include/protobuf/errors.pb.h)
    set_target_properties(TeslaBLE PROPERTIES PUBLIC_HEADER generated/include/protobuf/keys.pb.h)
    set_target_properties(TeslaBLE PROPERTIES PUBLIC_HEADER generated/include/protobuf/managed_charging.pb.h)
    set_target_properties(TeslaBLE PROPERTIES PUBLIC_HEADER generated/include/protobuf/signatures.pb.h)
    set_target_properties(TeslaBLE PROPERTIES PUBLIC_HEADER generated/include/protobuf/universal_message.pb.h)
    set_target_properties(TeslaBLE PROPERTIES PUBLIC_HEADER generated/include/protobuf/vcsec.pb.h)
    set_target_properties(TeslaBLE PROPERTIES PUBLIC_HEADER generated/include/protobuf/vehicle.pb.h)
    set_target_properties(TeslaBLE PROPERTIES PUBLIC_HEADER generated/include/protobuf/google/protobuf/timestamp.pb.h)
    
    # Only build tests if this is the main project
    if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
        # Enable testing
        enable_testing()
        
        # Add tests subdirectory
        add_subdirectory(tests)
    endif()
endif()
