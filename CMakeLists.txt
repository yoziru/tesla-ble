# Define generated files directory - used by both ESP-IDF and standalone builds
set(GENERATED_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/generated/include")
set(GENERATED_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/generated/src")

# Common source files across all builds
set(TESLABLE_SRCS
    "src/client.cpp"
    "src/crypto_context.cpp"
    "src/errors.cpp"
    "src/message_builders.cpp"
    "src/peer.cpp"
    "src/tb_logging.cpp"
    "src/tb_utils.cpp"
    "src/vehicle.cpp"
    "src/vin_utils.cpp"
    "src/logging_bridge.cpp"
)

# Protobuf generated source files
set(TESLABLE_PROTO_SRCS
    "${GENERATED_SRC_DIR}/car_server.pb.c"
    "${GENERATED_SRC_DIR}/common.pb.c"
    "${GENERATED_SRC_DIR}/errors.pb.c"
    "${GENERATED_SRC_DIR}/google/protobuf/timestamp.pb.c"
    "${GENERATED_SRC_DIR}/keys.pb.c"
    "${GENERATED_SRC_DIR}/managed_charging.pb.c"
    "${GENERATED_SRC_DIR}/signatures.pb.c"
    "${GENERATED_SRC_DIR}/universal_message.pb.c"
    "${GENERATED_SRC_DIR}/vcsec.pb.c"
    "${GENERATED_SRC_DIR}/vehicle.pb.c"
)

# Public headers
set(TESLABLE_PUBLIC_HEADERS
    include/client.h
    include/adapters.h
    include/errors.h
    include/peer.h
    include/tb_logging.h
    include/tb_utils.h
    include/vehicle.h
    include/vin_utils.h
)

# Detect if we're being used as an ESP-IDF component
# ESP-IDF sets IDF_PATH and includes component.cmake before processing CMakeLists.txt
if(DEFINED ENV{IDF_PATH} AND COMMAND idf_component_register)
    # ============================================================================
    # ESP-IDF Component Mode
    # ============================================================================
    # ESP-IDF runs CMakeLists.txt twice:
    # 1. In script mode to extract requirements (CMAKE_SCRIPT_MODE_FILE is set)
    # 2. In normal mode during actual build
    
    if(CMAKE_SCRIPT_MODE_FILE)
        # Script mode: register with minimal info for dependency resolution
        idf_component_register(
            SRCS ${TESLABLE_SRCS}
            INCLUDE_DIRS "include"
            REQUIRES mbedtls
        )
    else()
        # Normal build mode: fetch dependencies and build with prebuilt protobuf sources
        include(FetchContent)
        
        # Use FetchContent_Populate to avoid adding nanopb's build targets
        # which conflict with ESP-IDF's build system
        if(POLICY CMP0169)
            cmake_policy(SET CMP0169 OLD)
        endif()
        
        FetchContent_Declare(
            nanopb
            GIT_REPOSITORY https://github.com/nanopb/nanopb.git
            GIT_TAG 0.4.9.1
            GIT_SHALLOW TRUE
        )
        FetchContent_GetProperties(nanopb)
        if(NOT nanopb_POPULATED)
            FetchContent_Populate(nanopb)
        endif()
        
        # Nanopb library sources (must be defined after nanopb is populated)
        set(TESLABLE_NANOPB_SRCS
            "${nanopb_SOURCE_DIR}/pb_common.c"
            "${nanopb_SOURCE_DIR}/pb_decode.c"
            "${nanopb_SOURCE_DIR}/pb_encode.c"
        )
        
        idf_component_register(
            SRCS
                ${TESLABLE_SRCS}
                ${TESLABLE_PROTO_SRCS}
                ${TESLABLE_NANOPB_SRCS}
            INCLUDE_DIRS
                "include"
                "${GENERATED_INCLUDE_DIR}"
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
            VERSION 4.0.1
            DESCRIPTION "CPP Tesla BLE Library"
            LANGUAGES CXX C
    )
    set(CMAKE_CXX_STANDARD 23)
    
    # Disable mbedtls tests/programs/examples
    set(MBEDTLS_AS_SUBPROJECT ON)
    set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
    set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
    set(BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
    set(MBEDTLS_INSTALL OFF CACHE BOOL "" FORCE)
    
    FetchContent_Declare(
        nanopb
        GIT_REPOSITORY https://github.com/nanopb/nanopb.git
        GIT_TAG 0.4.9.1
        GIT_SHALLOW TRUE
    )
    FetchContent_Declare(
        mbedtls
        GIT_REPOSITORY https://github.com/espressif/mbedtls.git
        GIT_TAG mbedtls-3.6.5-idf
        GIT_SHALLOW TRUE
    )
    FetchContent_MakeAvailable(nanopb mbedtls)

    set(CMAKE_MODULE_PATH ${nanopb_SOURCE_DIR}/extra)
    find_package(Nanopb REQUIRED)

    # Nanopb library sources (must be defined after nanopb is available)
    set(TESLABLE_NANOPB_SRCS
        "${nanopb_SOURCE_DIR}/pb_common.c"
        "${nanopb_SOURCE_DIR}/pb_decode.c"
        "${nanopb_SOURCE_DIR}/pb_encode.c"
    )

    add_library(TeslaBLE STATIC
        ${TESLABLE_SRCS}
        ${TESLABLE_PROTO_SRCS}
        ${TESLABLE_NANOPB_SRCS}
    )

    target_include_directories(TeslaBLE
        PRIVATE
             src/
             ${GENERATED_INCLUDE_DIR}
             ${GENERATED_SRC_DIR}
             ${NANOPB_INCLUDE_DIRS}
             ${nanopb_SOURCE_DIR}
        PUBLIC
             include/
             ${GENERATED_INCLUDE_DIR}
             ${NANOPB_INCLUDE_DIRS}
     )
    
    target_link_libraries(TeslaBLE PUBLIC mbedcrypto mbedtls mbedx509)

    set_target_properties(TeslaBLE PROPERTIES PUBLIC_HEADER "${TESLABLE_PUBLIC_HEADERS}")
    
    # Only build tests if this is the main project
    if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
        # Enable testing
        enable_testing()
        
        # Add tests subdirectory
        add_subdirectory(tests)
    endif()
endif()
