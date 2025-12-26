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
        
        # Fetch nanopb for proto generation and runtime
        # We only need the sources and generator, not the build targets
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
        
        # Get Python from ESP-IDF
        idf_build_get_property(PYTHON PYTHON)
        if(NOT PYTHON)
            set(PYTHON "python3")
        endif()
        
        # Ensure protobuf is available for nanopb generator
        execute_process(
            COMMAND "${PYTHON}" -c "import google.protobuf"
            RESULT_VARIABLE PROTOBUF_CHECK
            OUTPUT_QUIET ERROR_QUIET
        )
        if(NOT PROTOBUF_CHECK EQUAL 0)
            message(STATUS "Installing Python protobuf package...")
            
            # First ensure pip is available
            execute_process(
                COMMAND "${PYTHON}" -m pip --version
                RESULT_VARIABLE PIP_CHECK
                OUTPUT_QUIET ERROR_QUIET
            )
            if(NOT PIP_CHECK EQUAL 0)
                message(STATUS "Bootstrapping pip...")
                execute_process(
                    COMMAND "${PYTHON}" -m ensurepip --default-pip
                    RESULT_VARIABLE ENSUREPIP_RESULT
                    ERROR_VARIABLE ENSUREPIP_ERROR
                )
                if(NOT ENSUREPIP_RESULT EQUAL 0)
                    message(FATAL_ERROR "Failed to bootstrap pip: ${ENSUREPIP_ERROR}")
                endif()
            endif()
            
            # Install protobuf
            execute_process(
                COMMAND "${PYTHON}" -m pip install --quiet protobuf
                RESULT_VARIABLE PIP_RESULT
                ERROR_VARIABLE PIP_ERROR
            )
            if(NOT PIP_RESULT EQUAL 0)
                message(FATAL_ERROR "Failed to install protobuf: ${PIP_ERROR}")
            endif()
        endif()
        
        # Get all proto files (including subdirectories)
        file(GLOB_RECURSE PROTO_FILES "${CMAKE_CURRENT_SOURCE_DIR}/proto/*.proto")
        
        set(PROTO_GENERATED_SRCS "")
        set(PROTO_GENERATED_HDRS "")
        
        # Use the nanopb generator from the fetched content
        set(NANOPB_GENERATOR "${nanopb_SOURCE_DIR}/generator/nanopb_generator.py")
        
        # Create google/protobuf directory for timestamp.pb.h
        file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/google/protobuf")
        
        foreach(PROTO_FILE ${PROTO_FILES})
            # Get relative path from proto directory
            file(RELATIVE_PATH PROTO_REL_PATH "${CMAKE_CURRENT_SOURCE_DIR}/proto" "${PROTO_FILE}")
            get_filename_component(PROTO_REL_DIR ${PROTO_REL_PATH} DIRECTORY)
            get_filename_component(PROTO_NAME ${PROTO_FILE} NAME_WE)
            
            # Output goes directly to build dir, nanopb will create subdirs as needed
            if(PROTO_REL_DIR)
                set(PROTO_GEN_C "${CMAKE_CURRENT_BINARY_DIR}/${PROTO_REL_DIR}/${PROTO_NAME}.pb.c")
                set(PROTO_GEN_H "${CMAKE_CURRENT_BINARY_DIR}/${PROTO_REL_DIR}/${PROTO_NAME}.pb.h")
            else()
                set(PROTO_GEN_C "${CMAKE_CURRENT_BINARY_DIR}/${PROTO_NAME}.pb.c")
                set(PROTO_GEN_H "${CMAKE_CURRENT_BINARY_DIR}/${PROTO_NAME}.pb.h")
            endif()
            
            # Check for .options file
            set(OPTIONS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/proto/${PROTO_NAME}.options")
            if(EXISTS ${OPTIONS_FILE})
                set(OPTIONS_ARG "-f" "${OPTIONS_FILE}")
            else()
                set(OPTIONS_ARG "")
            endif()
            
            list(APPEND PROTO_GENERATED_SRCS ${PROTO_GEN_C})
            list(APPEND PROTO_GENERATED_HDRS ${PROTO_GEN_H})
            
            # Generate at configure time using execute_process
            # Use the ESP-IDF Python which has protobuf installed
            # Use -D to specify output directory as CMAKE_CURRENT_BINARY_DIR
            # and rely on nanopb to preserve the relative path structure
            execute_process(
                COMMAND "${PYTHON}" "${NANOPB_GENERATOR}"
                        -I "${CMAKE_CURRENT_SOURCE_DIR}/proto"
                        -D "${CMAKE_CURRENT_BINARY_DIR}"
                        ${OPTIONS_ARG}
                        "${PROTO_REL_PATH}"
                WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/proto"
                RESULT_VARIABLE PROTO_RESULT
                OUTPUT_VARIABLE PROTO_OUTPUT
                ERROR_VARIABLE PROTO_ERROR
            )
            
            if(NOT PROTO_RESULT EQUAL 0)
                message(WARNING "Failed to generate ${PROTO_NAME}: ${PROTO_ERROR}")
            endif()
        endforeach()
        
        # Register as ESP-IDF component with all sources
        idf_component_register(
            SRCS
                "src/client.cpp"
                "src/errors.cpp"
                "src/peer.cpp"
                "src/tb_utils.cpp"
                "src/crypto_context.cpp"
                "src/message_builders.cpp"
                "${nanopb_SOURCE_DIR}/pb_common.c"
                "${nanopb_SOURCE_DIR}/pb_encode.c"
                "${nanopb_SOURCE_DIR}/pb_decode.c"
                ${PROTO_GENERATED_SRCS}
            INCLUDE_DIRS
                "include"
                "${CMAKE_CURRENT_BINARY_DIR}"
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
endif()
