cmake_minimum_required(VERSION 3.22)

include(FetchContent)
FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG v1.14.0
    GIT_SHALLOW TRUE
)

set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

include(GoogleTest)
enable_testing()

# Common test configuration
set(TEST_INCLUDE_DIRS
    PRIVATE
    ../include
    ../generated/include
    ../examples/simple
)

set(TEST_LINK_LIBS gtest_main gtest TeslaBLE)

# List of all test files
set(TEST_FILES
    test_ad_buffer_construction.cpp
    test_client.cpp
    test_error_handling.cpp
    test_key_generation.cpp
    test_logging.cpp
    test_message_building.cpp
    test_message_parsing.cpp
    test_protocol_authentication.cpp
    test_protocol_edge_cases.cpp
    test_protocol_failures.cpp
    test_protocol_handshake.cpp
    test_protocol_vectors.cpp
    test_session_management.cpp
    test_session_recovery.cpp
    test_sliding_window.cpp
    test_tb_utils.cpp
    test_vin_utils.cpp
    test_vehicle.cpp
)

# Individual test executables for granular testing
foreach(TEST_FILE ${TEST_FILES})
    string(REPLACE ".cpp" "" TEST_NAME ${TEST_FILE})
    add_executable(${TEST_NAME} ${TEST_FILE} ${TEST_SOURCE})
    target_link_libraries(${TEST_NAME} ${TEST_LINK_LIBS})
    target_include_directories(${TEST_NAME} ${TEST_INCLUDE_DIRS})
    gtest_discover_tests(${TEST_NAME})
endforeach()
