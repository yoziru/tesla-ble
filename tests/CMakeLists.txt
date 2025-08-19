cmake_minimum_required(VERSION 3.22)

# Fetch GoogleTest
include(FetchContent)
FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG v1.14.0
  GIT_SHALLOW TRUE
)

# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

# Include GoogleTest's CMake functions
include(GoogleTest)

# Enable testing
enable_testing()

# Create test executable
add_executable(
  tesla_ble_tests
  test_client.cpp
  test_key_generation.cpp
  test_message_building.cpp
  test_message_parsing.cpp
  test_session_management.cpp
  test_tb_utils.cpp
  test_error_handling.cpp
  test_ad_buffer_construction.cpp
  test_protocol_vectors.cpp
  test_protocol_handshake.cpp
  test_protocol_authentication.cpp
  test_protocol_edge_cases.cpp
  test_protocol_failures.cpp
  ../examples/simple/log.cpp
)

# Link against gtest, gtest_main, and TeslaBLE
target_link_libraries(
  tesla_ble_tests
  gtest_main
  gtest
  TeslaBLE
)

# Include directories
target_include_directories(
  tesla_ble_tests
  PRIVATE
  ../include
  ../examples/simple
)

# Discover tests
gtest_discover_tests(tesla_ble_tests)

# Add individual test files as separate targets for better granularity
add_executable(test_client test_client.cpp ../examples/simple/log.cpp)
target_link_libraries(test_client gtest_main TeslaBLE)
target_include_directories(test_client PRIVATE ../include ../examples/simple)

add_executable(test_key_generation test_key_generation.cpp ../examples/simple/log.cpp)
target_link_libraries(test_key_generation gtest_main TeslaBLE)
target_include_directories(test_key_generation PRIVATE ../include ../examples/simple)

add_executable(test_message_building test_message_building.cpp ../examples/simple/log.cpp)
target_link_libraries(test_message_building gtest_main TeslaBLE)
target_include_directories(test_message_building PRIVATE ../include ../examples/simple)

add_executable(test_message_parsing test_message_parsing.cpp ../examples/simple/log.cpp)
target_link_libraries(test_message_parsing gtest_main TeslaBLE)
target_include_directories(test_message_parsing PRIVATE ../include ../examples/simple)

add_executable(test_session_management test_session_management.cpp ../examples/simple/log.cpp)
target_link_libraries(test_session_management gtest_main TeslaBLE)
target_include_directories(test_session_management PRIVATE ../include ../examples/simple)

add_executable(test_tb_utils test_tb_utils.cpp ../examples/simple/log.cpp)
target_link_libraries(test_tb_utils gtest_main TeslaBLE)
target_include_directories(test_tb_utils PRIVATE ../include ../examples/simple)

add_executable(test_error_handling test_error_handling.cpp ../examples/simple/log.cpp)
target_link_libraries(test_error_handling gtest_main TeslaBLE)
target_include_directories(test_error_handling PRIVATE ../include ../examples/simple)

add_executable(test_ad_buffer_construction test_ad_buffer_construction.cpp ../examples/simple/log.cpp)
target_link_libraries(test_ad_buffer_construction gtest_main TeslaBLE)
target_include_directories(test_ad_buffer_construction PRIVATE ../include ../examples/simple)

add_executable(test_protocol_vectors test_protocol_vectors.cpp ../examples/simple/log.cpp)
target_link_libraries(test_protocol_vectors gtest_main TeslaBLE)
target_include_directories(test_protocol_vectors PRIVATE ../include ../examples/simple)

add_executable(test_protocol_handshake test_protocol_handshake.cpp ../examples/simple/log.cpp)
target_link_libraries(test_protocol_handshake gtest_main TeslaBLE)
target_include_directories(test_protocol_handshake PRIVATE ../include ../examples/simple)

add_executable(test_protocol_authentication test_protocol_authentication.cpp ../examples/simple/log.cpp)
target_link_libraries(test_protocol_authentication gtest_main TeslaBLE)
target_include_directories(test_protocol_authentication PRIVATE ../include ../examples/simple)

add_executable(test_protocol_edge_cases test_protocol_edge_cases.cpp ../examples/simple/log.cpp)
target_link_libraries(test_protocol_edge_cases gtest_main TeslaBLE)
target_include_directories(test_protocol_edge_cases PRIVATE ../include ../examples/simple)

# Register individual tests
gtest_discover_tests(test_client)
gtest_discover_tests(test_key_generation)
gtest_discover_tests(test_message_building)
gtest_discover_tests(test_message_parsing)
gtest_discover_tests(test_session_management)
gtest_discover_tests(test_tb_utils)
gtest_discover_tests(test_error_handling)
gtest_discover_tests(test_ad_buffer_construction)
gtest_discover_tests(test_protocol_vectors)
gtest_discover_tests(test_protocol_handshake)
gtest_discover_tests(test_protocol_authentication)
gtest_discover_tests(test_protocol_edge_cases)
