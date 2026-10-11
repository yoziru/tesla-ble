cmake_minimum_required(VERSION 3.22)
project(tesla_ble_python LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Build the C++ library as a subproject (fetches nanopb + mbedtls).
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../.. ${CMAKE_CURRENT_BINARY_DIR}/tesla_ble_cpp)

set(PYBIND11_FINDPYTHON ON)
find_package(pybind11 CONFIG REQUIRED)

# Version comes from the repository VERSION file (single source of truth).
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/../../VERSION" TESLA_BLE_VERSION)
string(STRIP "${TESLA_BLE_VERSION}" TESLA_BLE_VERSION)

pybind11_add_module(_tesla_ble
    cpp/module.cpp
    cpp/simulated_vehicle.cpp
    cpp/state_dicts.cpp
)

target_link_libraries(_tesla_ble PRIVATE TeslaBLE)
target_compile_definitions(_tesla_ble PRIVATE TESLA_BLE_VERSION="${TESLA_BLE_VERSION}")
target_compile_options(_tesla_ble PRIVATE $<$<COMPILE_LANGUAGE:CXX>:-Wall>)

install(TARGETS _tesla_ble LIBRARY DESTINATION tesla_ble COMPONENT python)

include(FetchContent)
FetchContent_GetProperties(mbedtls)
FetchContent_GetProperties(nanopb)
install(FILES "${mbedtls_SOURCE_DIR}/LICENSE"
    DESTINATION tesla_ble/licenses RENAME mbedtls.txt COMPONENT python)
install(FILES "${nanopb_SOURCE_DIR}/LICENSE.txt"
    DESTINATION tesla_ble/licenses RENAME nanopb.txt COMPONENT python)
