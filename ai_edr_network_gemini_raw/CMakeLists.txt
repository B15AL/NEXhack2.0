cmake_minimum_required(VERSION 3.16)

project(ai_edr_network_gemini_raw LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# On Linux, pkg-config also carries libcurl's transitive dependencies,
# which matters when a system exposes a static libcurl.
if(UNIX AND NOT APPLE)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(CURL_PC REQUIRED IMPORTED_TARGET libcurl)
    set(EDR_CURL_TARGET PkgConfig::CURL_PC)
else()
    find_package(CURL REQUIRED)
    set(EDR_CURL_TARGET CURL::libcurl)
endif()

add_library(edr_core
    src/collector.cpp
    src/raw_report.cpp
    src/gemini_client.cpp
)

target_include_directories(edr_core PUBLIC include)
target_link_libraries(edr_core PRIVATE ${EDR_CURL_TARGET})

if(WIN32)
    target_compile_definitions(edr_core PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)
    target_link_libraries(edr_core PRIVATE iphlpapi ws2_32)
endif()

add_executable(edr_network src/main.cpp)
target_link_libraries(edr_network PRIVATE edr_core)

add_executable(test_raw_report tests/test_raw_report.cpp)
target_link_libraries(test_raw_report PRIVATE edr_core)

enable_testing()
add_test(NAME raw_report_tests COMMAND test_raw_report)
