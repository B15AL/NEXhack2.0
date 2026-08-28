cmake_minimum_required(VERSION 3.20)

project(ai_edr_network LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(edr_network
    src/main.cpp
    src/config.cpp
    src/collector.cpp
    src/features.cpp
    src/rules.cpp
    src/report.cpp
    src/gemini_client.cpp
)

target_include_directories(edr_network PRIVATE include)

if(WIN32)
    target_compile_definitions(edr_network PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)
    target_link_libraries(edr_network PRIVATE iphlpapi ws2_32)
else()
    message(WARNING "The current network collector is implemented for Windows.")
endif()

add_executable(test_features
    tests/test_features.cpp
    src/features.cpp
)

target_include_directories(test_features PRIVATE include)
