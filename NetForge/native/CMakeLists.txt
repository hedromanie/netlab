cmake_minimum_required(VERSION 3.15)
project(netlab_native LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find Python (for pybind11)
find_package(Python3 COMPONENTS Interpreter Development REQUIRED)

# We expect pybind11 to be available via pip / system
# For now this is a skeleton — real build instructions will be added later.

add_library(netlab_flood STATIC
    flood/syn_flood.cpp
    flood/udp_flood.cpp
    flood/icmp_flood.cpp
)

target_include_directories(netlab_flood PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/flood)

# Placeholder message
message(STATUS "NetLab native skeleton configured. Implement flood functions next.")
