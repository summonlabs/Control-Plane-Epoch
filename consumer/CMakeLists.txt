# Control Plane Epoch 1.0.0 - Summon Software Labs
# Standalone consumer project, built out of tree against an INSTALLED package:
#
#   cmake --install <build-dir> --prefix <prefix>
#   cmake -S consumer -B <consumer-build> -G Ninja -DCMAKE_PREFIX_PATH=<prefix>
#   cmake --build <consumer-build>
#
# It is intentionally not part of the main build: it must consume exactly what a
# downstream project consumes, namely the installed headers, the exported target
# SummonSoftwareLabs::ControlPlaneEpoch, and the installed package config file.
cmake_minimum_required(VERSION 3.21)

project(ControlPlaneEpochConsumer
  VERSION 1.0.0
  DESCRIPTION "Out-of-tree consumer of the installed Control Plane Epoch package"
  HOMEPAGE_URL "https://github.com/summonlabs/Control-Plane-Epoch"
  LANGUAGES CXX)

if(NOT CMAKE_CXX_STANDARD)
  set(CMAKE_CXX_STANDARD 20)
endif()
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# The installed package is a single-configuration build and, on MSVC, the CRT a
# binary links against is chosen by the consumer's build type (Release -> /MD,
# Debug -> /MDd). A consumer that silently picks a different configuration than
# the installed library would mix CRT variants across an API boundary that
# passes std::string and std::vector by value, so this project defaults to
# Release and lets the caller override it explicitly:
#
#   cmake -S consumer -B <dir> -DCONTROL_PLANE_EPOCH_CONSUMER_BUILD_TYPE=Debug
set(CONTROL_PLANE_EPOCH_CONSUMER_BUILD_TYPE "Release" CACHE STRING
  "Build type used for the consumer executable (must match the installed package)")
set_property(CACHE CONTROL_PLANE_EPOCH_CONSUMER_BUILD_TYPE PROPERTY STRINGS Debug Release RelWithDebInfo MinSizeRel)
if(NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE "${CONTROL_PLANE_EPOCH_CONSUMER_BUILD_TYPE}" CACHE STRING "Build type" FORCE)
endif()

option(CONTROL_PLANE_EPOCH_CONSUMER_WARNINGS_AS_ERRORS "Treat consumer warnings as errors" ON)

find_package(ControlPlaneEpoch REQUIRED)

add_executable(control_plane_epoch_consumer main.cpp)

target_link_libraries(control_plane_epoch_consumer PRIVATE SummonSoftwareLabs::ControlPlaneEpoch)

if(MSVC)
  target_compile_options(control_plane_epoch_consumer PRIVATE /W4 /permissive- /utf-8 /EHsc)
  if(CONTROL_PLANE_EPOCH_CONSUMER_WARNINGS_AS_ERRORS)
    target_compile_options(control_plane_epoch_consumer PRIVATE /WX)
  endif()
else()
  target_compile_options(control_plane_epoch_consumer PRIVATE -Wall -Wextra -Wpedantic)
  if(CONTROL_PLANE_EPOCH_CONSUMER_WARNINGS_AS_ERRORS)
    target_compile_options(control_plane_epoch_consumer PRIVATE -Werror)
  endif()
endif()

message(STATUS "Control Plane Epoch consumer ${PROJECT_VERSION}: build type '${CMAKE_BUILD_TYPE}', found ControlPlaneEpoch ${ControlPlaneEpoch_VERSION}")
