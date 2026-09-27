cmake_minimum_required(VERSION 3.21)

project(ControlPlaneEpoch
  VERSION 1.0.0
  DESCRIPTION "Facility-wide incarnation and epoch authority for DCCP controllers"
  HOMEPAGE_URL "https://github.com/summonlabs/Control-Plane-Epoch"
  LANGUAGES CXX)

# ---------------------------------------------------------------------------
# Version consistency. The C++ header is authoritative; the CMake project
# version must agree with it or configuration fails fast.
# ---------------------------------------------------------------------------
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/include/control_plane_epoch/version.hpp" CONTROL_PLANE_EPOCH_VERSION_HEADER)

function(control_plane_epoch_header_constant NAME OUT_VAR)
  string(REGEX MATCH "inline constexpr int ${NAME} = ([0-9]+);" MATCH "${CONTROL_PLANE_EPOCH_VERSION_HEADER}")
  if(NOT MATCH)
    message(FATAL_ERROR "include/control_plane_epoch/version.hpp does not define ${NAME}")
  endif()
  set(${OUT_VAR} "${CMAKE_MATCH_1}" PARENT_SCOPE)
endfunction()

control_plane_epoch_header_constant(version_major CONTROL_PLANE_EPOCH_VERSION_MAJOR)
control_plane_epoch_header_constant(version_minor CONTROL_PLANE_EPOCH_VERSION_MINOR)
control_plane_epoch_header_constant(version_patch CONTROL_PLANE_EPOCH_VERSION_PATCH)

set(CONTROL_PLANE_EPOCH_HEADER_VERSION
  "${CONTROL_PLANE_EPOCH_VERSION_MAJOR}.${CONTROL_PLANE_EPOCH_VERSION_MINOR}.${CONTROL_PLANE_EPOCH_VERSION_PATCH}")

if(NOT CONTROL_PLANE_EPOCH_HEADER_VERSION STREQUAL PROJECT_VERSION)
  message(FATAL_ERROR
    "version mismatch: project() declares ${PROJECT_VERSION} but version.hpp declares "
    "${CONTROL_PLANE_EPOCH_HEADER_VERSION}")
endif()

message(STATUS "Control Plane Epoch ${PROJECT_VERSION}")

if(NOT CMAKE_CXX_STANDARD)
  set(CMAKE_CXX_STANDARD 20)
endif()
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

option(CONTROL_PLANE_EPOCH_BUILD_TESTS "Build the test suites" ON)
option(CONTROL_PLANE_EPOCH_BUILD_EXAMPLES "Build the examples" ON)
option(CONTROL_PLANE_EPOCH_BUILD_BENCHMARKS "Build the benchmarks" ON)
option(CONTROL_PLANE_EPOCH_BUILD_APPS "Build the authority runtime, controller runtime and CLI" ON)
option(CONTROL_PLANE_EPOCH_ENABLE_ANALYZE "Run the MSVC static analyzer on first-party code" OFF)
option(CONTROL_PLANE_EPOCH_WARNINGS_AS_ERRORS "Treat first-party warnings as errors" ON)
option(CONTROL_PLANE_EPOCH_BUILD_PROCESS_TESTS
  "Build the suites that start real authority and controller processes" ON)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

# ---------------------------------------------------------------------------
# Warning configuration, applied to first-party targets only.
# ---------------------------------------------------------------------------
function(control_plane_epoch_apply_warnings target)
  if(MSVC)
    target_compile_options(${target} PRIVATE /W4 /permissive- /utf-8 /EHsc)
    if(CONTROL_PLANE_EPOCH_WARNINGS_AS_ERRORS)
      target_compile_options(${target} PRIVATE /WX)
    endif()
    if(CONTROL_PLANE_EPOCH_ENABLE_ANALYZE)
      # Platform and standard-library headers are third-party code. They are
      # declared external so that analysis reports first-party findings only;
      # no first-party warning is suppressed by this.
      target_compile_options(${target} PRIVATE
        /analyze
        /external:anglebrackets
        /external:env:INCLUDE
        /external:W0)
    endif()
  else()
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
    if(CONTROL_PLANE_EPOCH_WARNINGS_AS_ERRORS)
      target_compile_options(${target} PRIVATE -Werror)
    endif()
  endif()
endfunction()

# ---------------------------------------------------------------------------
# Library
# ---------------------------------------------------------------------------
add_library(ControlPlaneEpoch
  src/authority.cpp
  src/authority_store.cpp
  src/client.cpp
  src/commands.cpp
  src/core.cpp
  src/durable.cpp
  src/encoding.cpp
  src/epoch.cpp
  src/error.cpp
  src/fault.cpp
  src/file_lock.cpp
  src/identity.cpp
  src/image.cpp
  src/incarnation.cpp
  src/inspection.cpp
  src/protocol.cpp
  src/provenance.cpp
  src/records.cpp
  src/recovery.cpp
  src/server.cpp
  src/service.cpp
  src/sha256.cpp
  src/socket.cpp
  src/store_reports.cpp
  src/transition.cpp
  src/wire.cpp)

add_library(SummonSoftwareLabs::ControlPlaneEpoch ALIAS ControlPlaneEpoch)

set_target_properties(ControlPlaneEpoch PROPERTIES
  EXPORT_NAME ControlPlaneEpoch
  POSITION_INDEPENDENT_CODE ON
  WINDOWS_EXPORT_ALL_SYMBOLS ON)

target_include_directories(ControlPlaneEpoch
  PUBLIC
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
    "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
  PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/src")

control_plane_epoch_apply_warnings(ControlPlaneEpoch)

if(WIN32)
  target_link_libraries(ControlPlaneEpoch PRIVATE ws2_32)
else()
  find_package(Threads REQUIRED)
  target_link_libraries(ControlPlaneEpoch PUBLIC Threads::Threads)
endif()

# ---------------------------------------------------------------------------
# Applications
# ---------------------------------------------------------------------------
if(CONTROL_PLANE_EPOCH_BUILD_APPS)
  add_executable(control-plane-epoch-authority apps/authority_main.cpp apps/arguments.cpp apps/tool_support.cpp)
  add_executable(control-plane-epoch-controller apps/controller_main.cpp apps/arguments.cpp apps/tool_support.cpp)
  add_executable(control-plane-epoch-cli apps/cli_main.cpp apps/arguments.cpp apps/tool_support.cpp)
  foreach(app control-plane-epoch-authority control-plane-epoch-controller control-plane-epoch-cli)
    target_link_libraries(${app} PRIVATE SummonSoftwareLabs::ControlPlaneEpoch)
    target_include_directories(${app} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/apps")
    control_plane_epoch_apply_warnings(${app})
  endforeach()
  install(TARGETS control-plane-epoch-authority control-plane-epoch-controller control-plane-epoch-cli
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

# ---------------------------------------------------------------------------
# Examples
# ---------------------------------------------------------------------------
if(CONTROL_PLANE_EPOCH_BUILD_EXAMPLES)
  set(CONTROL_PLANE_EPOCH_EXAMPLES
    initialize_domain
    controller_registration
    scoped_authority
    epoch_advancement
    stale_token_rejection
    revocation
    recovered_state_qualification
    persistence_recovery
    remote_controller)
  foreach(example ${CONTROL_PLANE_EPOCH_EXAMPLES})
    add_executable(control_plane_epoch_example_${example} examples/${example}.cpp)
    target_link_libraries(control_plane_epoch_example_${example} PRIVATE SummonSoftwareLabs::ControlPlaneEpoch)
    control_plane_epoch_apply_warnings(control_plane_epoch_example_${example})
  endforeach()
endif()

# ---------------------------------------------------------------------------
# Benchmarks
# ---------------------------------------------------------------------------
if(CONTROL_PLANE_EPOCH_BUILD_BENCHMARKS)
  add_executable(control_plane_epoch_benchmarks benchmarks/benchmarks.cpp)
  target_link_libraries(control_plane_epoch_benchmarks PRIVATE SummonSoftwareLabs::ControlPlaneEpoch)
  control_plane_epoch_apply_warnings(control_plane_epoch_benchmarks)
endif()

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
if(CONTROL_PLANE_EPOCH_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()

# ---------------------------------------------------------------------------
# Install / export
# ---------------------------------------------------------------------------
install(TARGETS ControlPlaneEpoch
  EXPORT ControlPlaneEpochTargets
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

set(CONTROL_PLANE_EPOCH_CMAKE_INSTALL_DIR "${CMAKE_INSTALL_LIBDIR}/cmake/ControlPlaneEpoch")

install(EXPORT ControlPlaneEpochTargets
  NAMESPACE SummonSoftwareLabs::
  FILE ControlPlaneEpochTargets.cmake
  DESTINATION ${CONTROL_PLANE_EPOCH_CMAKE_INSTALL_DIR})

configure_package_config_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/ControlPlaneEpochConfig.cmake.in"
  "${CMAKE_CURRENT_BINARY_DIR}/ControlPlaneEpochConfig.cmake"
  INSTALL_DESTINATION ${CONTROL_PLANE_EPOCH_CMAKE_INSTALL_DIR})

write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/ControlPlaneEpochConfigVersion.cmake"
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY SameMajorVersion)

install(FILES
  "${CMAKE_CURRENT_BINARY_DIR}/ControlPlaneEpochConfig.cmake"
  "${CMAKE_CURRENT_BINARY_DIR}/ControlPlaneEpochConfigVersion.cmake"
  DESTINATION ${CONTROL_PLANE_EPOCH_CMAKE_INSTALL_DIR})
