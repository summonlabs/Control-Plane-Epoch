# Control Plane Epoch 1.0.0 - Summon Software Labs
# Test suites. No TIMEOUT property is set anywhere and no timeout wrapper is
# used: a hanging test is a defect and must surface as a hang.

# The default is the full suite list. The variable may be overridden to build a
# focused subset while developing, for example
#   -DCONTROL_PLANE_EPOCH_TEST_SUITES="fencing;revocation"
set(CONTROL_PLANE_EPOCH_TEST_SUITES
  identity
  explanation
  epoch
  authority_scope
  registration
  authority_validation
  revocation
  fencing
  recovery_qualification
  idempotency
  persistence
  corruption
  protocol
  limits
  concurrency
  property
  adversarial
  CACHE STRING "Test suites to build")

add_library(control_plane_epoch_test_support STATIC test_harness.cpp)
target_include_directories(control_plane_epoch_test_support PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}"
  # White-box access to the canonical codec and image format lets the corruption
  # and adversarial suites craft durable images that the validating encoder would
  # never produce. Internal headers are never installed.
  "${CMAKE_SOURCE_DIR}/src")
target_link_libraries(control_plane_epoch_test_support PUBLIC SummonSoftwareLabs::ControlPlaneEpoch)
control_plane_epoch_apply_warnings(control_plane_epoch_test_support)

set(CONTROL_PLANE_EPOCH_TEST_SOURCES test_main.cpp)
foreach(suite ${CONTROL_PLANE_EPOCH_TEST_SUITES})
  list(APPEND CONTROL_PLANE_EPOCH_TEST_SOURCES test_${suite}.cpp)
endforeach()

if(CONTROL_PLANE_EPOCH_BUILD_PROCESS_TESTS AND CONTROL_PLANE_EPOCH_BUILD_APPS)
  list(APPEND CONTROL_PLANE_EPOCH_TEST_SOURCES test_multiprocess.cpp)
  file(GENERATE OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/test_executables.hpp" CONTENT
"#pragma once
#define CONTROL_PLANE_EPOCH_AUTHORITY_EXE \"$<TARGET_FILE:control-plane-epoch-authority>\"
#define CONTROL_PLANE_EPOCH_CONTROLLER_EXE \"$<TARGET_FILE:control-plane-epoch-controller>\"
#define CONTROL_PLANE_EPOCH_CLI_EXE \"$<TARGET_FILE:control-plane-epoch-cli>\"
")
  set_source_files_properties(test_multiprocess.cpp PROPERTIES
    INCLUDE_DIRECTORIES "${CMAKE_CURRENT_BINARY_DIR}")
endif()

add_executable(control_plane_epoch_tests ${CONTROL_PLANE_EPOCH_TEST_SOURCES})
target_link_libraries(control_plane_epoch_tests PRIVATE control_plane_epoch_test_support)
control_plane_epoch_apply_warnings(control_plane_epoch_tests)
if(CONTROL_PLANE_EPOCH_BUILD_PROCESS_TESTS AND CONTROL_PLANE_EPOCH_BUILD_APPS)
  add_dependencies(control_plane_epoch_tests
    control-plane-epoch-authority control-plane-epoch-controller control-plane-epoch-cli)
endif()

add_test(NAME control_plane_epoch_tests COMMAND control_plane_epoch_tests)
