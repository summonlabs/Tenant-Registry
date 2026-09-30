# Tenant Registry - build, test, install and packaging rules.
#
# Copyright 2026 Summon Software Labs.
# Licensed under the Apache License, Version 2.0.
#
# Everything here is target based: no directory-global flags are set, so the
# library, the tools, the examples, the benchmarks and the tests each carry
# exactly the options they need, and nothing this project uses for itself can
# leak into the installed package.

cmake_minimum_required(VERSION 3.20)

project(TenantRegistry
        VERSION 1.0.0
        DESCRIPTION "Canonical facility tenancy registry for the Data Center Control Plane"
        LANGUAGES CXX)

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------

option(BUILD_SHARED_LIBS "Build tenant_registry as a shared library instead of a static one" OFF)

option(TREG_BUILD_TESTS "Build the Tenant Registry test suite" ON)
option(TREG_BUILD_TOOLS "Build the Tenant Registry command line tools" ON)
option(TREG_BUILD_EXAMPLES "Build the Tenant Registry example programs" ON)
option(TREG_BUILD_BENCHMARKS "Build the Tenant Registry benchmarks" ON)
option(TREG_WARNINGS_AS_ERRORS "Treat every compiler warning as an error" ON)
option(TREG_SANITIZERS "Build with AddressSanitizer (and UndefinedBehaviorSanitizer on GCC and Clang)" OFF)
option(TREG_ANALYZE "Build with the MSVC static analyzer" OFF)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
include(CheckCXXCompilerFlag)
include(CTest)

set(TREG_INSTALL_CMAKEDIR "${CMAKE_INSTALL_LIBDIR}/cmake/TenantRegistry"
    CACHE STRING "Install destination of the Tenant Registry CMake package files")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Applies the project build policy to one target. Every entry is PRIVATE, so
# none of it is part of the installed package.
function(treg_configure_target target)
  if(MSVC)
    target_compile_options(${target} PRIVATE /W4 /permissive- /Zc:__cplusplus /utf-8 /EHsc)
    if(TREG_WARNINGS_AS_ERRORS AND NOT TREG_ANALYZE)
      target_compile_options(${target} PRIVATE /WX)
    endif()
    target_compile_definitions(${target} PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN _CRT_SECURE_NO_WARNINGS)
    target_compile_options(${target} PRIVATE $<$<CONFIG:Debug>:/RTC1>)
    target_compile_definitions(${target} PRIVATE $<$<CONFIG:Debug>:_ITERATOR_DEBUG_LEVEL=2>)
    target_compile_options(${target} PRIVATE
      $<$<CONFIG:Release>:/O2>
      $<$<CONFIG:Release>:/Gy>
      $<$<CONFIG:Release>:/Gw>)
  else()
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion)
    if(TREG_WARNINGS_AS_ERRORS)
      target_compile_options(${target} PRIVATE -Werror)
    endif()
  endif()
  if(MSVC AND TREG_ANALYZE)
    target_compile_options(${target} PRIVATE /analyze /analyze:WX-)
  endif()
  if(TREG_SANITIZERS)
    target_compile_options(${target} PRIVATE ${TREG_SANITIZER_COMPILE_OPTIONS})
    target_link_options(${target} PRIVATE ${TREG_SANITIZER_LINK_OPTIONS})
  endif()
endfunction()

# ---------------------------------------------------------------------------
# Sanitizers and static analysis
# ---------------------------------------------------------------------------

if(TREG_SANITIZERS)
  if(MSVC)
    check_cxx_compiler_flag("/fsanitize=address" TREG_COMPILER_HAS_ASAN)
    if(NOT TREG_COMPILER_HAS_ASAN)
      message(FATAL_ERROR
        "TREG_SANITIZERS=ON cannot be used with ${CMAKE_CXX_COMPILER_ID} "
        "${CMAKE_CXX_COMPILER_VERSION}: a program built with /fsanitize=address does not "
        "compile and link here. Either the toolset predates AddressSanitizer support "
        "(Visual Studio 2019 16.9) or the optional C++ AddressSanitizer component is not "
        "installed. Reconfigure with -DTREG_SANITIZERS=OFF or install that component.")
    endif()
    set(TREG_SANITIZER_COMPILE_OPTIONS /fsanitize=address /Zi)
    set(TREG_SANITIZER_LINK_OPTIONS /fsanitize=address)
    message(STATUS "TenantRegistry: AddressSanitizer enabled (MSVC)")
  elseif(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang|AppleClang")
    check_cxx_compiler_flag("-fsanitize=address,undefined" TREG_COMPILER_HAS_ASAN_UBSAN)
    if(NOT TREG_COMPILER_HAS_ASAN_UBSAN)
      message(FATAL_ERROR
        "TREG_SANITIZERS=ON cannot be used with ${CMAKE_CXX_COMPILER_ID} "
        "${CMAKE_CXX_COMPILER_VERSION}: the sanitizer runtime is unavailable. "
        "Reconfigure with -DTREG_SANITIZERS=OFF.")
    endif()
    set(TREG_SANITIZER_COMPILE_OPTIONS -fsanitize=address,undefined -fno-omit-frame-pointer)
    set(TREG_SANITIZER_LINK_OPTIONS -fsanitize=address,undefined)
    message(STATUS "TenantRegistry: AddressSanitizer and UndefinedBehaviorSanitizer enabled")
  else()
    message(FATAL_ERROR
      "TREG_SANITIZERS=ON is supported with MSVC (/fsanitize=address) and with GCC or Clang "
      "(-fsanitize=address,undefined); the configured compiler is "
      "${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}. "
      "Reconfigure with -DTREG_SANITIZERS=OFF.")
  endif()
endif()

# ---------------------------------------------------------------------------
# Library
# ---------------------------------------------------------------------------

set(TREG_PUBLIC_HEADERS
  include/tenant_registry/clock.hpp
  include/tenant_registry/digest.hpp
  include/tenant_registry/errors.hpp
  include/tenant_registry/ids.hpp
  include/tenant_registry/lifecycle.hpp
  include/tenant_registry/limits.hpp
  include/tenant_registry/metadata.hpp
  include/tenant_registry/persistence.hpp
  include/tenant_registry/provenance.hpp
  include/tenant_registry/query.hpp
  include/tenant_registry/records.hpp
  include/tenant_registry/registry.hpp
  include/tenant_registry/requests.hpp
  include/tenant_registry/snapshot.hpp
  include/tenant_registry/tenant_registry.hpp
  include/tenant_registry/version.hpp)

set(TREG_SOURCES
  src/byte_codec.cpp
  src/canonical_codec.cpp
  src/clock.cpp
  src/crc32.cpp
  src/digest.cpp
  src/durable_store.cpp
  src/errors.cpp
  src/export.cpp
  src/file_lock.cpp
  src/file_ops.cpp
  src/ids.cpp
  src/json_export.cpp
  src/lifecycle.cpp
  src/limits.cpp
  src/metadata.cpp
  src/provenance.cpp
  src/records.cpp
  src/registry.cpp
  src/registry_mutations.cpp
  src/registry_query.cpp
  src/registry_state.cpp
  src/requests.cpp
  src/sha256.cpp
  src/snapshot.cpp
  src/utf8.cpp
  src/version.cpp)

add_library(tenant_registry ${TREG_SOURCES})
add_library(TenantRegistry::tenant_registry ALIAS tenant_registry)

target_include_directories(tenant_registry
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src)

target_compile_features(tenant_registry PUBLIC cxx_std_20)
set_target_properties(tenant_registry PROPERTIES
  OUTPUT_NAME tenant_registry
  POSITION_INDEPENDENT_CODE ON
  CXX_VISIBILITY_PRESET hidden
  VISIBILITY_INLINES_HIDDEN ON)

treg_configure_target(tenant_registry)

# ---------------------------------------------------------------------------
# Tools, examples and benchmarks
# ---------------------------------------------------------------------------

function(treg_add_console_target target)
  add_executable(${target} ${ARGN})
  target_link_libraries(${target} PRIVATE TenantRegistry::tenant_registry)
  treg_configure_target(${target})
endfunction()

if(TREG_BUILD_TOOLS)
  treg_add_console_target(treg tools/treg_cli.cpp)
endif()

set(TREG_EXAMPLE_SOURCES
  examples/01_declare_tenancy.cpp
  examples/02_ownership_tree.cpp
  examples/03_isolation_domains.cpp
  examples/04_service_bindings.cpp
  examples/05_stale_generation.cpp
  examples/06_idempotent_retry.cpp
  examples/07_retire_and_tombstone.cpp
  examples/08_persistence_and_recovery.cpp)

if(TREG_BUILD_EXAMPLES)
  foreach(source IN LISTS TREG_EXAMPLE_SOURCES)
    string(SUBSTRING "${source}" 9 2 TREG_EXAMPLE_NUMBER)
    set(TREG_EXAMPLE_TARGET "treg_example_${TREG_EXAMPLE_NUMBER}")
    treg_add_console_target(${TREG_EXAMPLE_TARGET} ${source})
  endforeach()
endif()

if(TREG_BUILD_BENCHMARKS)
  treg_add_console_target(treg_benchmark benchmarks/benchmark_registry.cpp)
endif()

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

set(TREG_TEST_SOURCES
  tests/test_adversarial.cpp
  tests/test_authority.cpp
  tests/test_codec.cpp
  tests/test_concurrency.cpp
  tests/test_corruption.cpp
  tests/test_crash.cpp
  tests/test_dangling.cpp
  tests/test_digest.cpp
  tests/test_errors.cpp
  tests/test_explain.cpp
  tests/test_export.cpp
  tests/test_idempotency.cpp
  tests/test_ids.cpp
  tests/test_isolation.cpp
  tests/test_lifecycle.cpp
  tests/test_lifecycle_ops.cpp
  tests/test_limits.cpp
  tests/test_metadata.cpp
  tests/test_metadata_ops.cpp
  tests/test_multiprocess.cpp
  tests/test_ownership.cpp
  tests/test_paths.cpp
  tests/test_persistence.cpp
  tests/test_property.cpp
  tests/test_provenance.cpp
  tests/test_query.cpp
  tests/test_recovery.cpp
  tests/test_registry_create.cpp
  tests/test_service_binding.cpp
  tests/test_snapshot.cpp
  tests/test_tombstone.cpp
  tests/test_traversal.cpp
  tests/test_version.cpp)

if(TREG_BUILD_TESTS)
  add_executable(treg_tests
    ${TREG_TEST_SOURCES}
    tests/support/test_harness.cpp
    tests/support/test_main.cpp
    tests/support/test_process.cpp)
  target_link_libraries(treg_tests PRIVATE TenantRegistry::tenant_registry)
  # tests/ may reach src/ headers on purpose: the canonical codec, the store
  # layout and the writer lock are verified directly rather than only through
  # the public surface, and a test that could not see them could not prove the
  # properties they carry.
  target_include_directories(treg_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/support
    ${CMAKE_CURRENT_SOURCE_DIR}/src)
  treg_configure_target(treg_tests)

  # The test binary re-executes itself to obtain real independent operating
  # system processes for the shared-writer, restart and crash tests.
  add_test(NAME treg.tests COMMAND treg_tests)

  foreach(source IN LISTS TREG_EXAMPLE_SOURCES)
    if(TREG_BUILD_EXAMPLES)
      string(SUBSTRING "${source}" 9 2 TREG_EXAMPLE_NUMBER)
      add_test(NAME treg.example.${TREG_EXAMPLE_NUMBER} COMMAND treg_example_${TREG_EXAMPLE_NUMBER})
    endif()
  endforeach()

  if(TREG_BUILD_TOOLS)
    add_test(NAME treg.cli.selfcheck COMMAND treg ${CMAKE_CURRENT_BINARY_DIR}/cli-selfcheck --self-check)
    add_test(NAME treg.cli.scenario COMMAND treg ${CMAKE_CURRENT_BINARY_DIR}/cli-scenario --scenario)
  endif()

  if(TREG_BUILD_BENCHMARKS)
    add_test(NAME treg.benchmark.smoke COMMAND treg_benchmark --quick)
  endif()
endif()

# ---------------------------------------------------------------------------
# Install and package
# ---------------------------------------------------------------------------

install(TARGETS tenant_registry
  EXPORT TenantRegistryTargets
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(DIRECTORY include/tenant_registry DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

if(TREG_BUILD_TOOLS)
  install(TARGETS treg RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

install(EXPORT TenantRegistryTargets
  FILE TenantRegistryTargets.cmake
  NAMESPACE TenantRegistry::
  DESTINATION ${TREG_INSTALL_CMAKEDIR})

configure_package_config_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/cmake/TenantRegistryConfig.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/TenantRegistryConfig.cmake
  INSTALL_DESTINATION ${TREG_INSTALL_CMAKEDIR})

write_basic_package_version_file(
  ${CMAKE_CURRENT_BINARY_DIR}/TenantRegistryConfigVersion.cmake
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY SameMajorVersion)

install(FILES
  ${CMAKE_CURRENT_BINARY_DIR}/TenantRegistryConfig.cmake
  ${CMAKE_CURRENT_BINARY_DIR}/TenantRegistryConfigVersion.cmake
  DESTINATION ${TREG_INSTALL_CMAKEDIR})

install(FILES LICENSE NOTICE DESTINATION ${CMAKE_INSTALL_DATADIR}/TenantRegistry)

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

message(STATUS "TenantRegistry ${PROJECT_VERSION}")
message(STATUS "  compiler            : ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "  build type          : ${CMAKE_BUILD_TYPE}")
message(STATUS "  warnings as errors  : ${TREG_WARNINGS_AS_ERRORS}")
message(STATUS "  sanitizers          : ${TREG_SANITIZERS}")
message(STATUS "  tests/tools/examples: ${TREG_BUILD_TESTS}/${TREG_BUILD_TOOLS}/${TREG_BUILD_EXAMPLES}")
