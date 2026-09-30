# The downstream consumption proof.
#
# This project is deliberately separate from the repository's own build: it is
# configured against an installed prefix only, through find_package, and it
# exercises the public API rather than merely linking against it.

cmake_minimum_required(VERSION 3.20)

project(TenantRegistryConsumer LANGUAGES CXX)

find_package(TenantRegistry CONFIG REQUIRED)

add_executable(tenant_registry_consumer main.cpp)
target_link_libraries(tenant_registry_consumer PRIVATE TenantRegistry::tenant_registry)
set_target_properties(tenant_registry_consumer PROPERTIES
  CXX_STANDARD 20
  CXX_STANDARD_REQUIRED ON
  CXX_EXTENSIONS OFF)
