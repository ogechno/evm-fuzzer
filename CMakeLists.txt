cmake_minimum_required(VERSION 3.16.2)

set(CMAKE_CXX_STANDARD 20)
# TODO: put back in
set(CMAKE_CXX_COMPILER "/src/fuzzer/target/debug/libafl_cxx")
set(CMAKE_C_COMPILER "/src/fuzzer/target/debug/libafl_cc")

# set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")
# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")

if(NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/third-party/silkworm/third_party/evmone/evmc/.git)
  message(FATAL_ERROR "Git submodules not initialized, execute:\n  git submodule update --init --recursive")
endif()

include(third-party/silkworm/third_party/evmone/cmake/cable/bootstrap.cmake)
include(CableBuildType)

set(HUNTER_CONFIG_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/Hunter/config.cmake")

include(third-party/silkworm/third_party/evmone/cmake/cable/HunterGate.cmake)
# https://github.com/cpp-pm/hunter/releases/
HunterGate(
  URL "https://github.com/cpp-pm/hunter/archive/v0.24.15.tar.gz"
  SHA1 "8010d63d5ae611c564889d5fe12d3cb7a45703ac"
  FILEPATH "${HUNTER_CONFIG_PATH}"
)

# target_compile_options(${TARGET_CORE_NAME}  -fPIC)
# add_compile_options(-fPIC)
# set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fpic")
# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fpic")

# set(CPPETHEREUM 1)

project(evm-fuzzer)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)
# add_compile_definitions(_SILENCE_CXX17_OLD_ALLOCATOR_MEMBERS_DEPRECATION_WARNING)

# set(CPPETHEREUM ON)
#     CMAKE_POSITION_INDEPENDENT_CODE=ON
#     CMAKE_CXX_FLAGS="-fPIC"
#     CMAKE_C_FLAGS="-fPIC"

# set(CPPETHEREUM ON CACHE BOOL "" FORCE)

hunter_add_package(Catch)
hunter_add_package(intx)
hunter_add_package(Microsoft.GSL)
hunter_add_package(nlohmann_json)
hunter_add_package(ethash)
hunter_add_package(abseil)

# target_compile_options(ethash PRIVATE -fPIC)
# set_property(TARGET ethash PROPERTY POSITION_INDEPENDENT_CODE ON)

find_package(intx REQUIRED)
find_package(ethash CONFIG REQUIRED)
find_package(Microsoft.GSL REQUIRED)
find_package(nlohmann_json REQUIRED)
find_package(absl CONFIG REQUIRED)

# add_subdirectory(third-party/ethash)
# add_subdirectory(third-party/abseil-cpp)

# set(GMP_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third-party/silkworm/third_party/gmplib")
# set(GMP_INSTALL_DIR "${CMAKE_BINARY_DIR}/third-party/silkworm/third_party/gmplib")
# 
# set(GMP_INCLUDE_DIR "${GMP_INSTALL_DIR}" CACHE PATH "")
# set(GMP_LIBRARY "${GMP_INSTALL_DIR}/lib/libgmp.a" CACHE FILEPATH "")
# 
# include(ExternalProject)
# ExternalProject_Add(
#   gmplib
#   SOURCE_DIR "${GMP_SOURCE_DIR}"
#   BINARY_DIR "${GMP_INSTALL_DIR}"
#   CONFIGURE_COMMAND "${GMP_SOURCE_DIR}/configure"
#     "--prefix=${GMP_INSTALL_DIR}"
#     --with-pic=yes
#   PREFIX "${GMP_INSTALL_DIR}"
#   BUILD_BYPRODUCTS "${GMP_LIBRARY}"
# )

# add_subdirectory(third-party/silkworm/third_party/silkpre)
# 
# add_dependencies(silkpre gmplib)

# add_compile_options(-fPIC)

# Get rid of some errors with ethash
# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")
# target_compile_options(ethash PRIVATE -fPIC)

# add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/third-party/silkworm/third_party/ethash)
# add_subdirectory(third-party/ethash)
# add_dependencies(ethash)

set(SILKWORM_BUILD_SHARED_LIBS_OLD ${BUILD_SHARED_LIBS})
set(SILKWORM_CORE_ONLY ON CACHE BOOL "Build Silkworm core only" FORCE)
set(BUILD_SHARED_LIBS ON CACHE BOOL "Build Silkworm shared library" FORCE)
add_subdirectory(third-party/silkworm)
set(BUILD_SHARED_LIBS ${SILKWORM_BUILD_SHARED_LIBS_OLD} CACHE BOOL "Restore old BUILD_SHARED_LIBS value" FORCE)

set(SILKWORM_CORE_PRIVATE_LIBS "")
set(SILKWORM_CORE_PUBLIC_LIBS ethash::ethash evmc evmone intx::intx Microsoft.GSL::GSL nlohmann_json::nlohmann_json silkpre)
list(APPEND SILKWORM_CORE_PRIVATE_LIBS absl::flat_hash_map absl::flat_hash_set absl::node_hash_map)

add_executable(fuzzer silkworm/harness.cpp)

target_link_libraries(fuzzer PUBLIC ${SILKWORM_CORE_PUBLIC_LIBS} PRIVATE ${SILKWORM_CORE_PRIVATE_LIBS} ${CMAKE_CURRENT_SOURCE_DIR}/geth/libgeth.so silkworm_core stdc++ gcc pthread)
