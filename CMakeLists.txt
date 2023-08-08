cmake_minimum_required(VERSION 3.16.2)

set(CMAKE_CXX_STANDARD 20)

set(CMAKE_CXX_COMPILER "${CMAKE_CURRENT_SOURCE_DIR}/fuzzer/target/release/libafl_cxx")
set(CMAKE_C_COMPILER "${CMAKE_CURRENT_SOURCE_DIR}/fuzzer/target/release/libafl_cc")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize-coverage=trace-pc-guard")
set(CMAKE_C_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize-coverage=trace-pc-guard")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize-coverage=trace-pc-guard")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fprofile-instr-generate")
set(CMAKE_C_FLAGS "${CMAKE_CXX_FLAGS} -fprofile-instr-generate")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fprofile-instr-generate")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fcoverage-mapping")
set(CMAKE_C_FLAGS "${CMAKE_CXX_FLAGS} -fcoverage-mapping")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fcoverage-mapping")

add_compile_options(-g)
 
# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address")
# set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=address")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -stdlib=libc++")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lc++ -lc++abi")

if(NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/third-party/silkworm/third_party/evmone/evmc/.git)
  message(FATAL_ERROR "Git submodules not initialized, execute:\n  git submodule update --init --recursive")
endif()

include(third-party/silkworm/third_party/evmone/cmake/cable/bootstrap.cmake)
include(CableBuildType)

include(third-party/silkworm/third_party/evmone/cmake/cable/HunterGate.cmake)
# https://github.com/cpp-pm/hunter/releases/
HunterGate(
  URL "https://github.com/cpp-pm/hunter/archive/v0.24.15.tar.gz"
  SHA1 "8010d63d5ae611c564889d5fe12d3cb7a45703ac"
  FILEPATH "${HUNTER_CONFIG_PATH}"
)

project(evm-fuzzer)

add_subdirectory(third-party/silkworm)
add_executable(fuzzer harness.cpp)

target_link_libraries(fuzzer ${CMAKE_CURRENT_SOURCE_DIR}/geth/libgeth.so silkworm_core gcc pthread)
