cmake_minimum_required(VERSION 3.20)
project(gtasa_static_recomp LANGUAGES CXX)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux" OR NOT CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|amd64|AMD64)$")
    message(FATAL_ERROR "The initial host target is Linux x86_64")
endif()

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(RECOMP_GENERATED_DIR "${CMAKE_SOURCE_DIR}/generated" CACHE PATH "Validated lifted output")
if(NOT EXISTS "${RECOMP_GENERATED_DIR}/lifted.cpp" OR NOT EXISTS "${RECOMP_GENERATED_DIR}/manifest.json")
    message(FATAL_ERROR "Run uv sync --locked and uv run python tools/recomp.py lift --output generated first")
endif()

add_library(recomp_runtime STATIC src/runtime.cpp)
target_include_directories(recomp_runtime PUBLIC include)
target_compile_options(recomp_runtime PRIVATE -Wall -Wextra -Wpedantic -Werror -ffp-contract=off -fno-fast-math)

add_library(recomp_lifted STATIC "${RECOMP_GENERATED_DIR}/lifted.cpp")
target_include_directories(recomp_lifted PUBLIC "${RECOMP_GENERATED_DIR}")
target_link_libraries(recomp_lifted PUBLIC recomp_runtime)
target_compile_options(recomp_lifted PRIVATE -Wall -Wextra -Wpedantic -Werror -ffp-contract=off -fno-fast-math)

add_executable(recomp_leaf_smoke tests/leaf_smoke.cpp)
target_link_libraries(recomp_leaf_smoke PRIVATE recomp_lifted)
target_compile_options(recomp_leaf_smoke PRIVATE -Wall -Wextra -Wpedantic -Werror -ffp-contract=off -fno-fast-math)

include(CTest)
if(BUILD_TESTING)
    add_test(NAME lifted_leaf_semantics COMMAND recomp_leaf_smoke)
endif()
