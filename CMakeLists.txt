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

find_package(OpenSSL REQUIRED COMPONENTS Crypto)
add_library(recomp_runtime STATIC src/runtime.cpp src/elf_image.cpp)
target_link_libraries(recomp_runtime PUBLIC OpenSSL::Crypto recomp_aps2_rela recomp_relr)
target_include_directories(recomp_runtime PUBLIC include)
target_compile_options(recomp_runtime PRIVATE -Wall -Wextra -Wpedantic -Werror -ffp-contract=off -fno-fast-math)

# Pure byte decoders are reused by the explicit inventory-only loader profile.
add_library(recomp_aps2_rela STATIC src/aps2_rela.cpp)
target_include_directories(recomp_aps2_rela PUBLIC include)
target_compile_options(recomp_aps2_rela PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_executable(recomp_aps2_rela_test tests/aps2_rela_test.cpp)
target_link_libraries(recomp_aps2_rela_test PRIVATE recomp_aps2_rela)
target_compile_options(recomp_aps2_rela_test PRIVATE -Wall -Wextra -Wpedantic -Werror)

add_library(recomp_relr STATIC src/relr.cpp)
target_include_directories(recomp_relr PUBLIC include)
target_compile_options(recomp_relr PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_executable(recomp_relr_test tests/relr_test.cpp)
target_link_libraries(recomp_relr_test PRIVATE recomp_relr)
target_compile_options(recomp_relr_test PRIVATE -Wall -Wextra -Wpedantic -Werror)

add_library(recomp_lifted STATIC "${RECOMP_GENERATED_DIR}/lifted.cpp")
target_include_directories(recomp_lifted PUBLIC "${RECOMP_GENERATED_DIR}")
target_link_libraries(recomp_lifted PUBLIC recomp_runtime)
target_compile_options(recomp_lifted PRIVATE -Wall -Wextra -Wpedantic -Werror -ffp-contract=off -fno-fast-math)

add_executable(recomp_leaf_smoke tests/leaf_smoke.cpp)
target_link_libraries(recomp_leaf_smoke PRIVATE recomp_lifted)
target_compile_options(recomp_leaf_smoke PRIVATE -Wall -Wextra -Wpedantic -Werror -ffp-contract=off -fno-fast-math)

add_executable(recomp_memory_smoke tests/memory_smoke.cpp)
target_link_libraries(recomp_memory_smoke PRIVATE recomp_runtime)
target_compile_options(recomp_memory_smoke PRIVATE -Wall -Wextra -Wpedantic -Werror)

add_executable(recomp_control_flow_smoke tests/control_flow_smoke.cpp)
target_link_libraries(recomp_control_flow_smoke PRIVATE recomp_lifted)
target_compile_options(recomp_control_flow_smoke PRIVATE -Wall -Wextra -Wpedantic -Werror -ffp-contract=off -fno-fast-math)

add_executable(recomp_image_smoke tests/image_smoke.cpp)
target_link_libraries(recomp_image_smoke PRIVATE recomp_runtime)
target_compile_options(recomp_image_smoke PRIVATE -Wall -Wextra -Wpedantic -Werror)

include(CTest)
if(BUILD_TESTING)
    find_package(Python3 REQUIRED COMPONENTS Interpreter)
    add_test(NAME relocation_inventory_data_only COMMAND "${Python3_EXECUTABLE}" -m unittest
        discover -s "${CMAKE_SOURCE_DIR}/tests" -p test_relocation_inventory.py)
    add_test(NAME relr_data_only COMMAND recomp_relr_test)
    add_test(NAME aps2_rela_data_only COMMAND recomp_aps2_rela_test)
    add_test(NAME original_image_load COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_SOURCE_DIR}/tools/load_image.py"
        --runner "$<TARGET_FILE:recomp_image_smoke>" --load-bias 0x100000000 --guest-page-size 0x1000
        --output "${CMAKE_BINARY_DIR}/image-load.json")
    add_test(NAME lifted_leaf_semantics COMMAND recomp_leaf_smoke)
    add_test(NAME guest_memory_accesses COMMAND recomp_memory_smoke)
    add_test(NAME control_flow_semantics COMMAND recomp_control_flow_smoke)
endif()

add_executable(recomp_inventory_image tools/inventory_image.cpp)
target_link_libraries(recomp_inventory_image PRIVATE recomp_runtime)
target_compile_options(recomp_inventory_image PRIVATE -Wall -Wextra -Wpedantic -Werror)
