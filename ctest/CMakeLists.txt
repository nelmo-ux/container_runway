cmake_minimum_required(VERSION 3.16)
project(runway_ctest LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)

FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip
)

set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

enable_testing()

add_executable(runtime_gtest runtime_gtest.cpp)
target_include_directories(runtime_gtest PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/..)
target_link_libraries(runtime_gtest PRIVATE gtest_main)

add_test(NAME runtime_gtest COMMAND runtime_gtest)
