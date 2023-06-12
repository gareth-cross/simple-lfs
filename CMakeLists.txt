cmake_minimum_required(VERSION 3.17)
project(
  simplelfs
  VERSION 0.1
  DESCRIPTION "Messing around with git lfs."
  LANGUAGES CXX C)
set(CMAKE_COLOR_MAKEFILE ON)

# Detect windows, and set the architecture.
option(OVERRIDE_ARCH_ON_WIN32 "Automatically set x64 on windows platform." ON)
if(MSVC AND ${OVERRIDE_ARCH_ON_WIN32})
  message(STATUS "Changing architecture because we are on windows.")
  set(CMAKE_GENERATOR_PLATFORM
      "x64"
      CACHE STRING "" FORCE)
endif()

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Add third party
add_subdirectory(dependencies)

# Main project library
add_executable(
  ${PROJECT_NAME} source/main.cc source/structs.cc source/hashing.cc
                  source/server.cc source/uuid.cc source/configuration.cc)

# Link to dependencies
add_dependencies(
  ${PROJECT_NAME}
  fmt-header-only
  spdlog_header_only
  httplib
  nlohmann_json
  tomlplusplus::tomlplusplus
  tl::expected
  CLI11::CLI11
  aws-cpp-sdk-s3
  aws-cpp-sdk-core
  aws-cpp-sdk-transfer)
target_link_libraries(
  ${PROJECT_NAME}
  fmt-header-only
  spdlog_header_only
  httplib
  nlohmann_json
  tomlplusplus::tomlplusplus
  tl::expected
  CLI11::CLI11
  OpenSSL::Crypto
  aws-cpp-sdk-s3
  aws-cpp-sdk-core
  aws-cpp-sdk-transfer)

if(WIN32)
  # for UUID functionality on windows:
  target_link_libraries(${PROJECT_NAME} Rpcrt4)
endif()

# Turn on C++17
target_compile_features(${PROJECT_NAME} PUBLIC cxx_std_17)

# turn on maximum warnings
if(MSVC)
  target_compile_options(${PROJECT_NAME} PRIVATE /W4 /WX /wd4244)
else()
  target_compile_options(${PROJECT_NAME} PRIVATE -Wall -Wextra -pedantic
                                                 -Werror -Wno-sign-compare)
endif()

target_include_directories(
  ${PROJECT_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/dependencies/scope_guard")
