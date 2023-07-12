cmake_minimum_required(VERSION 3.17)
project(
  simplelfs
  VERSION 0.1
  DESCRIPTION "A simple git-lfs server implementation."
  LANGUAGES CXX C)
set(CMAKE_COLOR_MAKEFILE ON)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Add third party
add_subdirectory(dependencies)

# Main project library
add_executable(
  ${PROJECT_NAME}
  source/main.cc
  source/structs.cc
  source/hashing.cc
  source/server.cc
  source/uuid.cc
  source/configuration.cc
  source/storage.cc)

# Link to dependencies
target_link_libraries(
  ${PROJECT_NAME}
  aws-cpp-sdk-core
  aws-cpp-sdk-s3
  aws-cpp-sdk-transfer
  CLI11::CLI11
  fmt::fmt-header-only
  httplib::httplib
  nlohmann_json::nlohmann_json
  OpenSSL::Crypto
  scope_guard
  spdlog::spdlog_header_only
  tl::expected
  tomlplusplus::tomlplusplus)

if(WIN32)
  # for UUID functionality on windows:
  target_link_libraries(${PROJECT_NAME} Rpcrt4)
else()
  # for UUID functionality on linux:
  find_package(PkgConfig REQUIRED)
  pkg_search_module(UUID REQUIRED uuid)
  target_include_directories(${PROJECT_NAME} PRIVATE ${UUID_INCLUDE_DIRS})
  target_link_libraries(${PROJECT_NAME} ${UUID_LIBRARIES})
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
