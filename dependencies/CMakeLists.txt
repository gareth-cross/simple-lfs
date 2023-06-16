# Add libfmt
function(add_libfmt)
  set(FMT_INSTALL
      OFF
      CACHE BOOL "" FORCE)
  set(FMT_TEST
      OFF
      CACHE BOOL "" FORCE)
  add_subdirectory(fmt)
endfunction()
add_libfmt()

# Add spdlog
function(add_spdlog)
  set(SPDLOG_BUILD_PIC
      OFF
      CACHE BOOL "" FORCE)
  set(SPDLOG_FMT_EXTERNAL_HO
      ON
      CACHE BOOL "" FORCE)
  set(SPDLOG_INSTALL
      OFF
      CACHE BOOL "" FORCE)
  add_subdirectory(spdlog)
endfunction()
add_spdlog()

# Add cpp-httplib
function(add_httplib)
  add_subdirectory(cpp-httplib)
endfunction()
add_httplib()

# Add nlohmann json
function(add_json)
  add_subdirectory(json)
endfunction()
add_json()

# Add toml++
function(add_tomlplusplus)
  add_subdirectory(tomlplusplus)
endfunction()
add_tomlplusplus()

# Add expected
function(add_tl_expected)
  set(EXPECTED_BUILD_TESTS
      OFF
      CACHE BOOL "" FORCE)
  add_subdirectory(tl_expected)
endfunction()
add_tl_expected()

# Add CLI11
function(add_cli11)
  add_subdirectory(cli11)
endfunction()
add_cli11()

# Add AWS
function(add_aws)
  set(BUILD_SHARED_LIBS
      OFF
      CACHE BOOL "" FORCE)
  set(ENABLE_TESTING
      OFF
      CACHE BOOL "" FORCE)
  set(BUILD_ONLY
      "s3;core;transfer"
      CACHE STRING "" FORCE)
  add_subdirectory(aws-sdk-cpp)
  target_compile_options(aws-cpp-sdk-core PRIVATE /wd4267)
endfunction()
add_aws()
