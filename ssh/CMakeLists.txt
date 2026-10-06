cmake_minimum_required(VERSION 3.20)

project(crown-ssh
  VERSION 0.1.0
  DESCRIPTION "SSH client built on libssh2 with the crown crypto backend"
  LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

option(CROWN_SSH_BUILD_CLI "Build the crown-ssh client" ON)
set(CROWN_SSH_LIBSSH2_TAG "libssh2-1.11.1" CACHE STRING
  "libssh2 git tag to build the crown backend against")

set(CROWN_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/..")
set(CROWN_CABI_INCLUDE "${CROWN_ROOT}/crown-cabi/include")
set(CROWN_BACKEND_INCLUDE "${CMAKE_CURRENT_SOURCE_DIR}/backend")

# ---------------------------------------------------------------------------
# crown itself: build the C ABI static library with cargo
# ---------------------------------------------------------------------------

find_program(CARGO_EXECUTABLE cargo REQUIRED)

set(CROWN_TARGET_DIR "${CMAKE_CURRENT_BINARY_DIR}/crown-target")
set(CROWN_STATIC_LIB "${CROWN_TARGET_DIR}/release/libcrown.a")

file(GLOB_RECURSE CROWN_RUST_SOURCES CONFIGURE_DEPENDS
  "${CROWN_ROOT}/crown/src/*.rs"
  "${CROWN_ROOT}/crown-cabi/src/*.rs"
  "${CROWN_ROOT}/crown-derive/src/*.rs")
list(APPEND CROWN_RUST_SOURCES
  "${CROWN_ROOT}/Cargo.toml"
  "${CROWN_ROOT}/crown/Cargo.toml"
  "${CROWN_ROOT}/crown-cabi/Cargo.toml")

add_custom_command(
  OUTPUT "${CROWN_STATIC_LIB}"
  COMMAND "${CARGO_EXECUTABLE}" build --release
          --manifest-path "${CROWN_ROOT}/crown-cabi/Cargo.toml"
          --target-dir "${CROWN_TARGET_DIR}"
  DEPENDS ${CROWN_RUST_SOURCES}
  WORKING_DIRECTORY "${CROWN_ROOT}"
  COMMENT "Building crown-cabi static library (cargo)"
  VERBATIM)

add_custom_target(crown_static DEPENDS "${CROWN_STATIC_LIB}")

# ---------------------------------------------------------------------------
# libssh2 + the crown backend
# ---------------------------------------------------------------------------

find_package(Threads REQUIRED)

include(FetchContent)

FetchContent_Declare(libssh2
  GIT_REPOSITORY https://github.com/libssh2/libssh2.git
  GIT_TAG "${CROWN_SSH_LIBSSH2_TAG}"
  GIT_SHALLOW TRUE
  PATCH_COMMAND git apply --whitespace=nowarn
                "${CMAKE_CURRENT_SOURCE_DIR}/patches/libssh2-crown.patch"
  UPDATE_COMMAND "")

set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(BUILD_STATIC_LIBS ON CACHE BOOL "" FORCE)
set(BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
set(CRYPTO_BACKEND "Crown" CACHE STRING "" FORCE)
set(CROWN_LIBRARIES "${CROWN_STATIC_LIB}" CACHE STRING "" FORCE)
set(CROWN_INCLUDE_DIRS "${CROWN_CABI_INCLUDE};${CROWN_BACKEND_INCLUDE}" CACHE STRING "" FORCE)

FetchContent_MakeAvailable(libssh2)

# The crown backend is compiled as its own object library so it can see the
# private libssh2 headers in src/ (libssh2 only exports include/ on its
# target), then folded into the static library.
add_library(crown_backend OBJECT backend/libssh2_crown.c)
add_dependencies(crown_backend crown_static)
target_compile_definitions(crown_backend PRIVATE LIBSSH2_CROWN)
target_include_directories(crown_backend PRIVATE
  "${libssh2_SOURCE_DIR}/src"
  "${libssh2_SOURCE_DIR}/include"
  "${libssh2_BINARY_DIR}"
  "${libssh2_BINARY_DIR}/src"
  "${CROWN_BACKEND_INCLUDE}"
  "${CROWN_CABI_INCLUDE}")

if(NOT TARGET libssh2_static)
  message(FATAL_ERROR "libssh2 static target not found; "
                      "the crown backend needs libssh2_static")
endif()

target_sources(libssh2_static PRIVATE $<TARGET_OBJECTS:crown_backend>)
target_link_libraries(libssh2_static PRIVATE
  "${CROWN_STATIC_LIB}"
  ${CMAKE_DL_LIBS}
  Threads::Threads
  m)

# ---------------------------------------------------------------------------
# crown-ssh CLI
# ---------------------------------------------------------------------------

if(CROWN_SSH_BUILD_CLI)
  add_executable(crown-ssh cli/ssh.c)
  target_include_directories(crown-ssh PRIVATE "${CROWN_CABI_INCLUDE}")
  # -v turns on libssh2 tracing when the library was built with it.
  if(ENABLE_DEBUG_LOGGING)
    target_compile_definitions(crown-ssh PRIVATE LIBSSH2DEBUG)
  endif()
  target_link_libraries(crown-ssh PRIVATE libssh2_static)
  install(TARGETS crown-ssh RUNTIME DESTINATION bin)
endif()
