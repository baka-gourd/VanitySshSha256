cmake_minimum_required(VERSION 3.24)
project(vanity LANGUAGES CXX CUDA)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CUDA_STANDARD 20)


add_executable(vanity
  src/main.cpp
  src/match_rule.cpp
  cuda/kernel.cu
  cuda/ed25519/common.cu
  cuda/ed25519/fe.cu
  cuda/ed25519/ge.cu
  cuda/ed25519/sc.cu
  cuda/ed25519/sha512.cu
  cuda/ed25519/keypair.cu
)

target_include_directories(vanity PRIVATE include cuda cuda/ed25519)

if (MSVC)
  set_property(TARGET vanity PROPERTY
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
  )
  target_compile_options(vanity PRIVATE
    "$<$<COMPILE_LANGUAGE:CXX>:/utf-8>"
    "$<$<COMPILE_LANGUAGE:CUDA>:-Xcompiler=/utf-8>"
  )
endif()

set_target_properties(vanity PROPERTIES
  CUDA_SEPARABLE_COMPILATION ON
)

set_property(TARGET vanity PROPERTY CUDA_ARCHITECTURES 86)

find_package(re2 CONFIG REQUIRED)
target_link_libraries(vanity PRIVATE re2::re2)
