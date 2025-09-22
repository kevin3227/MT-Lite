cmake_minimum_required(VERSION 3.12)
project(merkle_tree VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g3 -O0 -fno-omit-frame-pointer")
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g3 -O0 -fno-omit-frame-pointer")

set(OPENSSL_ROOT_DIR "/usr/local/openssl")
set(OPENSSL_INCLUDE_DIR "${OPENSSL_ROOT_DIR}/include")
set(OPENSSL_CRYPTO_LIBRARY "${OPENSSL_ROOT_DIR}/lib64/libcrypto.so")
set(OPENSSL_SSL_LIBRARY "${OPENSSL_ROOT_DIR}/lib64/libssl.so")

find_path(OPENSSL_INCLUDE_DIR openssl/ssl.h
  PATHS "${OPENSSL_ROOT_DIR}"
  PATH_SUFFIXES include
  NO_DEFAULT_PATH
)

find_library(OPENSSL_CRYPTO_LIBRARY crypto
  PATHS "${OPENSSL_ROOT_DIR}"
  PATH_SUFFIXES lib64
  NO_DEFAULT_PATH
)

find_library(OPENSSL_SSL_LIBRARY ssl
  PATHS "${OPENSSL_ROOT_DIR}"
  PATH_SUFFIXES lib64
  NO_DEFAULT_PATH
)

if(NOT OPENSSL_INCLUDE_DIR OR NOT OPENSSL_CRYPTO_LIBRARY)
  message(FATAL_ERROR "OpenSSL not found in ${OPENSSL_ROOT_DIR}")
else()
  message(STATUS "Found OpenSSL includes: ${OPENSSL_INCLUDE_DIR}")
  message(STATUS "Found OpenSSL crypto: ${OPENSSL_CRYPTO_LIBRARY}")
  message(STATUS "Found OpenSSL ssl: ${OPENSSL_SSL_LIBRARY}")
endif()

find_package(OpenMP REQUIRED)
if(OpenMP_CXX_FOUND)
    message(STATUS "Found OpenMP support")
    add_compile_options(${OpenMP_CXX_FLAGS})
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenMP_CXX_FLAGS}")
else()
    message(WARNING "OpenMP not found - parallelization disabled")
endif()

# 主库目标
add_library(merkle_tree STATIC src/merkle_tree.cpp)
target_include_directories(merkle_tree PUBLIC 
  include
  ${OPENSSL_INCLUDE_DIR}
)

# 显式链接库文件
target_link_libraries(merkle_tree PRIVATE 
  ${OPENSSL_SSL_LIBRARY}
  ${OPENSSL_CRYPTO_LIBRARY}
  OpenMP::OpenMP_CXX
  tbb
)

# 测试配置
enable_testing()
find_package(GTest REQUIRED)
add_executable(merkle_tree_tests tests/main.cpp)
target_link_libraries(merkle_tree_tests PRIVATE 
  merkle_tree 
  GTest::GTest 
  GTest::Main
)
add_test(NAME merkle_tree_tests COMMAND merkle_tree_tests)

# 基准测试
find_package(benchmark REQUIRED)
add_executable(merkle_tree_benchmark benchmarks/benchmark.cpp)
target_link_libraries(merkle_tree_benchmark PRIVATE 
  merkle_tree 
  benchmark::benchmark
)