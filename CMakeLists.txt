cmake_minimum_required(VERSION 3.12)
project(merkle_tree VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 主库目标（直接使用tiny_sha3）
add_library(merkle_tree STATIC src/merkle_tree.cpp src/sha3.c)
target_include_directories(merkle_tree PUBLIC include)

# 测试配置
enable_testing()
find_package(GTest REQUIRED)
add_executable(merkle_tree_tests tests/main.cpp)
target_link_libraries(merkle_tree_tests PRIVATE merkle_tree GTest::GTest GTest::Main)
add_test(NAME merkle_tree_tests COMMAND merkle_tree_tests)
