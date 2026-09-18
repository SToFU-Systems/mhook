cmake_minimum_required(VERSION 3.24)
project(mhook_package_test LANGUAGES C)

find_package(mhook CONFIG REQUIRED)
add_executable(test_package test_package.c)
target_link_libraries(test_package PRIVATE mhook::mhook)
