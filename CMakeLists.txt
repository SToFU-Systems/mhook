cmake_minimum_required(VERSION 3.24)

project(mhook LANGUAGES C CXX)

include(cmake/MhookPlatform.cmake)

option(BUILD_TESTING "Build tests" ${PROJECT_IS_TOP_LEVEL})
option(MHOOK_BUILD_EXAMPLES "Build examples" ${PROJECT_IS_TOP_LEVEL})
option(MHOOK_ENABLE_SANITY_CHECKS "Enable decoder checks" ON)

add_subdirectory(disasm-lib)
add_subdirectory(mhook-lib)

if(MHOOK_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

if(BUILD_TESTING)
    enable_testing()
    add_subdirectory(tests)
endif()
