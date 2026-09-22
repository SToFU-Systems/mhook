cmake_minimum_required(VERSION 3.24)

set(MHOOK_VERSION_MAJOR 3)
set(MHOOK_VERSION_MINOR 0)
set(MHOOK_VERSION_PATCH 0)
set(MHOOK_VERSION "${MHOOK_VERSION_MAJOR}.${MHOOK_VERSION_MINOR}.${MHOOK_VERSION_PATCH}")

project(mhook VERSION ${MHOOK_VERSION} LANGUAGES C)

include(GNUInstallDirs)

# Deliberately NOT the global BUILD_TESTING. A parent project that calls
# include(CTest) caches BUILD_TESTING=ON, and option() never overrides an
# existing cache entry, so this library's nine test executables would be built
# inside a consumer that only wanted to link it. A project-scoped option keeps
# that switch ours; a consumer who does want the tests passes it explicitly.
option(MHOOK_BUILD_TESTING "Build the mhook tests" ${PROJECT_IS_TOP_LEVEL})
option(MHOOK_BUILD_EXAMPLES "Build examples" ${PROJECT_IS_TOP_LEVEL})
option(MHOOK_ENABLE_SANITY_CHECKS "Enable decoder checks" ON)

# The tests and the example are C++; the library itself is not.
if(MHOOK_BUILD_TESTING OR MHOOK_BUILD_EXAMPLES)
    enable_language(CXX)
endif()

# Included after the options and the enable_language(CXX) guard above, so its
# CXX-compiler-pairing check sees an accurate ENABLED_LANGUAGES list.
include(cmake/MhookPlatform.cmake)

# Generated into the binary tree, not the source tree: a generated header in
# include/ would be installed alongside the handwritten one and would show up
# as an untracked file after every configure.
set(MHOOK_GENERATED_INCLUDE_DIR "${PROJECT_BINARY_DIR}/generated")
configure_file(
    "${PROJECT_SOURCE_DIR}/cmake/version.in"
    "${MHOOK_GENERATED_INCLUDE_DIR}/mhook-lib/version.h"
    @ONLY
)

add_subdirectory(src/disasm-lib)
add_subdirectory(src/mhook-lib)
include(cmake/MhookInstall.cmake)

if(MHOOK_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

if(MHOOK_BUILD_TESTING)
    enable_testing()
    add_subdirectory(tests)
endif()

# A vendoring parent's own packaging should not be hijacked by mhook's
# generator, package name, output directory and PACKAGE target.
if(PROJECT_IS_TOP_LEVEL)
    set(CPACK_PACKAGE_DIRECTORY "${PROJECT_SOURCE_DIR}/_package")
    set(CPACK_PACKAGE_NAME ${CMAKE_PROJECT_NAME})
    set(CPACK_PACKAGE_VERSION ${MHOOK_VERSION})
    # MHOOK_ARCHITECTURE comes from MhookPlatform.cmake and reads x86 or x64.
    # CMAKE_SYSTEM_PROCESSOR would say AMD64 on both, which is useless in a
    # package name that has to tell the two apart.
    set(CPACK_SYSTEM_PROCESSOR ${MHOOK_ARCHITECTURE})
    set(CPACK_PROJECT_CONFIG_FILE "${PROJECT_SOURCE_DIR}/cmake/CPackProjectConfig.cmake")
    set(CPACK_PACKAGE_VENDOR "SToFU Systems")
    set(CPACK_PACKAGE_HOMEPAGE_URL "https://stofu.io")
    set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Windows inline function hooking library")
    set(CPACK_RESOURCE_FILE_LICENSE "${PROJECT_SOURCE_DIR}/LICENSE")

    # A ZIP keeps packaging dependency free.
    set(CPACK_GENERATOR "ZIP")

    include(CPack)
endif()
