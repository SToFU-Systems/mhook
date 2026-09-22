# Included by CPack at pack time, when the configuration passed to
# `cpack -C <config>` is known. Multi-config generators (Visual Studio) leave
# CMAKE_BUILD_TYPE empty at configure time, so the package file name cannot be
# assembled in CMakeLists.txt.

string(TOLOWER "${CPACK_BUILD_CONFIG}" PACKAGE_BUILD_TYPE)
if(NOT PACKAGE_BUILD_TYPE)
    set(PACKAGE_BUILD_TYPE "unknown")
endif()

set(CPACK_PACKAGE_FILE_NAME
    "${CPACK_PACKAGE_NAME}-${PACKAGE_BUILD_TYPE}-${CPACK_PACKAGE_VERSION}-${CPACK_SYSTEM_PROCESSOR}"
)
