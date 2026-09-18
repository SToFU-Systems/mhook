include(CMakePackageConfigHelpers)

set(MHOOK_CMAKE_INSTALL_DIR "${CMAKE_INSTALL_LIBDIR}/cmake/mhook")

install(TARGETS mhook mhook_headers EXPORT mhookTargets
    ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
)
install(FILES "${PROJECT_SOURCE_DIR}/mhook-lib/mhook.h"
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/mhook-lib"
)

configure_package_config_file(
    "${PROJECT_SOURCE_DIR}/cmake/mhook-config.cmake.in"
    "${PROJECT_BINARY_DIR}/mhook-config.cmake"
    INSTALL_DESTINATION "${MHOOK_CMAKE_INSTALL_DIR}"
)
install(FILES "${PROJECT_BINARY_DIR}/mhook-config.cmake"
    DESTINATION "${MHOOK_CMAKE_INSTALL_DIR}"
)
install(EXPORT mhookTargets
    FILE mhook-targets.cmake
    NAMESPACE mhook::
    DESTINATION "${MHOOK_CMAKE_INSTALL_DIR}"
)
install(FILES "${PROJECT_SOURCE_DIR}/LICENSE"
    DESTINATION "${CMAKE_INSTALL_DATADIR}/mhook"
)
