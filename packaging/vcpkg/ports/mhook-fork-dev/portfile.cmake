vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO SToFU-Systems/mhook
    REF "<release-tag>"
    SHA512 0
    HEAD_REF master
)

vcpkg_cmake_configure(
    SOURCE_PATH "${SOURCE_PATH}"
    OPTIONS
        -DBUILD_TESTING=OFF
        -DMHOOK_BUILD_EXAMPLES=OFF
)
vcpkg_cmake_install()
vcpkg_copy_pdbs()
vcpkg_cmake_config_fixup(PACKAGE_NAME mhook CONFIG_PATH lib/cmake/mhook)

file(REMOVE_RECURSE
    "${CURRENT_PACKAGES_DIR}/debug/include"
    "${CURRENT_PACKAGES_DIR}/debug/share"
)
file(REMOVE "${CURRENT_PACKAGES_DIR}/share/mhook/LICENSE")
vcpkg_install_copyright(FILE_LIST "${SOURCE_PATH}/LICENSE")
