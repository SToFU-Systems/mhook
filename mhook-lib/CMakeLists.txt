add_library(mhook_headers INTERFACE)
add_library(mhook::headers ALIAS mhook_headers)
set_target_properties(mhook_headers PROPERTIES EXPORT_NAME headers)
target_include_directories(mhook_headers INTERFACE
    "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}>"
    "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
)
target_sources(mhook_headers INTERFACE
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/mhook.h>"
)

add_library(mhook STATIC mhook.c $<TARGET_OBJECTS:mhook_disasm>)
add_library(mhook::mhook ALIAS mhook)
target_link_libraries(mhook PUBLIC mhook_headers)
target_compile_features(mhook PRIVATE c_std_11)
mhook_configure_private_target(mhook)

