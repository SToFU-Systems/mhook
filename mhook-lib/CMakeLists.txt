add_library(mhook_headers INTERFACE)
add_library(mhook::headers ALIAS mhook_headers)
target_include_directories(mhook_headers INTERFACE
    "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}>"
)
target_sources(mhook_headers INTERFACE
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/mhook.h>"
)

add_library(mhook STATIC mhook.cpp $<TARGET_OBJECTS:mhook_disasm>)
add_library(mhook::mhook ALIAS mhook)
target_link_libraries(mhook PUBLIC mhook_headers)
mhook_configure_private_target(mhook)

