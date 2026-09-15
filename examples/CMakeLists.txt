add_executable(mhook-example mhook-example.cpp)
target_link_libraries(mhook-example PRIVATE mhook::mhook ws2_32 gdi32 user32)
mhook_configure_private_target(mhook-example)
if(MHOOK_COMPILER_MINGW)
    target_link_options(mhook-example PRIVATE -municode)
endif()

