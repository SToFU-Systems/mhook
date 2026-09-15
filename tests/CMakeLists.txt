add_executable(mhook-decoder-test decoder-test.cpp)
target_link_libraries(mhook-decoder-test PRIVATE mhook::mhook)
mhook_configure_private_target(mhook-decoder-test)
add_test(NAME mhook.decoder COMMAND mhook-decoder-test)
set_tests_properties(mhook.decoder PROPERTIES TIMEOUT 15)

