add_executable(mhook-decoder-test decoder-test.cpp)
target_link_libraries(mhook-decoder-test PRIVATE mhook::mhook)
mhook_configure_private_target(mhook-decoder-test)
add_test(NAME mhook.decoder COMMAND mhook-decoder-test)
set_tests_properties(mhook.decoder PROPERTIES TIMEOUT 15)

foreach(language IN ITEMS c cpp)
    add_executable(mhook-header-${language}-test header-${language}-test.${language})
    target_link_libraries(mhook-header-${language}-test PRIVATE mhook::mhook)
    # Match the warning baseline without inheriting private build definitions.
    if(MHOOK_COMPILER_MSVC)
        target_compile_options(mhook-header-${language}-test PRIVATE /W3 /WX)
    endif()
    add_test(NAME mhook.header.${language} COMMAND mhook-header-${language}-test)
    set_tests_properties(mhook.header.${language} PROPERTIES TIMEOUT 15)
endforeach()

add_executable(mhook-hook-test hook-test.cpp)
target_link_libraries(mhook-hook-test PRIVATE mhook::mhook)
mhook_configure_private_target(mhook-hook-test)

foreach(case IN ITEMS basic trampoline restore passthrough thunk short_func threads reuse sweep)
    add_test(NAME mhook.hook.${case} COMMAND mhook-hook-test ${case})
endforeach()

set_tests_properties(
    mhook.hook.basic mhook.hook.trampoline mhook.hook.restore
    mhook.hook.passthrough mhook.hook.thunk mhook.hook.short_func
    PROPERTIES TIMEOUT 15)
# Every hook and unhook pair costs two system wide thread snapshots inside the
# library, and that rate, not the hook engine, sets the runtime of the bulk
# cases. They therefore sample by default, which is what these timeouts are
# sized for. Setting MHOOK_TEST_EXHAUSTIVE in the environment runs them in full
# instead, which takes roughly twenty minutes per configuration, so keep that
# for a nightly job rather than a pull request.
set_tests_properties(mhook.hook.threads PROPERTIES TIMEOUT 120)
set_tests_properties(mhook.hook.reuse PROPERTIES TIMEOUT 180)
set_tests_properties(mhook.hook.sweep PROPERTIES TIMEOUT 300)
