add_executable(mhook-decoder-test decoder-test.cpp)
target_link_libraries(mhook-decoder-test PRIVATE mhook::mhook)
mhook_configure_private_target(mhook-decoder-test)
add_test(NAME mhook.decoder COMMAND mhook-decoder-test)
set_tests_properties(mhook.decoder PROPERTIES TIMEOUT 15)

add_executable(mhook-status-test status-test.cpp)
target_link_libraries(mhook-status-test PRIVATE mhook::mhook)
mhook_configure_private_target(mhook-status-test)
set(statusCases
    initial
    invalid_set
    invalid_set_target_access
    invalid_set_target_execute
    invalid_set_hook_access
    invalid_set_thunk_boundary
    invalid_set_decode_boundary
    invalid_set_thunk_indirect
    invalid_set_thunk_cycle
    invalid_set_thunk_depth
    invalid_set_conflict
    invalid_set_slot_alignment
    invalid_set_slot_access
    invalid_set_slot_write
    invalid_unhook
    invalid_unhook_slot_alignment
    invalid_unhook_slot_access
    invalid_unhook_slot_write
    invalid_batch
    invalid_batch_alignment
    batch_failure_status
    invalid_unhook_address
    not_found
    thread_local
    success
)
foreach(case IN LISTS statusCases)
    add_test(NAME mhook.status.${case} COMMAND mhook-status-test ${case})
    set_tests_properties(mhook.status.${case} PROPERTIES TIMEOUT 15)
endforeach()

foreach(language IN ITEMS c cpp)
    add_executable(mhook-consumer-static-${language}-test consumer-${language}-test.${language})
    target_link_libraries(mhook-consumer-static-${language}-test PRIVATE mhook::mhook)
    # Verify that the public header compiles cleanly without private settings.
    if(MHOOK_COMPILER_MSVC)
        target_compile_options(mhook-consumer-static-${language}-test PRIVATE /W3 /WX)
    endif()
    add_test(NAME mhook.consumer.static.${language} COMMAND mhook-consumer-static-${language}-test)
    set_tests_properties(mhook.consumer.static.${language} PROPERTIES TIMEOUT 15)
endforeach()

set(directSources
    "${PROJECT_SOURCE_DIR}/mhook-lib/mhook.c"
    "${PROJECT_SOURCE_DIR}/disasm-lib/cpu.c"
    "${PROJECT_SOURCE_DIR}/disasm-lib/disasm.c"
    "${PROJECT_SOURCE_DIR}/disasm-lib/disasm_x86.c"
    "${PROJECT_SOURCE_DIR}/disasm-lib/misc.c"
)

add_executable(mhook-consumer-direct-c-test
    consumer-c-test.c
    ${directSources}
)
target_include_directories(mhook-consumer-direct-c-test PRIVATE "${PROJECT_SOURCE_DIR}")
target_compile_features(mhook-consumer-direct-c-test PRIVATE c_std_11)

if(MHOOK_COMPILER_MSVC)
    target_compile_options(mhook-consumer-direct-c-test PRIVATE /W3)
endif()

if(NOT MHOOK_ENABLE_SANITY_CHECKS)
    target_compile_definitions(mhook-consumer-direct-c-test PRIVATE NO_SANITY_CHECKS)
endif()

add_test(NAME mhook.consumer.direct.c COMMAND mhook-consumer-direct-c-test)
set_tests_properties(mhook.consumer.direct.c PROPERTIES TIMEOUT 15)

add_executable(mhook-hook-test hook-test.cpp)
target_link_libraries(mhook-hook-test PRIVATE mhook::mhook)
mhook_configure_private_target(mhook-hook-test)

foreach(case IN ITEMS basic batch trampoline restore conflict passthrough thunk snapshot_boundary short_func threads reuse sweep)
    add_test(NAME mhook.hook.${case} COMMAND mhook-hook-test ${case})
endforeach()

set_tests_properties(
    mhook.hook.basic mhook.hook.batch mhook.hook.trampoline mhook.hook.restore
    mhook.hook.conflict mhook.hook.passthrough mhook.hook.thunk
    mhook.hook.snapshot_boundary mhook.hook.short_func
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
