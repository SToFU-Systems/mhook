add_executable(mhook-decoder-test decoder-test.cpp)
target_link_libraries(mhook-decoder-test PRIVATE mhook::mhook)
target_include_directories(mhook-decoder-test PRIVATE
    "${PROJECT_SOURCE_DIR}/src/disasm-lib/include"
)
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
    invalid_unhook_target_access
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

# The public header must compile cleanly for a consumer on every standard the
# library claims to support, which is where a header portability break shows up
# first. Under MSVC the three C rows build identically, because MSVC has no
# /std:c99; MinGW is what makes that row meaningful.
set(consumerCStandards 99 11 17)
foreach(standard IN LISTS consumerCStandards)
    set(target mhook-consumer-c${standard}-test)
    add_executable(${target} consumer-c-test.c consumer-test.inc)
    target_link_libraries(${target} PRIVATE mhook::mhook)
    target_compile_features(${target} PRIVATE c_std_${standard})
    # The public header must compile warning free for a consumer that has none
    # of the private settings, so these fail on a warning even outside presets.
    set_target_properties(${target} PROPERTIES C_EXTENSIONS ON COMPILE_WARNING_AS_ERROR ON)
    mhook_enable_warnings(${target})
    add_test(NAME mhook.consumer.c${standard} COMMAND ${target})
    set_tests_properties(mhook.consumer.c${standard} PROPERTIES TIMEOUT 15)
endforeach()

set(consumerCxxStandards 17 20)
foreach(standard IN LISTS consumerCxxStandards)
    set(target mhook-consumer-cpp${standard}-test)
    add_executable(${target} consumer-cpp-test.cpp consumer-test.inc)
    target_link_libraries(${target} PRIVATE mhook::mhook)
    target_compile_features(${target} PRIVATE cxx_std_${standard})
    set_target_properties(${target} PROPERTIES CXX_EXTENSIONS OFF COMPILE_WARNING_AS_ERROR ON)
    mhook_enable_warnings(${target})
    add_test(NAME mhook.consumer.cpp${standard} COMMAND ${target})
    set_tests_properties(mhook.consumer.cpp${standard} PROPERTIES TIMEOUT 15)
endforeach()

source_group("test" FILES consumer-test.inc)

set(directSources
    "${PROJECT_SOURCE_DIR}/src/mhook-lib/src/mhook.c"
    "${PROJECT_SOURCE_DIR}/src/disasm-lib/src/cpu.c"
    "${PROJECT_SOURCE_DIR}/src/disasm-lib/src/disasm.c"
    "${PROJECT_SOURCE_DIR}/src/disasm-lib/src/disasm_x86.c"
    "${PROJECT_SOURCE_DIR}/src/disasm-lib/src/misc.c"
)

add_executable(mhook-consumer-direct-c-test
    consumer-c-test.c
    ${directSources}
)
target_include_directories(mhook-consumer-direct-c-test PRIVATE
    "${PROJECT_SOURCE_DIR}/src/mhook-lib/include"
    # mhook.h now includes <mhook-lib/version.h>, which is generated.
    "${MHOOK_GENERATED_INCLUDE_DIR}"
    "${PROJECT_SOURCE_DIR}/src/mhook-lib/include/mhook-lib"
    "${PROJECT_SOURCE_DIR}/src/disasm-lib/include"
    "${PROJECT_SOURCE_DIR}/src/disasm-lib/include/disasm-lib"
)
target_compile_features(mhook-consumer-direct-c-test PRIVATE c_std_99)
set_target_properties(mhook-consumer-direct-c-test PROPERTIES C_EXTENSIONS ON)
mhook_enable_warnings(mhook-consumer-direct-c-test)

if(NOT MHOOK_ENABLE_SANITY_CHECKS)
    target_compile_definitions(mhook-consumer-direct-c-test PRIVATE NO_SANITY_CHECKS)
endif()

add_test(NAME mhook.consumer.direct.c COMMAND mhook-consumer-direct-c-test)
set_tests_properties(mhook.consumer.direct.c PROPERTIES TIMEOUT 15)

add_executable(mhook-hook-test hook-test.cpp)
target_link_libraries(mhook-hook-test PRIVATE mhook::mhook Advapi32)
mhook_configure_private_target(mhook-hook-test)

set(hookCases
    basic
    batch
    batch_prepare_failure
    batch_conflict
    batch_commit_failure
    batch_unhook_prepare_failure
    batch_unhook_conflict
    batch_unhook_commit_failure
    trampoline
    restore
    conflict
    passthrough
    thunk
    snapshot_boundary
    short_func
    threads
    suspend_failure
    first_use_race
    late_thread
    reuse
    sweep
)
foreach(case IN LISTS hookCases)
    add_test(NAME mhook.hook.${case} COMMAND mhook-hook-test ${case})
    set_tests_properties(mhook.hook.${case} PROPERTIES TIMEOUT 15)
endforeach()

if(MHOOK_ARCHITECTURE STREQUAL "x64")
    add_test(NAME mhook.hook.pool COMMAND mhook-hook-test pool)
    set_tests_properties(mhook.hook.pool PROPERTIES TIMEOUT 15)
endif()

# Every hook and unhook pair costs at least two system wide thread snapshots in the
# library, and that rate, not the hook engine, sets the runtime of the bulk
# cases. They therefore sample by default, which is what these timeouts are
# sized for. Setting MHOOK_TEST_EXHAUSTIVE in the environment runs them in full
# instead, which takes roughly twenty minutes per configuration, so keep that
# for a nightly job rather than a pull request.
# mhook.hook.threads is the exception among these. Its cost is not the work it
# performs but how often a spinning worker happens to be inside the patch range
# when the engine suspends it, because each collision costs another snapshot
# and another retry. That is a property of the host's scheduler, not of the
# code: the case runs in about 12 seconds here, about 40 when pinned to a
# single core, and exceeded 120 on a CI runner. Its timeout is therefore sized
# to catch a hang rather than to hold a performance budget.
set_tests_properties(mhook.hook.threads PROPERTIES TIMEOUT 600)
set_tests_properties(mhook.hook.reuse PROPERTIES TIMEOUT 180)
set_tests_properties(mhook.hook.sweep PROPERTIES TIMEOUT 300)
