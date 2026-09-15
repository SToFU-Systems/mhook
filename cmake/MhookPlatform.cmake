if(NOT WIN32)
    message(FATAL_ERROR "Mhook supports Windows targets only.")
endif()

if(MSVC AND CMAKE_C_COMPILER_ID STREQUAL "MSVC"
        AND CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    set(MHOOK_COMPILER_MSVC TRUE)
elseif(MINGW AND CMAKE_C_COMPILER_ID STREQUAL "GNU"
        AND CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    set(MHOOK_COMPILER_MINGW TRUE)
else()
    message(FATAL_ERROR "Use MSVC or MinGW GCC for both C and C++.")
endif()

include(CheckCSourceCompiles)
check_c_source_compiles("
#if defined(_M_ARM64EC) || defined(_M_ARM64) || defined(__aarch64__)
#error Unsupported ARM target
#endif
#if !defined(_M_IX86) && !defined(_M_X64) && !defined(__i386__) && !defined(__x86_64__)
#error Expected x86 or x64 target
#endif
int main(void) { return 0; }
" MHOOK_TARGET_IS_X86_OR_X64)
if(NOT MHOOK_TARGET_IS_X86_OR_X64)
    message(FATAL_ERROR "Mhook supports x86 and x64 only; ARM64 and ARM64EC are unsupported.")
endif()

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(MHOOK_ARCHITECTURE x64)
elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)
    set(MHOOK_ARCHITECTURE x86)
else()
    message(FATAL_ERROR "Mhook requires a 32-bit or 64-bit target.")
endif()

if(DEFINED MHOOK_EXPECTED_ARCHITECTURE
        AND NOT MHOOK_EXPECTED_ARCHITECTURE STREQUAL MHOOK_ARCHITECTURE)
    message(FATAL_ERROR
        "Requested ${MHOOK_EXPECTED_ARCHITECTURE}, but the compiler targets ${MHOOK_ARCHITECTURE}.")
endif()

function(mhook_configure_private_target target)
    target_compile_definitions(${target} PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN)
    if(MHOOK_COMPILER_MSVC)
        target_compile_options(${target} PRIVATE /W3)
    elseif(MHOOK_COMPILER_MINGW)
        if(MHOOK_ARCHITECTURE STREQUAL "x64")
            target_compile_definitions(${target} PRIVATE _M_X64)
        else()
            target_compile_definitions(${target} PRIVATE _M_IX86)
        endif()
    endif()
endfunction()

message(STATUS "Mhook target: ${MHOOK_ARCHITECTURE} / ${CMAKE_CXX_COMPILER_ID}")
