if(NOT WIN32)
    message(FATAL_ERROR "Mhook supports Windows targets only.")
endif()

# CXX is not always an enabled language at this point: the root CMakeLists.txt
# only enables it when tests or examples are built, and this file is included
# before that guard. CMAKE_CXX_COMPILER_ID is empty when CXX is not enabled,
# so only fold it into the check when CXX is actually available; otherwise a
# pure-C configure would fail both branches below on an empty compiler id.
get_property(MHOOK_ENABLED_LANGUAGES GLOBAL PROPERTY ENABLED_LANGUAGES)
if("CXX" IN_LIST MHOOK_ENABLED_LANGUAGES)
    if(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
        set(MHOOK_CXX_IS_MSVC TRUE)
    else()
        set(MHOOK_CXX_IS_MSVC FALSE)
    endif()
    if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        set(MHOOK_CXX_IS_GNU TRUE)
    else()
        set(MHOOK_CXX_IS_GNU FALSE)
    endif()
else()
    set(MHOOK_CXX_IS_MSVC TRUE)
    set(MHOOK_CXX_IS_GNU TRUE)
endif()

if(MSVC AND CMAKE_C_COMPILER_ID STREQUAL "MSVC" AND MHOOK_CXX_IS_MSVC)
    set(MHOOK_COMPILER_MSVC TRUE)
elseif(MINGW AND CMAKE_C_COMPILER_ID STREQUAL "GNU" AND MHOOK_CXX_IS_GNU)
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

# The warning baseline every mhook target builds against. README.md, section
# "Compiler warnings", explains the choice and lists the allowed suppressions.
# Whether a warning fails the build is not decided here: the presets set
# CMAKE_COMPILE_WARNING_AS_ERROR, so CI and preset builds enforce the baseline
# while a project that vendors mhook is never broken by a newer compiler.
function(mhook_enable_warnings target)
    if(MHOOK_COMPILER_MSVC)
        target_compile_options(${target} PRIVATE /W4)
    else()
        target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion)
    endif()
endfunction()

function(mhook_configure_private_target target)
    target_compile_definitions(${target} PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN)
    mhook_enable_warnings(${target})
    if(MHOOK_COMPILER_MINGW)
        if(MHOOK_ARCHITECTURE STREQUAL "x64")
            target_compile_definitions(${target} PRIVATE _M_X64)
        else()
            target_compile_definitions(${target} PRIVATE _M_IX86)
        endif()
    endif()
endfunction()

message(STATUS "Mhook target: ${MHOOK_ARCHITECTURE} / ${CMAKE_C_COMPILER_ID}")
