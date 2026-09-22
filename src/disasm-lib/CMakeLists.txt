project(disasm-lib LANGUAGES C)

set(DISASM_INCLUDES
    include/disasm-lib/cpu.h
    include/disasm-lib/disasm.h
    include/disasm-lib/disasm_x86.h
    include/disasm-lib/disasm_x86_tables.h
    include/disasm-lib/misc.h
)

set(DISASM_SOURCES
    src/cpu.c
    src/disasm.c
    src/disasm_x86.c
    src/misc.c
)

source_group("include/disasm-lib" FILES ${DISASM_INCLUDES})
source_group("src" FILES ${DISASM_SOURCES})

add_library(mhook_disasm OBJECT ${DISASM_SOURCES} ${DISASM_INCLUDES})

# PUBLIC so that mhook.c can reach <disasm-lib/disasm.h> without a relative
# path climbing out of its own directory, which corporate rule 7.1 forbids.
target_include_directories(mhook_disasm PUBLIC
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
)

# The sources include their own headers unqualified, as "disasm.h". Those used
# to resolve because everything shared one directory; after the split they need
# the header directory on the search path.
target_include_directories(mhook_disasm PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/include/disasm-lib"
)

mhook_configure_private_target(mhook_disasm)
if(NOT MHOOK_ENABLE_SANITY_CHECKS)
    target_compile_definitions(mhook_disasm PRIVATE NO_SANITY_CHECKS)
endif()

target_compile_features(mhook_disasm PRIVATE c_std_99)
set_target_properties(mhook_disasm PROPERTIES C_EXTENSIONS ON)
