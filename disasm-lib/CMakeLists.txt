add_library(mhook_disasm OBJECT
    cpu.c
    disasm.c
    disasm_x86.c
    misc.c
    cpu.h
    disasm.h
    disasm_x86.h
    disasm_x86_tables.h
    misc.h
)

mhook_configure_private_target(mhook_disasm)
if(NOT MHOOK_ENABLE_SANITY_CHECKS)
    target_compile_definitions(mhook_disasm PRIVATE NO_SANITY_CHECKS)
endif()

