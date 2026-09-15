#include <windows.h>
#include <stdio.h>
#include "mhook-lib/mhook.h"
#include "disasm-lib/disasm.h"

static BOOL (*volatile set_hook)(PVOID*, PVOID) = &Mhook_SetHook;
static BOOL (*volatile remove_hook)(PVOID*) = &Mhook_Unhook;

static bool CheckInstruction(ARCHITECTURE_TYPE architecture, U8* bytes,
                             U32 length, INSTRUCTION_TYPE type)
{
    DISASSEMBLER decoder;
    if (!InitDisassembler(&decoder, architecture)) {
        fprintf(stderr, "Decoder initialization failed for architecture %d\n", architecture);
        return false;
    }

    INSTRUCTION* instruction = GetInstruction(
        &decoder, (U64)(ULONG_PTR)bytes, bytes, DISASM_DECODE | DISASM_SUPPRESSERRORS);
    const bool valid = instruction && !instruction->ErrorOccurred &&
                       instruction->Length == length && instruction->Type == type;
    if (!valid) {
        fprintf(stderr, "Decode failed for architecture %d: expected length %lu, type %d\n",
                architecture, (unsigned long)length, type);
    }
    CloseDisassembler(&decoder);
    return valid;
}

int main()
{
    if (!set_hook || !remove_hook) {
        fprintf(stderr, "Public hook API linkage failed\n");
        return 1;
    }

    // Padded buffers accommodate the legacy decoder's lookahead.
    U8 move_immediate[32] = { 0xb8, 0x2a, 0x00, 0x00, 0x00 }; // mov eax, 42
    U8 return_instruction[32] = { 0xc3 }; // ret
    const ARCHITECTURE_TYPE modes[] = { ARCH_X86, ARCH_X64 };
    for (unsigned i = 0; i < sizeof(modes) / sizeof(modes[0]); ++i) {
        if (!CheckInstruction(modes[i], move_immediate, 5, ITYPE_MOV) ||
            !CheckInstruction(modes[i], return_instruction, 1, ITYPE_RET)) {
            return 1;
        }
    }
    puts("Archive linkage and x86/x64 decoder checks passed.");
    return 0;
}

