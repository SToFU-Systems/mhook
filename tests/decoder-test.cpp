//================================================================================
// Mhook
//
// Modifications and original additions:
// Copyright (c) 2026, SToFU Systems (https://stofu.io). All rights reserved.
//
// Licensed under the MIT License.
// See LICENSE in the repository root for the full license text.
//================================================================================

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


/**
 * @brief Verifies that decoding from copied bytes preserves their represented virtual address.
 * @return True when a RIP-relative target is calculated from the virtual address.
 */
static bool CheckSnapshotVirtualAddress(void)
{
    const U64 kVirtualAddress = 0x10000000;
    const U64 kExpectedTargetAddress = 0x10000010;
    U8 bytes[32] = { 0x48, 0x8B, 0x05, 0x09, 0x00, 0x00, 0x00 };
    DISASSEMBLER decoder = {};
    if (!InitDisassembler(&decoder, ARCH_X64))
    {
        fprintf(stderr, "Decoder initialization failed for snapshot address test\n");
        return false;
    }

    INSTRUCTION* instruction = GetInstruction(&decoder, kVirtualAddress, bytes, DISASM_DECODE | DISASM_SUPPRESSERRORS);
    const U64 targetAddress = instruction ? instruction->Operands[1].TargetAddress + instruction->VirtualAddressDelta : 0;
    const bool valid = instruction && !instruction->ErrorOccurred && instruction->Length == 7 && instruction->Type == ITYPE_MOV && targetAddress == kExpectedTargetAddress;
    if (!valid)
        fprintf(stderr, "Snapshot decoding did not preserve the original virtual address\n");

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
    if (!CheckSnapshotVirtualAddress())
        return 1;
    puts("Archive linkage and x86/x64 decoder checks passed.");
    return 0;
}
