//================================================================================
//    /$$      /$$ /$$   /$$                     /$$
//   | $$$    /$$$| $$  | $$                    | $$
//   | $$$$  /$$$$| $$  | $$  /$$$$$$   /$$$$$$ | $$   /$$
//   | $$ $$/$$ $$| $$$$$$$$ /$$__  $$ /$$__  $$| $$  /$$/
//   | $$  $$$| $$| $$__  $$| $$  \ $$| $$  \ $$| $$$$$$/
//   | $$\  $ | $$| $$  | $$| $$  | $$| $$  | $$| $$_  $$
//   | $$ \/  | $$| $$  | $$|  $$$$$$/|  $$$$$$/| $$ \  $$
//   |__/     |__/|__/  |__/ \______/  \______/ |__/  \__/
//
// Modifications and original additions:
// Copyright (c) 2026, SToFU Systems (https://stofu.io). All rights reserved.
//
// Licensed under the MIT License.
// See LICENSE in the repository root for the full license text.
//
// Original author:
//
// Copyright (C) 2004, Matt Conover (mconover@gmail.com)
//================================================================================

#undef NDEBUG
#include <assert.h>
#include <windows.h>
#include "disasm.h"

#ifdef NO_SANITY_CHECKS
#define NDEBUG
#undef assert
#define assert(x)
#endif

//////////////////////////////////////////////////////////////////////
// Global variables
//////////////////////////////////////////////////////////////////////

ARCHITECTURE_FORMAT SupportedArchitectures[] =
    {{ARCH_X86, &X86}, {ARCH_X86_16, &X86}, {ARCH_X64, &X86}, {ARCH_UNKNOWN, NULL}};

typedef struct _DISASM_ARG_INFO
{
    INSTRUCTION* MatchedInstruction;
    BOOL MatchPrefix;
    U8* Opcode;
    U32 OpcodeLength;
    INSTRUCTION_TYPE InstructionType;
    U32 Count;
} DISASM_ARG_INFO;

//////////////////////////////////////////////////////////////////////
// Function prototypes
//////////////////////////////////////////////////////////////////////

BOOL InitInstruction(INSTRUCTION* Instruction, DISASSEMBLER* Disassembler);
struct _ARCHITECTURE_FORMAT* GetArchitectureFormat(ARCHITECTURE_TYPE Type);

//////////////////////////////////////////////////////////////////////
// Disassembler setup
//////////////////////////////////////////////////////////////////////

/**
 * @brief Initializes a disassembler for the requested architecture.
 * @param[out] Disassembler Disassembler instance to reset and configure.
 * @param[in] Architecture Architecture to configure the disassembler for.
 * @return TRUE on success; FALSE when Architecture is not supported.
 */
BOOL InitDisassembler(DISASSEMBLER* Disassembler, ARCHITECTURE_TYPE Architecture)
{
    ARCHITECTURE_FORMAT* ArchFormat;

    memset(Disassembler, 0, sizeof(DISASSEMBLER));
    Disassembler->Initialized = DISASSEMBLER_INITIALIZED;

    ArchFormat = GetArchitectureFormat(Architecture);
    if (!ArchFormat)
    {
        assert(0);
        return FALSE;
    }
    Disassembler->ArchType = ArchFormat->Type;
    Disassembler->Functions = ArchFormat->Functions;
    return TRUE;
}

/**
 * @brief Clears a disassembler instance, releasing its configuration.
 * @param[out] Disassembler Disassembler instance to reset.
 */
void CloseDisassembler(DISASSEMBLER* Disassembler)
{
    memset(Disassembler, 0, sizeof(DISASSEMBLER));
}

//////////////////////////////////////////////////////////////////////
// Instruction setup
//////////////////////////////////////////////////////////////////////

/**
 * @brief Resets an instruction and binds it to the disassembler that will decode into it.
 * @param[out] Instruction Instruction structure to clear and initialize.
 * @param[in] Disassembler Disassembler that owns Instruction.
 * @return TRUE, unconditionally.
 */
BOOL InitInstruction(INSTRUCTION* Instruction, DISASSEMBLER* Disassembler)
{
    memset(Instruction, 0, sizeof(INSTRUCTION));
    Instruction->Initialized = INSTRUCTION_INITIALIZED;
    Instruction->Disassembler = Disassembler;
    memset(Instruction->String, ' ', MAX_OPCODE_DESCRIPTION - 1);
    Instruction->String[MAX_OPCODE_DESCRIPTION - 1] = '\0';
    return TRUE;
}

/**
 * @brief Decodes the instruction at Address into the disassembler's shared instruction buffer.
 * @param[in,out] Disassembler Initialized disassembler whose shared instruction buffer is decoded into.
 * @param[in] VirtualAddress Virtual address the instruction is mapped at, used to compute VirtualAddressDelta.
 * @param[in] Address Address of the instruction bytes to decode.
 * @param[in] Flags Combination of DISASM_* flags controlling decoding and disassembly.
 * @return The decoded instruction, or NULL on failure.
 * @remark When Flags does not include DISASM_DECODE, only Length, Address, Prefixes, PrefixCount, OpcodeBytes, OpcodeLength, Groups, Type, and OperandCount are valid on the returned instruction; String is only valid when Flags also includes DISASM_DISASSEMBLE.
 * @remark Overwrites the instruction previously obtained from this disassembler.
 */
INSTRUCTION* GetInstruction(DISASSEMBLER* Disassembler, U64 VirtualAddress, U8* Address, U32 Flags)
{
    if (Disassembler->Initialized != DISASSEMBLER_INITIALIZED)
    {
        assert(0);
        return NULL;
    }
    assert(Address);
    InitInstruction(&Disassembler->Instruction, Disassembler);
    Disassembler->Instruction.Address = Address;
    Disassembler->Instruction.VirtualAddressDelta = VirtualAddress - (U64)Address;
    if (!Disassembler->Functions->GetInstruction(&Disassembler->Instruction, Address, Flags))
    {
        assert(Disassembler->Instruction.Address == Address);
        assert(Disassembler->Instruction.Length < MAX_INSTRUCTION_LENGTH);

        // Save the address that failed, in case the lower-level disassembler didn't
        Disassembler->Instruction.Address = Address;
        Disassembler->Instruction.ErrorOccurred = TRUE;
        return NULL;
    }
    return &Disassembler->Instruction;
}

///////////////////////////////////////////////////////////////////////////
// Miscellaneous
///////////////////////////////////////////////////////////////////////////

/**
 * @brief Finds the architecture format entry matching the requested architecture type.
 * @param[in] Type Architecture type to look up.
 * @return The matching format entry, or NULL when Type is not supported.
 */
static ARCHITECTURE_FORMAT* GetArchitectureFormat(ARCHITECTURE_TYPE Type)
{
    ARCHITECTURE_FORMAT* Format;
    for (Format = SupportedArchitectures; Format->Type != ARCH_UNKNOWN; Format++)
    {
        if (Format->Type == Type)
            return Format;
    }

    assert(0);
    return NULL;
}
