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

// Do not change the OP_*, ITYPE_*, or *_MASK flags, aside from those marked
// UNUSED. Part of each flag is architecture independent while the rest is left
// for individual architectures to define, so changing them without
// understanding how they relate to each other will break decoding.

#ifndef DISASM_H
#define DISASM_H
#ifdef __cplusplus
extern "C"
{
#endif
#include <windows.h>
#include <stdio.h>
#include "misc.h"

/**
 * @name Fixed-width integer aliases used throughout the decoder tables.
 * @{
 */
typedef signed char S8;
typedef unsigned char U8;
typedef signed short S16;
typedef unsigned short U16;
typedef signed long S32;
typedef unsigned long U32;
typedef LONG64 S64;
typedef ULONG64 U64;
/** @} */

#ifdef SPEEDY
// On Visual Studio 6, making the internal functions inline makes compiling take forever
/** Storage class for internal-only functions; non-inline under SPEEDY. */
#define INTERNAL static _inline
/** Inline qualifier used on internal helpers; forced inline under SPEEDY. */
#define INLINE _inline
#else
/** Storage class for internal-only functions. */
#define INTERNAL static
/** Inline qualifier used on internal helpers. */
#define INLINE
#endif

/** True if @p i is non-NULL and its ErrorOccurred flag is not set. */
#define VALID_INSTRUCTION(i) ((i) && !((i)->ErrorOccurred))
/** Address immediately following instruction @p i. */
#define NEXT_INSTRUCTION(i) ((i)->Address + (i)->Length)
/** Architecture type of disassembler @p dis. */
#define DISASM_ARCH_TYPE(dis) ((dis)->ArchType)
/** Architecture type of the disassembler that produced instruction @p ins. */
#define INS_ARCH_TYPE(ins) DISASM_ARCH_TYPE((ins)->Disassembler)

/**
 * @name Decoder capacity limits
 * These should each be set as big as the maximum of the supported architectures.
 * @{
 */
/** Maximum number of prefix bytes on one instruction. */
#define MAX_PREFIX_LENGTH 15
/** Maximum number of operands on one instruction. */
#define MAX_OPERAND_COUNT 3
/** Maximum length, in bytes, of one instruction. */
#define MAX_INSTRUCTION_LENGTH 25
/** Maximum length, in bytes, of one opcode. */
#define MAX_OPCODE_LENGTH 3
/** Size, in bytes, of the buffer holding an instruction's disassembled text. */
#define MAX_OPCODE_DESCRIPTION 256
/** @} */

/////////////////////////////////////////////////////////////////////
// Code branch
/////////////////////////////////////////////////////////////////////

/** Maximum number of target addresses recorded on one CODE_BRANCH. */
#define MAX_CODE_REFERENCE_COUNT 3

/** @brief Describes a code-transferring instruction (branch, call, or loop). */
typedef struct _CODE_BRANCH
{
    /** Target address(es); left NULL/unset if there are multiple possible targets. */
    U64 Addresses[MAX_CODE_REFERENCE_COUNT];
    /** Number of valid entries in Addresses. */
    U32 Count;
    /** Set for a looping branch (e.g. LOOP/LOOPcc). */
    U8 IsLoop : 1;
    /** Set for a call; clear for a (non-call) branch. */
    U8 IsCall : 1;
    /** Set for an indirect call/jump (e.g. call/jmp [Address]). */
    U8 IsIndirect : 1;
    /** Stride, in bytes, between successive candidate addresses in Addresses[] when the exact
     *  indirect target could not be resolved (e.g. a scaled jump-table access). */
    U8 AddressOffset : 5;
    /** The operand containing the address. */
    struct _INSTRUCTION_OPERAND* Operand;
} CODE_BRANCH;

/////////////////////////////////////////////////////////////////////
// Data references
/////////////////////////////////////////////////////////////////////

/** Maximum number of target addresses recorded on one DATA_REFERENCE. */
#define MAX_DATA_REFERENCE_COUNT 3

/** @brief Describes a data address read or written by an instruction's operand. */
typedef struct _DATA_REFERENCE
{
    /** Target address(es); left NULL/unset if there are multiple possible targets. */
    U64 Addresses[MAX_DATA_REFERENCE_COUNT];
    /** Number of valid entries in Addresses. */
    U32 Count;
    /** Size, in bytes, of the referenced data. */
    ULONG_PTR DataSize;
    /** The operand containing the address. */
    struct _INSTRUCTION_OPERAND* Operand;
} DATA_REFERENCE;

////////////////////////////////////////////////////////////////////
// Instruction
/////////////////////////////////////////////////////////////////////

//
// Instruction types (bits 0-7)
// Instruction groups (bits 8-26)
//

/**
 * @name Instruction group bits (bits 8-26)
 * Each ORs the INSTRUCTION::Groups field; the first enumerator of each group
 * in INSTRUCTION_TYPE is set to its offset.
 * @{
 */
/** Execution-transfer instructions (branch/call/ret/loop). */
#define ITYPE_EXEC_OFFSET (1 << 8)
/** Arithmetic instructions. */
#define ITYPE_ARITH_OFFSET (1 << 9)
/** Logical instructions. */
#define ITYPE_LOGIC_OFFSET (1 << 10)
/** Stack instructions. */
#define ITYPE_STACK_OFFSET (1 << 11)
/** Test/compare instructions. */
#define ITYPE_TESTCOND_OFFSET (1 << 12)
/** Load/move instructions. */
#define ITYPE_LOAD_OFFSET (1 << 13)
/** Array/string instructions. */
#define ITYPE_ARRAY_OFFSET (1 << 14)
/** Bit-test/set/clear instructions. */
#define ITYPE_BIT_OFFSET (1 << 15)
/** Flag clear/set/toggle instructions. */
#define ITYPE_FLAG_OFFSET (1 << 16)
/** FPU instructions. */
#define ITYPE_FPU_OFFSET (1 << 17)
/** Trap-generating instructions. */
#define ITYPE_TRAPS_OFFSET (1 << 18)
/** System instructions. */
#define ITYPE_SYSTEM_OFFSET (1 << 19)
/** Instructions not covered by another group. */
#define ITYPE_OTHER_OFFSET (1 << 20)
/** Reused below as ITYPE_3DNOW_OFFSET. */
#define ITYPE_UNUSED1_OFFSET (1 << 21)
/** Reused below as ITYPE_MMX_OFFSET. */
#define ITYPE_UNUSED2_OFFSET (1 << 22)
/** Reused below as ITYPE_SSE_OFFSET. */
#define ITYPE_UNUSED3_OFFSET (1 << 23)
/** Reused below as ITYPE_SSE2_OFFSET. */
#define ITYPE_UNUSED4_OFFSET (1 << 24)
/** Reused below as ITYPE_SSE3_OFFSET. */
#define ITYPE_UNUSED5_OFFSET (1 << 25)
/** Free for use by a new architecture or instruction group. */
#define ITYPE_UNUSED6_OFFSET (1 << 26)
/** Free for use by a new architecture; reused below as the ITYPE_EXT_* flags. */
#define ITYPE_EXT_UNUSED1 (1 << 27)
/** Free for use by a new architecture; reused below as the ITYPE_EXT_* flags. */
#define ITYPE_EXT_UNUSED2 (1 << 28)
/** Free for use by a new architecture; reused below as the ITYPE_EXT_* flags. */
#define ITYPE_EXT_UNUSED3 (1 << 29)
/** Free for use by a new architecture; reused below as the ITYPE_EXT_* flags. */
#define ITYPE_EXT_UNUSED4 (1 << 30)
/** Free for use by a new architecture; reused below as the ITYPE_EXT_* flags. */
#define ITYPE_EXT_UNUSED5 (1 << 31)
/** @} */

//
// X86-specific flags (bits 27-31)
//

/**
 * @name X86-specific flags (bits 27-31)
 * @{
 */
/** Use index 1 if in 64-bit mode and 0 otherwise. */
#define ITYPE_EXT_64 ITYPE_EXT_UNUSED1 // Use index 1 if in 64-bit mode and 0 otherwise
/** ModRM byte may extend the opcode. */
#define ITYPE_EXT_MODRM ITYPE_EXT_UNUSED2 // ModRM byte may extend the opcode
/** Byte after ModRM/SIB/displacement is the third opcode byte. */
#define ITYPE_EXT_SUFFIX ITYPE_EXT_UNUSED3 // byte after ModRM/SIB/displacement is the third opcode
/** Prefix byte. */
#define ITYPE_EXT_PREFIX ITYPE_EXT_UNUSED4 // prefix
/** FPU instructions require special handling. */
#define ITYPE_EXT_FPU ITYPE_EXT_UNUSED5 // FPU instructions require special handling
/** @} */

/**
 * @name Instruction-set extension groups, aliased onto the unused group bits
 * @{
 */
#define ITYPE_3DNOW_OFFSET ITYPE_UNUSED1_OFFSET
#define ITYPE_MMX_OFFSET ITYPE_UNUSED2_OFFSET
#define ITYPE_SSE_OFFSET ITYPE_UNUSED3_OFFSET
#define ITYPE_SSE2_OFFSET ITYPE_UNUSED4_OFFSET
#define ITYPE_SSE3_OFFSET ITYPE_UNUSED5_OFFSET
/** @} */

//
// Instruction types
//

/** Bits of INSTRUCTION::Type that identify the specific instruction type. */
#define ITYPE_TYPE_MASK 0x7FFFFFFF
/** Bits of INSTRUCTION::Type that identify the instruction's group (one of the ITYPE_*_OFFSET values). */
#define ITYPE_GROUP_MASK 0x7FFFFF00

/** @brief Specific instruction type, e.g. ITYPE_ADD or ITYPE_RET; INSTRUCTION::Type holds exactly one. */
typedef enum _INSTRUCTION_TYPE
{
    // ITYPE_EXEC group
    /** Execution-transfer group tag (see ITYPE_EXEC_OFFSET). */
    ITYPE_EXEC = ITYPE_EXEC_OFFSET,
    /** Unconditional branch/jump. */
    ITYPE_BRANCH,
    /** Conditional branch (not necessarily just flags). */
    ITYPE_BRANCHCC, // conditional (not necessarily just flags)
    /** Unconditional call. */
    ITYPE_CALL,
    /** Conditional call (not necessarily just flags). */
    ITYPE_CALLCC, // conditional (not necessarily just flags)
    /** Return from call. */
    ITYPE_RET,
    /** Conditional loop (e.g. LOOP/LOOPcc). */
    ITYPE_LOOPCC,

    // ITYPE_ARITH group
    /** Arithmetic group tag (see ITYPE_ARITH_OFFSET). */
    ITYPE_ARITH = ITYPE_ARITH_OFFSET,
    /** Combined exchange-and-add. */
    ITYPE_XCHGADD,
    /** Addition. */
    ITYPE_ADD,
    /** Subtraction. */
    ITYPE_SUB,
    /** Multiplication. */
    ITYPE_MUL,
    /** Division. */
    ITYPE_DIV,
    /** Increment. */
    ITYPE_INC,
    /** Decrement. */
    ITYPE_DEC,
    /** Shift left. */
    ITYPE_SHL,
    /** Shift right. */
    ITYPE_SHR,
    /** Rotate left. */
    ITYPE_ROL,
    /** Rotate right. */
    ITYPE_ROR,

    // ITYPE_LOGIC group
    /** Logic group tag (see ITYPE_LOGIC_OFFSET). */
    ITYPE_LOGIC = ITYPE_LOGIC_OFFSET,
    /** Bitwise AND. */
    ITYPE_AND,
    /** Bitwise OR. */
    ITYPE_OR,
    /** Bitwise XOR. */
    ITYPE_XOR,
    /** Bitwise NOT. */
    ITYPE_NOT,
    /** Arithmetic negation. */
    ITYPE_NEG,

    // ITYPE_STACK group
    /** Stack group tag (see ITYPE_STACK_OFFSET). */
    ITYPE_STACK = ITYPE_STACK_OFFSET,
    /** Push onto the stack. */
    ITYPE_PUSH,
    /** Pop off the stack. */
    ITYPE_POP,
    /** Push all general registers. */
    ITYPE_PUSHA,
    /** Pop all general registers. */
    ITYPE_POPA,
    /** Push the flags register. */
    ITYPE_PUSHF,
    /** Pop the flags register. */
    ITYPE_POPF,
    /** Create a stack frame. */
    ITYPE_ENTER,
    /** Release a stack frame. */
    ITYPE_LEAVE,

    // ITYPE_TESTCOND group
    /** Test/compare group tag (see ITYPE_TESTCOND_OFFSET). */
    ITYPE_TESTCOND = ITYPE_TESTCOND_OFFSET,
    /** Bitwise test (sets flags without storing a result). */
    ITYPE_TEST,
    /** Compare (subtracts without storing a result). */
    ITYPE_CMP,

    // ITYPE_LOAD group
    /** Load/move group tag (see ITYPE_LOAD_OFFSET). */
    ITYPE_LOAD = ITYPE_LOAD_OFFSET,
    /** Move. */
    ITYPE_MOV,
    /** Conditional move. */
    ITYPE_MOVCC, // conditional
    /** Load effective address. */
    ITYPE_LEA,
    /** Exchange two operands. */
    ITYPE_XCHG,
    /** Conditional exchange. */
    ITYPE_XCHGCC, // conditional

    // ITYPE_ARRAY group
    /** Array/string group tag (see ITYPE_ARRAY_OFFSET). */
    ITYPE_ARRAY = ITYPE_ARRAY_OFFSET,
    /** String compare. */
    ITYPE_STRCMP,
    /** String load. */
    ITYPE_STRLOAD,
    /** String move. */
    ITYPE_STRMOV,
    /** String store. */
    ITYPE_STRSTOR,
    /** Table lookup/translate. */
    ITYPE_XLAT,

    // ITYPE_BIT group
    /** Bit group tag (see ITYPE_BIT_OFFSET). */
    ITYPE_BIT = ITYPE_BIT_OFFSET,
    /** Test a single bit. */
    ITYPE_BITTEST,
    /** Set a single bit. */
    ITYPE_BITSET,
    /** Clear a single bit. */
    ITYPE_BITCLR,

    // ITYPE_FLAG group
    // PF = parify flag
    // ZF = zero flag
    // OF = overflow flag
    // DF = direction flag
    // SF = sign flag
    /**
     * @brief Flag group tag (see ITYPE_FLAG_OFFSET).
     *
     * The CLEAR/SET/TOG members below name the flag they act on: CF = carry
     * flag, PF = parity flag, ZF = zero flag, OF = overflow flag,
     * DF = direction flag, SF = sign flag.
     */
    ITYPE_FLAG = ITYPE_FLAG_OFFSET,
    // clear
    /** Clears the carry flag. */
    ITYPE_CLEARCF,
    /** Clears the zero flag. */
    ITYPE_CLEARZF,
    /** Clears the overflow flag. */
    ITYPE_CLEAROF,
    /** Clears the direction flag. */
    ITYPE_CLEARDF,
    /** Clears the sign flag. */
    ITYPE_CLEARSF,
    /** Clears the parity flag. */
    ITYPE_CLEARPF,
    // set
    /** Sets the carry flag. */
    ITYPE_SETCF,
    /** Sets the zero flag. */
    ITYPE_SETZF,
    /** Sets the overflow flag. */
    ITYPE_SETOF,
    /** Sets the direction flag. */
    ITYPE_SETDF,
    /** Sets the sign flag. */
    ITYPE_SETSF,
    /** Sets the parity flag. */
    ITYPE_SETPF,
    // toggle
    /** Toggles the carry flag. */
    ITYPE_TOGCF,
    /** Toggles the zero flag. */
    ITYPE_TOGZF,
    /** Toggles the overflow flag. */
    ITYPE_TOGOF,
    /** Toggles the direction flag. */
    ITYPE_TOGDF,
    /** Toggles the sign flag. */
    ITYPE_TOGSF,
    /** Toggles the parity flag. */
    ITYPE_TOGPF,

    // ITYPE_FPU group
    /** FPU group tag (see ITYPE_FPU_OFFSET). */
    ITYPE_FPU = ITYPE_FPU_OFFSET,
    /** FPU addition. */
    ITYPE_FADD,
    /** FPU subtraction. */
    ITYPE_FSUB,
    /** FPU multiplication. */
    ITYPE_FMUL,
    /** FPU division. */
    ITYPE_FDIV,
    /** FPU compare. */
    ITYPE_FCOMP,
    /** FPU register exchange. */
    ITYPE_FEXCH,
    /** FPU load (onto the register stack). */
    ITYPE_FLOAD,
    /** FPU load environment/control state. */
    ITYPE_FLOADENV,
    /** FPU store (from the register stack). */
    ITYPE_FSTORE,
    /** FPU store environment/control state. */
    ITYPE_FSTOREENV,
    /** FPU save full state. */
    ITYPE_FSAVE,
    /** FPU restore full state. */
    ITYPE_FRESTORE,
    /** FPU conditional move. */
    ITYPE_FMOVCC,

    /** Reserved group tag, currently unused. */
    ITYPE_UNUSED1 = ITYPE_UNUSED1_OFFSET,
    /** Reserved group tag, currently unused. */
    ITYPE_UNUSED2 = ITYPE_UNUSED2_OFFSET,
    /** Reserved group tag, currently unused. */
    ITYPE_UNUSED3 = ITYPE_UNUSED3_OFFSET,

    // ITYPE_MMX group
    /** MMX group tag (see ITYPE_MMX_OFFSET). */
    ITYPE_MMX = ITYPE_MMX_OFFSET,
    /** MMX move. */
    ITYPE_MMX_MOV,
    /** MMX addition. */
    ITYPE_MMX_ADD,
    /** MMX subtraction. */
    ITYPE_MMX_SUB,
    /** MMX multiplication. */
    ITYPE_MMX_MUL,
    /** MMX division. */
    ITYPE_MMX_DIV,
    /** MMX bitwise AND. */
    ITYPE_MMX_AND,
    /** MMX bitwise OR. */
    ITYPE_MMX_OR,
    /** MMX bitwise XOR. */
    ITYPE_MMX_XOR,
    /** MMX compare. */
    ITYPE_MMX_CMP,

    // ITYPE_SSE group
    /** SSE group tag (see ITYPE_SSE_OFFSET). */
    ITYPE_SSE = ITYPE_SSE_OFFSET,
    /** SSE move. */
    ITYPE_SSE_MOV,
    /** SSE addition. */
    ITYPE_SSE_ADD,
    /** SSE subtraction. */
    ITYPE_SSE_SUB,
    /** SSE multiplication. */
    ITYPE_SSE_MUL,
    /** SSE division. */
    ITYPE_SSE_DIV,
    /** SSE bitwise AND. */
    ITYPE_SSE_AND,
    /** SSE bitwise OR. */
    ITYPE_SSE_OR,
    /** SSE bitwise XOR. */
    ITYPE_SSE_XOR,
    /** SSE compare. */
    ITYPE_SSE_CMP,

    // ITYPE_SSE2 group
    /** SSE2 group tag (see ITYPE_SSE2_OFFSET). */
    ITYPE_SSE2 = ITYPE_SSE2_OFFSET,
    /** SSE2 move. */
    ITYPE_SSE2_MOV,
    /** SSE2 addition. */
    ITYPE_SSE2_ADD,
    /** SSE2 subtraction. */
    ITYPE_SSE2_SUB,
    /** SSE2 multiplication. */
    ITYPE_SSE2_MUL,
    /** SSE2 division. */
    ITYPE_SSE2_DIV,
    /** SSE2 bitwise AND. */
    ITYPE_SSE2_AND,
    /** SSE2 bitwise OR. */
    ITYPE_SSE2_OR,
    /** SSE2 bitwise XOR. */
    ITYPE_SSE2_XOR,
    /** SSE2 compare. */
    ITYPE_SSE2_CMP,

    // ITYPE_SSE3 group
    /** SSE3 group tag (see ITYPE_SSE3_OFFSET). */
    ITYPE_SSE3 = ITYPE_SSE3_OFFSET,
    /** SSE3 move. */
    ITYPE_SSE3_MOV,
    /** SSE3 addition. */
    ITYPE_SSE3_ADD,
    /** SSE3 subtraction. */
    ITYPE_SSE3_SUB,
    /** SSE3 multiplication. */
    ITYPE_SSE3_MUL,
    /** SSE3 division. */
    ITYPE_SSE3_DIV,
    /** SSE3 bitwise AND. */
    ITYPE_SSE3_AND,
    /** SSE3 bitwise OR. */
    ITYPE_SSE3_OR,
    /** SSE3 bitwise XOR. */
    ITYPE_SSE3_XOR,
    /** SSE3 compare. */
    ITYPE_SSE3_CMP,

    // ITYPE_3DNOW group
    /** 3DNow! group tag (see ITYPE_3DNOW_OFFSET). */
    ITYPE_3DNOW = ITYPE_3DNOW_OFFSET,
    /** 3DNow! addition. */
    ITYPE_3DNOW_ADD,
    /** 3DNow! subtraction. */
    ITYPE_3DNOW_SUB,
    /** 3DNow! multiplication. */
    ITYPE_3DNOW_MUL,
    /** 3DNow! division. */
    ITYPE_3DNOW_DIV,
    /** 3DNow! compare. */
    ITYPE_3DNOW_CMP,
    /** 3DNow! exchange. */
    ITYPE_3DNOW_XCHG,

    // ITYPE_TRAP
    /** Trap group tag (see ITYPE_TRAPS_OFFSET). */
    ITYPE_TRAPS = ITYPE_TRAPS_OFFSET,
    /** Generates a trap. */
    ITYPE_TRAP, // generate trap
    /** Conditionally generates a trap. */
    ITYPE_TRAPCC, // conditional trap gen
    /** Returns from a trap. */
    ITYPE_TRAPRET, // return from trap
    /** Generates a bounds-check trap. */
    ITYPE_BOUNDS, // gen bounds trap
    /** Generates a breakpoint trap. */
    ITYPE_DEBUG, // gen breakpoint trap
    /** Generates a single-step trap. */
    ITYPE_TRACE, // gen single step trap
    /** Generates an invalid-instruction trap. */
    ITYPE_INVALID, // gen invalid instruction
    /** Generates an overflow trap. */
    ITYPE_OFLOW, // gen overflow trap

    // ITYPE_SYSTEM group
    /** System group tag (see ITYPE_SYSTEM_OFFSET). */
    ITYPE_SYSTEM = ITYPE_SYSTEM_OFFSET,
    /** Halts the machine. */
    ITYPE_HALT, // halt machine
    /** Reads input from a port. */
    ITYPE_IN, // input form port
    /** Writes output to a port. */
    ITYPE_OUT, // output to port
    /** Identifies the CPU. */
    ITYPE_CPUID, // identify cpu
    /** Allows interrupts. */
    ITYPE_SETIF, // allow interrupts
    /** Blocks interrupts. */
    ITYPE_CLEARIF, // block interrupts
    /** Enters system-call mode. */
    ITYPE_SYSCALL,
    /** Returns from system-call mode. */
    ITYPE_SYSCALLRET,

    // ITYPE_OTHER group
    /** Group tag for instructions not covered elsewhere (see ITYPE_OTHER_OFFSET). */
    ITYPE_OTHER = ITYPE_OTHER_OFFSET,
    /** No-op. */
    ITYPE_NOP,
    /** Converts to/from BCD. */
    ITYPE_BCDCONV, // convert to/from BCD
    /** Converts the size of an operand. */
    ITYPE_SZCONV // convert size of operand
} INSTRUCTION_TYPE;

//
// Operand flags
//

/**
 * @name Operand type (INSTRUCTION_OPERAND::Flags bits 0-6)
 * Mutually exclusive: bits 0-6 are always a power of 2.
 * @{
 */
/** No operand type set. */
#define OPTYPE_NONE 0x00
/** Immediate value. */
#define OPTYPE_IMM 0x01 // immediate value
/** Relative offset. */
#define OPTYPE_OFFSET 0x02 // relative offset
/** Floating point. */
#define OPTYPE_FLOAT 0x03 // floating point
/** Binary-coded decimal. */
#define OPTYPE_BCD 0x04
/** String. */
#define OPTYPE_STRING 0x05
/** Architecture-specific special operand; see the OPTYPE_* values in disasm_x86.h. */
#define OPTYPE_SPECIAL 0x06
/** Isolates the operand-type bits from INSTRUCTION_OPERAND::Flags. */
#define OPTYPE_MASK 0x7F
/** @} */

/**
 * @name Operand flags (INSTRUCTION_OPERAND::Flags bits 7-23)
 * These can be combined, and are used in the X86 opcode table.
 * @{
 */
/** Operand is a register; 0x80. */
#define OP_REG (1 << 7) // 0x80
/** Operand is signed. */
#define OP_SIGNED (1 << 8)
/** Operand is an index into some system structure. */
#define OP_SYS (1 << 9) // parameter is an index into some system structure
/** Operand is read only if a precondition holds. */
#define OP_CONDR (1 << 10)
/** Operand is written only if a precondition holds. */
#define OP_CONDW (1 << 11)
/** Reserved, currently unused. */
#define OP_UNUSED (1 << 12)
/** Operand is a source operand. */
#define OP_SRC (1 << 13) // operand is source operand
/** Operand is a destination operand. */
#define OP_DST (1 << 14) // operand is destination operand
/** Operand is executed. */
#define OP_EXEC (1 << 15) // operand is executed
/** @} */

/** Alias for OP_CONDR, used when read access is what a precondition gates. */
#define OP_CONDE OP_CONDR
/** Executed only if the preconditions are met. */
#define OP_COND_EXEC (OP_CONDE | OP_EXEC) // executed only if the pre-conditions are met
/** Set (as a source) only if the preconditions are met. */
#define OP_COND_SRC (OP_CONDR | OP_SRC) // set only if pre-conditions are met
/** Set (as a destination) only if the preconditions are met. */
#define OP_COND_DST (OP_CONDW | OP_DST) // set only if pre-conditions are met
/** Either conditional-read or conditional-write. */
#define OP_COND (OP_CONDR | OP_CONDW)

// Bits 16-31 are available for use outside of the opcode table, but they can only
// be used in INSTRUCTION_OPERAND.Flags, they may conflit with the architecture specific
// operands. For example, bits 16-31 are used in X86 for AMODE_* and OPTYPE_*
/**
 * @name Operand flags outside the opcode table (INSTRUCTION_OPERAND::Flags bits 16-21)
 * Available for use outside the opcode table; only valid in
 * INSTRUCTION_OPERAND::Flags, since bits 16-31 may otherwise be reused by an
 * architecture (e.g. X86's AMODE_* and OPTYPE_* values).
 * @{
 */
/** Operand is an address. */
#define OP_ADDRESS (1 << 16)
/** Operand refers to a local variable. */
#define OP_LOCAL (1 << 17)
/** Operand refers to a parameter. */
#define OP_PARAM (1 << 18)
/** Operand refers to a global. */
#define OP_GLOBAL (1 << 19)
/** Operand is a far reference. */
#define OP_FAR (1 << 20)
/** Operand is instruction-pointer relative. */
#define OP_IPREL (1 << 21)
/** @} */

//
// X86-specific flags (bits 27-31)
//
/** Operand names a model-specific register. */
#define OP_MSR (OP_SYS | OP_UNUSED)

//
// Other architecture flags
//
/** Delayed instruction (e.g. a delayed branch that executes after the next instruction). */
#define OP_DELAY OP_UNUSED // delayed instruction (e.g., delayed branch that executes after the next instruction)

/////////////////////////////////////////////////////////////////////
// Architectures
/////////////////////////////////////////////////////////////////////

/**
 * @brief Identifies the instruction set a DISASSEMBLER decodes.
 *
 * Only the x86-based entries (ARCH_X86, ARCH_X86_16, ARCH_X64) are wired up
 * to a function table in this build; the rest are placeholders for
 * architectures this decoder does not implement.
 */
typedef enum _ARCHITECTURE_TYPE
{
    /** No/invalid architecture. */
    ARCH_UNKNOWN = 0,

    // x86-based
    /** 32-bit x86. */
    ARCH_X86, // 32-bit x86
    /** 16-bit x86. */
    ARCH_X86_16, // 16-bit x86
    /** AMD64 and Intel EM64T. */
    ARCH_X64, // AMD64 and Intel EMD64

    // everything else
    /** DEC Alpha; not implemented by this decoder. */
    ARCH_ALPHA,
    /** ARM; not implemented by this decoder. */
    ARCH_ARM,
    /** .NET (CIL/MSIL); not implemented by this decoder. */
    ARCH_DOTNET,
    /** EFI byte code; not implemented by this decoder. */
    ARCH_EFI,
    /** Itanium (IA-64); not implemented by this decoder. */
    ARCH_IA64,
    /** Motorola 68000 family; not implemented by this decoder. */
    ARCH_M68K,
    /** MIPS; not implemented by this decoder. */
    ARCH_MIPS,
    /** PowerPC; not implemented by this decoder. */
    ARCH_PPC,
    /** Hitachi/Renesas SH-3; not implemented by this decoder. */
    ARCH_SH3,
    /** Hitachi/Renesas SH-4; not implemented by this decoder. */
    ARCH_SH4,
    /** SPARC; not implemented by this decoder. */
    ARCH_SPARC,
    /** ARM Thumb; not implemented by this decoder. */
    ARCH_THUMB

} ARCHITECTURE_TYPE;

// Both structures are defined further down, but the function-pointer types
// below mention them first. Without these declarations at file scope, C treats
// a tag first seen inside a parameter list as a new type local to that
// prototype, and the resulting pointers are then incompatible with the real
// ones. MSVC lets it pass; GCC does not.
struct _INSTRUCTION;
struct _ARCHITECTURE_FORMAT;

/** Architecture-specific one-time setup for an INSTRUCTION before it is decoded. */
typedef BOOL (*INIT_INSTRUCTION)(struct _INSTRUCTION* Instruction);
/** Architecture-specific textual dump of a decoded INSTRUCTION. */
typedef void (*DUMP_INSTRUCTION)(struct _INSTRUCTION* Instruction, BOOL ShowBytes, BOOL Verbose);
/** Architecture-specific decode of the instruction at Address into Instruction. */
typedef BOOL (*GET_INSTRUCTION)(struct _INSTRUCTION* Instruction, U8* Address, U32 Flags);
/** Architecture-specific search for a function prologue within [StartAddress, EndAddress). */
typedef U8* (*FIND_FUNCTION_BY_PROLOGUE)(struct _INSTRUCTION* Instruction, U8* StartAddress, U8* EndAddress, U32 Flags);

/** @brief Dispatch table of the decoding entry points one architecture implements. */
typedef struct _ARCHITECTURE_FORMAT_FUNCTIONS
{
    /** Per-instruction setup hook. */
    INIT_INSTRUCTION InitInstruction;
    /** Debug/disassembly dump hook. */
    DUMP_INSTRUCTION DumpInstruction;
    /** Main decode entry point. */
    GET_INSTRUCTION GetInstruction;
    /** Prologue-search entry point. */
    FIND_FUNCTION_BY_PROLOGUE FindFunctionByPrologue;
} ARCHITECTURE_FORMAT_FUNCTIONS;

/** @brief Pairs an ARCHITECTURE_TYPE with the functions that implement it. */
typedef struct _ARCHITECTURE_FORMAT
{
    /** Architecture this entry implements. */
    ARCHITECTURE_TYPE Type;
    /** Decoding entry points for Type. */
    ARCHITECTURE_FORMAT_FUNCTIONS* Functions;
} ARCHITECTURE_FORMAT;

/** Sentinel stored in DISASSEMBLER::Initialized once InitDisassembler() has run. */
#define DISASSEMBLER_INITIALIZED 0x1234566F
/** Sentinel stored in INSTRUCTION::Initialized once the instruction has been reset for decoding. */
#define INSTRUCTION_INITIALIZED 0x1234567F

#include "disasm_x86.h"

/** @brief 128-bit signed integer, split into 64-bit halves. */
typedef struct DECLSPEC_ALIGN(16) _S128
{
    /** Low 64 bits. */
    U64 Low;
    /** High 64 bits (sign-extended). */
    S64 High;
} S128;

/** @brief 128-bit unsigned integer, split into 64-bit halves. */
typedef struct DECLSPEC_ALIGN(16) _U128
{
    /** Low 64 bits. */
    U64 Low;
    /** High 64 bits. */
    U64 High;
} U128;

/** @brief One decoded operand of an INSTRUCTION. */
typedef struct _INSTRUCTION_OPERAND
{
    /** OPTYPE_ and OP_ flags describing this operand; see OPTYPE_MASK and the OP_* bit groups above. */
    U32 Flags;
    /** Operand type; the same value as (Flags & OPTYPE_MASK). */
    U8 Type : 6;
    /** Reserved, currently unused. */
    U8 Unused : 2;
    /** Length, in bytes, of this operand as encoded in the instruction. */
    U16 Length;


    /**
     * If non-NULL, the target address of the instruction (e.g., a branch or
     * a displacement with no base register). However, this address is only
     * reliable if the image is mapped correctly (e.g., the executable is
     * mapped as an image and fixups have been applied if it is not at its
     * preferred image base).
     *
     * If disassembling a 16-bit DOS application, TargetAddress is in the
     * context of X86Instruction->Segment. For example, if TargetAddress is
     * the address of a code branch, it is in the CS segment (unless
     * X86Instruction->HasSegmentOverridePrefix is set). If TargetAddress is
     * a data pointer, it is in the DS segment (unless
     * X86Instruction->HasSegmentOverridePrefix is set).
     */
    U64 TargetAddress;
    /** Register this operand names, when Flags & OP_REG is set; architecture-specific encoding. */
    U32 Register;

    /**
     * @brief The operand's value, in the representation matching its Type.
     *
     * All 8/16/32-bit operands are extended to 64 bits automatically. To
     * downcast, check whether Flags & OP_SIGNED is set, e.g.:
     * @code
     * U32 GetOperand32(OPERAND *Operand)
     * {
     *     if (Operand->Flags & OP_SIGNED) return (S32)Operand->Value_S64;
     *     else return (U32)Operand->Value_U64;
     * }
     * @endcode
     */
    union
    {
        /** Value, unsigned. */
        U64 Value_U64;
        /** Value, signed. */
        S64 Value_S64;
        /** Value, 128-bit unsigned integer. */
        U128 Value_U128;
        /** Value, 128-bit floating point. */
        U128 Float128;
        /** Value, 80-bit floating point. */
        U8 Float80[80];
        /** Value, binary-coded decimal. */
        U8 BCD[10];
    };
} INSTRUCTION_OPERAND;

/** @brief One decoded instruction, filled in by GetInstruction(). */
typedef struct _INSTRUCTION
{
    /** INSTRUCTION_INITIALIZED once InitInstruction() has reset this record. */
    U32 Initialized;
    /** Disassembler that decoded (or will decode) this instruction. */
    struct _DISASSEMBLER* Disassembler;

    /** Disassembled text, valid when GetInstruction() was called with DISASM_DISASSEMBLE. */
    char String[MAX_OPCODE_DESCRIPTION];
    /** Current write offset into String while it is being built. */
    U8 StringIndex;
    /** VirtualAddress - Address, as passed to GetInstruction(); relates decoded pointers back to a mapped image. */
    U64 VirtualAddressDelta;

    /** ITYPE_EXEC, ITYPE_ARITH, etc.; groups can be OR'd together. */
    U32 Groups; // ITYPE_EXEC, ITYPE_ARITH, etc. -- NOTE groups can be OR'd together
    /** ITYPE_ADD, ITYPE_RET, etc.; exactly one type applies. */
    INSTRUCTION_TYPE Type; // ITYPE_ADD, ITYPE_RET, etc. -- NOTE there is only one possible type

    /** Address the instruction was decoded from. */
    U8* Address;
    /** Address of the opcode byte(s), i.e. Address plus any prefixes. */
    U8* OpcodeAddress;
    /** Total length, in bytes, of the instruction (prefixes, opcode, and operands). */
    U32 Length;

    /** Prefix bytes preceding the opcode. */
    U8 Prefixes[MAX_PREFIX_LENGTH];
    /** Number of valid entries in Prefixes. */
    U32 PrefixCount;

    /** Last byte of the opcode. */
    U8 LastOpcode; // last byte of opcode
    /** Opcode bytes. */
    U8 OpcodeBytes[MAX_OPCODE_LENGTH];
    /** Length, in bytes, of the opcode; excludes any operands and prefixes. */
    U32 OpcodeLength; // excludes any operands and prefixes

    /** Decoded operands. */
    INSTRUCTION_OPERAND Operands[MAX_OPERAND_COUNT];
    /** Number of valid entries in Operands. */
    U32 OperandCount;

    /** x86/x64-specific decode state; see disasm_x86.h. */
    X86_INSTRUCTION X86;

    /** Data address(es) this instruction reads from, if any. */
    DATA_REFERENCE DataSrc;
    /** Data address(es) this instruction writes to, if any. */
    DATA_REFERENCE DataDst;
    /** Code-transfer details, if this instruction is a branch/call/loop. */
    CODE_BRANCH CodeBranch;

    /**
     * Direction depends on which direction the stack grows. For example, on
     * x86 a push results in StackChange < 0 since the stack grows down.
     * This is only relevant if (Groups & ITYPE_STACK) is true.
     *
     * If Groups & ITYPE_STACK is set but StackChange is 0, it means the
     * change couldn't be determined (non-constant).
     */
    LONG StackChange;

    // Used to assist in debugging
    // If set, the current instruction is doing something that requires special handling
    // For example, popf can cause tracing to be disabled

    /** Internal only: set once String has been padded/aligned. */
    U8 StringAligned : 1; // internal only
    /** Instruction does something that re[quires special handling]; comment is truncated in the original source and its exact intent could not be recovered. */
    U8 NeedsEmulation : 1; // instruction does something that re
    /** Instruction repeats until some condition is met (e.g., REP prefix on X86). */
    U8 Repeat : 1; // instruction repeats until some condition is met (e.g., REP prefix on X86)
    /** Set if the instruction is invalid. */
    U8 ErrorOccurred : 1; // set if instruction is invalid
    /** Set if the instruction is anomalous. */
    U8 AnomalyOccurred : 1; // set if instruction is anomalous
    /** Tells the iterator callback this is the last instruction. */
    U8 LastInstruction : 1; // tells the iterator callback it is the last instruction
    /** Intended to mark the first instruction of a code block; not set anywhere in this decoder's current implementation. */
    U8 CodeBlockFirst : 1;
    /** Intended to mark the last instruction of a code block; not set anywhere in this decoder's current implementation. */
    U8 CodeBlockLast : 1;
} INSTRUCTION;

/** @brief Decoder handle for one architecture, created by InitDisassembler(). */
typedef struct _DISASSEMBLER
{
    /** DISASSEMBLER_INITIALIZED once InitDisassembler() has configured this instance. */
    U32 Initialized;
    /** Architecture this instance decodes. */
    ARCHITECTURE_TYPE ArchType;
    /** Decoding entry points for ArchType. */
    ARCHITECTURE_FORMAT_FUNCTIONS* Functions;
    /** Shared buffer GetInstruction() decodes into; overwritten on each call. */
    INSTRUCTION Instruction;
    /** Number of times GetInstruction() was called. */
    U32 Stage1Count; // GetInstruction called
    /** Number of times the opcode was fully decoded. */
    U32 Stage2Count; // Opcode fully decoded
    /** Number of instructions that passed all checks when DISASM_DECODE was not set. */
    U32 Stage3CountNoDecode; // made it through all checks when DISASM_DECODE is not set
    /** Number of instructions that passed all checks when DISASM_DECODE was set. */
    U32 Stage3CountWithDecode; // made it through all checks when DISASM_DECODE is set
} DISASSEMBLER;

/**
 * @name Flags for GetInstruction()
 * @{
 */
/** Produce a disassembled text form in INSTRUCTION::String. */
#define DISASM_DISASSEMBLE (1 << 1)
/** Fully decode the instruction, including its operands. */
#define DISASM_DECODE (1 << 2)
/** Suppress diagnostic output for malformed instructions. */
#define DISASM_SUPPRESSERRORS (1 << 3)
/** Include condition-flag preconditions in the disassembled text. */
#define DISASM_SHOWFLAGS (1 << 4)
/** Align the disassembled output's columns. */
#define DISASM_ALIGNOUTPUT (1 << 5)
/** Combination of flags relevant to producing disassembled output. */
#define DISASM_DISASSEMBLE_MASK (DISASM_ALIGNOUTPUT | DISASM_SHOWBYTES | DISASM_DISASSEMBLE)
/** @} */

/**
 * @brief Initializes a disassembler for the requested architecture.
 * @param[out] Disassembler Disassembler instance to reset and configure.
 * @param[in]  Architecture Architecture to configure the disassembler for.
 * @return TRUE on success; FALSE when Architecture is not supported.
 */
BOOL InitDisassembler(DISASSEMBLER* Disassembler, ARCHITECTURE_TYPE Architecture);

/**
 * @brief Clears a disassembler instance, releasing its configuration.
 * @param[in,out] Disassembler Disassembler instance to reset.
 */
void CloseDisassembler(DISASSEMBLER* Disassembler);

/**
 * @brief Decodes the instruction at Address into the disassembler's shared instruction buffer.
 * @param[in,out] Disassembler Initialized disassembler whose shared instruction buffer is decoded into.
 * @param[in]     VirtualAddress Virtual address the instruction is mapped at, used to compute VirtualAddressDelta.
 * @param[in]     Address Address of the instruction bytes to decode.
 * @param[in]     Flags Combination of DISASM_* flags controlling decoding and disassembly.
 * @return The decoded instruction, or NULL on failure.
 * @note When Flags does not include DISASM_DECODE, only Length, Address, Prefixes, PrefixCount,
 *       OpcodeBytes, OpcodeLength, Groups, Type, and OperandCount are valid on the returned
 *       instruction; String is only valid when Flags also includes DISASM_DISASSEMBLE.
 * @warning Overwrites the instruction previously obtained from this disassembler.
 */
INSTRUCTION* GetInstruction(DISASSEMBLER* Disassembler, U64 VirtualAddress, U8* Address, U32 Flags);

#ifdef __cplusplus
}
#endif
#endif // DISASM_H
