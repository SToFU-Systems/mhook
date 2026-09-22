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

#ifndef X86_DISASM_H
#define X86_DISASM_H
#ifdef __cplusplus
extern "C"
{
#endif

/**
 * @name AMD64 instruction size limits
 * @{
 */

// NOTE: the processor may actually accept less than this amount (officially 15)
// #define AMD64_MAX_INSTRUCTION_LEN 15 // theoretical max 25=5+2+1+1+8+8

/** 4 legacy prefixes + 1 REX prefix. */
#define AMD64_MAX_PREFIX_LENGTH 5

/** ModRM + SIB + 8 byte displacement + 8 byte immediate value. */
#define AMD64_MAX_ADDRESS_LENGTH 18

/** @} */

/**
 * @name x86 instruction size limits
 * @{
 */

// NOTE: the processor may actually accept less than this amount (officially 15)

/** Theoretical max 16 = 4 (prefixes) + 2 (opcode) + 1 (ModRM) + 1 (SIB) + 4 (displacement) + 4 (immediate). */
#define X86_MAX_INSTRUCTION_LEN 15

/** Maximum number of legacy prefix bytes. */
#define X86_MAX_PREFIX_LENGTH 4

/** Third byte is either a suffix or prefix. */
#define X86_MAX_OPCODE_LENGTH 3

/** ModRM + SIB + 4 byte displacement + 4 byte immediate value. */
#define X86_MAX_ADDRESS_LENGTH 10

/** Maximum number of operands an instruction can have. */
#define X86_MAX_OPERANDS 3

/** @} */

/**
 * @name X86_OPCODE accessors
 * Convenience macros for reading fields packed into an X86_OPCODE entry.
 * @{
 */

/** True if this X86_OPCODE entry describes a legacy prefix byte rather than an instruction. */
#define X86_PREFIX(a) ((a)->MnemonicFlags == ITYPE_EXT_PREFIX)

/** True if decoding this opcode needs one of the special-case extension mechanisms. */
#define X86_SPECIAL_EXTENSION(a)                                                                                       \
    ((a)->MnemonicFlags & (ITYPE_EXT_MODRM | ITYPE_EXT_FPU | ITYPE_EXT_SUFFIX | ITYPE_EXT_64))

/** True if this entry points at a further sub-table (an opcode group) rather than terminating decoding. */
#define X86_EXTENDED_OPCODE(a) ((a)->Table)

/** True if this entry is neither a valid instruction nor a group/extension table. */
#define X86_INVALID(a) (!(a)->MnemonicFlags && !(a)->Table)

/** Number of non-zero entries in OperandFlags, i.e. the instruction's operand count. */
#define X86_OPERAND_COUNT(a) ((a)->OperandFlags[0] ? ((a)->OperandFlags[1] ? ((a)->OperandFlags[2] ? 3 : 2) : 1) : 0)

/** Extracts the ITYPE_*_OFFSET instruction group from MnemonicFlags. */
#define X86_GET_CATEGORY(p) ((p)->MnemonicFlags & ITYPE_GROUP_MASK)

/** Extracts the specific INSTRUCTION_TYPE from MnemonicFlags. */
#define X86_GET_TYPE(p) ((p)->MnemonicFlags & ITYPE_TYPE_MASK)

/** @} */

/**
 * @name Special opcode and prefix bytes
 * Various instructions being specially decoded.
 * @{
 */

/** Escape byte introducing the two-byte opcode map. */
#define X86_TWO_BYTE_OPCODE 0x0f

/** ES segment override prefix. */
#define PREFIX_SEGMENT_OVERRIDE_ES 0x26

/** CS segment override prefix. */
#define PREFIX_SEGMENT_OVERRIDE_CS 0x2e

/** Used only with conditional jumps. */
#define PREFIX_BRANCH_NOT_TAKEN 0x2e

/** SS segment override prefix. */
#define PREFIX_SEGMENT_OVERRIDE_SS 0x36

/** DS segment override prefix. */
#define PREFIX_SEGMENT_OVERRIDE_DS 0x3e

/** Used only with conditional jumps. */
#define PREFIX_BRANCH_TAKEN 0x3e

/** FS segment override prefix. */
#define PREFIX_SEGMENT_OVERRIDE_FS 0x64

/** GS segment override prefix. */
#define PREFIX_SEGMENT_OVERRIDE_GS 0x65

/** Operand-size override prefix. */
#define PREFIX_OPERAND_SIZE 0x66

/** Address-size override prefix. */
#define PREFIX_ADDRESS_SIZE 0x67

/** LOCK prefix. */
#define PREFIX_LOCK 0xf0

/** REPNE/REPNZ prefix. */
#define PREFIX_REPNE 0xf2

/** REP/REPE/REPZ prefix. */
#define PREFIX_REP 0xf3

/** @} */

//////////////////////////////////////////////////////////////////
// Implicit operand handling
//////////////////////////////////////////////////////////////////

/**
 * @name Operand-flags bit layout
 * How an X86_OPCODE.OperandFlags entry's 32 bits are divided between the
 * addressing mode, the generic operand flags and the operand type.
 * @{
 */

/** Bits 16-23: addressing mode (AMODE_* in disasm_x86_tables.h). */
#define X86_AMODE_MASK 0x00FF0000

/** Bits 7-15: generic operand flags (OPTYPE_* in disasm_x86_tables.h). */
#define X86_OPFLAGS_MASK 0x0000FF80

/** Bits 0-7 (OPTYPE_* below + OP_REG) and 24-31 (OPTYPE_* in disasm_x86_tables.h): operand type. */
#define X86_OPTYPE_MASK 0xFF0000FF

/** @} */

/**
 * @name Implicit immediate operands
 * A fixed immediate value used where the encoding does not carry one, e.g.
 * a shift-by-1 opcode.
 * @{
 */

/** Implicit immediate 0. */
#define OPTYPE_0 0x01

/** Implicit immediate 1. */
#define OPTYPE_1 0x02

/** Implicit immediate 0xFF. */
#define OPTYPE_FF 0x03

/** @} */

/**
 * @name Implicit segment and control-register operands
 * @{
 */

/** Implicit CS. */
#define OPTYPE_CS 0x10

/** Implicit DS. */
#define OPTYPE_DS 0x11

/** Implicit ES. */
#define OPTYPE_ES 0x12

/** Implicit FS. */
#define OPTYPE_FS 0x13

/** Implicit GS. */
#define OPTYPE_GS 0x14

/** Implicit SS. */
#define OPTYPE_SS 0x15

/** Implicit CR0. */
#define OPTYPE_CR0 0x16

/** Time stamp counter. */
#define OPTYPE_TSC 0x17

/** @} */

/**
 * @name Implicit flags and paired-register operands
 * @{
 */

/** Implicit FLAGS/EFLAGS/RFLAGS. */
#define OPTYPE_FLAGS 0x20

/** RFLAGS/EFLAGS (depending on operand size). */
#define OPTYPE_xFLAGS 0x21

/** Represented by 2 registers CX:BX or ECX:EBX (depending on operand size). */
#define OPTYPE_xCX_HI_xBX_LO 0x22

/** DX:AX or EDX:EAX (depending on operand size). */
#define OPTYPE_xDX_HI_xAX_LO 0x23

/** DX:AX or EDX:EAX (depending on operand size). */
#define OPTYPE_EDX_HI_EAX_LO 0x24

/** All registers are set: EDX, ECX, EBX and EAX (e.g. the CPUID result). */
#define OPTYPE_EDX_ECX_EBX_EAX 0x25

/** @} */

/**
 * @name Implicit FPU operands
 * @{
 */

/** The FPU stack register addressed by the ModRM reg/rm field. */
#define OPTYPE_STx 0x30

/** Implicit ST(0). */
#define OPTYPE_ST0 0x31

/** Implicit ST(1). */
#define OPTYPE_ST1 0x32

/** FPU status word. */
#define OPTYPE_FPU_STATUS 0x33

/** FPU control word. */
#define OPTYPE_FPU_CONTROL 0x34

/** FPU tag word. */
#define OPTYPE_FPU_TAG 0x35

/** 0 */
#define OPTYPE_FLDZ 0x36

/** 1 */
#define OPTYPE_FLD1 0x37

/** pi */
#define OPTYPE_FLDPI 0x38

/** lg 10 */
#define OPTYPE_FLDL2T 0x39

/** lg e */
#define OPTYPE_FLDL2E 0x3A

/** log_10 2 */
#define OPTYPE_FLDLG2 0x3B

/** log_e 2 */
#define OPTYPE_FLDLN2 0x3C

/** @} */

/**
 * @name Implicit MSR operands
 * MSRs consumed or produced by sysenter/sysexit (CS/EIP/ESP/KernelBase) and
 * syscall/sysret (STAR/CSTAR/LSTAR/FMASK).
 * @{
 */

/** sysenter/sysexit target CS MSR. */
#define OPTYPE_CS_MSR 0x40

/** sysenter/sysexit target EIP MSR. */
#define OPTYPE_EIP_MSR 0x41

/** sysenter/sysexit target ESP MSR. */
#define OPTYPE_ESP_MSR 0x42

/** sysenter kernel-base MSR. */
#define OPTYPE_KERNELBASE_MSR 0x43

/** syscall/sysret EFLAGS mask MSR. */
#define OPTYPE_FMASK_MSR 0x44

/** syscall/sysret CS/SS and sysenter CS/EIP/ESP base MSR. */
#define OPTYPE_STAR_MSR 0x45

/** 32-bit mode */
#define OPTYPE_CSTAR_MSR 0x46

/** 64-bit mode */
#define OPTYPE_LSTAR_MSR 0x47

/** @} */

/**
 * @name Implicit register operands
 * NOTE: OPTYPES >= 0x80 reserved for registers (OP_REG+XX)
 * @{
 */

/** Implicit AL. */
#define OPTYPE_REG_AL OP_REG + 0x01

/** Implicit CL. */
#define OPTYPE_REG_CL OP_REG + 0x02

/** Implicit AH. */
#define OPTYPE_REG_AH OP_REG + 0x03

/** Implicit AX. */
#define OPTYPE_REG_AX OP_REG + 0x04

/** Implicit DX. */
#define OPTYPE_REG_DX OP_REG + 0x05

/** Implicit ECX. */
#define OPTYPE_REG_ECX OP_REG + 0x06

/** An 8-bit register whose index is encoded in the low bits of the opcode byte itself. */
#define OPTYPE_REG8 OP_REG + 0x07

/**
 * The address-size-dependent base pointer register.
 * If address size is 2, use BP
 * If address size is 4, use EBP
 * If address size is 8, use RBP
 */
#define OPTYPE_REG_xBP OP_REG + 0x08

/**
 * The address-size-dependent stack pointer register.
 * If address size is 2, use BP
 * If address size is 4, use EBP
 * If address size is 8, use RBP
 */
#define OPTYPE_REG_xSP OP_REG + 0x09

/**
 * The operand-size-dependent accumulator register, one size class down.
 * If operand size is 2, take 8-bit register
 * If operand size is 4, take 16-bit register
 * If operand size is 8, take 32-bit register
 */
#define OPTYPE_REG_xAX_SMALL OP_REG + 0x0a

/**
 * The operand-size-dependent accumulator register.
 * If operand size is 2, take 16-bit register
 * If operand size is 4, take 32-bit register
 * If operand size is 8, take 64-bit register
 */
#define OPTYPE_REG_xAX_BIG OP_REG + 0x0b

/** @} */

/** @brief Minimum CPU generation an X86_OPCODE entry requires, used to gate CPU_TYPE-specific decoding. */
typedef enum _CPU_TYPE
{
    /** No minimum recorded. */
    CPU_UNKNOWN = 0,

    ///////////////////////////////////////
    // 1st generation
    ///////////////////////////////////////
    // 1978
    // CPU_8086 = 1MB address limit, 16-bit registers
    // 1982
    // CPU_i186

    ///////////////////////////////////////
    // 2nd generation
    ///////////////////////////////////////
    // 1982
    // CPU_I286 // 16MB limit, 16-bit registers, added protected mode

    /** CPU_I286 + math coprocessor */
    CPU_I287,

    ///////////////////////////////////////
    // 3rd generation
    ///////////////////////////////////////
    // 1985

    /** 32-bit registers, 4GB memory limit */
    CPU_I386,
    // 1988

    /** CPU_I386 + math coprocessor */
    CPU_I387,

    ///////////////////////////////////////
    // 4th generation (1989)
    ///////////////////////////////////////
    CPU_I486,

    ///////////////////////////////////////
    // 5th generation
    ///////////////////////////////////////
    // 1993

    /** superscalar architecture */
    CPU_PENTIUM,
    // 1997
    // CPU_PENTIUM_MMX

    ///////////////////////////////////////
    // 6th generation (1995)
    ///////////////////////////////////////

    /** P6 architecture, no MMX, out-of-order execution, speculative execution */
    CPU_PENTIUM_PRO,
    // CPU_CYRIX_6X86,
    // CPU_AMD_K5 // RISC processor
    // 1997

    /** Pentium Pro architecture + MMX */
    CPU_PENTIUM2,
    // CPU_AMD_K6,
    // CPU_CYRIX_6X86MX, // Cyrix 6x86 + MMX
    // 1998

    /** added 3DNow! (MMX) */
    CPU_AMD_K6_2,
    // 1999
    // CPU_AMD_K6_3 // added SSE

    ///////////////////////////////////////
    // 7th generation
    ///////////////////////////////////////
    // 1999

    /** introduced SSE */
    CPU_PENTIUM3,
    // CPU_AMD_K7 // aka Athlon
    // 2000

    /** introduced SSE2 and hyperthreading */
    CPU_PENTIUM4,

    // 2004? 2005?

    /** introduced SSE3 */
    CPU_PRESCOTT,

    ///////////////////////////////////////
    // 8th generation (X86-64)
    // IA32 instruction set with 64-bit extensions, >4GB RAM
    ///////////////////////////////////////

    // 2003

    /** includes Athlon 64 and Opteron aka X86-64 */
    CPU_AMD64,

    // 2004?
    // CPU_EMD64 // Intel's version of AMD64

    /** aka Itanium: new instruction set -- adds JMPE to IA32 mode to return to IA64 native code */
    CPU_IA64

} CPU_TYPE;

//////////////////////////////////////////////////////////////////
// Conditions (these can be OR'd)
//////////////////////////////////////////////////////////////////

/**
 * @name Condition codes
 * Used for Flags.Preconditions; these can be OR'd.
 * @{
 */

/** overflow (signed) */
#define COND_O (1 << 0)

/** below (unsigned) */
#define COND_C (1 << 1)

/** equal (unsigned) */
#define COND_Z (1 << 2)

/** sign set (signed) */
#define COND_S (1 << 3)

/** parity even */
#define COND_P (1 << 4)

/** CF or ZF is set (unsigned) */
#define COND_BE (1 << 5)

/** (SF && !OF) || (OF && !SF) */
#define COND_L (1 << 6)

/** ZF || (SF && !OF) || (OF && !SF) (signed) */
#define COND_LE (1 << 7)

/** !O */
#define COND_NO (1 << 8)

/** !C (not below, above or equal to) */
#define COND_NC (1 << 9)

/** !Z (not equal) */
#define COND_NZ (1 << 10)

/** !S */
#define COND_NS (1 << 11)

/** !P (parity odd) */
#define COND_NP (1 << 12)

/** (!SF && !OF) || (SF && OF) */
#define COND_NL (1 << 13)

/** !ZF && ((!SF && !OF) || (SF && OF)) */
#define COND_G (1 << 14)

/** DF */
#define COND_D (1 << 15)

/** CX/ECX/RCX (depending on address size) == 0 */
#define COND_REG_xCX_BIG_Z (1 << 16)

/** CX/ECX/RCX (depending on address size) != 0 */
#define COND_REG_xCX_BIG_NZ (1 << 17)

/** First and second operands are equal. */
#define COND_OP1_EQ_OP2 (1 << 18)

/** First and third operands are equal. */
#define COND_OP1_EQ_OP3 (1 << 19)

/** Alias for COND_C: below. */
#define COND_B COND_C

/** Alias for COND_C: not above or equal. */
#define COND_NAE COND_C

/** Alias for COND_Z: equal. */
#define COND_E COND_Z

/** Alias for COND_BE: not above. */
#define COND_NA COND_BE

/** Alias for COND_P: parity even. */
#define COND_PE COND_P

/** Alias for COND_P: unordered (FPU compares). */
#define COND_U COND_P

/** Alias for COND_L: not greater or equal. */
#define COND_NGE COND_L

/** Alias for COND_LE: not greater. */
#define COND_NG COND_LE

/** Alias for COND_NP: parity odd. */
#define COND_PO COND_NP

/** Alias for COND_NP: not unordered (FPU compares). */
#define COND_NU COND_NP

/** Alias for COND_NZ: not equal. */
#define COND_NE COND_NZ

/** Alias for COND_NC: not below. */
#define COND_NB COND_NC

/** Alias for COND_NC: above or equal. */
#define COND_AE COND_NC

/** Alias for COND_NZ: not equal. */
#define COND_NE COND_NZ

/** Above: not below and not equal (unsigned). */
#define COND_A (COND_NC | COND_NZ)

/** Alias for COND_A: not below or equal. */
#define COND_NBE COND_A

/** Alias for COND_NL: greater or equal. */
#define COND_GE COND_NL

/** Alias for COND_G: not less or equal. */
#define COND_NLE COND_G

/** @} */

/**
 * @name Flags unconditionally set
 * Used for Opcode.FlagsChanged.
 * @{
 */

/** CF is set. */
#define FLAG_CF_SET (1 << 0)

/** DF is set. */
#define FLAG_DF_SET (1 << 1)

/** IF is set. */
#define FLAG_IF_SET (1 << 2)

/** All of the FLAG_*_SET bits. */
#define FLAG_SET_MASK (FLAG_CF_SET | FLAG_DF_SET | FLAG_IF_SET)

/** @} */

/**
 * @name Flags unconditionally cleared
 * @{
 */

/** SF is cleared. */
#define FLAG_SF_CLR (1 << 3)

/** ZF is cleared. */
#define FLAG_ZF_CLR (1 << 4)

/** AF is cleared. */
#define FLAG_AF_CLR (1 << 5)

/** CF is cleared. */
#define FLAG_CF_CLR (1 << 6)

/** DF is cleared. */
#define FLAG_DF_CLR (1 << 7)

/** IF is cleared. */
#define FLAG_IF_CLR (1 << 8)

/** OF is cleared. */
#define FLAG_OF_CLR (1 << 9)

/** FPU condition code C0 is cleared. */
#define FPU_C0_CLR (1 << 19)

/** FPU condition code C1 is cleared. */
#define FPU_C1_CLR (1 << 20)

/** FPU condition code C2 is cleared. */
#define FPU_C2_CLR (1 << 21)

/** FPU condition code C3 is cleared. */
#define FPU_C3_CLR (1 << 22)

/** All of the FPU_C*_CLR bits. */
#define FPU_ALL_CLR (FPU_C0_CLR | FPU_C1_CLR | FPU_C2_CLR | FPU_C3_CLR)

/** All of the FLAG_*_CLR and FPU_*_CLR bits. */
#define FLAG_CLR_MASK                                                                                                  \
    (FLAG_SF_CLR | FLAG_ZF_CLR | FLAG_AF_CLR | FLAG_CF_CLR | FLAG_DF_CLR | FLAG_IF_CLR | FLAG_OF_CLR | FPU_ALL_CLR)

/** @} */

/**
 * @name Flags modified according to the result
 * @{
 */

/** OF is set according to the result. */
#define FLAG_OF_MOD (1 << 10)

/** SF is set according to the result. */
#define FLAG_SF_MOD (1 << 11)

/** ZF is set according to the result. */
#define FLAG_ZF_MOD (1 << 12)

/** AF is set according to the result. */
#define FLAG_AF_MOD (1 << 13)

/** PF is set according to the result. */
#define FLAG_PF_MOD (1 << 14)

/** CF is set according to the result. */
#define FLAG_CF_MOD (1 << 15)

/** DF is set according to the result. */
#define FLAG_DF_MOD (1 << 16)

/** IF is set according to the result. */
#define FLAG_IF_MOD (1 << 17)

/** All of the FLAG_*_MOD bits. */
#define FLAG_ALL_MOD                                                                                                   \
    (FLAG_OF_MOD | FLAG_SF_MOD | FLAG_ZF_MOD | FLAG_AF_MOD | FLAG_PF_MOD | FLAG_CF_MOD | FLAG_DF_MOD | FLAG_IF_MOD)

/** The arithmetic flags commonly updated together: OF, SF, ZF, AF, PF and CF. */
#define FLAG_COMMON_MOD (FLAG_OF_MOD | FLAG_SF_MOD | FLAG_ZF_MOD | FLAG_AF_MOD | FLAG_PF_MOD | FLAG_CF_MOD)

/** FPU condition code C0 is set according to the result. */
#define FPU_C0_MOD (1 << 23)

/** FPU condition code C1 is set according to the result. */
#define FPU_C1_MOD (1 << 24)

/** FPU condition code C2 is set according to the result. */
#define FPU_C2_MOD (1 << 25)

/** FPU condition code C3 is set according to the result. */
#define FPU_C3_MOD (1 << 26)

/** All of the FPU_C*_MOD bits. */
#define FPU_ALL_MOD (FPU_C0_MOD | FPU_C1_MOD | FPU_C2_MOD | FPU_C3_MOD)

/** All of the FLAG_ALL_MOD and FPU_ALL_MOD bits. */
#define FLAG_MOD_MASK (FLAG_ALL_MOD | FPU_ALL_MOD)

/** @} */

/**
 * @name Flags toggled
 * @{
 */

/** CF is toggled. */
#define FLAG_CF_TOG (1 << 18)

/** All of the FLAG_*_TOG bits. */
#define FLAG_TOG_MASK FLAG_CF_TOG

/** @} */

/**
 * @name Instruction results
 * Used for Opcode.ResultsIfTrue and Opcode.ResultsIfFalse.
 * @{
 */

/** First operand is a destination. */
#define OP1_DST (1 << 0)

/** Second operand is a destination. */
#define OP2_DST (1 << 1)

/** Third operand is a destination. */
#define OP3_DST (1 << 2)

/** First operand is a source. */
#define OP1_SRC (1 << 3)

/** Second operand is a source. */
#define OP2_SRC (1 << 4)

/** Third operand is a source. */
#define OP3_SRC (1 << 5)

/** FPU stack pointer is incremented by 1. */
#define FPU_STACK_INC (1 << 6)

/** FPU stack pointer is incremented by 2. */
#define FPU_STACK_INC2 (1 << 7)

/** FPU stack pointer is decremented by 1. */
#define FPU_STACK_DEC (1 << 8)

/** Instruction serializes on write. */
#define SERIALIZE_WRITE (1 << 9)

/** Instruction serializes on read. */
#define SERIALIZE_READ (1 << 10)

/** xCX (CX/ECX/RCX, depending on address size) is decremented. */
#define xCX_DEC (1 << 11)

/** xCX is decremented on each iteration of a REP-prefixed string instruction. */
#define xCX_REP_DEC (1 << 12)

/** xDI is decremented. */
#define xDI_DEC (1 << 13)

/** xDI is incremented. */
#define xDI_INC (1 << 14)

/** xSI is decremented. */
#define xSI_DEC (1 << 15)

/** xSI is incremented. */
#define xSI_INC (1 << 16)

/** xDI is decremented by the operand size. */
#define xDI_DECx (1 << 17)

/** xDI is incremented by the operand size. */
#define xDI_INCx (1 << 18)

/** xSI is decremented by the operand size. */
#define xSI_DECx (1 << 19)

/** xSI is incremented by the operand size. */
#define xSI_INCx (1 << 20)

/** Alias for FPU_STACK_DEC: a push onto the FPU stack. */
#define FPU_STACK_PUSH FPU_STACK_DEC

/** Alias for FPU_STACK_INC: a pop off the FPU stack. */
#define FPU_STACK_POP FPU_STACK_INC

/** Alias for FPU_STACK_INC2: a two-element pop off the FPU stack. */
#define FPU_STACK_POP2 FPU_STACK_INC2

/** Both SERIALIZE_WRITE and SERIALIZE_READ. */
#define SERIALIZE_ALL (SERIALIZE_WRITE | SERIALIZE_READ)

/** @} */

/**
 * @name X86_REGISTER class offsets
 * Base value of each register class within the X86_REGISTER enumeration.
 * @{
 */

/** Base of the segment registers. */
#define X86_SEGMENT_OFFSET 0x00

/** Base of the test registers. */
#define X86_TEST_OFFSET 0x10

/** Base of the control registers. */
#define X86_CONTROL_OFFSET 0x20

/** Base of the debug registers. */
#define X86_DEBUG_OFFSET 0x30

/** Base of the FPU registers. */
#define X86_FPU_OFFSET 0x40

/** Base of the MMX registers. */
#define X86_MMX_OFFSET 0x50

/** Base of the XMM registers. */
#define X86_XMM_OFFSET 0x60

/** Base of the x86 8-bit general-purpose registers. */
#define X86_8BIT_OFFSET 0x70

/** Base of the x86 16-bit general-purpose registers. */
#define X86_16BIT_OFFSET 0x80

/** Base of the x86 32-bit general-purpose registers. */
#define X86_32BIT_OFFSET 0x90

/** Base of the AMD64 8-bit general-purpose registers. */
#define AMD64_8BIT_OFFSET 0xA0

/** Base of the AMD64 16-bit general-purpose registers. */
#define AMD64_16BIT_OFFSET 0xB0

/** Base of the AMD64 32-bit general-purpose registers. */
#define AMD64_32BIT_OFFSET 0xC0

/** Base of the AMD64 64-bit general-purpose registers. */
#define AMD64_64BIT_OFFSET 0xD0

/** @} */

/**
 * @brief Identifies a specific x86 or AMD64 register across all register classes.
 *
 * Each class starts at its own offset (X86_SEGMENT_OFFSET, X86_FPU_OFFSET, etc.),
 * so a plain integer comparison can test which class a value belongs to.
 */
typedef enum _X86_REGISTER
{
    /**
     * @name Segment registers
     * @{
     */
    X86_SEG_ES = X86_SEGMENT_OFFSET,
    X86_SEG_CS,
    X86_SEG_SS,
    X86_SEG_DS,
    X86_SEG_FS,
    X86_SEG_GS,
    /** @} */

    /**
     * @name Flags and instruction pointer
     * @{
     */
    X86_REG_FLAGS,
    X86_REG_EFLAGS,
    AMD64_REG_RFLAGS,
    X86_REG_IP,
    X86_REG_EIP,
    AMD64_REG_RIP,
    /** @} */

    /**
     * @name Test registers
     * @{
     */
    X86_REG_TR0 = X86_TEST_OFFSET,
    X86_REG_TR1,
    X86_REG_TR2,
    X86_REG_TR3,
    X86_REG_TR4,
    X86_REG_TR5,
    X86_REG_TR6,
    X86_REG_TR7,
    X86_REG_TR8,
    X86_REG_TR9,
    X86_REG_TR10,
    X86_REG_TR11,
    X86_REG_TR12,
    X86_REG_TR13,
    X86_REG_TR14,
    X86_REG_TR15,
    /** @} */

    /**
     * @name Control registers
     * @{
     */
    X86_REG_CR0 = X86_CONTROL_OFFSET,
    X86_REG_CR1,
    X86_REG_CR2,
    X86_REG_CR3,
    X86_REG_CR4,
    X86_REG_CR5,
    X86_REG_CR6,
    X86_REG_CR7,
    X86_REG_CR8,
    X86_REG_CR9,
    X86_REG_CR10,
    X86_REG_CR11,
    X86_REG_CR12,
    X86_REG_CR13,
    X86_REG_CR14,
    X86_REG_CR15,
    /** @} */

    /**
     * @name Debug registers
     * @{
     */
    X86_REG_DR0 = X86_DEBUG_OFFSET,
    X86_REG_DR1,
    X86_REG_DR2,
    X86_REG_DR3,
    X86_REG_DR4,
    X86_REG_DR5,
    X86_REG_DR6,
    X86_REG_DR7,
    X86_REG_DR8,
    X86_REG_DR9,
    X86_REG_DR10,
    X86_REG_DR11,
    X86_REG_DR12,
    X86_REG_DR13,
    X86_REG_DR14,
    X86_REG_DR15,
    /** @} */

    /**
     * @name FPU registers
     * @{
     */
    X86_REG_ST0 = X86_FPU_OFFSET,
    X86_REG_ST1,
    X86_REG_ST2,
    X86_REG_ST3,
    X86_REG_ST4,
    X86_REG_ST5,
    X86_REG_ST6,
    X86_REG_ST7,
    /** @} */

    /**
     * @name MMX registers
     * @{
     */
    X86_REG_MM0 = X86_MMX_OFFSET,
    X86_REG_MM1,
    X86_REG_MM2,
    X86_REG_MM3,
    X86_REG_MM4,
    X86_REG_MM5,
    X86_REG_MM6,
    X86_REG_MM7,
    /** @} */

    /**
     * @name XMM registers
     * @{
     */
    X86_REG_XMM0 = X86_XMM_OFFSET,
    X86_REG_XMM1,
    X86_REG_XMM2,
    X86_REG_XMM3,
    X86_REG_XMM4,
    X86_REG_XMM5,
    X86_REG_XMM6,
    X86_REG_XMM7,
    /** @} */

    /**
     * @name x86 8-bit registers
     * @{
     */
    X86_REG_AL = X86_8BIT_OFFSET,
    X86_REG_CL,
    X86_REG_DL,
    X86_REG_BL,
    X86_REG_AH,
    X86_REG_CH,
    X86_REG_DH,
    X86_REG_BH,
    /** @} */

    /**
     * @name x86 16-bit registers
     * @{
     */
    X86_REG_AX = X86_16BIT_OFFSET,
    X86_REG_CX,
    X86_REG_DX,
    X86_REG_BX,
    X86_REG_SP,
    X86_REG_BP,
    X86_REG_SI,
    X86_REG_DI,
    /** @} */

    /**
     * @name x86 32-bit registers
     * @{
     */
    X86_REG_EAX = X86_32BIT_OFFSET,
    X86_REG_ECX,
    X86_REG_EDX,
    X86_REG_EBX,
    X86_REG_ESP,
    X86_REG_EBP,
    X86_REG_ESI,
    X86_REG_EDI,
    /** @} */

    /**
     * @name AMD64 8-bit registers
     * @{
     */
    AMD64_REG_AL = AMD64_8BIT_OFFSET,
    AMD64_REG_CL,
    AMD64_REG_DL,
    AMD64_REG_BL,
    AMD64_REG_SPL,
    AMD64_REG_BPL,
    AMD64_REG_SIL,
    AMD64_REG_DIL,
    AMD64_REG_R8B,
    AMD64_REG_R9B,
    AMD64_REG_R10B,
    AMD64_REG_R11B,
    AMD64_REG_R12B,
    AMD64_REG_R13B,
    AMD64_REG_R14B,
    AMD64_REG_R15B,
    /** @} */

    /**
     * @name AMD64 16-bit registers
     * @{
     */
    AMD64_REG_AX = AMD64_16BIT_OFFSET,
    AMD64_REG_CX,
    AMD64_REG_DX,
    AMD64_REG_BX,
    AMD64_REG_SP,
    AMD64_REG_BP,
    AMD64_REG_SI,
    AMD64_REG_DI,
    AMD64_REG_R8W,
    AMD64_REG_R9W,
    AMD64_REG_R10W,
    AMD64_REG_R11W,
    AMD64_REG_R12W,
    AMD64_REG_R13W,
    AMD64_REG_R14W,
    AMD64_REG_R15W,
    /** @} */

    /**
     * @name AMD64 32-bit registers
     * @{
     */
    AMD64_REG_EAX = AMD64_32BIT_OFFSET,
    AMD64_REG_ECX,
    AMD64_REG_EDX,
    AMD64_REG_EBX,
    AMD64_REG_ESP,
    AMD64_REG_EBP,
    AMD64_REG_ESI,
    AMD64_REG_EDI,
    AMD64_REG_R8D,
    AMD64_REG_R9D,
    AMD64_REG_R10D,
    AMD64_REG_R11D,
    AMD64_REG_R12D,
    AMD64_REG_R13D,
    AMD64_REG_R14D,
    AMD64_REG_R15D,
    /** @} */

    /**
     * @name AMD64 64-bit registers
     * @{
     */
    AMD64_REG_RAX = AMD64_64BIT_OFFSET,
    AMD64_REG_RCX,
    AMD64_REG_RDX,
    AMD64_REG_RBX,
    AMD64_REG_RSP,
    AMD64_REG_RBP,
    AMD64_REG_RSI,
    AMD64_REG_RDI,
    AMD64_REG_R8,
    AMD64_REG_R9,
    AMD64_REG_R10,
    AMD64_REG_R11,
    AMD64_REG_R12,
    AMD64_REG_R13,
    AMD64_REG_R14,
    AMD64_REG_R15
    /** @} */
} X86_REGISTER;

/** @brief A raw 0-based test register index, as encoded in the ModRM reg field. */
typedef enum _X86_TEST_REGISTER
{
    REG_TR0 = 0,
    REG_TR1,
    REG_TR2,
    REG_TR3,
    REG_TR4,
    REG_TR5,
    REG_TR6,
    REG_TR7,
    REG_TR8,
    REG_TR9,
    REG_TR10,
    REG_TR11,
    REG_TR12,
    REG_TR13,
    REG_TR14,
    REG_TR15
} X86_TEST_REGISTER;

/** @brief A raw 0-based control register index, as encoded in the ModRM reg field. */
typedef enum _X86_CONTROL_REGISTER
{
    REG_CR0,
    REG_CR1,
    REG_CR2,
    REG_CR3,
    REG_CR4,
    REG_CR5,
    REG_CR6,
    REG_CR7,
    REG_CR8,
    REG_CR9,
    REG_CR10,
    REG_CR11,
    REG_CR12,
    REG_CR13,
    REG_CR14,
    REG_CR15
} X86_CONTROL_REGISTER;

/** @brief A raw 0-based debug register index, as encoded in the ModRM reg field. */
typedef enum _X86_DEBUG_REGISTER
{
    REG_DR0,
    REG_DR1,
    REG_DR2,
    REG_DR3,
    REG_DR4,
    REG_DR5,
    REG_DR6,
    REG_DR7,
    REG_DR8,
    REG_DR9,
    REG_DR10,
    REG_DR11,
    REG_DR12,
    REG_DR13,
    REG_DR14,
    REG_DR15
} X86_DEBUG_REGISTER;

/** @brief A raw 0-based MMX register index, as encoded in the ModRM reg or rm field. */
typedef enum _X86_MMX_REGISTER
{
    REG_MM0 = 0,
    REG_MM1 = 1,
    REG_MM2 = 2,
    REG_MM3 = 3,
    REG_MM4 = 4,
    REG_MM5 = 5,
    REG_MM6 = 6,
    REG_MM7 = 7
} X86_MMX_REGISTER;

/** @brief A raw 0-based XMM register index, as encoded in the ModRM reg or rm field. */
typedef enum _X86_SSE_REGISTER
{
    REG_XMM0 = 0,
    REG_XMM1 = 1,
    REG_XMM2 = 2,
    REG_XMM3 = 3,
    REG_XMM4 = 4,
    REG_XMM5 = 5,
    REG_XMM6 = 6,
    REG_XMM7 = 7
} X86_SSE_REGISTER;

/** @brief A raw 0-based FPU stack register index, as encoded in the ModRM reg or rm field. */
typedef enum _X86_FPU_REGISTER
{
    REG_ST0 = 0,
    REG_ST1 = 1,
    REG_ST2 = 2,
    REG_ST3 = 3,
    REG_ST4 = 4,
    REG_ST5 = 5,
    REG_ST6 = 6,
    REG_ST7 = 7
} X86_FPU_REGISTER;

/** @brief A raw 0-based 8-bit register index, as encoded in the ModRM reg or rm field. */
typedef enum _X86_8BIT_REGISTER
{
    REG_AL = 0,
    REG_CL = 1,
    REG_DL = 2,
    REG_BL = 3,
    REG_AH = 4,
    REG_CH = 5,
    REG_DH = 6,
    REG_BH = 7
} X86_8BIT_REGISTER;

/** @brief A raw 0-based 16-bit register index, as encoded in the ModRM reg or rm field. */
typedef enum _X86_16BIT_REGISTER
{
    REG_AX = 0,
    REG_CX = 1,
    REG_DX = 2,
    REG_BX = 3,
    REG_SP = 4,
    REG_BP = 5,
    REG_SI = 6,
    REG_DI = 7
} X86_16BIT_REGISTER;

/** @brief A raw 0-based 32-bit register index, as encoded in the ModRM reg or rm field. */
typedef enum _X86_32BIT_REGISTER
{
    REG_EAX = 0,
    REG_ECX = 1,
    REG_EDX = 2,
    REG_EBX = 3,
    REG_ESP = 4,
    REG_EBP = 5,
    REG_ESI = 6,
    REG_EDI = 7
} X86_32BIT_REGISTER;

/** @brief A raw 0-based segment register index. */
typedef enum _X86_SEGMENT
{
    SEG_ES = 0,
    SEG_CS = 1,
    SEG_SS = 2,
    SEG_DS = 3,
    SEG_FS = 4,
    SEG_GS = 5,

    /** Number of segment registers. */
    SEG_MAX = 6
} X86_SEGMENT;

/** Display names for the X86_REGISTER values. */
extern char* X86_Registers[];

#pragma pack(push, 1)

/** @brief The ModRM byte: addressing mode plus a register or opcode-extension field and an rm field. */
typedef struct _MODRM
{
    /** Addressing mode (00/01/10 = memory with 0/1/4-byte displacement, 11 = register). */
    U8 mod : 2;

    /** Register operand, or an opcode extension for group opcodes. */
    U8 reg : 3;

    /** Register or memory-addressing operand. */
    U8 rm : 3;
} MODRM;

/** @brief The SIB (scale-index-base) byte, present when ModRM.rm selects SIB addressing. */
typedef struct _SIB
{
    /** log2 of the scale factor applied to the index register. */
    U8 scale : 2;

    /** Index register. */
    U8 index : 3;

    /** Base register. */
    U8 base : 3;
} SIB;

/** @brief The AMD64 REX prefix, extending the ModRM/SIB register fields to 4 bits. */
typedef struct _REX
{
    U8 unused : 4; // bits 4,5,6,7

    /** bit 3: 1 selects a 64-bit operand size. */
    U8 w : 1;

    /** bit 2: extends ModRM.reg. */
    U8 r : 1;

    /** bit 1: extends SIB.index. */
    U8 x : 1;

    /** bit 0: extends ModRM.rm or SIB.base. */
    U8 b : 1;
} REX;

/** @brief ModRM's reg and rm fields after being extended by a REX prefix. */
typedef struct _REX_MODRM
{
    /** REX.r:ModRM.reg. */
    U8 reg : 4;

    /** REX.b:ModRM.rm. */
    U8 rm : 4;
} REX_MODRM;

/** @brief SIB's index and base fields after being extended by a REX prefix. */
typedef struct _REX_SIB
{
    /** REX.x:SIB.index. */
    U8 index : 4;

    /** REX.b:SIB.base. */
    U8 base : 4;
} REX_SIB;

#pragma pack(pop)

/**
 * @brief One opcode table entry: an instruction's mnemonic, operands and semantic flags.
 *
 * Properties:
 *
 * If an operand is OP_COND_EXEC, it means that it is executed only if the pre-conditions are met.
 *
 * If if an instruction has one or more OP_COND_DST operands, then the actions are determined by
 * whether the Opcode.Preconditions are met or not. If all the COND_* flags in Opcode.Preconditions
 * are true, then the results are determined by ResultsIfTrue. If the preconditions are not met, then
 * the results are determined by ResultsIfFalse.
 *
 * If Preconditions == NOCOND, then results in ResultsIfTrue are unconditional and ResultsIfFalse
 * is ignored
 */
typedef struct _X86_OPCODE
{
    /** Non-NULL if this entry is a group/extension pointing at a further opcode sub-table. */
    struct _X86_OPCODE* Table;

    /** Minimum CPU (starting with i386). */
    CPU_TYPE CPU;

    /** INSTRUCTION_TYPE and ITYPE_* group, plus the ITYPE_EXT_* extension bits. */
    U32 MnemonicFlags;

    /** Instruction mnemonic text. */
    char Mnemonic[X86_MAX_INSTRUCTION_LEN + 1];

    /** Per-operand AMODE_*, OPTYPE_* and OP_* flags; see X86_OPERAND_COUNT(). */
    U32 OperandFlags[X86_MAX_OPERANDS];

    /** COND_* flags that must hold for ResultsIfTrue to apply. */
    U32 Preconditions;

    /** Changes in flags: FLAG_* and FPU_* bits. */
    U32 FlagsChanged;

    /** Results if Preconditions are met. */
    U32 ResultsIfTrue;

    /** Results if Preconditions are not met. */
    U32 ResultsIfFalse;
} X86_OPCODE;

/** @brief x86/AMD64-specific decode state and addressing details for one instruction. */
typedef struct _X86_INSTRUCTION
{
    /** The generic instruction format representing this instruction. */
    struct _INSTRUCTION* Instruction;

    /** The matched opcode table entry. */
    X86_OPCODE Opcode;

    U8 sib_b;
    U8 modrm_b;
    MODRM modrm;
    SIB sib;
    U8 rex_b;
    REX rex;
    REX_MODRM rex_modrm;
    REX_SIB rex_sib;

    /** Segment used for the destination operand of a two-segment string instruction (see HasDstSegment). */
    X86_SEGMENT DstSegment;

    union
    {
        X86_SEGMENT Segment;
        DWORD Selector;
    };

    /**
     * NOTE: these are for internal use, use Instruction->Operands[]
     *
     * If DstRegAddressing or SrcRegAddressing = TRUE then BaseRegister is the base register
     * It is the operand represented by SIBOperand
     *
     * The operand indices of the destination operands is in DstOpIndex[0 to DstOpCount-1]
     * The operand indices of the source operands is in SrcOpIndex[0 to SrcOpCount-1]
     *
     * These are used both for instructions like xadd/xchg (where both operands are source/destination)
     * and to represent implicit registers (e.g., cmpxchg)
     */
    U8 SrcOpIndex[3];

    /** Same encoding as SrcOpIndex, for the destination operands. */
    U8 DstOpIndex[3];

    /**
     * Addressing mode:
     * If DstRegAddressing = TRUE, then these apply to DstReg
     * If SrcRegAddressing = TRUE, then this applies to SrcReg[AddressIndex]
     * If both are false, then SrcReg and DstReg are not addresses
     */
    X86_REGISTER BaseRegister;

    /** Same conditions as BaseRegister. */
    X86_REGISTER IndexRegister;

    /** SIB scale factor (1, 2, 4 or 8). */
    U8 Scale;

    U8 HasDefault64Operand : 1;
    U8 HasOperandSizePrefix : 1;
    U8 HasAddressSizePrefix : 1;
    U8 HasSegmentOverridePrefix : 1;
    U8 HasLockPrefix : 1;
    U8 HasRepeatWhileEqualPrefix : 1;
    U8 HasRepeatWhileNotEqualPrefix : 1;
    U8 HasBranchTakenPrefix : 1;
    U8 HasBranchNotTakenPrefix : 1;
    U8 HasDstAddressing : 1;
    U8 HasSrcAddressing : 1;
    U8 HasModRM : 1;
    U8 HasBaseRegister : 1;
    U8 HasIndexRegister : 1;
    U8 HasFullDisplacement : 1;

    /** Used for ins/cmps/scas/movs/etc which have 2 segments. */
    U8 HasDstSegment : 1;

    /** DstOpIndex[DstAddressIndex]. */
    U8 DstAddressIndex : 2;

    /** SrcOpIndex[SrcAddressIndex]. */
    U8 SrcAddressIndex : 2;

    U8 DstOpCount : 2;
    U8 SrcOpCount : 2;
    U8 OperandSize : 4;
    U8 AddressSize : 4;
    U8 Relative : 1;

    /** Segment is actually a selector. */
    U8 HasSelector : 1;

    U8 Group : 5;

    /** Decoded displacement value. */
    S64 Displacement;

} X86_INSTRUCTION;

////////////////////////////////////////////////////////////////////////////////////
// Exported functions
////////////////////////////////////////////////////////////////////////////////////

/** The x86/AMD64 ARCHITECTURE_FORMAT_FUNCTIONS table, for use with InitDisassembler(). */
extern ARCHITECTURE_FORMAT_FUNCTIONS X86;

// Instruction setup

/**
 * @brief Resets the X86-specific decode state and sets its default address/operand sizes.
 * @param[in,out] Instruction Instruction whose X86 sub-structure is cleared and initialized;
 *        its architecture type (set by the caller) selects the sizes.
 * @return TRUE once the sizes have been set; FALSE if the architecture type is not recognized.
 */
BOOL X86_InitInstruction(struct _INSTRUCTION* Instruction);

/**
 * @brief Counterpart to X86_InitInstruction().
 *
 * Declared for symmetry with X86_InitInstruction(); not implemented in this
 * vendored subset of the library, and not wired into the X86
 * ARCHITECTURE_FORMAT_FUNCTIONS table.
 *
 * @param[in,out] Instruction Instruction previously initialized with X86_InitInstruction().
 */
void X86_CloseInstruction(struct _INSTRUCTION* Instruction);

// Instruction translator

/**
 * @brief Declared for a disassembly/text-rendering step on an already-decoded instruction.
 *
 * Not implemented in this vendored subset of the library, and not wired
 * into the X86 ARCHITECTURE_FORMAT_FUNCTIONS table.
 *
 * @param[in,out] Instruction Decoded instruction.
 * @param[in]     Verbose     Presumably selects a more detailed rendering.
 * @return Presumably TRUE on success.
 */
BOOL X86_TranslateInstruction(struct _INSTRUCTION* Instruction, BOOL Verbose);

// Instruction decoder

/**
 * @brief Decodes (and, when requested, disassembles) one x86/x64 instruction at Address.
 *
 * Resolves prefixes, its one/two/three-byte opcode and any opcode group or
 * SSE extension against the tables in disasm_x86_tables.h, then delegates
 * operand decoding to SetOperands() and classifies the result (branch
 * targets, stack effects, anomalies, emulation needs).
 *
 * @param[in,out] Instruction Instruction to decode into; Instruction->Address must already
 *        equal Address, and its X86 sub-structure and text output are populated by this call.
 * @param[in] Address Address of the first byte of the instruction to decode.
 * @param[in] Flags Decode flags, e.g. DISASM_DECODE to populate operand fields,
 *        DISASM_DISASSEMBLE to also format the text representation, DISASM_SUPPRESSERRORS
 *        to silence the diagnostic printf()s, and DISASM_ALIGNOUTPUT to pad operand columns.
 * @return TRUE if the instruction was successfully decoded; FALSE if an invalid opcode,
 *         prefix or other error was encountered.
 */
BOOL X86_GetInstruction(struct _INSTRUCTION* Instruction, U8* Address, DWORD Flags);

// Function finding

/**
 * @brief Intended to find the first function between StartAddress and EndAddress.
 *
 * Would do so by matching a standard prologue and then analyzing the
 * following instructions to verify it is a valid function; not yet
 * implemented (the body is `assert(0); // TODO`).
 *
 * @param[in] Instruction Unused by the current stub.
 * @param[in] StartAddress Unused by the current stub.
 * @param[in] EndAddress Unused by the current stub.
 * @param[in] Flags Unused by the current stub.
 * @return Always NULL.
 */
U8* X86_FindFunctionByPrologue(struct _INSTRUCTION* Instruction, U8* StartAddress, U8* EndAddress, DWORD Flags);

#ifdef __cplusplus
}
#endif
#endif // X86_DISASM_H
