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
// Copyright (C) 2003, Matt Conover (mconover@gmail.com)
//================================================================================

#ifndef CPU_H
#define CPU_H
#ifdef __cplusplus
extern "C"
{
#endif

#include <windows.h>
#include "misc.h"

#pragma pack(push, 1)

////////////////////////////////////////////////////////
// System descriptors
////////////////////////////////////////////////////////

/**
 * @name Windows x86 GDT selectors
 * Fixed selector values used by the Windows x86 kernel's GDT layout.
 * @{
 */

/** The null selector. */
#define GDT_NULL 0

/** Ring 0 (kernel) code segment. */
#define GDT_R0_CODE 0x08

/** Ring 0 (kernel) data segment. */
#define GDT_R0_DATA 0x10

/** Ring 3 (user) code segment. */
#define GDT_R3_CODE 0x18

/** Ring 3 (user) data segment. */
#define GDT_R3_DATA 0x20

/** Task State Segment. */
#define GDT_TSS 0x28

/** Processor Control Region (KPCR), addressed through FS. */
#define GDT_PCR 0x30

/** Ring 3 Thread Environment Block, addressed through FS. */
#define GDT_R3_TEB 0x38

/** Virtual DOS Machine segment. */
#define GDT_VDM 0x40

/** Local Descriptor Table. */
#define GDT_LDT 0x48

/** TSS used to handle double-fault exceptions. */
#define GDT_DOUBLEFAULT_TSS 0x50

/** TSS used to handle non-maskable interrupts. */
#define GDT_NMI_TSS 0x58

/** @} */

// 16-bit GDT entries:
// TODO: #define GDT_ABIOS_UNKNOWN   0x60  (22F30-32F2F)

/**
 * @name ABIOS (Advanced BIOS) GDT selectors
 * 16-bit selectors reserved for the ABIOS compatibility subsystem.
 * @{
 */

/** ABIOS video segment. */
#define GDT_ABIOS_VIDEO 0x68

/** descriptor describing ABIOS GDT itself */
#define GDT_ABIOS_GDT 0x70

/** first 64K of NTOSKRNL */
#define GDT_ABIOS_NTOS 0x78

/** common data area */
#define GDT_ABIOS_CDA 0xE8

/** KiI386AbiosCall */
#define GDT_ABIOS_CODE 0xF0

/** ABIOS stack segment. */
#define GDT_ABIOS_STACK 0xF8

/** @} */

/**
 * @name Selector bit fields
 * @{
 */

/** Requested privilege level (bits 0-1). */
#define SELECTOR_RPL_MASK 0x03

/** Set if the selector references the LDT rather than the GDT (bit 2). */
#define SELECTOR_LDT 0x04

/** @} */

/**
 * @name Data-segment descriptor type bits
 * @{
 */

/** Accessed bit. */
#define DATA_ACCESS_MASK (1 << 0)

/** Segment is writable. */
#define DATA_WRITE_ENABLE_MASK (1 << 1)

/** Segment expands downward (e.g. a stack segment). */
#define DATA_EXPAND_DOWN_MASK (1 << 2)

/** @} */

/**
 * @name Code-segment descriptor type bits
 * @{
 */

/** Accessed bit. */
#define CODE_ACCESS_MASK (1 << 0)

/** Segment is readable. */
#define CODE_READ_MASK (1 << 1)

/** Conforming segment. */
#define CODE_CONFORMING_MASK (1 << 2)

/** Set for a code segment (as opposed to a data segment). */
#define CODE_FLAG (1 << 3)

/** @} */

/**
 * @name IDT gate descriptor types
 * @{
 */

/** Task gate. */
#define TASK_GATE 5

/** Interrupt gate. */
#define INTERRUPT_GATE 6

/** Trap gate. */
#define TRAP_GATE 7

/** @} */

/** @brief An IDT interrupt or trap gate descriptor. */
typedef struct _IDT_ENTRY
{
    /** Low 16 bits of the handler entry point offset. */
    USHORT LowOffset;

    /** Code segment selector of the handler. */
    USHORT Selector;

    UCHAR Ignored : 5;
    UCHAR Zero : 3;

    /** Gate type; see INTERRUPT_GATE and TRAP_GATE. */
    UCHAR Type : 3;

    /** Set if this is a 32-bit gate. */
    UCHAR Is32Bit : 1;
    UCHAR Ignored2 : 1;

    /** Descriptor privilege level required to invoke the gate directly. */
    UCHAR DPL : 2;

    /** Set if the gate is present (valid). */
    UCHAR Present : 1;

    /** High 16 bits of the handler entry point offset. */
    USHORT HighOffset;
#ifdef _WIN64
    /** Bits 32-63 of the handler entry point offset. */
    ULONG HighOffset64;
    ULONG Reserved;
#endif
} IDT_ENTRY, TRAP_GATE_ENTRY;

/** @brief A call gate descriptor. */
typedef struct _CALL_GATE_ENTRY
{
    /** Low 16 bits of the entry point offset. */
    USHORT LowOffset;

    /** Code segment selector of the target routine. */
    USHORT Selector;

    /** Number of DWORD parameters to copy from the caller's stack. */
    UCHAR ParameterCount : 4;

    UCHAR Ignored : 3;

    /** Gate type. */
    UCHAR Type : 5;

    /** Descriptor privilege level required to invoke the gate directly. */
    UCHAR DPL : 2;

    /** Set if the gate is present (valid). */
    UCHAR Present : 1;

    /** High 16 bits of the entry point offset. */
    USHORT HighOffset;
#ifdef _WIN64
    /** Bits 32-63 of the entry point offset. */
    ULONG HighOffset64;
    ULONG Reserved;
#endif
} CALL_GATE_ENTRY;

/** @brief A task gate descriptor, referencing a TSS selector to task-switch to. */
typedef struct _TASK_GATE_ENTRY
{
    USHORT Ignored;

    /** TSS selector to task-switch to. */
    USHORT Selector;

    UCHAR Ignored2 : 5;
    UCHAR Zero : 3;

    /** Gate type. */
    UCHAR Type : 5;

    /** Descriptor privilege level required to invoke the gate directly. */
    UCHAR DPL : 2;

    /** Set if the gate is present (valid). */
    UCHAR Present : 1;

    USHORT Ignored3;
} TASK_GATE_ENTRY;

/** @brief A GDT/LDT segment descriptor. */
typedef struct _DESCRIPTOR_ENTRY
{
    /** Low 16 bits of the segment limit. */
    USHORT LimitLow;

    /** Low 16 bits of the segment base address. */
    USHORT BaseLow;

    /** Bits 16-23 of the segment base address. */
    UCHAR BaseMid;

    /**
     * Segment type.
     * 10EWA (code), E=ExpandDown, W=Writable, A=Accessed
     * 11CRA (data), C=Conforming, R=Readable, A=Accessed
     */
    UCHAR Type : 4;

    /** If 1 then it is a gate or LDT. */
    UCHAR System : 1;

    /**
     * Descriptor privilege level.
     * For data selectors, MAX(CPL, RPL) must be <= DPL to access (or else GP# fault).
     * For non-conforming code selectors (without callgate), MAX(CPL, RPL) must be <= DPL to
     * access (or else GP# fault).
     * For conforming code selectors, MAX(CPL, RPL) must be >= DPL (i.e., CPL 0-2 cannot access
     * if DPL is 3).
     * For non-conforming code selectors (with call gate), DPL indicates lowest privilege
     * allowed to access gate.
     */
    UCHAR DPL : 2;

    /** Set if the segment is present (valid). */
    UCHAR Present : 1;

    /** Bits 16-19 of the segment limit. */
    UCHAR LimitHigh : 4;

    /** Available for use by system software; aka AVL. */
    UCHAR Available : 1;

    UCHAR Reserved : 1;

    /** Aka B flag: default operation size/upper bound. */
    UCHAR Is32Bit : 1;

    /** Aka G flag: limit is scaled by 4K when set. */
    UCHAR Granularity : 1;

    /** Bits 24-31 of the segment base address. */
    UCHAR BaseHi : 8;
#ifdef _WIN64
    /** Bits 32-63 of the segment base address. */
    ULONG HighOffset64;
    ULONG Reserved2;
#endif
} DESCRIPTOR_ENTRY;

/** @brief A generic call/interrupt/trap gate descriptor. */
typedef struct _GATE_ENTRY
{
    /** Low 16 bits of the handler entry point offset. */
    USHORT LowOffset;

    UCHAR Skip;

    /** Gate type. */
    UCHAR Type : 5;

    /** Descriptor privilege level required to invoke the gate directly. */
    UCHAR DPL : 2;

    /** Set if the gate is present (valid). */
    UCHAR Present : 1;

    /** High 16 bits of the handler entry point offset. */
    USHORT HighOffset;
#ifdef _WIN64
    /** Bits 32-63 of the handler entry point offset. */
    ULONG HighOffset64;
    ULONG Reserved;
#endif
} GATE_ENTRY;

/** @brief A 32-bit page table entry. */
// TODO: update for X64
typedef struct _PTE_ENTRY
{
    /** Set if the mapped page is present in physical memory. */
    ULONG Present : 1;

    /** Set if the page is writable. */
    ULONG Write : 1;

    /** E.g., user mode or supervisor mode. */
    ULONG Owner : 1;

    /** Write-through caching is enabled for this page. */
    ULONG WriteThrough : 1;

    /** Caching is disabled for this page. */
    ULONG CacheDisable : 1;

    /** Set by the CPU when the page has been accessed. */
    ULONG Accessed : 1;

    /** Set by the CPU when the page has been written to. */
    ULONG Dirty : 1;

    /** Page attribute table bit. */
    ULONG PAT : 1;

    /** Global page: not flushed from the TLB on a CR3 reload. */
    ULONG Global : 1;

    /** Copy-on-write bit (software-defined). */
    ULONG CopyOnWrite : 1;

    /** Prototype PTE bit (software-defined). */
    ULONG Prototype : 1;

    /** Page is in transition (software-defined). */
    ULONG Transition : 1;

    /** Physical page frame number. */
    ULONG Address : 20;
} PTE_ENTRY;

/** @brief A 32-bit page directory entry. */
// TODO: update for X64
typedef struct _PDE_ENTRY
{
    /** Set if the referenced page table is present in physical memory. */
    ULONG Present : 1;

    /** Set if the mapped region is writable. */
    ULONG Write : 1;

    /** E.g., user mode or supervisor mode. */
    ULONG Owner : 1;

    /** Write-through caching is enabled. */
    ULONG WriteThrough : 1;

    /** Caching is disabled. */
    ULONG CacheDisable : 1;

    /** Set by the CPU when the entry has been accessed. */
    ULONG Accessed : 1;

    ULONG Reserved1 : 1;

    /** Set for a large (4MB) page rather than a page table reference. */
    ULONG PageSize : 1;

    /** Global page: not flushed from the TLB on a CR3 reload. */
    ULONG Global : 1;

    ULONG Reserved : 3;

    /** Physical page frame number (of the page table, or of the large page). */
    ULONG Address : 20;
} PDE_ENTRY;

/** @brief The TSS I/O permission bitmap: a direction map plus a per-port I/O map. */
// TODO: update for X64
typedef struct _IO_ACCESS_MAP
{
    /** Per-port direction bitmap. */
    UCHAR DirectionMap[32];

    /** Per-port I/O permission bitmap. */
    UCHAR IoMap[8196];
} IO_ACCESS_MAP;

/** Minimum TSS size that excludes the trailing I/O permission bitmap. */
#define MIN_TSS_SIZE FIELD_OFFSET(TSS_ENTRY, IoMaps)

/** @brief The 32-bit Task State Segment: the register state saved on a hardware task switch. */
// TODO: update for X64
typedef struct _TSS_ENTRY
{
    /** Selector of the previous TSS, for a nested task. */
    USHORT Backlink;
    USHORT Reserved0;

    /** Ring 0 stack pointer. */
    ULONG Esp0;

    /** Ring 0 stack segment selector. */
    USHORT Ss0;
    USHORT Reserved1;

    /** Ring 1 and ring 2 SS:ESP pairs. */
    ULONG NotUsed1[4];

    /** Page directory base (CR3) for the task. */
    ULONG CR3;

    /** Saved EIP. */
    ULONG Eip;

    /** Saved EFLAGS, then EAX/ECX/EDX/EBX/ESP/EBP/ESI/EDI. */
    ULONG NotUsed2[9];

    /** Saved ES selector. */
    USHORT Es;
    USHORT Reserved2;

    /** Saved CS selector. */
    USHORT Cs;
    USHORT Reserved3;

    /** Saved SS selector. */
    USHORT Ss;
    USHORT Reserved4;

    /** Saved DS selector. */
    USHORT Ds;
    USHORT Reserved5;

    /** Saved FS selector. */
    USHORT Fs;
    USHORT Reserved6;

    /** Saved GS selector. */
    USHORT Gs;
    USHORT Reserved7;

    /** LDT selector for the task. */
    USHORT LDT;
    USHORT Reserved8;

    /** Debug-trap-on-task-switch flag (bit 0). */
    USHORT Flags;

    /** Offset from the start of the TSS to the I/O permission bitmap. */
    USHORT IoMapBase;

    /** I/O permission bitmap; see MIN_TSS_SIZE. */
    IO_ACCESS_MAP IoMaps[1];

    UCHAR IntDirectionMap[32];
} TSS_ENTRY;

/** @brief The legacy 16-bit Task State Segment. Fields mirror TSS_ENTRY's saved state. */
// TODO: update for X64
typedef struct _TSS16_ENTRY
{
    /** Selector of the previous TSS, for a nested task. */
    USHORT Backlink;

    /** Ring 0 stack pointer. */
    USHORT Sp0;

    /** Ring 0 stack segment selector. */
    USHORT Ss0;

    /** Ring 1 stack pointer. */
    USHORT Sp1;

    /** Ring 1 stack segment selector. */
    USHORT Ss1;

    /** Ring 2 stack pointer. */
    USHORT Sp2;

    /** Ring 2 stack segment selector. */
    USHORT Ss3;

    /** Saved IP. */
    USHORT Ip;

    /** Saved FLAGS. */
    USHORT Flags;

    /** Saved AX. */
    USHORT Ax;

    /** Saved CX. */
    USHORT Cx;

    /** Saved DX. */
    USHORT Dx;

    /** Saved BX. */
    USHORT Bx;

    /** Saved SP. */
    USHORT Sp;

    /** Saved BP. */
    USHORT Bp;

    /** Saved SI. */
    USHORT Si;

    /** Saved DI. */
    USHORT Di;

    /** Saved ES selector. */
    USHORT Es;

    /** Saved CS selector. */
    USHORT Cs;

    /** Saved SS selector. */
    USHORT Ss;

    /** Saved DS selector. */
    USHORT Ds;

    /** LDT selector for the task. */
    USHORT LDT;
} TSS16_ENTRY;

/** @brief A GDT/LDT segment descriptor, laid out for byte- or bitfield-wise access to its high word. */
// TODO: update for X64
typedef struct _GDT_ENTRY
{
    /** Low 16 bits of the segment limit. */
    USHORT LimitLow;

    /** Low 16 bits of the segment base address. */
    USHORT BaseLow;

    union
    {
        struct
        {
            /** Bits 16-23 of the segment base address. */
            UCHAR BaseMid;

            /** Low byte of the descriptor's high word (type/DPL/present/limit bits). */
            UCHAR Flags1;

            /** High byte of the descriptor's high word (AVL/default-size/granularity bits). */
            UCHAR Flags2;

            /** Bits 24-31 of the segment base address. */
            UCHAR BaseHi;
        } Bytes;

        struct
        {
            /** Bits 16-23 of the segment base address. */
            ULONG BaseMid : 8;

            /** Segment type. */
            ULONG Type : 5;

            /** Descriptor privilege level. */
            ULONG Dpl : 2;

            /** Set if the segment is present (valid). */
            ULONG Pres : 1;

            /** Bits 16-19 of the segment limit. */
            ULONG LimitHi : 4;

            /** If 1 then it is a gate or LDT. */
            ULONG Sys : 1;

            ULONG Reserved_0 : 1;

            /** Default operation size/upper bound (aka B flag). */
            ULONG Default_Big : 1;

            /** Limit is scaled by 4K when set (aka G flag). */
            ULONG Granularity : 1;

            /** Bits 24-31 of the segment base address. */
            ULONG BaseHi : 8;
        } Bits;
    } HighWord;
} GDT_ENTRY;

/**
 * @brief Resolves a flat-model x86 segment register to an absolute address.
 *
 * Assumes the default Windows flat memory model: CS/DS/ES/SS have base 0 and
 * a 4GB limit, so the returned address is simply the offset. This is not
 * verified against the actual GDT.
 *
 * @param[in] Segment x86 segment register (SEG_ES = 0, SEG_CS = 1, ...).
 * @param[in] Offset  Offset within the segment.
 * @return The absolute address corresponding to Segment:Offset.
 */
BYTE* GetAbsoluteAddressFromSegment(BYTE Segment, DWORD Offset);

/**
 * @brief Resolves a GDT/LDT selector to an absolute address.
 *
 * Looks up the selector's descriptor for the current thread and adds Offset
 * to its base address. For a gate descriptor, the offset encoded in the gate
 * itself is used instead and Offset must be zero.
 *
 * @param[in] Selector GDT or LDT selector.
 * @param[in] Offset   Offset added to the descriptor's base address.
 * @return The absolute address, or NULL if the selector's entry could not be
 *         retrieved or is not present.
 */
BYTE* GetAbsoluteAddressFromSelector(WORD Selector, DWORD Offset);

#pragma pack(pop)
#ifdef __cplusplus
}
#endif
#endif // CPU_H
