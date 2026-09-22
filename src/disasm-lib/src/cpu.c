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

#include "cpu.h"
#include <assert.h>

/**
 * @brief Resolves an offset within an x86 segment register to an absolute address under the OS's flat memory model.
 * @param[in] Segment x86 segment register identifying which segment Offset is relative to (SEG_ES = 0, SEG_CS = 1, ...).
 * @param[in] Offset Offset within the segment.
 * @return The absolute address corresponding to Segment and Offset.
 * @remark Assumes the default scenario, where CS/DS/ES/SS all have a base of 0 and a limit of 0xffffffff; this is not verified against the GDT.
 * @remark FS and GS are handled the same way here; using their real base would require adding the address returned by get_teb(), which is not implemented in this version of the disassembler.
 * @remark TODO left by the original author: use inline assembly to get the selector for the segment.
 */
BYTE* GetAbsoluteAddressFromSegment(BYTE Segment, DWORD Offset)
{
    switch (Segment)
    {
    // Windows uses a flat address space (except FS for x86 and GS for x64)
    case 0: // SEG_ES
    case 1: // SEG_CS
    case 2: // SEG_SS
    case 3: // SEG_DS
        return (BYTE*)(DWORD_PTR)Offset;
    case 4: // SEG_FS
    case 5: // SEG_GS
        return (BYTE*)(DWORD_PTR)Offset;
        // Note: we're really supposed to do this, but get_teb is not implemented
        // in this bastardized version of the disassembler.
        // return (BYTE *)get_teb() + Offset;
    default:
        assert(0);
        return (BYTE*)(DWORD_PTR)Offset;
    }
}

/**
 * @brief Resolves a GDT or LDT selector's descriptor to an absolute base address.
 * @param[in] Selector GDT or LDT selector to resolve (pGDT + Selector).
 * @param[in] Offset Offset added to the resolved base address.
 * @return The absolute address for Selector and Offset, or NULL when the selector's entry cannot be read or is not present.
 * @remark When Entry.System is set, or Entry.Type identifies a 16-/32-bit TSS or LDT descriptor, the base is read from the descriptor's Base fields. When Entry.Type identifies a call, interrupt, or task gate, the base is read from the gate's offset fields instead, and Offset is expected to be zero. Any other Entry.Type triggers an assertion failure and returns NULL.
 */
BYTE* GetAbsoluteAddressFromSelector(WORD Selector, DWORD Offset)
{
    DESCRIPTOR_ENTRY Entry;
    GATE_ENTRY* Gate;
    ULONG_PTR Base;

    assert(Selector < 0x10000);
    if (!GetThreadSelectorEntry(GetCurrentThread(), Selector, (LDT_ENTRY*)&Entry))
        return NULL;
    if (!Entry.Present)
        return NULL;
    if (Entry.System)
    {
        Base = 0;
#ifdef _WIN64
        Base |= (ULONG_PTR)Entry.HighOffset64 << 32;
#endif
        Base |= Entry.BaseHi << 24;
        Base |= Entry.BaseMid << 16;
        Base |= Entry.BaseLow;
    }
    else
    {
        switch (Entry.Type)
        {
        case 1:  // 16-bit TSS (available)
        case 2:  // LDT
        case 3:  // 16-bit TSS (busy)
        case 9:  // 32-bit TSS (available)
        case 11: // 32-bit TSS (busy)
            Base = 0;
#ifdef _WIN64
            Base |= (ULONG_PTR)Entry.HighOffset64 << 32;
#endif
            Base |= Entry.BaseHi << 24;
            Base |= Entry.BaseMid << 16;
            Base |= Entry.BaseLow;
            break;

        case 4:  // 16-bit call gate
        case 5:  // task gate
        case 6:  // 16-bit interrupt gate
        case 7:  // 16-bit task gate
        case 12: // 32-bit call gate
        case 14: // 32-bit interrupt gate
        case 15: // 32-bit trap gate
            Gate = (GATE_ENTRY*)&Entry;
#ifdef _WIN64
            Base = ((ULONG_PTR)Gate->HighOffset64 << 32) | (Gate->HighOffset << 16) | Gate->LowOffset;
#else
            Base = (Gate->HighOffset << 16) | Gate->LowOffset;
#endif
            assert(!Offset);
            Offset = 0;
            break;
        default:
            assert(0);
            return NULL;
        }
    }
    return (BYTE*)Base + Offset;
}
