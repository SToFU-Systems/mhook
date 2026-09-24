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
// Copyright (c) 2007-2008, Marton Anka
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
// THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.
//================================================================================

#include <windows.h>
#include <tlhelp32.h>
#include <assert.h>
#include <ctype.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wctype.h>
#include "mhook.h"
#include <disasm-lib/disasm.h>

#ifdef _M_IX86
#define _M_IX86_X64
#elif defined _M_X64
#define _M_IX86_X64
#endif

//=========================================================================
// C11's _Alignof is not available under C99, and sizeof is not a substitute:
// for a struct it exceeds the alignment, which would make the checks below
// stricter than intended and reject valid addresses. Both supported compilers
// provide an intrinsic that gives the true alignment in C99 mode.
#if defined(_MSC_VER)
#define MHOOK_ALIGNOF(type) __alignof(type)
#else
#define MHOOK_ALIGNOF(type) __alignof__(type)
#endif

//=========================================================================
#ifndef cntof
#define cntof(a) (sizeof(a) / sizeof(a[0]))
#endif

//=========================================================================
#ifndef GOOD_HANDLE
#define GOOD_HANDLE(a) ((a != INVALID_HANDLE_VALUE) && (a != NULL))
#endif

//=========================================================================
#ifndef gle
#define gle GetLastError
#endif

//=========================================================================
#ifndef ODPRINTF

#ifdef _DEBUG
#define ODPRINTF(a) odprintfW a
#define ODPRINTFA(a) odprintfA a

/**
 * @brief Formats a message and sends it to the debugger via OutputDebugStringA.
 * @param[in] format printf-style format string, followed by its arguments.
 */
static void __cdecl odprintfA(PCSTR format, ...)
{
    va_list args;
    va_start(args, format);
    int len = _vscprintf(format, args);
    if (len > 0)
    {
        len += (1 + 2);
        PSTR buf = (PSTR)malloc(len);
        if (buf)
        {
            len = vsprintf_s(buf, len, format, args);
            if (len > 0)
            {
                while (len && isspace(buf[len - 1]))
                    len--;
                buf[len++] = '\r';
                buf[len++] = '\n';
                buf[len] = 0;
                OutputDebugStringA(buf);
            }
            free(buf);
        }
        va_end(args);
    }
}

/**
 * @brief Formats a message and sends it to the debugger via OutputDebugStringW.
 * @param[in] format printf-style wide format string, followed by its arguments.
 */
static void __cdecl odprintfW(PCWSTR format, ...)
{
    va_list args;
    va_start(args, format);
    int len = _vscwprintf(format, args);
    if (len > 0)
    {
        len += (1 + 2);
        PWSTR buf = (PWSTR)malloc(sizeof(WCHAR) * len);
        if (buf)
        {
            len = vswprintf_s(buf, len, format, args);
            if (len > 0)
            {
                while (len && iswspace(buf[len - 1]))
                    len--;
                buf[len++] = L'\r';
                buf[len++] = L'\n';
                buf[len] = 0;
                OutputDebugStringW(buf);
            }
            free(buf);
        }
        va_end(args);
    }
}

#else
// A statement rather than nothing, so "if (x) ODPRINTF(...);" keeps a body.
#define ODPRINTF(a) ((void)0)
#define ODPRINTFA(a) ((void)0)
#endif // #ifdef _DEBUG

#endif // #ifndef ODPRINTF

#ifndef ODPRINTFA
#define ODPRINTFA(a) ODPRINTF(a)
#endif

//=========================================================================
#define MHOOKS_MAX_CODE_BYTES 32
#define MHOOKS_MAX_RIPS 4

//=========================================================================
// The trampoline structure - stores every bit of info about a hook
typedef struct MHOOKS_TRAMPOLINE
{
    PBYTE pSystemFunction;                              // the original system function
    DWORD cbOverwrittenCode;                            // number of bytes overwritten by the jump
    PBYTE pHookFunction;                                // the hook function that we provide
    BYTE codeJumpToHookFunction[MHOOKS_MAX_CODE_BYTES]; // placeholder for code that jumps to the hook function
    BYTE codeTrampoline[MHOOKS_MAX_CODE_BYTES];         // placeholder for code that holds the first few
                                                        //   bytes from the system function and a jump to the remainder
                                                        //   in the original location
    BYTE codeUntouched[MHOOKS_MAX_CODE_BYTES];          // placeholder for unmodified original code
                                                        //   (we patch IP-relative addressing)
    BYTE codeInstalledPatch[MHOOKS_MAX_CODE_BYTES];     // the exact bytes we left in the prologue, so
                                                        //   Mhook_Unhook can tell our own patch apart
                                                        //   from one somebody else wrote later
    struct MHOOKS_TRAMPOLINE* pPrevTrampoline; // When in the free list, thess are pointers to the prev and next entry.
    struct MHOOKS_TRAMPOLINE*
        pNextTrampoline; // When not in the free list, this is a pointer to the prev and next trampoline in use.
} MHOOKS_TRAMPOLINE;

//=========================================================================
// The patch data structures - store info about rip-relative instructions
// during hook placement
typedef struct MHOOKS_RIPINFO
{
    DWORD dwOffset;
    S64 nDisplacement;
} MHOOKS_RIPINFO;

typedef struct MHOOKS_PATCHDATA
{
    S64 nLimitUp;
    S64 nLimitDown;
    DWORD nRipCnt;
    MHOOKS_RIPINFO rips[MHOOKS_MAX_RIPS];
} MHOOKS_PATCHDATA;

/**
 * @brief Identifies one peer thread suspended by the current hook operation.
 */
typedef struct SuspendedThread
{
    HANDLE handle;
    DWORD threadId;
} SuspendedThread;

/**
 * @brief Stores the peer threads suspended by the current hook operation so they can be resumed.
 * @remark The storage comes from VirtualAlloc, not the heap: it grows while peers are suspended,
 *         and a suspended peer may hold the heap lock.
 */
typedef struct ThreadSuspension
{
    SuspendedThread* threads;
    SIZE_T count;
    SIZE_T capacity;
} ThreadSuspension;

//=========================================================================
// Global vars
// Statically initialized, so concurrent first calls cannot race to set it up
// and there is no initialization that could fail or teardown to order.
static SRWLOCK g_registryLock = SRWLOCK_INIT;
static MHOOKS_TRAMPOLINE* g_pHooks = NULL;
static MHOOKS_TRAMPOLINE* g_pFreeList = NULL;
// GCC ignores __declspec(thread) and says so only in a warning, which would
// have left this status shared between threads under MinGW while the public
// contract promises it is per thread. C11's _Thread_local is not available at
// C99, so each compiler gets the spelling it understands.
#if defined(_MSC_VER)
#define MHOOK_THREAD_LOCAL __declspec(thread)
#else
#define MHOOK_THREAD_LOCAL __thread
#endif

static MHOOK_THREAD_LOCAL MHOOK_STATUS g_lastStatus = MHOOK_STATUS_SUCCESS;

#define MHOOK_JMPSIZE 5
#define MHOOK_MINALLOCSIZE 4096

enum
{
    kReadableCodeProtectionMask = PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY,
    kReadableProtectionMask = PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | kReadableCodeProtectionMask,
    kWritableProtectionMask = PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
};

static const SIZE_T kMaximumRelativeJumpDistance = 0x7fff0000;

//=========================================================================
/**
 * @brief Unlinks a trampoline from a doubly linked list, updating the head pointer if necessary.
 * @param[in,out] pListHead List head to update when pNode is the current head.
 * @param[in,out] pNode Trampoline to unlink; its own link pointers are cleared.
 */
static VOID ListRemove(MHOOKS_TRAMPOLINE** pListHead, MHOOKS_TRAMPOLINE* pNode)
{
    if (pNode->pPrevTrampoline)
    {
        pNode->pPrevTrampoline->pNextTrampoline = pNode->pNextTrampoline;
    }

    if (pNode->pNextTrampoline)
    {
        pNode->pNextTrampoline->pPrevTrampoline = pNode->pPrevTrampoline;
    }

    if ((*pListHead) == pNode)
    {
        (*pListHead) = pNode->pNextTrampoline;
        assert(!(*pListHead) || (*pListHead)->pPrevTrampoline == NULL);
    }

    pNode->pPrevTrampoline = NULL;
    pNode->pNextTrampoline = NULL;
}

//=========================================================================
/**
 * @brief Inserts a trampoline at the head of a doubly linked list.
 * @param[in,out] pListHead List head, updated to point at pNode.
 * @param[in,out] pNode Trampoline to insert at the head.
 */
static VOID ListPrepend(MHOOKS_TRAMPOLINE** pListHead, MHOOKS_TRAMPOLINE* pNode)
{
    pNode->pPrevTrampoline = NULL;
    pNode->pNextTrampoline = (*pListHead);
    if ((*pListHead))
    {
        (*pListHead)->pPrevTrampoline = pNode;
    }
    (*pListHead) = pNode;
}

/**
 * @brief Acquires the process-wide lock guarding the hook registry and trampoline pool.
 * @remark The lock is not recursive; no path that holds it may acquire it again.
 */
static void lockRegistry(void)
{
    AcquireSRWLockExclusive(&g_registryLock);
}

/**
 * @brief Releases the lock acquired by lockRegistry.
 */
static void unlockRegistry(void)
{
    ReleaseSRWLockExclusive(&g_registryLock);
}

/**
 * @brief Reads the longest validated memory prefix up to the requested size.
 * @param[in] source Address to read.
 * @param[in] maximumSize Maximum number of bytes to read.
 * @param[in] protectionMask Allowed page protections.
 * @param[out] destination Buffer receiving the bytes.
 * @return Number of consecutive bytes validated and read.
 */
static SIZE_T readMemoryPrefix(const void* source, SIZE_T maximumSize, DWORD protectionMask, OUT void* destination)
{
    assert(destination);
    assert(maximumSize);

    const uintptr_t sourceAddress = (uintptr_t)source;

    if (!sourceAddress || maximumSize > UINTPTR_MAX - sourceAddress)
        return 0;

    const uintptr_t endAddress = sourceAddress + maximumSize;
    uintptr_t currentAddress = sourceAddress;

    // Find the consecutive prefix covered by allowed memory regions.
    while (currentAddress < endAddress)
    {
        MEMORY_BASIC_INFORMATION memory = {0};
        const SIZE_T querySize = VirtualQuery((const void*)currentAddress, &memory, sizeof(memory));

        if (querySize != sizeof(memory))
            break;

        const BOOL isCommitted = memory.State == MEM_COMMIT;
        const BOOL isGuarded = (memory.Protect & PAGE_GUARD) != 0;
        const BOOL hasAllowedProtection = (memory.Protect & protectionMask) != 0;

        if (!isCommitted || isGuarded || !hasAllowedProtection)
            break;

        const uintptr_t regionAddress = (uintptr_t)memory.BaseAddress;

        if (regionAddress > currentAddress || memory.RegionSize > UINTPTR_MAX - regionAddress)
            break;

        const uintptr_t regionEnd = regionAddress + memory.RegionSize;

        if (regionEnd <= currentAddress)
            break;

        currentAddress = regionEnd < endAddress ? regionEnd : endAddress;
    }

    // Copy only the prefix that passed validation.
    const SIZE_T readableSize = currentAddress - sourceAddress;

    if (!readableSize)
        return 0;

    SIZE_T bytesRead = 0;
    const BOOL readResult = ReadProcessMemory(GetCurrentProcess(), source, destination, readableSize, &bytesRead);

    if (!readResult || bytesRead != readableSize)
        return 0;

    return bytesRead;
}

/**
 * @brief Reads memory only when the complete range has an allowed protection.
 * @param[in] source Address to read.
 * @param[in] size Number of bytes to read.
 * @param[in] protectionMask Allowed page protections.
 * @param[out] destination Buffer receiving the bytes.
 * @return TRUE when the complete range was validated and read.
 */
static BOOL readMemory(const void* source, SIZE_T size, DWORD protectionMask, OUT void* destination)
{
    return readMemoryPrefix(source, size, protectionMask, destination) == size;
}

/**
 * @brief Validates and reads a caller-owned function-pointer slot.
 * @param[in] slot Pointer slot supplied to a public hook operation.
 * @param[out] value Function pointer read from the slot.
 * @return TRUE when the slot is aligned, committed, readable, and writable.
 */
static BOOL readWritablePointerSlot(PVOID* slot, OUT PVOID* value)
{
    assert(slot);
    assert(value);

    const uintptr_t slotAddress = (uintptr_t)slot;
    const BOOL isAligned = slotAddress % MHOOK_ALIGNOF(PVOID) == 0;

    if (!isAligned)
        return FALSE;

    return readMemory(slot, sizeof(*slot), kWritableProtectionMask, value);
}

/**
 * @brief Validates that a batch array can be read and receive per-request results.
 * @param[in,out] hooks Caller-owned descriptor array.
 * @param[in] hookCount Number of descriptors in hooks.
 * @return MHOOK_STATUS_SUCCESS when the entire array is usable; otherwise the validation failure.
 */
static MHOOK_STATUS validateHookInfoArray(MHOOK_HOOK_INFO* hooks, SIZE_T hookCount)
{
    const SIZE_T kHookMaxCount = SIZE_MAX / sizeof(*hooks);

    // Reject empty or overflowing ranges before calculating descriptor addresses.
    if (!hooks || !hookCount || hookCount > kHookMaxCount)
        return MHOOK_STATUS_INVALID_ARGUMENT;

    // Require natural alignment so every descriptor can be accessed safely.
    const uintptr_t hooksAddress = (uintptr_t)hooks;
    const BOOL isAligned = hooksAddress % MHOOK_ALIGNOF(MHOOK_HOOK_INFO) == 0;

    if (!isAligned)
        return MHOOK_STATUS_INVALID_DESCRIPTOR;

    // Validate every descriptor because each operation reads its fields and writes its status.
    for (SIZE_T index = 0; index < hookCount; ++index)
    {
        MHOOK_HOOK_INFO hook = {0};

        if (!readMemory(&hooks[index], sizeof(hook), kWritableProtectionMask, &hook))
            return MHOOK_STATUS_INVALID_DESCRIPTOR;
    }

    return MHOOK_STATUS_SUCCESS;
}

/**
 * @brief Carries the library status and legacy Win32 error for one unhook attempt.
 */
typedef struct UnhookResult
{
    MHOOK_STATUS status;
    DWORD lastError;
} UnhookResult;

/**
 * @brief Compares live target code with bytes retained by the hook transaction.
 * @param[in] target Target address to read through validated memory access.
 * @param[in] expected Expected target bytes.
 * @param[in] size Number of bytes to compare.
 * @return SUCCESS when the bytes match, INVALID_TARGET when they cannot be read, or TARGET_MODIFIED when they differ.
 */
static MHOOK_STATUS validateTargetCode(PBYTE target, const BYTE* expected, DWORD size)
{
    assert(target);
    assert(expected);
    assert(size && size <= MHOOKS_MAX_CODE_BYTES);

    BYTE liveCode[MHOOKS_MAX_CODE_BYTES] = {0};

    // Copy through validated access so an inaccessible target cannot crash the transaction.
    if (!readMemory(target, size, kReadableCodeProtectionMask, liveCode))
        return MHOOK_STATUS_INVALID_TARGET;

    // Refuse modification when another writer changed the retained target image.
    if (memcmp(liveCode, expected, size) != 0)
        return MHOOK_STATUS_TARGET_MODIFIED;

    return MHOOK_STATUS_SUCCESS;
}

/**
 * @brief Verifies that a hook target still contains Mhook's installed patch.
 * @param[in] trampoline Registered trampoline describing the target and patch.
 * @return SUCCESS when the patch matches, INVALID_TARGET when the target cannot be read, or TARGET_MODIFIED when its bytes differ.
 */
static MHOOK_STATUS validateInstalledPatch(const MHOOKS_TRAMPOLINE* trampoline)
{
    assert(trampoline);
    return validateTargetCode(
        trampoline->pSystemFunction,
        trampoline->codeInstalledPatch,
        trampoline->cbOverwrittenCode
    );
}

/**
 * @brief Restores the original target bytes when Mhook still owns the installed patch.
 * @param[in] trampoline Registered trampoline containing the original target bytes.
 * @param[in] callerLastError Error value to preserve when validation fails.
 * @return Detailed unhook status and corresponding LastError value.
 */
static UnhookResult restoreHookTarget(MHOOKS_TRAMPOLINE* trampoline, DWORD callerLastError)
{
    assert(trampoline);

    const DWORD patchSize = trampoline->cbOverwrittenCode;
    UnhookResult result = {0};
    result.status = validateInstalledPatch(trampoline);
    result.lastError = callerLastError;

    if (result.status == MHOOK_STATUS_TARGET_MODIFIED)
    {
        result.lastError = MHOOK_ERROR_TARGET_MODIFIED;
        return result;
    }

    if (result.status != MHOOK_STATUS_SUCCESS)
        return result;

    // Make the target writable only while restoring its original bytes.
    DWORD oldProtection = 0;
    if (!VirtualProtect(trampoline->pSystemFunction, patchSize, PAGE_EXECUTE_READWRITE, &oldProtection))
    {
        result.status = MHOOK_STATUS_MEMORY_PROTECTION_FAILED;
        result.lastError = GetLastError();
        return result;
    }

    memcpy(trampoline->pSystemFunction, trampoline->codeUntouched, patchSize);
    FlushInstructionCache(GetCurrentProcess(), trampoline->pSystemFunction, patchSize);
    VirtualProtect(trampoline->pSystemFunction, patchSize, oldProtection, &oldProtection);
    return result;
}

/**
 * @brief Finds an active hook by its resolved target address.
 * @param[in] targetFunction Resolved target address to find.
 * @return The registered trampoline, or NULL when the target is not hooked.
 * @remark The caller must hold the hook registry lock.
 */
static MHOOKS_TRAMPOLINE* findActiveHookByTarget(PBYTE targetFunction)
{
    assert(targetFunction);

    MHOOKS_TRAMPOLINE* currentHook = g_pHooks;
    while (currentHook)
    {
        if (currentHook->pSystemFunction == targetFunction)
            return currentHook;

        currentHook = currentHook->pNextTrampoline;
    }

    return NULL;
}

/**
 * @brief Calculates a checked address relative to the end of an instruction.
 * @param[in] instruction Address of the instruction.
 * @param[in] instructionSize Encoded instruction size.
 * @param[in] displacement Signed displacement from the instruction end.
 * @param[out] address Calculated non-null address.
 * @return TRUE when the address calculation does not overflow or underflow.
 */
static BOOL calculateRelativeAddress(
    PBYTE instruction,
    SIZE_T instructionSize,
    int32_t displacement,
    OUT PBYTE* address
)
{
    assert(instruction);
    assert(address);

    const uintptr_t instructionAddress = (uintptr_t)instruction;
    const int64_t signedDisplacement = displacement;

    if (instructionSize > UINTPTR_MAX - instructionAddress)
        return FALSE;

    uintptr_t resultAddress = instructionAddress + instructionSize;

    if (signedDisplacement < 0)
    {
        const uint64_t magnitude = (uint64_t)-signedDisplacement;

        if (magnitude > resultAddress)
            return FALSE;

        resultAddress -= (uintptr_t)magnitude;
    }
    else
    {
        const uint64_t magnitude = (uint64_t)signedDisplacement;

        if (magnitude > UINTPTR_MAX - resultAddress)
            return FALSE;

        resultAddress += (uintptr_t)magnitude;
    }

    if (!resultAddress)
        return FALSE;

    *address = (PBYTE)resultAddress;
    return TRUE;
}

/**
 * @brief Resolves a supported indirect entry-point jump.
 * @param[in] instruction Address of the jump instruction.
 * @param[in] hasRexPrefix Whether the x64 REX prefix was detected.
 * @param[out] nextFunction Jump destination, or NULL when the instruction is not a supported indirect jump.
 * @return Success or a validation failure.
 */
static MHOOK_STATUS resolveIndirectJump(PBYTE instruction, BOOL hasRexPrefix, OUT PBYTE* nextFunction)
{
    assert(instruction);
    assert(nextFunction);

    enum
    {
        kIndirectJumpOperand = 0x25,
        kIndirectOpcodeSize = 2,
        kIndirectJumpSize = 6,
        kIndirectDisplacementOffset = 2,
        kMaximumJumpSize = 7
    };

#ifdef _M_X64
    enum
    {
        kIndirectJumpOpcode = 0xFF,
        kRexOpcodeSize = 3,
        kRexIndirectJumpSize = 7,
        kRexIndirectDisplacementOffset = 3
    };
#endif // _M_X64

    SIZE_T jumpSize = kIndirectJumpSize;
    SIZE_T displacementOffset = kIndirectDisplacementOffset;
    uint8_t code[kMaximumJumpSize] = {0};

    if (!hasRexPrefix)
    {
        if (!readMemory(instruction, kIndirectOpcodeSize, kReadableCodeProtectionMask, code))
            return MHOOK_STATUS_INVALID_TARGET;

        if (code[1] != kIndirectJumpOperand)
            return MHOOK_STATUS_SUCCESS;
    }
#ifdef _M_X64
    else
    {
        if (!readMemory(instruction, kIndirectOpcodeSize, kReadableCodeProtectionMask, code))
            return MHOOK_STATUS_INVALID_TARGET;

        if (code[1] != kIndirectJumpOpcode)
            return MHOOK_STATUS_SUCCESS;

        if (!readMemory(instruction, kRexOpcodeSize, kReadableCodeProtectionMask, code))
            return MHOOK_STATUS_INVALID_TARGET;

        if (code[2] != kIndirectJumpOperand)
            return MHOOK_STATUS_SUCCESS;

        jumpSize = kRexIndirectJumpSize;
        displacementOffset = kRexIndirectDisplacementOffset;
    }
#else  // !_M_X64
    else
        return MHOOK_STATUS_INVALID_TARGET;
#endif // _M_X64

    if (!readMemory(instruction, jumpSize, kReadableCodeProtectionMask, code))
        return MHOOK_STATUS_INVALID_TARGET;

    PBYTE pointerSlot = NULL;

#ifdef _M_IX86
    uint32_t slotAddress = 0;
    memcpy(&slotAddress, code + displacementOffset, sizeof(slotAddress));
    pointerSlot = (PBYTE)(uintptr_t)slotAddress;
#elif defined _M_X64
    int32_t displacement = 0;
    memcpy(&displacement, code + displacementOffset, sizeof(displacement));

    if (!calculateRelativeAddress(instruction, jumpSize, displacement, &pointerSlot))
        return MHOOK_STATUS_INVALID_TARGET;
#else // !_M_IX86 && !_M_X64
#error unsupported platform
#endif // _M_IX86 || _M_X64

    *nextFunction = NULL;
    const BOOL readResult = readMemory(pointerSlot, sizeof(*nextFunction), kReadableProtectionMask, nextFunction);

    if (!readResult || !*nextFunction)
        return MHOOK_STATUS_INVALID_TARGET;

    return MHOOK_STATUS_SUCCESS;
}

/**
 * @brief Resolves a supported relative entry-point jump.
 * @param[in] instruction Address of the jump instruction.
 * @param[in] isNearJump Whether the instruction contains a 32-bit displacement.
 * @param[out] nextFunction Jump destination.
 * @return Success or a validation failure.
 */
static MHOOK_STATUS resolveRelativeJump(PBYTE instruction, BOOL isNearJump, OUT PBYTE* nextFunction)
{
    assert(instruction);
    assert(nextFunction);

    enum
    {
        kNearJumpSize = 5,
        kShortJumpSize = 2
    };

    const SIZE_T jumpSize = isNearJump ? kNearJumpSize : kShortJumpSize;

    uint8_t code[kNearJumpSize] = {0};

    if (!readMemory(instruction, jumpSize, kReadableCodeProtectionMask, code))
        return MHOOK_STATUS_INVALID_TARGET;

    int32_t displacement = 0;
    if (isNearJump)
        memcpy(&displacement, code + 1, sizeof(displacement));
    else
    {
        int8_t shortDisplacement = 0;
        memcpy(&shortDisplacement, code + 1, sizeof(shortDisplacement));
        displacement = shortDisplacement;
    }

    *nextFunction = NULL;
    if (!calculateRelativeAddress(instruction, jumpSize, displacement, nextFunction))
        return MHOOK_STATUS_INVALID_TARGET;

    return MHOOK_STATUS_SUCCESS;
}

/**
 * @brief Resolves one supported entry-point jump.
 * @param[in] function Address whose first instruction is inspected.
 * @param[out] nextFunction Jump destination, or NULL when no jump is present.
 * @return Success or a validation failure.
 */
static MHOOK_STATUS resolveSingleJump(PBYTE function, OUT PBYTE* nextFunction)
{
    assert(function);
    assert(nextFunction);

    enum
    {
        kNearJumpOpcode = 0xE9,
        kShortJumpOpcode = 0xEB,
        kIndirectJumpOpcode = 0xFF
    };

#ifdef _M_X64
    enum
    {
        kRexPrefix = 0x48
    };
#endif // _M_X64

#ifdef _M_IX86
    const uint8_t kHotPatchSequence[] = {0x8B, 0xFF};
    const uint8_t kCollapsedFrameSequence[] = {0x55, 0x8B, 0xEC, 0x5D};
#endif // _M_IX86

    *nextFunction = NULL;
    PBYTE instruction = function;

#ifdef _M_IX86
    uint8_t entryBytes[sizeof(kCollapsedFrameSequence)] = {0};

    // Preserve jumps placed after the x86 hot-patch sequence.
    if (!readMemory(instruction, 1, kReadableCodeProtectionMask, entryBytes))
        return MHOOK_STATUS_INVALID_TARGET;

    if (entryBytes[0] == kHotPatchSequence[0])
    {
        if (!readMemory(instruction, sizeof(kHotPatchSequence), kReadableCodeProtectionMask, entryBytes))
            return MHOOK_STATUS_INVALID_TARGET;

        if (memcmp(entryBytes, kHotPatchSequence, sizeof(kHotPatchSequence)) == 0)
            instruction += sizeof(kHotPatchSequence);
    }

    // Preserve jumps placed after MSVC's collapsed stack-frame sequence.
    if (!readMemory(instruction, 1, kReadableCodeProtectionMask, entryBytes))
        return MHOOK_STATUS_INVALID_TARGET;

    if (entryBytes[0] == kCollapsedFrameSequence[0])
    {
        if (!readMemory(instruction, sizeof(kCollapsedFrameSequence), kReadableCodeProtectionMask, entryBytes))
            return MHOOK_STATUS_INVALID_TARGET;

        if (memcmp(entryBytes, kCollapsedFrameSequence, sizeof(kCollapsedFrameSequence)) == 0)
            instruction += sizeof(kCollapsedFrameSequence);
    }
#endif // _M_IX86

    uint8_t opcode = 0;

    if (!readMemory(instruction, sizeof(opcode), kReadableCodeProtectionMask, &opcode))
        return MHOOK_STATUS_INVALID_TARGET;

    switch (opcode)
    {
    case kIndirectJumpOpcode:
        return resolveIndirectJump(instruction, FALSE, nextFunction);

#ifdef _M_X64
    case kRexPrefix:
        return resolveIndirectJump(instruction, TRUE, nextFunction);
#endif // _M_X64

    case kNearJumpOpcode:
        return resolveRelativeJump(instruction, TRUE, nextFunction);

    case kShortJumpOpcode:
        return resolveRelativeJump(instruction, FALSE, nextFunction);

    default:
        return MHOOK_STATUS_SUCCESS;
    }
}

/**
 * @brief Resolves a function through a bounded, acyclic jump chain.
 * @param[in] function Initial function address.
 * @param[out] target Final function address.
 * @return Success or the first resolution failure.
 */
static MHOOK_STATUS resolveFunctionTarget(PBYTE function, OUT PBYTE* target)
{
    assert(function);
    assert(target);

    enum
    {
        kMaximumJumpDepth = 16
    };

    PBYTE visitedFunctions[kMaximumJumpDepth + 1] = {0};
    PBYTE currentFunction = function;

    *target = NULL;

    for (SIZE_T depth = 0; depth <= kMaximumJumpDepth; ++depth)
    {
        if (findActiveHookByTarget(currentFunction))
            return MHOOK_STATUS_ALREADY_HOOKED;

        visitedFunctions[depth] = currentFunction;

        PBYTE nextFunction = NULL;
        const MHOOK_STATUS status = resolveSingleJump(currentFunction, &nextFunction);

        if (status != MHOOK_STATUS_SUCCESS)
            return status;

        if (!nextFunction)
        {
            *target = currentFunction;
            return MHOOK_STATUS_SUCCESS;
        }

        // Report a cycle even when it closes at the depth boundary.
        for (SIZE_T index = 0; index <= depth; ++index)
        {
            if (visitedFunctions[index] == nextFunction)
                return MHOOK_STATUS_JUMP_CYCLE;
        }

        currentFunction = nextFunction;
    }

    return MHOOK_STATUS_JUMP_DEPTH_EXCEEDED;
}

/**
 * @brief Resolves and validates both functions in a hook request.
 * @param[in] systemFunction Requested target function.
 * @param[in] hookFunction Requested replacement function.
 * @param[out] resolvedSystemFunction Resolved target function.
 * @param[out] resolvedHookFunction Resolved replacement function.
 * @return Success or the first request validation failure.
 */
static MHOOK_STATUS resolveHookRequest(
    PBYTE systemFunction,
    PBYTE hookFunction,
    OUT PBYTE* resolvedSystemFunction,
    OUT PBYTE* resolvedHookFunction
)
{
    assert(systemFunction);
    assert(hookFunction);
    assert(resolvedSystemFunction);
    assert(resolvedHookFunction);

    MHOOK_STATUS status = resolveFunctionTarget(systemFunction, resolvedSystemFunction);
    if (status != MHOOK_STATUS_SUCCESS)
        return status;

    status = resolveFunctionTarget(hookFunction, resolvedHookFunction);
    if (status != MHOOK_STATUS_SUCCESS)
        return status;

    if (*resolvedSystemFunction == *resolvedHookFunction)
        return MHOOK_STATUS_INVALID_ARGUMENT;

    return MHOOK_STATUS_SUCCESS;
}

/**
 * @brief Encodes a jump into private storage for a specified execution address.
 * @param[in] source Address where the instruction will execute after publication.
 * @param[in] destination Address reached by the jump.
 * @param[out] output Storage receiving the encoded instruction.
 * @return First byte after the encoded instruction in output.
 */
static PBYTE emitJump(PBYTE source, PBYTE destination, OUT PBYTE output)
{
    assert(output);
    assert(source);
    assert(destination);

    const uint8_t kRelativeJumpOpcode = 0xe9;
    const uint8_t kIndirectJumpOpcode = 0xff;
    const uint8_t kIndirectJumpOperand = 0x25;
    const SIZE_T kRelativeJumpSize = 5;
    const SIZE_T kIndirectJumpHeaderSize = 6;

#ifdef _M_IX86_X64
    ULONG_PTR nextInstructionAddress = (ULONG_PTR)source + kRelativeJumpSize;
    ULONG_PTR destinationAddress = (ULONG_PTR)destination;
    SIZE_T distance = nextInstructionAddress > destinationAddress ? nextInstructionAddress - destinationAddress
                                                                  : destinationAddress - nextInstructionAddress;

    ODPRINTF((L"mhooks: emitJump: Jumping from %p to %p, diff is %p", source, destination, distance));

    if (distance <= kMaximumRelativeJumpDistance)
    {
        uint32_t displacement = (uint32_t)(destinationAddress - nextInstructionAddress);

        output[0] = kRelativeJumpOpcode;
        memcpy(output + 1, &displacement, sizeof(displacement));
        return output + kRelativeJumpSize;
    }

    output[0] = kIndirectJumpOpcode;
    output[1] = kIndirectJumpOperand;

#ifdef _M_IX86
    // The absolute operand points to the destination stored after the instruction.
    uint32_t pointerAddress = (uint32_t)((ULONG_PTR)source + kIndirectJumpHeaderSize);
    memcpy(output + 2, &pointerAddress, sizeof(pointerAddress));
#elif defined _M_X64
    // The zero displacement addresses the destination stored after the instruction.
    uint32_t displacement = 0;
    memcpy(output + 2, &displacement, sizeof(displacement));
#endif // _M_IX86 || _M_X64

    memcpy(output + kIndirectJumpHeaderSize, &destinationAddress, sizeof(destinationAddress));
    return output + kIndirectJumpHeaderSize + sizeof(destinationAddress);
#else // !_M_IX86_X64
#error unsupported platform
#endif // _M_IX86_X64
}

//=========================================================================
/**
 * @brief Rounds an address down to the nearest lower multiple of a given granularity.
 * @param[in] addr Address to round down.
 * @param[in] rndDown Granularity to round to.
 * @return addr rounded down to the nearest multiple of rndDown.
 */
static size_t RoundDown(size_t addr, size_t rndDown)
{
    return (addr / rndDown) * rndDown;
}

//=========================================================================
/**
 * @brief Allocates a new page of trampoline-sized entries as close as possible to a target function and chains it onto the free list.
 * @param[in] pSystemFunction Address the allocation should land near.
 * @param[in] pbLower Lowest address the search is allowed to consider.
 * @param[in] pbUpper Highest address the search is allowed to consider.
 * @return Head of the newly allocated block, already linked to the previous g_pFreeList; NULL when no suitable free region was found.
 */
static MHOOKS_TRAMPOLINE* BlockAlloc(PBYTE pSystemFunction, PBYTE pbLower, PBYTE pbUpper)
{
    SYSTEM_INFO sSysInfo = {0};
    GetSystemInfo(&sSysInfo);

    // Always allocate in bulk, in case the system actually has a smaller allocation granularity than MINALLOCSIZE.
    const SIZE_T cAllocSize = max(sSysInfo.dwAllocationGranularity, MHOOK_MINALLOCSIZE);

    MHOOKS_TRAMPOLINE* pRetVal = NULL;
    PBYTE pModuleGuess = (PBYTE)RoundDown((size_t)pSystemFunction, cAllocSize);
    int loopCount = 0;
    for (PBYTE pbAlloc = pModuleGuess; pbLower < pbAlloc && pbAlloc < pbUpper; ++loopCount)
    {
        // determine current state
        MEMORY_BASIC_INFORMATION mbi;
        ODPRINTF((L"mhooks: BlockAlloc: Looking at address %p", pbAlloc));
        if (!VirtualQuery(pbAlloc, &mbi, sizeof(mbi)))
            break;
        // free & large enough?
        if (mbi.State == MEM_FREE && mbi.RegionSize >= cAllocSize)
        {
            // and then try to allocate it
            pRetVal =
                (MHOOKS_TRAMPOLINE*)VirtualAlloc(pbAlloc, cAllocSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (pRetVal)
            {
                size_t trampolineCount = cAllocSize / sizeof(MHOOKS_TRAMPOLINE);
                ODPRINTF((L"mhooks: BlockAlloc: Allocated block at %p as %zu trampolines", pRetVal, trampolineCount));

                pRetVal[0].pPrevTrampoline = NULL;
                pRetVal[0].pNextTrampoline = &pRetVal[1];

                // prepare them by having them point down the line at the next entry.
                for (size_t s = 1; s < trampolineCount; ++s)
                {
                    pRetVal[s].pPrevTrampoline = &pRetVal[s - 1];
                    pRetVal[s].pNextTrampoline = &pRetVal[s + 1];
                }

                MHOOKS_TRAMPOLINE* lastTrampoline = &pRetVal[trampolineCount - 1];

                // Join the new block to the existing free list in both directions.
                lastTrampoline->pNextTrampoline = g_pFreeList;

                if (g_pFreeList)
                    g_pFreeList->pPrevTrampoline = lastTrampoline;
                break;
            }
        }

        // This is a spiral, should be -1, 1, -2, 2, -3, 3, etc. (* cAllocSize)
        ptrdiff_t bytesToOffset = ((ptrdiff_t)cAllocSize * (loopCount + 1) * ((loopCount % 2 == 0) ? -1 : 1));
        pbAlloc = pbAlloc + bytesToOffset;
    }

    return pRetVal;
}

//=========================================================================
/**
 * @brief Finds and detaches the first free-list trampoline located strictly within an address range.
 * @param[in] pLower Exclusive lower bound of the accepted range.
 * @param[in] pUpper Exclusive upper bound of the accepted range.
 * @return The detached trampoline, or NULL when none of the free list entries fall within range.
 */
static MHOOKS_TRAMPOLINE* FindTrampolineInRange(PBYTE pLower, PBYTE pUpper)
{
    if (!g_pFreeList)
    {
        return NULL;
    }

    // This is a standard free list, except we're doubly linked to deal with soem return shenanigans.
    MHOOKS_TRAMPOLINE* curEntry = g_pFreeList;
    while (curEntry)
    {
        if ((MHOOKS_TRAMPOLINE*)pLower < curEntry && curEntry < (MHOOKS_TRAMPOLINE*)pUpper)
        {
            ListRemove(&g_pFreeList, curEntry);

            return curEntry;
        }

        curEntry = curEntry->pNextTrampoline;
    }

    return NULL;
}

/**
 * @brief Reserves unpublished trampoline storage within the required relocation range.
 * @param[in] systemFunction Resolved target used as the center of the allocation range.
 * @param[in] limitUp Furthest positive RIP-relative displacement copied from the target.
 * @param[in] limitDown Furthest negative RIP-relative displacement copied from the target.
 * @return Cleared private storage, or NULL when no suitable allocation is available.
 */
static MHOOKS_TRAMPOLINE* reserveTrampoline(PBYTE systemFunction, S64 limitUp, S64 limitDown)
{
    assert(systemFunction);

    // Restrict the allocation range so relocated instructions remain representable.
    PBYTE lower = systemFunction + limitUp;
    lower = lower < (PBYTE)(DWORD_PTR)0x0000000080000000 ? (PBYTE)0x1 : lower - kMaximumRelativeJumpDistance;

    // The bounds near the top of the address space are built with ~ at pointer
    // width, so they mean the same thing on x86 instead of truncating a 64-bit
    // literal.
    PBYTE upper = systemFunction + limitDown;
    upper = upper < (PBYTE) ~(DWORD_PTR)0x7fffffff ? upper + (DWORD_PTR)0x7ff80000 : (PBYTE) ~(DWORD_PTR)0x7ffff;

    ODPRINTF((L"mhooks: reserveTrampoline: Allocating for %p between %p and %p", systemFunction, lower, upper));

    // Reuse a suitable free entry or allocate another block when necessary.
    MHOOKS_TRAMPOLINE* trampoline = FindTrampolineInRange(lower, upper);
    if (!trampoline)
    {
        g_pFreeList = BlockAlloc(systemFunction, lower, upper);
        trampoline = FindTrampolineInRange(lower, upper);
    }

    if (trampoline)
        memset(trampoline, 0, sizeof(*trampoline));

    return trampoline;
}

/**
 * @brief Publishes a fully prepared trampoline in the active-hook registry.
 * @param[in] trampoline Prepared trampoline whose target patch is installed.
 */
static void activateTrampoline(MHOOKS_TRAMPOLINE* trampoline)
{
    assert(trampoline);

    ListPrepend(&g_pHooks, trampoline);
}

/**
 * @brief Returns an unpublished trampoline reservation to the free list.
 * @param[in] trampoline Reserved trampoline that was never exposed to callers.
 */
static void releaseTrampoline(MHOOKS_TRAMPOLINE* trampoline)
{
    assert(trampoline);

    ListPrepend(&g_pFreeList, trampoline);
}

//=========================================================================
/**
 * @brief Finds the active trampoline whose generated trampoline code starts at a given address.
 * @param[in] pHookedFunction Address previously handed to a caller as a hook's trampoline.
 * @return The matching registered trampoline, or NULL when none matches.
 * @remark The caller must hold the hook registry lock.
 */
static MHOOKS_TRAMPOLINE* TrampolineGet(PBYTE pHookedFunction)
{
    MHOOKS_TRAMPOLINE* pCurrent = g_pHooks;

    while (pCurrent)
    {
        if (pCurrent->codeTrampoline == pHookedFunction)
        {
            return pCurrent;
        }

        pCurrent = pCurrent->pNextTrampoline;
    }

    return NULL;
}

/**
 * @brief Removes an active trampoline without making executable storage reusable.
 * @param[in] trampoline Registered trampoline being removed.
 */
static void retireTrampoline(MHOOKS_TRAMPOLINE* trampoline)
{
    assert(trampoline);

    ListRemove(&g_pHooks, trampoline);

    // Active storage remains allocated because another thread may return through it.
}

/**
 * @brief Releases every peer-thread suspension owned by one transaction.
 * @param[in,out] suspension Owned threads to resume, close, and discard.
 * @return SUCCESS, or THREAD_RESUME_FAILED with the error of the first thread that could not be resumed.
 */
static MHOOK_STATUS resumeOtherThreads(ThreadSuspension* suspension)
{
    assert(suspension);

    MHOOK_STATUS status = MHOOK_STATUS_SUCCESS;
    DWORD resumeError = ERROR_SUCCESS;

    // Attempt every release even when an earlier thread cannot be resumed.
    for (SIZE_T index = 0; index < suspension->count; ++index)
    {
        HANDLE handle = suspension->threads[index].handle;
        assert(GOOD_HANDLE(handle));

        if (ResumeThread(handle) == (DWORD)-1 && status == MHOOK_STATUS_SUCCESS)
        {
            status = MHOOK_STATUS_THREAD_RESUME_FAILED;
            resumeError = GetLastError();
        }

        if (!CloseHandle(handle))
            ODPRINTF((L"mhooks: resumeOtherThreads: failed to close a peer thread handle: %d", gle()));
    }

    // Discard the thread list after every thread release was attempted.
    if (suspension->threads && !VirtualFree(suspension->threads, 0, MEM_RELEASE))
        ODPRINTF((L"mhooks: resumeOtherThreads: failed to free the suspended thread list: %d", gle()));

    suspension->threads = NULL;
    suspension->count = 0;
    suspension->capacity = 0;

    if (status != MHOOK_STATUS_SUCCESS)
        SetLastError(resumeError);

    return status;
}

/**
 * @brief Reports whether a thread is already suspended by this transaction.
 * @param[in] suspension Threads suspended so far.
 * @param[in] threadId Identifier to look for.
 * @return TRUE when threadId is in the suspension.
 * @remark An identifier cannot be reused while this transaction holds a handle to its thread.
 */
static BOOL isThreadSuspended(const ThreadSuspension* suspension, DWORD threadId)
{
    assert(suspension);

    // ponytail: linear scan per snapshot entry, quadratic in the thread count; a sorted set if that ever shows up.
    for (SIZE_T index = 0; index < suspension->count; ++index)
    {
        if (suspension->threads[index].threadId == threadId)
            return TRUE;
    }

    return FALSE;
}

/**
 * @brief Guarantees room for one more suspended thread before the next suspension.
 * @param[in,out] suspension Thread list to grow when it is full.
 * @return TRUE when the list can take another entry.
 */
static BOOL reserveSuspendedThread(ThreadSuspension* suspension)
{
    assert(suspension);

    if (suspension->count < suspension->capacity)
        return TRUE;

    // Grow without the heap, which a suspended peer may have locked.
    const SIZE_T kInitialCapacity = 256;
    const SIZE_T capacity = suspension->capacity ? suspension->capacity * 2 : kInitialCapacity;
    SuspendedThread* threads =
        (SuspendedThread*)VirtualAlloc(NULL, capacity * sizeof(*threads), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!threads)
        return FALSE;

    if (suspension->threads)
    {
        memcpy(threads, suspension->threads, suspension->count * sizeof(*threads));
        if (!VirtualFree(suspension->threads, 0, MEM_RELEASE))
            ODPRINTF((L"mhooks: reserveSuspendedThread: failed to free the previous thread list: %d", gle()));
    }

    suspension->threads = threads;
    suspension->capacity = capacity;
    return TRUE;
}

/**
 * @brief Classifies a peer that SuspendThread refused although its handle holds the right to suspend it.
 * @param[in] threadId Peer whose suspension failed.
 * @param[in] suspendError Error reported by SuspendThread.
 * @return SUCCESS when the peer has exited and needs no suspension, THREAD_BUSY while it is still
 *         exiting, otherwise THREAD_SUSPENSION_FAILED.
 * @remark SuspendThread refuses a terminating thread with ERROR_ACCESS_DENIED, the error a missing
 *         access right would give. The handle holds that right, so the thread is checked for exit.
 */
static MHOOK_STATUS classifySuspendFailure(DWORD threadId, DWORD suspendError)
{
    const DWORD kExitWaitMilliseconds = 100;

    if (suspendError != ERROR_ACCESS_DENIED)
    {
        SetLastError(suspendError);
        return MHOOK_STATUS_THREAD_SUSPENSION_FAILED;
    }

    // Only a thread that has finished exiting is known to run no more code.
    HANDLE handle = OpenThread(SYNCHRONIZE, FALSE, threadId);
    if (!GOOD_HANDLE(handle))
    {
        if (GetLastError() == ERROR_INVALID_PARAMETER)
            return MHOOK_STATUS_SUCCESS;

        SetLastError(suspendError);
        return MHOOK_STATUS_THREAD_SUSPENSION_FAILED;
    }

    const DWORD waitResult = WaitForSingleObject(handle, kExitWaitMilliseconds);

    if (!CloseHandle(handle))
        ODPRINTF((L"mhooks: classifySuspendFailure: failed to close thread %d: %d", threadId, gle()));

    if (waitResult == WAIT_OBJECT_0)
        return MHOOK_STATUS_SUCCESS;

    if (waitResult == WAIT_TIMEOUT)
    {
        SetLastError(ERROR_RETRY);
        return MHOOK_STATUS_THREAD_BUSY;
    }

    SetLastError(suspendError);
    return MHOOK_STATUS_THREAD_SUSPENSION_FAILED;
}

/**
 * @brief Suspends one peer outside every pending code range.
 * @param[in] threadId Identifier of the peer thread to suspend.
 * @param[in] trampolines Prepared or active hooks whose target bytes will be modified.
 * @param[in] trampolineCount Number of entries in trampolines.
 * @param[out] suspendedHandle Owned suspended handle, or NULL when no suspension remains.
 * @return SUCCESS when the peer is suspended at a safe instruction pointer, or has exited since the
 *         snapshot and needs no suspension, leaving suspendedHandle NULL. Otherwise the thread failure.
 */
static MHOOK_STATUS suspendOneThread(
    DWORD threadId,
    MHOOKS_TRAMPOLINE** trampolines,
    SIZE_T trampolineCount,
    OUT HANDLE* suspendedHandle
)
{
    assert(threadId);
    assert(trampolines);
    assert(trampolineCount);
    assert(suspendedHandle);

    const DWORD kMaximumInstructionPointerRetries = 3;

    *suspendedHandle = NULL;

    HANDLE handle = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT, FALSE, threadId);
    if (!GOOD_HANDLE(handle))
    {
        const DWORD openError = GetLastError();

        // The thread exited, and its object is gone, after the snapshot listed it.
        if (openError == ERROR_INVALID_PARAMETER)
            return MHOOK_STATUS_SUCCESS;

        return openError == ERROR_ACCESS_DENIED ? MHOOK_STATUS_THREAD_ACCESS_DENIED
                                                : MHOOK_STATUS_THREAD_SUSPENSION_FAILED;
    }

    // Retry when the peer stops inside bytes that the operation will modify.
    for (DWORD retry = 0;; ++retry)
    {
        if (SuspendThread(handle) == (DWORD)-1)
        {
            const MHOOK_STATUS status = classifySuspendFailure(threadId, GetLastError());
            const DWORD failureError = GetLastError();

            if (!CloseHandle(handle))
                ODPRINTF((L"mhooks: suspendOneThread: failed to close thread %d: %d", threadId, gle()));

            SetLastError(failureError);
            return status;
        }

        *suspendedHandle = handle;

        CONTEXT context = {0};
        context.ContextFlags = CONTEXT_CONTROL;

        if (!GetThreadContext(handle, &context))
            return MHOOK_STATUS_THREAD_SUSPENSION_FAILED;

        PBYTE instructionPointer = NULL;

#ifdef _M_IX86
        instructionPointer = (PBYTE)(DWORD_PTR)context.Eip;
#elif defined _M_X64
        instructionPointer = (PBYTE)(DWORD_PTR)context.Rip;
#endif // _M_IX86

        const uintptr_t instructionAddress = (uintptr_t)instructionPointer;
        BOOL isColliding = FALSE;

        // Compare the instruction pointer with every target in the transaction.
        for (SIZE_T index = 0; index < trampolineCount; ++index)
        {
            const uintptr_t rangeAddress = (uintptr_t)trampolines[index]->pSystemFunction;
            const SIZE_T rangeSize = trampolines[index]->cbOverwrittenCode;

            if (instructionAddress >= rangeAddress && instructionAddress < rangeAddress + rangeSize)
            {
                isColliding = TRUE;
                break;
            }
        }

        if (!isColliding)
            return MHOOK_STATUS_SUCCESS;

        if (retry == kMaximumInstructionPointerRetries)
        {
            SetLastError(ERROR_RETRY);
            return MHOOK_STATUS_THREAD_BUSY;
        }

        // Release only this transaction's suspension while the instruction pointer moves.
        if (ResumeThread(handle) == (DWORD)-1)
            return MHOOK_STATUS_THREAD_RESUME_FAILED;

        *suspendedHandle = NULL;
        Sleep(100);
    }
}

/**
 * @brief Suspends every peer in a fresh snapshot that earlier snapshots did not list.
 * @param[in] trampolines Prepared or active hooks whose target bytes will be changed.
 * @param[in] trampolineCount Number of entries in trampolines.
 * @param[in,out] suspension Threads suspended so far, extended with the newly suspended ones.
 * @return SUCCESS when every newly listed peer is suspended at a safe instruction pointer or has exited.
 */
static MHOOK_STATUS suspendSnapshotThreads(
    MHOOKS_TRAMPOLINE** trampolines,
    SIZE_T trampolineCount,
    ThreadSuspension* suspension
)
{
    assert(trampolines);
    assert(trampolineCount);
    assert(suspension);

    const DWORD processId = GetCurrentProcessId();
    const DWORD currentThreadId = GetCurrentThreadId();

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, processId);
    if (!GOOD_HANDLE(snapshot))
        return MHOOK_STATUS_THREAD_ENUMERATION_FAILED;

    THREADENTRY32 entry = {0};
    entry.dwSize = sizeof(entry);

    MHOOK_STATUS status =
        Thread32First(snapshot, &entry) ? MHOOK_STATUS_SUCCESS : MHOOK_STATUS_THREAD_ENUMERATION_FAILED;

    while (status == MHOOK_STATUS_SUCCESS)
    {
        const BOOL isNewPeer = entry.th32OwnerProcessID == processId && entry.th32ThreadID != currentThreadId &&
                               !isThreadSuspended(suspension, entry.th32ThreadID);

        if (isNewPeer)
        {
            if (!reserveSuspendedThread(suspension))
            {
                SetLastError(ERROR_NOT_ENOUGH_MEMORY);
                status = MHOOK_STATUS_THREAD_SUSPENSION_FAILED;
                break;
            }

            HANDLE suspendedHandle = NULL;
            status = suspendOneThread(entry.th32ThreadID, trampolines, trampolineCount, &suspendedHandle);

            if (GOOD_HANDLE(suspendedHandle))
            {
                suspension->threads[suspension->count].handle = suspendedHandle;
                suspension->threads[suspension->count].threadId = entry.th32ThreadID;
                ++suspension->count;
            }

            if (status != MHOOK_STATUS_SUCCESS)
                break;
        }

        entry.dwSize = sizeof(entry);
        if (!Thread32Next(snapshot, &entry))
        {
            if (GetLastError() != ERROR_NO_MORE_FILES)
                status = MHOOK_STATUS_THREAD_ENUMERATION_FAILED;
            break;
        }
    }

    // Preserve the failure across snapshot cleanup.
    const DWORD lastError = GetLastError();
    if (!CloseHandle(snapshot))
        ODPRINTF((L"mhooks: suspendSnapshotThreads: failed to close the thread snapshot: %d", gle()));

    SetLastError(lastError);
    return status;
}

/**
 * @brief Suspends every peer, including threads started while earlier peers were being suspended.
 * @param[in] trampolines Prepared or active hooks whose target bytes will be changed.
 * @param[in] trampolineCount Number of entries in trampolines.
 * @param[out] suspension Owned suspension context to release after code modification.
 * @return SUCCESS once a snapshot lists no peer that is not already suspended at a safe instruction
 *         pointer. Otherwise the thread failure, with every peer already suspended released again.
 * @remark A thread started from outside the process, by CreateRemoteThread or by the kernel, can
 *         still appear after the final snapshot. Only the process's own threads are held.
 */
static MHOOK_STATUS suspendOtherThreads(
    MHOOKS_TRAMPOLINE** trampolines,
    SIZE_T trampolineCount,
    OUT ThreadSuspension* suspension
)
{
    assert(trampolines);
    assert(trampolineCount);
    assert(suspension);

    const DWORD kMaximumSnapshotPasses = 8;

    suspension->threads = NULL;
    suspension->count = 0;
    suspension->capacity = 0;

    MHOOK_STATUS status = MHOOK_STATUS_THREAD_BUSY;

    // A running peer can start a thread after the snapshot that listed it, so repeat until a
    // snapshot finds nothing new. Suspended peers start nothing, so this normally takes two.
    for (DWORD pass = 0; pass < kMaximumSnapshotPasses; ++pass)
    {
        const SIZE_T suspendedBefore = suspension->count;

        status = suspendSnapshotThreads(trampolines, trampolineCount, suspension);
        if (status != MHOOK_STATUS_SUCCESS)
            break;

        if (suspension->count == suspendedBefore)
            return MHOOK_STATUS_SUCCESS;

        // Reported only if the thread set never settles within the pass limit.
        status = MHOOK_STATUS_THREAD_BUSY;
        SetLastError(ERROR_RETRY);
    }

    // A peer left suspended outweighs the failure that ended the suspension.
    const DWORD failureError = GetLastError();
    if (resumeOtherThreads(suspension) != MHOOK_STATUS_SUCCESS)
        return MHOOK_STATUS_THREAD_RESUME_FAILED;

    SetLastError(failureError);
    return status;
}

//=========================================================================
/**
 * @brief Rewrites each recorded RIP-relative displacement so relocated code still addresses the original location.
 * @param[in,out] pbNew Relocated code buffer whose displacement operands are patched in place.
 * @param[in] pbOriginal Original address the relocated code was copied from.
 * @param[in] pdata Per-instruction offsets and original displacements collected while decoding.
 * @remark Compiles to a no-op outside x64 builds, since pdata->nRipCnt is only ever populated there.
 */
static void FixupIPRelativeAddressing(PBYTE pbNew, PBYTE pbOriginal, MHOOKS_PATCHDATA* pdata)
{
#if defined _M_X64
    S64 diff = pbNew - pbOriginal;
    for (DWORD i = 0; i < pdata->nRipCnt; i++)
    {
        DWORD dwNewDisplacement = (DWORD)(pdata->rips[i].nDisplacement - diff);
        ODPRINTF(
            (L"mhooks: fixing up RIP instruction operand for code at 0x%p: "
             L"old displacement: 0x%8.8x, new displacement: 0x%8.8x",
             pbNew + pdata->rips[i].dwOffset,
             (DWORD)pdata->rips[i].nDisplacement,
             dwNewDisplacement)
        );
        *(PDWORD)(pbNew + pdata->rips[i].dwOffset) = dwNewDisplacement;
    }
#else
    (void)pbNew;
    (void)pbOriginal;
    (void)pdata;
#endif
}

/**
 * @brief Decodes a function prologue through complete instruction boundaries.
 * @param[in] pFunction Function entry point represented by the decoded bytes.
 * @param[in] dwMinLen Minimum number of complete bytes required for the patch.
 * @param[out] snapshot Validated target bytes used by the decoder.
 * @param[out] pdata Collected relocation limits and RIP-relative patch data.
 * @param[out] instructionLength Number of complete bytes decoded.
 * @return Status describing whether the prologue can be patched.
 */
static MHOOK_STATUS DisassembleAndSkip(
    PVOID pFunction,
    DWORD dwMinLen,
    OUT U8 snapshot[MHOOKS_MAX_CODE_BYTES],
    OUT MHOOKS_PATCHDATA* pdata,
    OUT DWORD* instructionLength
)
{
    assert(pFunction);
    assert(snapshot);
    assert(pdata);
    assert(instructionLength);
    assert(dwMinLen && dwMinLen <= MHOOKS_MAX_CODE_BYTES);

    *instructionLength = 0;
    pdata->nLimitDown = 0;
    pdata->nLimitUp = 0;
    pdata->nRipCnt = 0;
    memset(snapshot, 0, MHOOKS_MAX_CODE_BYTES);

    // Decode only from bytes copied out of validated executable memory.
    SIZE_T snapshotSize = readMemoryPrefix(pFunction, MHOOKS_MAX_CODE_BYTES, kReadableCodeProtectionMask, snapshot);

    if (!snapshotSize)
        return MHOOK_STATUS_INVALID_TARGET;

    DWORD dwRet = 0;
    MHOOK_STATUS status = MHOOK_STATUS_DECODE_FAILED;

#ifdef _M_IX86
    ARCHITECTURE_TYPE arch = ARCH_X86;
#elif defined _M_X64
    ARCHITECTURE_TYPE arch = ARCH_X64;
#else
#error unsupported platform
#endif

    DISASSEMBLER dis;

    if (InitDisassembler(&dis, arch))
    {
        U8* pLoc = (U8*)pFunction;
        U8* snapshotLocation = snapshot;
        DWORD dwFlags = DISASM_DECODE | DISASM_DISASSEMBLE | DISASM_ALIGNOUTPUT;

        ODPRINTF((L"mhooks: DisassembleAndSkip: Disassembling %p", pLoc));
        while (dwRet < dwMinLen)
        {
            INSTRUCTION* pins = GetInstruction(&dis, (ULONG_PTR)pLoc, snapshotLocation, dwFlags);

            if (!pins)
            {
                status = MHOOK_STATUS_DECODE_FAILED;
                break;
            }

            const SIZE_T remainingSize = snapshotSize - dwRet;

            if (!pins->Length || pins->Length > remainingSize)
            {
                status = MHOOK_STATUS_INVALID_TARGET;
                break;
            }

            status = MHOOK_STATUS_UNSUPPORTED_PROLOGUE;
            ODPRINTFA(("mhooks: DisassembleAndSkip: %p:(0x%2.2x) %s", pLoc, pins->Length, pins->String));
            if (pins->Type == ITYPE_RET)
                break;
            if (pins->Type == ITYPE_BRANCH)
                break;
            if (pins->Type == ITYPE_BRANCHCC)
                break;
            if (pins->Type == ITYPE_CALL)
                break;
            if (pins->Type == ITYPE_CALLCC)
                break;

#if defined _M_X64
            BOOL bProcessRip = FALSE;
            // mov or lea to register from rip+imm32
            if ((pins->Type == ITYPE_MOV || pins->Type == ITYPE_LEA) && (pins->X86.Relative) &&
                (pins->X86.OperandSize == 8) && (pins->OperandCount == 2) && (pins->Operands[1].Flags & OP_IPREL) &&
                (pins->Operands[1].Register == AMD64_REG_RIP))
            {
                // rip-addressing "mov reg, [rip+imm32]"
                ODPRINTF(
                    (L"mhooks: DisassembleAndSkip: found OP_IPREL on operand %d with displacement 0x%x (in memory: "
                     L"0x%x)",
                     1,
                     pins->X86.Displacement,
                     *(PDWORD)(snapshotLocation + 3))
                );
                bProcessRip = TRUE;
            }
            // mov or lea to rip+imm32 from register
            else if ((pins->Type == ITYPE_MOV || pins->Type == ITYPE_LEA) && (pins->X86.Relative) &&
                     (pins->X86.OperandSize == 8) && (pins->OperandCount == 2) &&
                     (pins->Operands[0].Flags & OP_IPREL) && (pins->Operands[0].Register == AMD64_REG_RIP))
            {
                // rip-addressing "mov [rip+imm32], reg"
                ODPRINTF(
                    (L"mhooks: DisassembleAndSkip: found OP_IPREL on operand %d with displacement 0x%x (in memory: "
                     L"0x%x)",
                     0,
                     pins->X86.Displacement,
                     *(PDWORD)(snapshotLocation + 3))
                );
                bProcessRip = TRUE;
            }
            else if ((pins->OperandCount >= 1) && (pins->Operands[0].Flags & OP_IPREL))
            {
                // unsupported rip-addressing
                ODPRINTF((L"mhooks: DisassembleAndSkip: found unsupported OP_IPREL on operand %d", 0));
                // dump instruction bytes to the debug output
                for (DWORD i = 0; i < pins->Length; i++)
                {
                    ODPRINTF((L"mhooks: DisassembleAndSkip: instr byte %2.2d: 0x%2.2x", i, snapshotLocation[i]));
                }
                break;
            }
            else if ((pins->OperandCount >= 2) && (pins->Operands[1].Flags & OP_IPREL))
            {
                // unsupported rip-addressing
                ODPRINTF((L"mhooks: DisassembleAndSkip: found unsupported OP_IPREL on operand %d", 1));
                // dump instruction bytes to the debug output
                for (DWORD i = 0; i < pins->Length; i++)
                {
                    ODPRINTF((L"mhooks: DisassembleAndSkip: instr byte %2.2d: 0x%2.2x", i, snapshotLocation[i]));
                }
                break;
            }
            else if ((pins->OperandCount >= 3) && (pins->Operands[2].Flags & OP_IPREL))
            {
                // unsupported rip-addressing
                ODPRINTF((L"mhooks: DisassembleAndSkip: found unsupported OP_IPREL on operand %d", 2));
                // dump instruction bytes to the debug output
                for (DWORD i = 0; i < pins->Length; i++)
                {
                    ODPRINTF((L"mhooks: DisassembleAndSkip: instr byte %2.2d: 0x%2.2x", i, snapshotLocation[i]));
                }
                break;
            }
            // follow through with RIP-processing if needed
            if (bProcessRip)
            {
                // calculate displacement relative to function start
                S64 nAdjustedDisplacement = pins->X86.Displacement + (pLoc - (U8*)pFunction);
                // store displacement values furthest from zero (both positive and negative)
                if (nAdjustedDisplacement < pdata->nLimitDown)
                    pdata->nLimitDown = nAdjustedDisplacement;
                if (nAdjustedDisplacement > pdata->nLimitUp)
                    pdata->nLimitUp = nAdjustedDisplacement;
                // store patch info
                if (pdata->nRipCnt < MHOOKS_MAX_RIPS)
                {
                    pdata->rips[pdata->nRipCnt].dwOffset = dwRet + 3;
                    pdata->rips[pdata->nRipCnt].nDisplacement = pins->X86.Displacement;
                    pdata->nRipCnt++;
                }
                else
                {
                    // no room for patch info, stop disassembly
                    break;
                }
            }
#endif

            dwRet += pins->Length;
            pLoc += pins->Length;
            snapshotLocation += pins->Length;
        }

        if (dwRet >= dwMinLen)
            status = MHOOK_STATUS_SUCCESS;

        CloseDisassembler(&dis);
    }

    *instructionLength = dwRet;
    return status;
}

/**
 * @brief Reads the calling thread's own g_lastStatus slot, which each set/unhook call on that thread overwrites.
 * @return The thread-local status value, left unchanged by this call.
 */
MHOOK_STATUS Mhook_GetLastStatus(void)
{
    return g_lastStatus;
}

/**
 * @brief Returns the version string compiled into this translation unit.
 * @return MHOOK_VERSION_STRING as baked into this build, independent of any headers the caller compiled against.
 */
const char* Mhook_GetVersion(void)
{
    // Baked into this translation unit, so the answer describes the compiled
    // library rather than whatever headers the caller happened to use.
    return MHOOK_VERSION_STRING;
}

/**
 * @brief Builds the callable trampoline and exact target patch from validated bytes.
 * @param[in,out] trampoline Reserved storage receiving all generated code.
 * @param[in] systemFunction Resolved address represented by snapshot.
 * @param[in] hookFunction Resolved replacement address.
 * @param[in] snapshot Validated bytes copied from the target.
 * @param[in] instructionLength Number of complete instruction bytes being replaced.
 * @param[in] patchData Relocation information collected during decoding.
 * @return Success when generated code is ready, otherwise the cache publication failure.
 */
static MHOOK_STATUS buildHookCode(
    MHOOKS_TRAMPOLINE* trampoline,
    PBYTE systemFunction,
    PBYTE hookFunction,
    const U8* snapshot,
    DWORD instructionLength,
    MHOOKS_PATCHDATA* patchData
)
{
    assert(trampoline);
    assert(systemFunction);
    assert(hookFunction);
    assert(snapshot);
    assert(instructionLength);
    assert(instructionLength <= MHOOKS_MAX_CODE_BYTES);
    assert(patchData);

    // Preserve the original bytes and construct the callable trampoline.
    memcpy(trampoline->codeUntouched, snapshot, instructionLength);
    memcpy(trampoline->codeTrampoline, snapshot, instructionLength);

    PBYTE continuation = trampoline->codeTrampoline + instructionLength;
    PBYTE trampolineEnd = emitJump(continuation, systemFunction + instructionLength, continuation);
    FixupIPRelativeAddressing(trampoline->codeTrampoline, systemFunction, patchData);

    // Use a nearby stub when the target cannot jump directly to the replacement.
    PBYTE patchDestination = hookFunction;
    ULONG_PTR systemAddress = (ULONG_PTR)systemFunction;
    ULONG_PTR hookAddress = (ULONG_PTR)hookFunction;
    SIZE_T hookDistance = systemAddress > hookAddress ? systemAddress - hookAddress : hookAddress - systemAddress;

    if (hookDistance > kMaximumRelativeJumpDistance)
    {
        PBYTE hookStubEnd =
            emitJump(trampoline->codeJumpToHookFunction, hookFunction, trampoline->codeJumpToHookFunction);

        if (!FlushInstructionCache(
                GetCurrentProcess(),
                trampoline->codeJumpToHookFunction,
                (SIZE_T)(hookStubEnd - trampoline->codeJumpToHookFunction)
            ))
            return MHOOK_STATUS_PATCH_FAILED;

        patchDestination = trampoline->codeJumpToHookFunction;
    }

    // Generate the future target image without modifying executable memory.
    memcpy(trampoline->codeInstalledPatch, snapshot, instructionLength);
    emitJump(systemFunction, patchDestination, trampoline->codeInstalledPatch);

    if (!FlushInstructionCache(
            GetCurrentProcess(),
            trampoline->codeTrampoline,
            (SIZE_T)(trampolineEnd - trampoline->codeTrampoline)
        ))
        return MHOOK_STATUS_PATCH_FAILED;

    return MHOOK_STATUS_SUCCESS;
}

/**
 * @brief Validates and prepares one hook without changing its target, registry, or caller slot.
 * @param[in] systemFunctionSlot Caller slot containing the requested target.
 * @param[in] hookFunction Requested replacement function.
 * @param[out] preparedTrampoline Completed private reservation on success, otherwise NULL.
 * @return Success when the hook is ready for installation, otherwise the preparation failure.
 * @remark The caller must hold the hook registry lock.
 */
static MHOOK_STATUS prepareHook(
    PVOID* systemFunctionSlot,
    PVOID hookFunction,
    OUT MHOOKS_TRAMPOLINE** preparedTrampoline
)
{
    assert(preparedTrampoline);

    *preparedTrampoline = NULL;

    // Validate the caller-owned descriptor before resolving its target.
    if (!systemFunctionSlot || !hookFunction)
        return MHOOK_STATUS_INVALID_ARGUMENT;

    PVOID systemFunction = NULL;
    if (!readWritablePointerSlot(systemFunctionSlot, &systemFunction))
        return MHOOK_STATUS_INVALID_DESCRIPTOR;

    if (!systemFunction)
        return MHOOK_STATUS_INVALID_ARGUMENT;

    // Resolve entry jumps and reject requests conflicting with active hooks.
    PBYTE resolvedSystemFunction = NULL;
    PBYTE resolvedHookFunction = NULL;
    MHOOK_STATUS status =
        resolveHookRequest((PBYTE)systemFunction, (PBYTE)hookFunction, &resolvedSystemFunction, &resolvedHookFunction);
    if (status != MHOOK_STATUS_SUCCESS)
        return status;

    // Decode once and retain the exact validated bytes used by the decoder.
    U8 snapshot[MHOOKS_MAX_CODE_BYTES] = {0};
    MHOOKS_PATCHDATA patchData = {0};
    DWORD instructionLength = 0;

    status = DisassembleAndSkip(resolvedSystemFunction, MHOOK_JMPSIZE, snapshot, &patchData, &instructionLength);
    if (status != MHOOK_STATUS_SUCCESS)
        return status;

    // Reserve private storage before generating the trampoline and target patch.
    MHOOKS_TRAMPOLINE* trampoline = reserveTrampoline(resolvedSystemFunction, patchData.nLimitUp, patchData.nLimitDown);
    if (!trampoline)
        return MHOOK_STATUS_TRAMPOLINE_ALLOCATION_FAILED;

    status = buildHookCode(
        trampoline,
        resolvedSystemFunction,
        resolvedHookFunction,
        snapshot,
        instructionLength,
        &patchData
    );
    if (status != MHOOK_STATUS_SUCCESS)
    {
        releaseTrampoline(trampoline);
        return status;
    }

    // Record the ownership information needed during installation and removal.
    trampoline->cbOverwrittenCode = instructionLength;
    trampoline->pSystemFunction = resolvedSystemFunction;
    trampoline->pHookFunction = resolvedHookFunction;

    *preparedTrampoline = trampoline;
    return MHOOK_STATUS_SUCCESS;
}

/**
 * @brief Checks whether an address belongs to code overwritten by one prepared hook.
 * @param[in] address Address to compare with the target range.
 * @param[in] trampoline Prepared hook that owns the target range.
 * @return TRUE when address is inside the overwritten target bytes.
 */
static BOOL addressBelongsToHookTarget(PBYTE address, const MHOOKS_TRAMPOLINE* trampoline)
{
    assert(address);
    assert(trampoline);
    assert(trampoline->pSystemFunction);
    assert(trampoline->cbOverwrittenCode);

    const uintptr_t addressValue = (uintptr_t)address;
    const uintptr_t targetValue = (uintptr_t)trampoline->pSystemFunction;
    return addressValue - targetValue < trampoline->cbOverwrittenCode;
}

/**
 * @brief Detects target overlap and replacement-to-target dependencies within a batch.
 * @param[in] first Earlier prepared request.
 * @param[in] second Later prepared request.
 * @return TRUE when both requests cannot be installed in one transaction.
 */
static BOOL preparedHooksConflict(const MHOOKS_TRAMPOLINE* first, const MHOOKS_TRAMPOLINE* second)
{
    assert(first);
    assert(second);

    const BOOL firstTargetInsideSecond = addressBelongsToHookTarget(first->pSystemFunction, second);
    const BOOL secondTargetInsideFirst = addressBelongsToHookTarget(second->pSystemFunction, first);
    const BOOL firstReplacementInsideSecond = addressBelongsToHookTarget(first->pHookFunction, second);
    const BOOL secondReplacementInsideFirst = addressBelongsToHookTarget(second->pHookFunction, first);

    return firstTargetInsideSecond || secondTargetInsideFirst || firstReplacementInsideSecond ||
           secondReplacementInsideFirst;
}

/**
 * @brief Prepares every request and detects conflicts before executable memory is changed.
 * @param[in] hookCount Number of descriptors and output entries.
 * @param[in,out] hooks Requests receiving their preparation status.
 * @param[out] preparedTrampolines Reserved trampoline for each successful request, otherwise NULL.
 * @return The first preparation failure, or SUCCESS when the complete batch is ready.
 * @remark The caller must hold the hook registry lock.
 */
static MHOOK_STATUS prepareHookBatch(
    SIZE_T hookCount,
    MHOOK_HOOK_INFO* hooks,
    OUT MHOOKS_TRAMPOLINE** preparedTrampolines
)
{
    assert(hookCount);
    assert(hooks);
    assert(preparedTrampolines);

    MHOOK_STATUS batchStatus = MHOOK_STATUS_SUCCESS;

    // Prepare every request so each descriptor receives an independent diagnostic status.
    for (SIZE_T index = 0; index < hookCount; ++index)
    {
        MHOOKS_TRAMPOLINE* trampoline = NULL;
        MHOOK_STATUS status = prepareHook(hooks[index].ppSystemFunction, hooks[index].pHookFunction, &trampoline);

        // Reject conflicts that the active-hook registry cannot see before publication.
        if (status == MHOOK_STATUS_SUCCESS && addressBelongsToHookTarget(trampoline->pHookFunction, trampoline))
            status = MHOOK_STATUS_ALREADY_HOOKED;

        if (status == MHOOK_STATUS_SUCCESS)
        {
            for (SIZE_T previousIndex = 0; previousIndex < index; ++previousIndex)
            {
                MHOOKS_TRAMPOLINE* previousTrampoline = preparedTrampolines[previousIndex];
                if (!previousTrampoline)
                    continue;

                const BOOL hasConflict = preparedHooksConflict(previousTrampoline, trampoline);
                if (hasConflict)
                {
                    status = MHOOK_STATUS_ALREADY_HOOKED;
                    break;
                }
            }
        }

        if (status != MHOOK_STATUS_SUCCESS && trampoline)
        {
            releaseTrampoline(trampoline);
            trampoline = NULL;
        }

        preparedTrampolines[index] = trampoline;
        hooks[index].status = status;

        if (batchStatus == MHOOK_STATUS_SUCCESS && status != MHOOK_STATUS_SUCCESS)
            batchStatus = status;
    }

    return batchStatus;
}

/**
 * @brief Returns every unpublished trampoline reservation to the free list.
 * @param[in] hookCount Number of entries in preparedTrampolines.
 * @param[in,out] preparedTrampolines Reservations to release and clear.
 * @remark The caller must hold the hook registry lock.
 */
static void releasePreparedHooks(SIZE_T hookCount, MHOOKS_TRAMPOLINE** preparedTrampolines)
{
    assert(hookCount);
    assert(preparedTrampolines);

    // Release every successful preparation while ignoring failed entries.
    for (SIZE_T index = 0; index < hookCount; ++index)
    {
        if (preparedTrampolines[index])
        {
            releaseTrampoline(preparedTrampolines[index]);
            preparedTrampolines[index] = NULL;
        }
    }
}

/**
 * @brief Installs one prepared patch and restores the target locally if commit fails.
 * @param[in] trampoline Prepared hook whose retained snapshot still represents the target.
 * @return SUCCESS when the patch and original protection are installed, otherwise the commit failure.
 */
static MHOOK_STATUS installPreparedHook(MHOOKS_TRAMPOLINE* trampoline)
{
    assert(trampoline);

    const DWORD patchSize = trampoline->cbOverwrittenCode;

    // Revalidate the exact snapshot before changing protection or target bytes.
    MHOOK_STATUS status = validateTargetCode(trampoline->pSystemFunction, trampoline->codeUntouched, patchSize);
    if (status != MHOOK_STATUS_SUCCESS)
        return status;

    DWORD originalProtection = 0;
    if (!VirtualProtect(trampoline->pSystemFunction, patchSize, PAGE_EXECUTE_READWRITE, &originalProtection))
        return MHOOK_STATUS_MEMORY_PROTECTION_FAILED;

    // Write and flush the prepared patch while retaining the determining Win32 error.
    DWORD lastError = ERROR_SUCCESS;
    memcpy(trampoline->pSystemFunction, trampoline->codeInstalledPatch, patchSize);
    if (!FlushInstructionCache(GetCurrentProcess(), trampoline->pSystemFunction, patchSize))
    {
        status = MHOOK_STATUS_PATCH_FAILED;
        lastError = GetLastError();
    }

    DWORD writableProtection = 0;
    if (status == MHOOK_STATUS_SUCCESS)
    {
        if (VirtualProtect(trampoline->pSystemFunction, patchSize, originalProtection, &writableProtection))
            return MHOOK_STATUS_SUCCESS;

        status = MHOOK_STATUS_MEMORY_PROTECTION_FAILED;
        lastError = GetLastError();
    }

    // A failed commit restores its own target before the batch rolls back earlier patches.
    memcpy(trampoline->pSystemFunction, trampoline->codeUntouched, patchSize);
    if (!FlushInstructionCache(GetCurrentProcess(), trampoline->pSystemFunction, patchSize))
    {
        status = MHOOK_STATUS_PATCH_FAILED;
        lastError = GetLastError();
    }

    if (!VirtualProtect(trampoline->pSystemFunction, patchSize, originalProtection, &writableProtection))
    {
        status = MHOOK_STATUS_MEMORY_PROTECTION_FAILED;
        lastError = GetLastError();
    }

    SetLastError(lastError);
    return status;
}

/**
 * @brief Restores every patch committed before a later request failed.
 * @param[in] installedCount Number of leading requests whose patches were installed.
 * @param[in,out] hooks Requests receiving any rollback failures.
 * @param[in,out] preparedTrampolines Prepared hooks corresponding to hooks.
 * @return The first rollback failure, or SUCCESS when every installed patch was restored.
 */
static MHOOK_STATUS rollbackHookBatch(
    SIZE_T installedCount,
    MHOOK_HOOK_INFO* hooks,
    MHOOKS_TRAMPOLINE** preparedTrampolines
)
{
    assert(installedCount);
    assert(hooks);
    assert(preparedTrampolines);

    MHOOK_STATUS rollbackStatus = MHOOK_STATUS_SUCCESS;

    // Reverse installation order while attempting every restoration.
    for (SIZE_T remaining = installedCount; remaining > 0; --remaining)
    {
        const SIZE_T index = remaining - 1;
        const UnhookResult result = restoreHookTarget(preparedTrampolines[index], ERROR_SUCCESS);

        if (result.status != MHOOK_STATUS_SUCCESS)
        {
            hooks[index].status = result.status;

            // Keep uncertain executable storage reserved so it cannot back another hook.
            preparedTrampolines[index] = NULL;

            if (rollbackStatus == MHOOK_STATUS_SUCCESS)
                rollbackStatus = result.status;
        }
    }

    return rollbackStatus;
}

/**
 * @brief Publishes a completely installed batch in the registry and caller slots.
 * @param[in] hookCount Number of installed hooks.
 * @param[in,out] hooks Caller descriptors receiving trampoline addresses.
 * @param[in] preparedTrampolines Installed hooks to publish.
 * @remark The caller must hold the hook registry lock.
 */
static void publishHookBatch(SIZE_T hookCount, MHOOK_HOOK_INFO* hooks, MHOOKS_TRAMPOLINE** preparedTrampolines)
{
    assert(hookCount);
    assert(hooks);
    assert(preparedTrampolines);

    // Expose ownership only after every target contains its prepared patch.
    for (SIZE_T index = 0; index < hookCount; ++index)
    {
        activateTrampoline(preparedTrampolines[index]);
        *hooks[index].ppSystemFunction = preparedTrampolines[index]->codeTrampoline;
    }
}

/**
 * @brief Commits all prepared hooks while peer threads remain suspended.
 * @param[in] hookCount Number of prepared hooks.
 * @param[in,out] hooks Requests receiving commit or rollback failures.
 * @param[in,out] preparedTrampolines Complete prepared batch, cleared when rollback cannot restore an entry.
 * @param[out] resumeStatus THREAD_RESUME_FAILED when a peer could not be resumed after the commit or rollback.
 * @return SUCCESS when every hook is installed and published, otherwise the transaction failure.
 */
static MHOOK_STATUS commitHookBatch(
    SIZE_T hookCount,
    MHOOK_HOOK_INFO* hooks,
    MHOOKS_TRAMPOLINE** preparedTrampolines,
    OUT MHOOK_STATUS* resumeStatus
)
{
    assert(hookCount);
    assert(hooks);
    assert(preparedTrampolines);

    ThreadSuspension suspension = {0};
    MHOOK_STATUS status = suspendOtherThreads(preparedTrampolines, hookCount, &suspension);

    if (status != MHOOK_STATUS_SUCCESS)
    {
        for (SIZE_T index = 0; index < hookCount; ++index)
            hooks[index].status = status;

        return status;
    }

    // Install in descriptor order and stop at the first failed commit.
    SIZE_T installedCount = 0;
    for (SIZE_T index = 0; index < hookCount; ++index)
    {
        status = installPreparedHook(preparedTrampolines[index]);
        if (status != MHOOK_STATUS_SUCCESS)
        {
            hooks[index].status = status;
            break;
        }

        ++installedCount;
    }

    if (status == MHOOK_STATUS_SUCCESS)
    {
        publishHookBatch(hookCount, hooks, preparedTrampolines);
    }
    else if (installedCount)
    {
        const MHOOK_STATUS rollbackStatus = rollbackHookBatch(installedCount, hooks, preparedTrampolines);
        if (rollbackStatus != MHOOK_STATUS_SUCCESS)
            status = rollbackStatus;
    }

    // Resume peers only after publication or rollback has completed.
    *resumeStatus = resumeOtherThreads(&suspension);
    return status;
}

/**
 * @brief Owns preparation, commit, and cleanup for one atomic installation batch.
 * @param[in] hookCount Number of validated descriptors.
 * @param[in,out] hooks Requests receiving per-hook results and trampolines on success.
 * @param[out] resumeStatus THREAD_RESUME_FAILED when a peer could not be resumed after the commit or rollback.
 * @return SUCCESS when the whole batch is installed, otherwise the transaction failure.
 */
static MHOOK_STATUS installHookBatch(SIZE_T hookCount, MHOOK_HOOK_INFO* hooks, OUT MHOOK_STATUS* resumeStatus)
{
    assert(hookCount);
    assert(hooks);

    // Allocate only the pointer storage retained between transaction phases.
    MHOOKS_TRAMPOLINE** preparedTrampolines = malloc(hookCount * sizeof(*preparedTrampolines));
    if (!preparedTrampolines)
    {
        const MHOOK_STATUS errorStatus = MHOOK_STATUS_TRAMPOLINE_ALLOCATION_FAILED;
        for (SIZE_T index = 0; index < hookCount; ++index)
            hooks[index].status = errorStatus;

        return errorStatus;
    }

    // Serialize registry reads, preparation, code changes, and publication.
    lockRegistry();

    MHOOK_STATUS status = prepareHookBatch(hookCount, hooks, preparedTrampolines);

    if (status == MHOOK_STATUS_SUCCESS)
        status = commitHookBatch(hookCount, hooks, preparedTrampolines, resumeStatus);

    // commitHookBatch can fail
    if (status != MHOOK_STATUS_SUCCESS)
        releasePreparedHooks(hookCount, preparedTrampolines);

    unlockRegistry();
    free(preparedTrampolines);
    return status;
}

/**
 * @brief Atomically installs a validated batch or leaves every request unpublished.
 * @param[in,out] hooks Requests to install and storage for their results.
 * @param[in] hookCount Number of descriptors in hooks.
 * @return TRUE only when every request is installed.
 */
BOOL Mhook_SetHookBatch(MHOOK_HOOK_INFO* hooks, SIZE_T hookCount)
{
    const DWORD callerLastError = GetLastError();
    const MHOOK_STATUS validationStatus = validateHookInfoArray(hooks, hookCount);

    // Reject the complete transaction when its descriptor storage cannot be used.
    if (validationStatus != MHOOK_STATUS_SUCCESS)
    {
        g_lastStatus = validationStatus;
        SetLastError(callerLastError);
        return FALSE;
    }

    MHOOK_STATUS resumeStatus = MHOOK_STATUS_SUCCESS;
    const MHOOK_STATUS status = installHookBatch(hookCount, hooks, &resumeStatus);

    // A peer left suspended is reported even over a completed installation, which stays in place.
    g_lastStatus = resumeStatus != MHOOK_STATUS_SUCCESS ? resumeStatus : status;
    SetLastError(callerLastError);
    return status == MHOOK_STATUS_SUCCESS;
}

/**
 * @brief Preserves the legacy API by submitting one descriptor to the batch path.
 * @param[in,out] ppSystemFunction Caller slot receiving the trampoline on success.
 * @param[in] pHookFunction Replacement function with the target's calling contract.
 * @return TRUE when the one-request batch succeeds.
 */
BOOL Mhook_SetHook(PVOID* ppSystemFunction, PVOID pHookFunction)
{
    MHOOK_HOOK_INFO hook = {ppSystemFunction, pHookFunction, MHOOK_STATUS_SUCCESS};
    return Mhook_SetHookBatch(&hook, 1);
}

//=========================================================================
/**
 * @brief Validates one removal request without changing its target or caller slot.
 * @param[in] hookedFunctionSlot Caller slot containing a registered trampoline.
 * @param[in] callerLastError Error value preserved for validation failures.
 * @param[out] preparedTrampoline Active trampoline ready for removal on success.
 * @return Detailed validation status and corresponding LastError value.
 * @remark The caller must hold the hook registry lock.
 */
static UnhookResult prepareUnhook(
    PVOID* hookedFunctionSlot,
    DWORD callerLastError,
    OUT MHOOKS_TRAMPOLINE** preparedTrampoline
)
{
    assert(preparedTrampoline);

    UnhookResult result = {MHOOK_STATUS_SUCCESS, callerLastError};

    // Reject a missing slot before reading caller-owned memory.
    if (!hookedFunctionSlot)
    {
        result.status = MHOOK_STATUS_INVALID_ARGUMENT;
        return result;
    }

    // Read through validated writable storage so failure leaves the slot unchanged.
    PVOID hookedFunction = NULL;
    if (!readWritablePointerSlot(hookedFunctionSlot, &hookedFunction))
    {
        result.status = MHOOK_STATUS_INVALID_DESCRIPTOR;
        return result;
    }

    if (!hookedFunction)
    {
        result.status = MHOOK_STATUS_INVALID_ARGUMENT;
        return result;
    }

    // Resolve only registered trampolines so untrusted pointer values are never dereferenced.
    MHOOKS_TRAMPOLINE* trampoline = TrampolineGet((PBYTE)hookedFunction);
    if (!trampoline)
    {
        result.status = MHOOK_STATUS_HOOK_NOT_FOUND;
        result.lastError = MHOOK_ERROR_NOT_HOOKED;
        return result;
    }

    result.status = validateInstalledPatch(trampoline);

    if (result.status == MHOOK_STATUS_TARGET_MODIFIED)
        result.lastError = MHOOK_ERROR_TARGET_MODIFIED;

    if (result.status == MHOOK_STATUS_SUCCESS)
        *preparedTrampoline = trampoline;

    return result;
}

/**
 * @brief Prepares every removal and rejects repeated trampolines before code is changed.
 * @param[in] hookCount Number of descriptors and output entries.
 * @param[in] callerLastError Error value preserved for validation failures.
 * @param[in,out] hooks Requests receiving their preparation status.
 * @param[out] preparedTrampolines Active trampoline for each successful request, otherwise NULL.
 * @return The first preparation failure, or SUCCESS when the complete batch is ready.
 * @remark The caller must hold the hook registry lock.
 */
static UnhookResult prepareUnhookBatch(
    SIZE_T hookCount,
    DWORD callerLastError,
    MHOOK_HOOK_INFO* hooks,
    OUT MHOOKS_TRAMPOLINE** preparedTrampolines
)
{
    assert(hookCount);
    assert(hooks);
    assert(preparedTrampolines);

    UnhookResult batchResult = {MHOOK_STATUS_SUCCESS, callerLastError};

    // Prepare every descriptor so callers receive an independent diagnostic status.
    for (SIZE_T index = 0; index < hookCount; ++index)
    {
        MHOOKS_TRAMPOLINE* trampoline = NULL;
        UnhookResult result = prepareUnhook(hooks[index].ppSystemFunction, callerLastError, &trampoline);

        // One active hook can participate in the transaction only once.
        if (result.status == MHOOK_STATUS_SUCCESS)
        {
            for (SIZE_T previousIndex = 0; previousIndex < index; ++previousIndex)
            {
                const BOOL isRepeated = preparedTrampolines[previousIndex] == trampoline;

                if (isRepeated)
                {
                    result.status = MHOOK_STATUS_INVALID_ARGUMENT;
                    trampoline = NULL;
                    break;
                }
            }
        }

        preparedTrampolines[index] = trampoline;
        hooks[index].status = result.status;

        if (batchResult.status == MHOOK_STATUS_SUCCESS && result.status != MHOOK_STATUS_SUCCESS)
            batchResult = result;
    }

    return batchResult;
}

/**
 * @brief Reinstalls every patch restored before a later removal failed.
 * @param[in] restoredCount Number of leading targets containing original bytes.
 * @param[in] callerLastError Error value preserved when rollback succeeds.
 * @param[in] preparedTrampolines Active hooks corresponding to hooks.
 * @param[in,out] hooks Requests receiving any rollback failures.
 * @return The first rollback failure and its LastError, or SUCCESS when every patch was reinstalled.
 */
static UnhookResult rollbackUnhookBatch(
    SIZE_T restoredCount,
    DWORD callerLastError,
    MHOOKS_TRAMPOLINE** preparedTrampolines,
    MHOOK_HOOK_INFO* hooks
)
{
    assert(restoredCount);
    assert(hooks);
    assert(preparedTrampolines);

    UnhookResult result = {MHOOK_STATUS_SUCCESS, callerLastError};

    // Reverse restoration order while attempting every patch reinstallation.
    for (SIZE_T remaining = restoredCount; remaining > 0; --remaining)
    {
        const SIZE_T index = remaining - 1;
        SetLastError(callerLastError);
        const MHOOK_STATUS status = installPreparedHook(preparedTrampolines[index]);
        const DWORD lastError = GetLastError();

        if (status != MHOOK_STATUS_SUCCESS)
        {
            hooks[index].status = status;

            if (result.status == MHOOK_STATUS_SUCCESS)
            {
                result.status = status;
                result.lastError = lastError;
            }
        }
    }

    return result;
}

/**
 * @brief Restores every prepared target and publishes removals only after complete success.
 * @param[in] hookCount Number of prepared removals.
 * @param[in] callerLastError Error value preserved when the transaction succeeds.
 * @param[in] preparedTrampolines Complete prepared batch in descriptor order.
 * @param[in,out] hooks Requests receiving commit or rollback failures.
 * @param[out] resumeStatus THREAD_RESUME_FAILED when a peer could not be resumed after the commit or rollback.
 * @return Detailed transaction status and corresponding LastError value.
 * @remark The caller must hold the hook registry lock.
 */
static UnhookResult commitUnhookBatch(
    SIZE_T hookCount,
    DWORD callerLastError,
    MHOOKS_TRAMPOLINE** preparedTrampolines,
    MHOOK_HOOK_INFO* hooks,
    OUT MHOOK_STATUS* resumeStatus
)
{
    assert(hookCount);
    assert(hooks);
    assert(preparedTrampolines);

    UnhookResult result = {MHOOK_STATUS_SUCCESS, callerLastError};
    ThreadSuspension suspension = {0};
    result.status = suspendOtherThreads(preparedTrampolines, hookCount, &suspension);

    if (result.status != MHOOK_STATUS_SUCCESS)
    {
        result.lastError = GetLastError();

        for (SIZE_T index = 0; index < hookCount; ++index)
            hooks[index].status = result.status;

        return result;
    }

    // Restore targets in descriptor order and stop at the first failed removal.
    SIZE_T restoredCount = 0;
    for (SIZE_T index = 0; index < hookCount; ++index)
    {
        result = restoreHookTarget(preparedTrampolines[index], callerLastError);
        if (result.status != MHOOK_STATUS_SUCCESS)
        {
            hooks[index].status = result.status;
            break;
        }

        ++restoredCount;
    }

    if (result.status == MHOOK_STATUS_SUCCESS)
    {
        // Publish caller slots and registry removals only after every target is restored.
        for (SIZE_T index = 0; index < hookCount; ++index)
        {
            *hooks[index].ppSystemFunction = preparedTrampolines[index]->pSystemFunction;
            retireTrampoline(preparedTrampolines[index]);
        }
    }
    else if (restoredCount)
    {
        const UnhookResult rollbackResult =
            rollbackUnhookBatch(restoredCount, callerLastError, preparedTrampolines, hooks);
        if (rollbackResult.status != MHOOK_STATUS_SUCCESS)
            result = rollbackResult;
    }

    // Resume peers only after publication or rollback has completed.
    *resumeStatus = resumeOtherThreads(&suspension);
    return result;
}

/**
 * @brief Owns preparation and commit for one atomic removal batch.
 * @param[in] hookCount Number of validated descriptors.
 * @param[in] callerLastError Error value preserved when the transaction succeeds.
 * @param[in,out] hooks Requests receiving per-hook results and restored targets.
 * @param[out] resumeStatus THREAD_RESUME_FAILED when a peer could not be resumed after the commit or rollback.
 * @return Detailed transaction status and corresponding LastError value.
 */
static UnhookResult removeHookBatch(
    SIZE_T hookCount,
    DWORD callerLastError,
    MHOOK_HOOK_INFO* hooks,
    OUT MHOOK_STATUS* resumeStatus
)
{
    assert(hookCount);
    assert(hooks);

    UnhookResult result = {MHOOK_STATUS_TRAMPOLINE_ALLOCATION_FAILED, ERROR_NOT_ENOUGH_MEMORY};

    // Allocate only the pointer storage retained between transaction phases.
    MHOOKS_TRAMPOLINE** preparedTrampolines = malloc(hookCount * sizeof(*preparedTrampolines));

    if (!preparedTrampolines)
    {
        for (SIZE_T index = 0; index < hookCount; ++index)
            hooks[index].status = result.status;

        return result;
    }

    // Serialize registry reads, target restoration, and publication.
    lockRegistry();

    result = prepareUnhookBatch(hookCount, callerLastError, hooks, preparedTrampolines);

    if (result.status == MHOOK_STATUS_SUCCESS)
        result = commitUnhookBatch(hookCount, callerLastError, preparedTrampolines, hooks, resumeStatus);

    unlockRegistry();
    free(preparedTrampolines);
    return result;
}

/**
 * @brief Atomically removes a validated batch or leaves every hook published.
 * @param[in,out] hooks Requests to remove and storage for their results.
 * @param[in] hookCount Number of descriptors in hooks.
 * @return TRUE only when every hook is removed.
 */
BOOL Mhook_UnhookBatch(MHOOK_HOOK_INFO* hooks, SIZE_T hookCount)
{
    const DWORD callerLastError = GetLastError();
    const MHOOK_STATUS validationStatus = validateHookInfoArray(hooks, hookCount);

    // Reject the complete transaction when its descriptor storage cannot be used.
    if (validationStatus != MHOOK_STATUS_SUCCESS)
    {
        g_lastStatus = validationStatus;
        SetLastError(callerLastError);
        return FALSE;
    }

    MHOOK_STATUS resumeStatus = MHOOK_STATUS_SUCCESS;
    const UnhookResult result = removeHookBatch(hookCount, callerLastError, hooks, &resumeStatus);

    // A peer left suspended is reported even over a completed removal, which stays in place.
    g_lastStatus = resumeStatus != MHOOK_STATUS_SUCCESS ? resumeStatus : result.status;
    SetLastError(result.status == MHOOK_STATUS_SUCCESS ? callerLastError : result.lastError);
    return result.status == MHOOK_STATUS_SUCCESS;
}

/**
 * @brief Preserves the legacy API by submitting one descriptor to the batch path.
 * @param[in,out] ppHookedFunction Caller slot containing the registered trampoline.
 * @return TRUE when the one-request batch succeeds.
 */
BOOL Mhook_Unhook(PVOID* ppHookedFunction)
{
    MHOOK_HOOK_INFO hook = {ppHookedFunction, NULL, MHOOK_STATUS_SUCCESS};
    return Mhook_UnhookBatch(&hook, 1);
}

//=========================================================================
/**
 * @brief Looks up the registered trampoline under the registry lock and returns its resolved target.
 * @param[in] pHookedFunction Trampoline address to look up in the active-hook registry.
 * @return The resolved target address, or NULL when pHookedFunction names no active hook.
 * @remark Unlike the set/unhook operations, this does not update the status Mhook_GetLastStatus() reports.
 */
PVOID Mhook_GetTarget(PVOID pHookedFunction)
{
    lockRegistry();
    MHOOKS_TRAMPOLINE* pTrampoline = TrampolineGet((PBYTE)pHookedFunction);
    PVOID pTarget = pTrampoline ? (PVOID)pTrampoline->pSystemFunction : NULL;
    unlockRegistry();
    if (!pTarget)
        SetLastError(MHOOK_ERROR_NOT_HOOKED);
    return pTarget;
}

//=========================================================================
