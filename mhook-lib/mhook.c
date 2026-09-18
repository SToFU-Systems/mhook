//================================================================================
// Mhook
//
// Modifications and original additions:
// Copyright (c) 2026, SToFU Systems (https://stofu.io). All rights reserved.
//
// Licensed under the MIT License.
// See LICENSE in the repository root for the full license text.
//================================================================================

//Copyright (c) 2007-2008, Marton Anka
//
//Permission is hereby granted, free of charge, to any person obtaining a 
//copy of this software and associated documentation files (the "Software"), 
//to deal in the Software without restriction, including without limitation 
//the rights to use, copy, modify, merge, publish, distribute, sublicense, 
//and/or sell copies of the Software, and to permit persons to whom the 
//Software is furnished to do so, subject to the following conditions:
//
//The above copyright notice and this permission notice shall be included 
//in all copies or substantial portions of the Software.
//
//THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS 
//OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
//FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL 
//THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
//LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING 
//FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS 
//IN THE SOFTWARE.

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
#include "../disasm-lib/disasm.h"

#ifdef _M_IX86
#define _M_IX86_X64
#elif defined _M_X64
#define _M_IX86_X64
#endif

//=========================================================================
#ifndef cntof
#define cntof(a) (sizeof(a)/sizeof(a[0]))
#endif

//=========================================================================
#ifndef GOOD_HANDLE
#define GOOD_HANDLE(a) ((a!=INVALID_HANDLE_VALUE)&&(a!=NULL))
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
#else
#define ODPRINTF(a)
#define ODPRINTFA(a)
#endif

static void __cdecl odprintfA(PCSTR format, ...) {
	va_list	args;
	va_start(args, format);
	int len = _vscprintf(format, args);
	if (len > 0) {
		len += (1 + 2);
		PSTR buf = (PSTR) malloc(len);
		if (buf) {
			len = vsprintf_s(buf, len, format, args);
			if (len > 0) {
				while (len && isspace(buf[len-1])) len--;
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

static void __cdecl odprintfW(PCWSTR format, ...) {
	va_list	args;
	va_start(args, format);
	int len = _vscwprintf(format, args);
	if (len > 0) {
		len += (1 + 2);
		PWSTR buf = (PWSTR) malloc(sizeof(WCHAR)*len);
		if (buf) {
			len = vswprintf_s(buf, len, format, args);
			if (len > 0) {
				while (len && iswspace(buf[len-1])) len--;
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

#endif //#ifndef ODPRINTF

#ifndef ODPRINTFA
#define ODPRINTFA(a) ODPRINTF(a)
#endif

//=========================================================================
#define MHOOKS_MAX_CODE_BYTES	32
#define MHOOKS_MAX_RIPS			 4

//=========================================================================
// The trampoline structure - stores every bit of info about a hook
typedef struct MHOOKS_TRAMPOLINE {
	PBYTE	pSystemFunction;								// the original system function
	DWORD	cbOverwrittenCode;								// number of bytes overwritten by the jump
	PBYTE	pHookFunction;									// the hook function that we provide
	BYTE	codeJumpToHookFunction[MHOOKS_MAX_CODE_BYTES];	// placeholder for code that jumps to the hook function
	BYTE	codeTrampoline[MHOOKS_MAX_CODE_BYTES];			// placeholder for code that holds the first few
															//   bytes from the system function and a jump to the remainder
															//   in the original location
	BYTE	codeUntouched[MHOOKS_MAX_CODE_BYTES];			// placeholder for unmodified original code
															//   (we patch IP-relative addressing)
	BYTE	codeInstalledPatch[MHOOKS_MAX_CODE_BYTES];		// the exact bytes we left in the prologue, so
															//   Mhook_Unhook can tell our own patch apart
															//   from one somebody else wrote later
	struct MHOOKS_TRAMPOLINE* pPrevTrampoline;			// When in the free list, thess are pointers to the prev and next entry.
	struct MHOOKS_TRAMPOLINE* pNextTrampoline;			// When not in the free list, this is a pointer to the prev and next trampoline in use.
} MHOOKS_TRAMPOLINE;

//=========================================================================
// The patch data structures - store info about rip-relative instructions
// during hook placement
typedef struct MHOOKS_RIPINFO
{
	DWORD	dwOffset;
	S64		nDisplacement;
} MHOOKS_RIPINFO;

typedef struct MHOOKS_PATCHDATA
{
	S64				nLimitUp;
	S64				nLimitDown;
	DWORD			nRipCnt;
	MHOOKS_RIPINFO	rips[MHOOKS_MAX_RIPS];
} MHOOKS_PATCHDATA;

//=========================================================================
// Global vars
static BOOL g_bVarsInitialized = FALSE;
static CRITICAL_SECTION g_cs;
static MHOOKS_TRAMPOLINE* g_pHooks = NULL;
static MHOOKS_TRAMPOLINE* g_pFreeList = NULL;
static DWORD g_nHooksInUse = 0;
static HANDLE* g_hThreadHandles = NULL;
static DWORD g_nThreadHandles = 0;
static __declspec(thread) MHOOK_STATUS g_lastStatus = MHOOK_STATUS_SUCCESS;

#define MHOOK_JMPSIZE 5
#define MHOOK_MINALLOCSIZE 4096

enum
{
    kReadableCodeProtectionMask = PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY,
    kReadableProtectionMask = PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | kReadableCodeProtectionMask,
    kWritableProtectionMask = PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
};

//=========================================================================
// Toolhelp defintions so the functions can be dynamically bound to
typedef HANDLE (WINAPI * _CreateToolhelp32Snapshot)(
	DWORD dwFlags,	   
	DWORD th32ProcessID  
	);

typedef BOOL (WINAPI * _Thread32First)(
									   HANDLE hSnapshot,	 
									   LPTHREADENTRY32 lpte
									   );

typedef BOOL (WINAPI * _Thread32Next)(
									  HANDLE hSnapshot,	 
									  LPTHREADENTRY32 lpte
									  );

//=========================================================================
// Toolhelp functions are resolved before thread enumeration.
static _CreateToolhelp32Snapshot fnCreateToolhelp32Snapshot = NULL;
static _Thread32First fnThread32First = NULL;
static _Thread32Next fnThread32Next = NULL;

//=========================================================================
// Internal function:
//
// Remove the trampoline from the specified list, updating the head pointer
// if necessary.
//=========================================================================
static VOID ListRemove(MHOOKS_TRAMPOLINE** pListHead, MHOOKS_TRAMPOLINE* pNode) {
	if (pNode->pPrevTrampoline) {
		pNode->pPrevTrampoline->pNextTrampoline = pNode->pNextTrampoline;
	}

	if (pNode->pNextTrampoline) {
		pNode->pNextTrampoline->pPrevTrampoline = pNode->pPrevTrampoline;
	}

	if ((*pListHead) == pNode) {
		(*pListHead) = pNode->pNextTrampoline;
		assert(!(*pListHead) || (*pListHead)->pPrevTrampoline == NULL);
	}

	pNode->pPrevTrampoline = NULL;
	pNode->pNextTrampoline = NULL;
}

//=========================================================================
// Internal function:
//
// Prepend the trampoline from the specified list and update the head pointer.
//=========================================================================
static VOID ListPrepend(MHOOKS_TRAMPOLINE** pListHead, MHOOKS_TRAMPOLINE* pNode) {
	pNode->pPrevTrampoline = NULL;
	pNode->pNextTrampoline = (*pListHead);
	if ((*pListHead)) {
		(*pListHead)->pPrevTrampoline = pNode;
	}
	(*pListHead) = pNode;
}

//=========================================================================
static VOID EnterCritSec(void) {
	if (!g_bVarsInitialized) {
		InitializeCriticalSection(&g_cs);
		g_bVarsInitialized = TRUE;
	}
	EnterCriticalSection(&g_cs);
}

//=========================================================================
static VOID LeaveCritSec(void) {
	LeaveCriticalSection(&g_cs);
}


/**
 * @brief Loads the Toolhelp functions required for thread enumeration.
 * @return TRUE when every required function is available.
 */
static BOOL loadToolhelpFunctions(void)
{
    if (fnCreateToolhelp32Snapshot && fnThread32First && fnThread32Next)
        return TRUE;

    HMODULE kernel32Module = GetModuleHandleW(L"kernel32");

    if (!kernel32Module)
        return FALSE;

    fnCreateToolhelp32Snapshot = (_CreateToolhelp32Snapshot)GetProcAddress(kernel32Module, "CreateToolhelp32Snapshot");
    fnThread32First = (_Thread32First)GetProcAddress(kernel32Module, "Thread32First");
    fnThread32Next = (_Thread32Next)GetProcAddress(kernel32Module, "Thread32Next");

    return fnCreateToolhelp32Snapshot && fnThread32First && fnThread32Next;
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
        MEMORY_BASIC_INFORMATION memory = { 0 };
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
    const BOOL isAligned = slotAddress % _Alignof(PVOID) == 0;

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
    const BOOL isAligned = hooksAddress % _Alignof(MHOOK_HOOK_INFO) == 0;

    if (!isAligned)
        return MHOOK_STATUS_INVALID_DESCRIPTOR;

    // Validate every descriptor because each operation reads its fields and writes its status.
    for (SIZE_T index = 0; index < hookCount; ++index)
    {
        MHOOK_HOOK_INFO hook = { 0 };

        if (!readMemory(&hooks[index], sizeof(hook), kWritableProtectionMask, &hook))
            return MHOOK_STATUS_INVALID_DESCRIPTOR;
    }

    return MHOOK_STATUS_SUCCESS;
}


/**
 * @brief Finds an active hook by its resolved target address.
 * @param[in] targetFunction Resolved target address to find.
 * @return The registered trampoline, or NULL when the target is not hooked.
 * @remark The caller must hold the hook registry critical section.
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
static BOOL calculateRelativeAddress(PBYTE instruction, SIZE_T instructionSize, int32_t displacement, OUT PBYTE* address)
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
    uint8_t code[kMaximumJumpSize] = { 0 };

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
#else // !_M_X64
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

    uint8_t code[kNearJumpSize] = { 0 };

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
    const uint8_t kHotPatchSequence[] = { 0x8B, 0xFF };
    const uint8_t kCollapsedFrameSequence[] = { 0x55, 0x8B, 0xEC, 0x5D };
#endif // _M_IX86

    *nextFunction = NULL;
    PBYTE instruction = function;

#ifdef _M_IX86
    uint8_t entryBytes[sizeof(kCollapsedFrameSequence)] = { 0 };

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

    return MHOOK_STATUS_SUCCESS;
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

    PBYTE visitedFunctions[kMaximumJumpDepth + 1] = { 0 };
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
static MHOOK_STATUS resolveHookRequest(PBYTE systemFunction, PBYTE hookFunction, OUT PBYTE* resolvedSystemFunction, OUT PBYTE* resolvedHookFunction)
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


//=========================================================================
// Internal function:
//
// Writes code at pbCode that jumps to pbJumpTo. Will attempt to do this
// in as few bytes as possible. Important on x64 where the long jump
// (0xff 0x25 ....) can take up 14 bytes.
//=========================================================================
static PBYTE EmitJump(PBYTE pbCode, PBYTE pbJumpTo) {
#ifdef _M_IX86_X64
	PBYTE pbJumpFrom = pbCode + 5;
	SIZE_T cbDiff = pbJumpFrom > pbJumpTo ? pbJumpFrom - pbJumpTo : pbJumpTo - pbJumpFrom;
	ODPRINTF((L"mhooks: EmitJump: Jumping from %p to %p, diff is %p", pbJumpFrom, pbJumpTo, cbDiff));
	if (cbDiff <= 0x7fff0000) {
		pbCode[0] = 0xe9;
		pbCode += 1;
		*((PDWORD)pbCode) = (DWORD)(DWORD_PTR)(pbJumpTo - pbJumpFrom);
		pbCode += sizeof(DWORD);
	} else {
		pbCode[0] = 0xff;
		pbCode[1] = 0x25;
		pbCode += 2;
#ifdef _M_IX86
		// on x86 we write an absolute address (just behind the instruction)
		*((PDWORD)pbCode) = (DWORD)(DWORD_PTR)(pbCode + sizeof(DWORD));
#elif defined _M_X64
		// on x64 we write the relative address of the same location
		*((PDWORD)pbCode) = (DWORD)0;
#endif
		pbCode += sizeof(DWORD);
		*((PDWORD_PTR)pbCode) = (DWORD_PTR)(pbJumpTo);
		pbCode += sizeof(DWORD_PTR);
	}
#else 
#error unsupported platform
#endif
	return pbCode;
}


//=========================================================================
// Internal function:
//
// Round down to the next multiple of rndDown
//=========================================================================
static size_t RoundDown(size_t addr, size_t rndDown)
{
	return (addr / rndDown) * rndDown;
}

//=========================================================================
// Internal function:
//
// Will attempt allocate a block of memory within the specified range, as 
// near as possible to the specified function.
//=========================================================================
static MHOOKS_TRAMPOLINE* BlockAlloc(PBYTE pSystemFunction, PBYTE pbLower, PBYTE pbUpper) {
	SYSTEM_INFO sSysInfo =  {0};
	GetSystemInfo(&sSysInfo);

	// Always allocate in bulk, in case the system actually has a smaller allocation granularity than MINALLOCSIZE.
	const ptrdiff_t cAllocSize = max(sSysInfo.dwAllocationGranularity, MHOOK_MINALLOCSIZE);

	MHOOKS_TRAMPOLINE* pRetVal = NULL;
	PBYTE pModuleGuess = (PBYTE) RoundDown((size_t)pSystemFunction, cAllocSize);
	int loopCount = 0;
	for (PBYTE pbAlloc = pModuleGuess; pbLower < pbAlloc && pbAlloc < pbUpper; ++loopCount) {
		// determine current state
		MEMORY_BASIC_INFORMATION mbi;
		ODPRINTF((L"mhooks: BlockAlloc: Looking at address %p", pbAlloc));
		if (!VirtualQuery(pbAlloc, &mbi, sizeof(mbi)))
			break;
		// free & large enough?
		if (mbi.State == MEM_FREE && mbi.RegionSize >= (unsigned)cAllocSize) {
			// and then try to allocate it
			pRetVal = (MHOOKS_TRAMPOLINE*) VirtualAlloc(pbAlloc, cAllocSize, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			if (pRetVal) {
				size_t trampolineCount = cAllocSize / sizeof(MHOOKS_TRAMPOLINE);
				ODPRINTF((L"mhooks: BlockAlloc: Allocated block at %p as %d trampolines", pRetVal, trampolineCount));

				pRetVal[0].pPrevTrampoline = NULL;
				pRetVal[0].pNextTrampoline = &pRetVal[1];

				// prepare them by having them point down the line at the next entry.
				for (size_t s = 1; s < trampolineCount; ++s) {
					pRetVal[s].pPrevTrampoline = &pRetVal[s - 1];
					pRetVal[s].pNextTrampoline = &pRetVal[s + 1];
				}

				// last entry points to the current head of the free list
				pRetVal[trampolineCount - 1].pNextTrampoline = g_pFreeList;
				break;
			}
		}
				
		// This is a spiral, should be -1, 1, -2, 2, -3, 3, etc. (* cAllocSize)
		ptrdiff_t bytesToOffset = (cAllocSize * (loopCount + 1) * ((loopCount % 2 == 0) ? -1 : 1));
		pbAlloc = pbAlloc + bytesToOffset;
	}
	
	return pRetVal;
}

//=========================================================================
// Internal function:
//
// Will try to allocate a big block of memory inside the required range. 
//=========================================================================
static MHOOKS_TRAMPOLINE* FindTrampolineInRange(PBYTE pLower, PBYTE pUpper) {
	if (!g_pFreeList) {
		return NULL;
	}

	// This is a standard free list, except we're doubly linked to deal with soem return shenanigans.
	MHOOKS_TRAMPOLINE* curEntry = g_pFreeList;
	while (curEntry) {
		if ((MHOOKS_TRAMPOLINE*) pLower < curEntry && curEntry < (MHOOKS_TRAMPOLINE*) pUpper) {
			ListRemove(&g_pFreeList, curEntry);

			return curEntry;
		}

		curEntry = curEntry->pNextTrampoline;
	}

	return NULL;
}

//=========================================================================
// Internal function:
//
// Will try to allocate the trampoline structure within 2 gigabytes of
// the target function. 
//=========================================================================
static MHOOKS_TRAMPOLINE* TrampolineAlloc(PBYTE pSystemFunction, S64 nLimitUp, S64 nLimitDown) {

	MHOOKS_TRAMPOLINE* pTrampoline = NULL;

	// determine lower and upper bounds for the allocation locations.
	// in the basic scenario this is +/- 2GB but IP-relative instructions
	// found in the original code may require a smaller window.
	PBYTE pLower = pSystemFunction + nLimitUp;
	pLower = pLower < (PBYTE)(DWORD_PTR)0x0000000080000000 ? 
						(PBYTE)(0x1) : (PBYTE)(pLower - (PBYTE)0x7fff0000);
	PBYTE pUpper = pSystemFunction + nLimitDown;
	pUpper = pUpper < (PBYTE)(DWORD_PTR)0xffffffff80000000 ? 
		(PBYTE)(pUpper + (DWORD_PTR)0x7ff80000) : (PBYTE)(DWORD_PTR)0xfffffffffff80000;
	ODPRINTF((L"mhooks: TrampolineAlloc: Allocating for %p between %p and %p", pSystemFunction, pLower, pUpper));

	// try to find a trampoline in the specified range
	pTrampoline = FindTrampolineInRange(pLower, pUpper);
	if (!pTrampoline) {
		// if it we can't find it, then we need to allocate a new block and 
		// try again. Just fail if that doesn't work 
		g_pFreeList = BlockAlloc(pSystemFunction, pLower, pUpper);
		pTrampoline = FindTrampolineInRange(pLower, pUpper);
	}

	// found and allocated a trampoline?
	if (pTrampoline) {
		ListPrepend(&g_pHooks, pTrampoline);
	}

	return pTrampoline;
}

//=========================================================================
// Internal function:
//
// Return the internal trampoline structure that belongs to a hooked function.
//=========================================================================
static MHOOKS_TRAMPOLINE* TrampolineGet(PBYTE pHookedFunction) {
	MHOOKS_TRAMPOLINE* pCurrent = g_pHooks;

	while (pCurrent) {
		if (pCurrent->codeTrampoline == pHookedFunction) {
			return pCurrent;
		}

		pCurrent = pCurrent->pNextTrampoline;
	}

	return NULL;
}

//=========================================================================
// Internal function:
//
// Free a trampoline structure.
//=========================================================================
static VOID TrampolineFree(MHOOKS_TRAMPOLINE* pTrampoline, BOOL bNeverUsed) {
	ListRemove(&g_pHooks, pTrampoline);

	// If a thread could feasinbly have some of our trampoline code 
	// on its stack and we yank the region from underneath it then it will
	// surely crash upon returning. So instead of freeing the 
	// memory we just let it leak. Ugly, but safe.
	if (bNeverUsed) {
		ListPrepend(&g_pFreeList, pTrampoline);
	}

	g_nHooksInUse--;
}

//=========================================================================
// Internal function:
//
// Suspend a given thread and try to make sure that its instruction
// pointer is not in the given range.
//=========================================================================
static HANDLE SuspendOneThread(DWORD dwThreadId, PBYTE pbCode, DWORD cbBytes) {
	// open the thread
	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, dwThreadId);
	if (GOOD_HANDLE(hThread)) {
		// attempt suspension
		DWORD dwSuspendCount = SuspendThread(hThread);
		if (dwSuspendCount != -1) {
			// see where the IP is
			CONTEXT ctx;
			ctx.ContextFlags = CONTEXT_CONTROL;
			int nTries = 0;
			while (GetThreadContext(hThread, &ctx)) {
#ifdef _M_IX86
				PBYTE pIp = (PBYTE)(DWORD_PTR)ctx.Eip;
#elif defined _M_X64
				PBYTE pIp = (PBYTE)(DWORD_PTR)ctx.Rip;
#endif
				if (pIp >= pbCode && pIp < (pbCode + cbBytes)) {
					if (nTries < 3) {
						// oops - we should try to get the instruction pointer out of here. 
						ODPRINTF((L"mhooks: SuspendOneThread: suspended thread %d - IP is at %p - IS COLLIDING WITH CODE", dwThreadId, pIp));
						ResumeThread(hThread);
						Sleep(100);
						SuspendThread(hThread);
						nTries++;
					} else {
						// we gave it all we could. (this will probably never 
						// happen - unless the thread has already been suspended 
						// to begin with)
						ODPRINTF((L"mhooks: SuspendOneThread: suspended thread %d - IP is at %p - IS COLLIDING WITH CODE - CAN'T FIX", dwThreadId, pIp));
						ResumeThread(hThread);
						CloseHandle(hThread);
						hThread = NULL;
						break;
					}
				} else {
					// success, the IP is not conflicting
					ODPRINTF((L"mhooks: SuspendOneThread: Successfully suspended thread %d - IP is at %p", dwThreadId, pIp));
					break;
				}
			}
		} else {
			// couldn't suspend
			CloseHandle(hThread);
			hThread = NULL;
		}
	}
	return hThread;
}

//=========================================================================
// Internal function:
//
// Resumes all previously suspended threads in the current process.
//=========================================================================
static VOID ResumeOtherThreads(void) {
	// make sure things go as fast as possible
	INT nOriginalPriority = GetThreadPriority(GetCurrentThread());
	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
	// go through our list
	for (DWORD i=0; i<g_nThreadHandles; i++) {
		// and resume & close thread handles
		ResumeThread(g_hThreadHandles[i]);
		CloseHandle(g_hThreadHandles[i]);
	}
	// clean up
	free(g_hThreadHandles);
	g_hThreadHandles = NULL;
	g_nThreadHandles = 0;
	SetThreadPriority(GetCurrentThread(), nOriginalPriority);
}

//=========================================================================
// Internal function:
//
// Suspend all threads in this process while trying to make sure that their 
// instruction pointer is not in the given range.
//=========================================================================
static BOOL SuspendOtherThreads(PBYTE pbCode, DWORD cbBytes) {
	BOOL bRet = FALSE;
	if (!loadToolhelpFunctions())
		return FALSE;

	// make sure we're the most important thread in the process
	INT nOriginalPriority = GetThreadPriority(GetCurrentThread());
	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
	// get a view of the threads in the system
	HANDLE hSnap = fnCreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, GetCurrentProcessId());
	if (GOOD_HANDLE(hSnap)) {
		THREADENTRY32 te;
		te.dwSize = sizeof(te);
		// count threads in this process (except for ourselves)
		DWORD nThreadsInProcess = 0;
		if (fnThread32First(hSnap, &te)) {
			do {
				if (te.th32OwnerProcessID == GetCurrentProcessId()) {
					if (te.th32ThreadID != GetCurrentThreadId()) {
						nThreadsInProcess++;
					}
				}
				te.dwSize = sizeof(te);
			} while(fnThread32Next(hSnap, &te));
		}
		ODPRINTF((L"mhooks: SuspendOtherThreads: counted %d other threads", nThreadsInProcess));
		if (nThreadsInProcess) {
			// alloc buffer for the handles we really suspended
			g_hThreadHandles = (HANDLE*)malloc(nThreadsInProcess*sizeof(HANDLE));
			if (g_hThreadHandles) {
				ZeroMemory(g_hThreadHandles, nThreadsInProcess*sizeof(HANDLE));
				DWORD nCurrentThread = 0;
				BOOL bFailed = FALSE;
				te.dwSize = sizeof(te);
				// go through every thread
				if (fnThread32First(hSnap, &te)) {
					do {
						if (te.th32OwnerProcessID == GetCurrentProcessId()) {
							if (te.th32ThreadID != GetCurrentThreadId()) {
								// attempt to suspend it
								g_hThreadHandles[nCurrentThread] = SuspendOneThread(te.th32ThreadID, pbCode, cbBytes);
								if (GOOD_HANDLE(g_hThreadHandles[nCurrentThread])) {
									ODPRINTF((L"mhooks: SuspendOtherThreads: successfully suspended %d", te.th32ThreadID));
									nCurrentThread++;
								} else {
									ODPRINTF((L"mhooks: SuspendOtherThreads: error while suspending thread %d: %d", te.th32ThreadID, gle()));
									// TODO: this might not be the wisest choice
									// but we can choose to ignore failures on
									// thread suspension. It's pretty unlikely that
									// we'll fail - and even if we do, the chances
									// of a thread's IP being in the wrong place
									// is pretty small.
									// bFailed = TRUE;
								}
							}
						}
						te.dwSize = sizeof(te);
					} while(fnThread32Next(hSnap, &te) && !bFailed);
				}
				g_nThreadHandles = nCurrentThread;
				bRet = !bFailed;
			}
		}
		CloseHandle(hSnap);
		//TODO: we might want to have another pass to make sure all threads
		// in the current process (including those that might have been
		// created since we took the original snapshot) have been 
		// suspended.
	} else {
		ODPRINTF((L"mhooks: SuspendOtherThreads: can't CreateToolhelp32Snapshot: %d", gle()));
	}
	SetThreadPriority(GetCurrentThread(), nOriginalPriority);
	if (!bRet) {
		ODPRINTF((L"mhooks: SuspendOtherThreads: Had a problem (or not running multithreaded), resuming all threads."));
		ResumeOtherThreads();
	}
	return bRet;
}

//=========================================================================
// if IP-relative addressing has been detected, fix up the code so the
// offset points to the original location
static void FixupIPRelativeAddressing(PBYTE pbNew, PBYTE pbOriginal, MHOOKS_PATCHDATA* pdata)
{
#if defined _M_X64
	S64 diff = pbNew - pbOriginal;
	for (DWORD i = 0; i < pdata->nRipCnt; i++) {
		DWORD dwNewDisplacement = (DWORD)(pdata->rips[i].nDisplacement - diff);
		ODPRINTF((L"mhooks: fixing up RIP instruction operand for code at 0x%p: "
			L"old displacement: 0x%8.8x, new displacement: 0x%8.8x", 
			pbNew + pdata->rips[i].dwOffset, 
			(DWORD)pdata->rips[i].nDisplacement, 
			dwNewDisplacement));
		*(PDWORD)(pbNew + pdata->rips[i].dwOffset) = dwNewDisplacement;
	}
#endif
}

/**
 * @brief Decodes a function prologue through complete instruction boundaries.
 * @param[in] pFunction Function entry point represented by the decoded bytes.
 * @param[in] dwMinLen Minimum number of complete bytes required for the patch.
 * @param[out] pdata Collected relocation limits and RIP-relative patch data.
 * @param[out] instructionLength Number of complete bytes decoded.
 * @return Status describing whether the prologue can be patched.
 */
static MHOOK_STATUS DisassembleAndSkip(PVOID pFunction, DWORD dwMinLen, OUT MHOOKS_PATCHDATA* pdata, OUT DWORD* instructionLength)
{
    U8 snapshot[MHOOKS_MAX_CODE_BYTES] = { 0 };
    DWORD dwRet = 0;
    MHOOK_STATUS status = MHOOK_STATUS_INVALID_TARGET;

    assert(pdata);
    assert(instructionLength);

    *instructionLength = 0;
	pdata->nLimitDown = 0;
	pdata->nLimitUp = 0;
	pdata->nRipCnt = 0;

    // Decode only from bytes copied out of validated executable memory.
    const SIZE_T snapshotSize = readMemoryPrefix(pFunction, sizeof(snapshot), kReadableCodeProtectionMask, snapshot);

    if (!snapshotSize)
        return status;

    status = MHOOK_STATUS_DECODE_FAILED;

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
			if (pins->Type == ITYPE_RET		) break;
			if (pins->Type == ITYPE_BRANCH	) break;
			if (pins->Type == ITYPE_BRANCHCC) break;
			if (pins->Type == ITYPE_CALL	) break;
			if (pins->Type == ITYPE_CALLCC	) break;

			#if defined _M_X64
				BOOL bProcessRip = FALSE;
				// mov or lea to register from rip+imm32
				if ((pins->Type == ITYPE_MOV || pins->Type == ITYPE_LEA) && (pins->X86.Relative) && 
					(pins->X86.OperandSize == 8) && (pins->OperandCount == 2) &&
					(pins->Operands[1].Flags & OP_IPREL) && (pins->Operands[1].Register == AMD64_REG_RIP))
				{
					// rip-addressing "mov reg, [rip+imm32]"
					ODPRINTF((L"mhooks: DisassembleAndSkip: found OP_IPREL on operand %d with displacement 0x%x (in memory: 0x%x)", 1, pins->X86.Displacement, *(PDWORD)(snapshotLocation+3)));
					bProcessRip = TRUE;
				}
				// mov or lea to rip+imm32 from register
				else if ((pins->Type == ITYPE_MOV || pins->Type == ITYPE_LEA) && (pins->X86.Relative) && 
					(pins->X86.OperandSize == 8) && (pins->OperandCount == 2) &&
					(pins->Operands[0].Flags & OP_IPREL) && (pins->Operands[0].Register == AMD64_REG_RIP))
				{
					// rip-addressing "mov [rip+imm32], reg"
					ODPRINTF((L"mhooks: DisassembleAndSkip: found OP_IPREL on operand %d with displacement 0x%x (in memory: 0x%x)", 0, pins->X86.Displacement, *(PDWORD)(snapshotLocation+3)));
					bProcessRip = TRUE;
				}
				else if ( (pins->OperandCount >= 1) && (pins->Operands[0].Flags & OP_IPREL) )
				{
					// unsupported rip-addressing
					ODPRINTF((L"mhooks: DisassembleAndSkip: found unsupported OP_IPREL on operand %d", 0));
					// dump instruction bytes to the debug output
					for (DWORD i=0; i<pins->Length; i++) {
						ODPRINTF((L"mhooks: DisassembleAndSkip: instr byte %2.2d: 0x%2.2x", i, snapshotLocation[i]));
					}
					break;
				}
				else if ( (pins->OperandCount >= 2) && (pins->Operands[1].Flags & OP_IPREL) )
				{
					// unsupported rip-addressing
					ODPRINTF((L"mhooks: DisassembleAndSkip: found unsupported OP_IPREL on operand %d", 1));
					// dump instruction bytes to the debug output
					for (DWORD i=0; i<pins->Length; i++) {
						ODPRINTF((L"mhooks: DisassembleAndSkip: instr byte %2.2d: 0x%2.2x", i, snapshotLocation[i]));
					}
					break;
				}
				else if ( (pins->OperandCount >= 3) && (pins->Operands[2].Flags & OP_IPREL) )
				{
					// unsupported rip-addressing
					ODPRINTF((L"mhooks: DisassembleAndSkip: found unsupported OP_IPREL on operand %d", 2));
					// dump instruction bytes to the debug output
					for (DWORD i=0; i<pins->Length; i++) {
						ODPRINTF((L"mhooks: DisassembleAndSkip: instr byte %2.2d: 0x%2.2x", i, snapshotLocation[i]));
					}
					break;
				}
				// follow through with RIP-processing if needed
				if (bProcessRip) {
					// calculate displacement relative to function start
					S64 nAdjustedDisplacement = pins->X86.Displacement + (pLoc - (U8*)pFunction);
					// store displacement values furthest from zero (both positive and negative)
					if (nAdjustedDisplacement < pdata->nLimitDown)
						pdata->nLimitDown = nAdjustedDisplacement;
					if (nAdjustedDisplacement > pdata->nLimitUp)
						pdata->nLimitUp = nAdjustedDisplacement;
					// store patch info
					if (pdata->nRipCnt < MHOOKS_MAX_RIPS) {
						pdata->rips[pdata->nRipCnt].dwOffset = dwRet + 3;
						pdata->rips[pdata->nRipCnt].nDisplacement = pins->X86.Displacement;
						pdata->nRipCnt++;
					} else {
						// no room for patch info, stop disassembly
						break;
					}
				}
			#endif

			dwRet += pins->Length;
			pLoc  += pins->Length;
            snapshotLocation += pins->Length;
		}

		if (dwRet >= dwMinLen)
            status = MHOOK_STATUS_SUCCESS;

		CloseDisassembler(&dis);
	}

    *instructionLength = dwRet;
    return status;
}

MHOOK_STATUS Mhook_GetLastStatus(void)
{
    return g_lastStatus;
}

//=========================================================================
/**
 * @brief Installs one hook and records the operation status.
 * @param[in,out] ppSystemFunction Caller slot receiving the trampoline on success.
 * @param[in] pHookFunction Replacement function with the target's calling contract.
 * @return TRUE after the target is patched and the trampoline is published.
 */
static BOOL setHook(PVOID* ppSystemFunction, PVOID pHookFunction) {
    const DWORD callerLastError = GetLastError();

    // Reject missing inputs before reading caller-owned memory.
    if (!ppSystemFunction || !pHookFunction)
    {
        g_lastStatus = MHOOK_STATUS_INVALID_ARGUMENT;
        SetLastError(callerLastError);
        return FALSE;
    }

    // Copy the target from validated writable storage so failure leaves the slot unchanged.
    PVOID pSystemFunction = NULL;
    if (!readWritablePointerSlot(ppSystemFunction, &pSystemFunction))
    {
        g_lastStatus = MHOOK_STATUS_INVALID_DESCRIPTOR;
        SetLastError(callerLastError);
        return FALSE;
    }

    // A writable slot still cannot describe a hook without a target value.
    if (!pSystemFunction)
    {
        g_lastStatus = MHOOK_STATUS_INVALID_ARGUMENT;
        SetLastError(callerLastError);
        return FALSE;
    }

	MHOOKS_TRAMPOLINE* pTrampoline = NULL;

	// Serialize resolution, registry access, and patch publication as one operation.
	EnterCritSec();
	ODPRINTF((L"mhooks: Mhook_SetHook: Started on the job: %p / %p", pSystemFunction, pHookFunction));

    // Resolve entry jumps before allocation so conflicts fail without changing process state.
    PBYTE resolvedSystemFunction = NULL;
    PBYTE resolvedHookFunction = NULL;

    MHOOK_STATUS operationStatus = resolveHookRequest((PBYTE)pSystemFunction, (PBYTE)pHookFunction, &resolvedSystemFunction, &resolvedHookFunction);

    if (operationStatus != MHOOK_STATUS_SUCCESS)
    {
        LeaveCritSec();
        g_lastStatus = operationStatus;
        SetLastError(callerLastError);
        return FALSE;
    }

    pSystemFunction = resolvedSystemFunction;
    pHookFunction = resolvedHookFunction;

	ODPRINTF((L"mhooks: Mhook_SetHook: Started on the job: %p / %p", pSystemFunction, pHookFunction));
	// Decode whole instructions so the target patch never splits an instruction.
	MHOOKS_PATCHDATA patchdata = {0};

	DWORD dwInstructionLength = 0;
	operationStatus = DisassembleAndSkip(pSystemFunction, MHOOK_JMPSIZE, &patchdata, &dwInstructionLength);

	if (operationStatus == MHOOK_STATUS_SUCCESS)
	{
		ODPRINTF((L"mhooks: Mhook_SetHook: disassembly signals %d bytes", dwInstructionLength));

		// Move peer instruction pointers away before executable bytes are changed.
		SuspendOtherThreads((PBYTE)pSystemFunction, dwInstructionLength);

		// Allocate near the target so relocated instructions and jumps remain representable.
		pTrampoline = TrampolineAlloc((PBYTE)pSystemFunction, patchdata.nLimitUp, patchdata.nLimitDown);

		if (pTrampoline)
		{
			ODPRINTF((L"mhooks: Mhook_SetHook: allocated structure at %p", pTrampoline));
			DWORD dwOldProtectSystemFunction = 0;
			DWORD dwOldProtectTrampolineFunction = 0;

			// Make the target writable only while its patch is installed.
			if (VirtualProtect(pSystemFunction, dwInstructionLength, PAGE_EXECUTE_READWRITE, &dwOldProtectSystemFunction))
			{
				ODPRINTF((L"mhooks: Mhook_SetHook: readwrite set on system function"));

				// Make the trampoline writable while copied instructions and jumps are emitted.
				if (VirtualProtect(pTrampoline, sizeof(MHOOKS_TRAMPOLINE), PAGE_EXECUTE_READWRITE, &dwOldProtectTrampolineFunction))
				{
					ODPRINTF((L"mhooks: Mhook_SetHook: readwrite set on trampoline structure"));

					// Copy the overwritten instructions before appending the continuation jump.
					PBYTE pbCode = pTrampoline->codeTrampoline;

					for (DWORD i = 0; i < dwInstructionLength; i++)
						pTrampoline->codeUntouched[i] = pbCode[i] = ((PBYTE)pSystemFunction)[i];

					pbCode += dwInstructionLength;

					// Continue after the overwritten region when callers use the trampoline.
					pbCode = EmitJump(pbCode, ((PBYTE)pSystemFunction) + dwInstructionLength);
					ODPRINTF((L"mhooks: Mhook_SetHook: updated the trampoline"));

					// Rebase copied IP-relative operands so relocated instructions keep their targets.
					FixupIPRelativeAddressing(pTrampoline->codeTrampoline, (PBYTE)pSystemFunction, &patchdata);

					DWORD_PTR dwDistance = (PBYTE)pHookFunction < (PBYTE)pSystemFunction ? 
						(PBYTE)pSystemFunction - (PBYTE)pHookFunction : (PBYTE)pHookFunction - (PBYTE)pSystemFunction;

					if (dwDistance > 0x7fff0000)
					{
						// Route distant hooks through a nearby stub so the target needs only a short jump.
						pbCode = pTrampoline->codeJumpToHookFunction;
						pbCode = EmitJump(pbCode, (PBYTE)pHookFunction);

						ODPRINTF((L"mhooks: Mhook_SetHook: created reverse trampoline"));
						FlushInstructionCache(GetCurrentProcess(), pTrampoline->codeJumpToHookFunction, 
							pbCode - pTrampoline->codeJumpToHookFunction);

						// Redirect the target to the nearby hook stub.
						pbCode = (PBYTE)pSystemFunction;
						pbCode = EmitJump(pbCode, pTrampoline->codeJumpToHookFunction);
					}
					else
					{
						// Redirect directly when the replacement is within short-jump range.
						pbCode = (PBYTE)pSystemFunction;
						pbCode = EmitJump(pbCode, (PBYTE)pHookFunction);
					}

					// Save the installed bytes so unhook refuses to overwrite a later patch.
					memcpy(pTrampoline->codeInstalledPatch, pSystemFunction, dwInstructionLength);

					// Record ownership data required to identify and restore this hook.
					pTrampoline->cbOverwrittenCode = dwInstructionLength;
					pTrampoline->pSystemFunction = (PBYTE)pSystemFunction;
					pTrampoline->pHookFunction = (PBYTE)pHookFunction;

					// Publish generated code before restoring the trampoline's protection.
					FlushInstructionCache(GetCurrentProcess(), pTrampoline->codeTrampoline, dwInstructionLength);
					VirtualProtect(pTrampoline, sizeof(MHOOKS_TRAMPOLINE), dwOldProtectTrampolineFunction, &dwOldProtectTrampolineFunction);
				}
				else
				{
                    operationStatus = MHOOK_STATUS_MEMORY_PROTECTION_FAILED;
					ODPRINTF((L"mhooks: Mhook_SetHook: failed VirtualProtect 2: %d", gle()));
				}

				// Publish the target patch before restoring its original protection.
				FlushInstructionCache(GetCurrentProcess(), pSystemFunction, dwInstructionLength);
				VirtualProtect(pSystemFunction, dwInstructionLength, dwOldProtectSystemFunction, &dwOldProtectSystemFunction);
			}
			else
			{
                operationStatus = MHOOK_STATUS_MEMORY_PROTECTION_FAILED;
				ODPRINTF((L"mhooks: Mhook_SetHook: failed VirtualProtect 1: %d", gle()));
			}

			if (pTrampoline->pSystemFunction)
			{
				// Publish the trampoline only after the target patch is complete.
				*ppSystemFunction = pTrampoline->codeTrampoline;
				ODPRINTF((L"mhooks: Mhook_SetHook: Hooked the function!"));
			}
			else
			{
				// Discard incomplete state so failed requests remain unpublished.
				TrampolineFree(pTrampoline, TRUE);
				pTrampoline = NULL;
			}
		}
		else
		{
            operationStatus = MHOOK_STATUS_TRAMPOLINE_ALLOCATION_FAILED;
		}

		// Resume peer threads after all executable-memory writes are complete.
		ResumeOtherThreads();
	}
	else 
	{
		ODPRINTF((L"mhooks: disassembly signals %d bytes (unacceptable)", dwInstructionLength));
	}

	// Release serialized state before publishing the thread-local result.
	LeaveCritSec();
    g_lastStatus = operationStatus;
    SetLastError(callerLastError);
    return operationStatus == MHOOK_STATUS_SUCCESS;
}


/**
 * @brief Installs each valid batch request through the shared single-hook workflow.
 * @param[in,out] hooks Requests to install and storage for their results.
 * @param[in] hookCount Number of descriptors in hooks.
 * @return TRUE only when every request succeeds.
 */
BOOL Mhook_SetHookBatch(MHOOK_HOOK_INFO* hooks, SIZE_T hookCount)
{
    const DWORD callerLastError = GetLastError();
    const MHOOK_STATUS validationStatus = validateHookInfoArray(hooks, hookCount);

    // Reject the entire request before any hook runs when result storage is unusable.
    if (validationStatus != MHOOK_STATUS_SUCCESS)
    {
        g_lastStatus = validationStatus;
        SetLastError(callerLastError);
        return FALSE;
    }

    BOOL result = TRUE;
    MHOOK_STATUS batchStatus = MHOOK_STATUS_SUCCESS;

    // Process every request so callers receive a status for each descriptor.
    for (SIZE_T index = 0; index < hookCount; ++index)
    {
        SetLastError(callerLastError);
        const BOOL hookResult = setHook(hooks[index].ppSystemFunction, hooks[index].pHookFunction);
        hooks[index].status = g_lastStatus;

        // Preserve the first failure as the deterministic overall batch result.
        if (!hookResult && result)
            batchStatus = g_lastStatus;

        result = result && hookResult;
    }

    // Preserve the set API's LastError contract while publishing the overall status.
    g_lastStatus = batchStatus;
    SetLastError(callerLastError);
    return result;
}


/**
 * @brief Preserves the legacy API by submitting one descriptor to the batch path.
 * @param[in,out] ppSystemFunction Caller slot receiving the trampoline on success.
 * @param[in] pHookFunction Replacement function with the target's calling contract.
 * @return TRUE when the one-request batch succeeds.
 */
BOOL Mhook_SetHook(PVOID* ppSystemFunction, PVOID pHookFunction)
{
    MHOOK_HOOK_INFO hook = { ppSystemFunction, pHookFunction, MHOOK_STATUS_SUCCESS };
    return Mhook_SetHookBatch(&hook, 1);
}


//=========================================================================
/**
 * @brief Removes one hook and records the operation status.
 * @param[in,out] ppHookedFunction Caller slot containing the registered trampoline.
 * @return TRUE after the target and caller slot are restored.
 */
static BOOL unhook(PVOID* ppHookedFunction)
{
    const DWORD callerLastError = GetLastError();

    // Reject a missing slot before reading caller-owned memory.
    if (!ppHookedFunction)
    {
        g_lastStatus = MHOOK_STATUS_INVALID_ARGUMENT;
        SetLastError(callerLastError);
        return FALSE;
    }

    // Copy the trampoline from validated writable storage so failure leaves the slot unchanged.
    PVOID pHookedFunction = NULL;
    if (!readWritablePointerSlot(ppHookedFunction, &pHookedFunction))
    {
        g_lastStatus = MHOOK_STATUS_INVALID_DESCRIPTOR;
        SetLastError(callerLastError);
        return FALSE;
    }

    // A writable slot still cannot identify an installed hook without a value.
    if (!pHookedFunction)
    {
        g_lastStatus = MHOOK_STATUS_INVALID_ARGUMENT;
        SetLastError(callerLastError);
        return FALSE;
    }

	ODPRINTF((L"mhooks: Mhook_Unhook: %p", pHookedFunction));
	BOOL bRet = FALSE;
	DWORD dwError = MHOOK_ERROR_NOT_HOOKED;
	MHOOK_STATUS operationStatus = MHOOK_STATUS_HOOK_NOT_FOUND;

	// Serialize registry lookup and target restoration with hook installation.
	EnterCritSec();

	// Resolve only registered trampolines so untrusted pointer values are never dereferenced.
	MHOOKS_TRAMPOLINE* pTrampoline = TrampolineGet((PBYTE)pHookedFunction);

	if (pTrampoline)
	{
		// Move peer instruction pointers away before executable bytes are restored.
		SuspendOtherThreads(pTrampoline->pSystemFunction, pTrampoline->cbOverwrittenCode);
		ODPRINTF((L"mhooks: Mhook_Unhook: found struct at %p", pTrampoline));
		DWORD dwOldProtectSystemFunction = 0;

		// Refuse changed targets because restoring saved bytes would destroy another writer's patch.
		// Keep the hook registered so its only saved copy of the original bytes remains recoverable.
		if (memcmp(pTrampoline->pSystemFunction, pTrampoline->codeInstalledPatch,
				pTrampoline->cbOverwrittenCode) != 0)
		{
			ODPRINTF((L"mhooks: Mhook_Unhook: %p no longer holds our patch, refusing to restore",
				pTrampoline->pSystemFunction));

			operationStatus = MHOOK_STATUS_TARGET_MODIFIED;
			dwError = MHOOK_ERROR_TARGET_MODIFIED;
		} // Make an unchanged target writable only while its original bytes are restored.
		else if (VirtualProtect(pTrampoline->pSystemFunction, pTrampoline->cbOverwrittenCode, PAGE_EXECUTE_READWRITE, &dwOldProtectSystemFunction))
		{
			ODPRINTF((L"mhooks: Mhook_Unhook: readwrite set on system function"));
			PBYTE pbCode = (PBYTE)pTrampoline->pSystemFunction;

			for (DWORD i = 0; i<pTrampoline->cbOverwrittenCode; i++)
				pbCode[i] = pTrampoline->codeUntouched[i];

			// Publish restored code before reinstating the target's original protection.
			FlushInstructionCache(GetCurrentProcess(), pTrampoline->pSystemFunction, pTrampoline->cbOverwrittenCode);
			VirtualProtect(pTrampoline->pSystemFunction, pTrampoline->cbOverwrittenCode, dwOldProtectSystemFunction, &dwOldProtectSystemFunction);

			// Restore the caller slot only after the target bytes are valid again.
			*ppHookedFunction = pTrampoline->pSystemFunction;
            operationStatus = MHOOK_STATUS_SUCCESS;
			bRet = TRUE;
			ODPRINTF((L"mhooks: Mhook_Unhook: sysfunc: %p", *ppHookedFunction));

			// Retire the trampoline without releasing memory that another thread may still execute.
			TrampolineFree(pTrampoline, FALSE);
			ODPRINTF((L"mhooks: Mhook_Unhook: unhook successful"));
		}
		else
		{
			// Preserve VirtualProtect's reason because it identifies the failed system operation.
			operationStatus = MHOOK_STATUS_MEMORY_PROTECTION_FAILED;
			dwError = gle();
			ODPRINTF((L"mhooks: Mhook_Unhook: failed VirtualProtect 1: %d", dwError));
		}

		// Resume peer threads after executable-memory access is complete.
		ResumeOtherThreads();
	}

	// Release serialized state before publishing status and LastError.
	LeaveCritSec();
	g_lastStatus = operationStatus;

	// Set LastError last so cleanup cannot replace the reason returned to the caller.
	if (bRet)
		SetLastError(callerLastError);
	else
		SetLastError(dwError);

	return operationStatus == MHOOK_STATUS_SUCCESS;
}


/**
 * @brief Removes each valid batch request through the shared single-unhook workflow.
 * @param[in,out] hooks Requests to remove and storage for their results.
 * @param[in] hookCount Number of descriptors in hooks.
 * @return TRUE only when every request succeeds.
 */
BOOL Mhook_UnhookBatch(MHOOK_HOOK_INFO* hooks, SIZE_T hookCount)
{
    const DWORD callerLastError = GetLastError();
    const MHOOK_STATUS validationStatus = validateHookInfoArray(hooks, hookCount);

    // Reject the entire request before any unhook runs when result storage is unusable.
    if (validationStatus != MHOOK_STATUS_SUCCESS)
    {
        g_lastStatus = validationStatus;
        SetLastError(callerLastError);
        return FALSE;
    }

    BOOL result = TRUE;
    DWORD batchLastError = callerLastError;
    MHOOK_STATUS batchStatus = MHOOK_STATUS_SUCCESS;

    // Process every request so callers receive a status for each descriptor.
    for (SIZE_T index = 0; index < hookCount; ++index)
    {
        SetLastError(callerLastError);
        const BOOL hookResult = unhook(hooks[index].ppSystemFunction);
        const DWORD hookLastError = GetLastError();
        hooks[index].status = g_lastStatus;

        // Preserve the first failure and its legacy error as the deterministic batch result.
        if (!hookResult && result)
        {
            batchStatus = g_lastStatus;
            batchLastError = hookLastError;
        }

        result = result && hookResult;
    }

    // Publish the overall status and preserve the legacy unhook LastError contract.
    g_lastStatus = batchStatus;
    SetLastError(result ? callerLastError : batchLastError);
    return result;
}


/**
 * @brief Preserves the legacy API by submitting one descriptor to the batch path.
 * @param[in,out] ppHookedFunction Caller slot containing the registered trampoline.
 * @return TRUE when the one-request batch succeeds.
 */
BOOL Mhook_Unhook(PVOID* ppHookedFunction)
{
    MHOOK_HOOK_INFO hook = { ppHookedFunction, NULL, MHOOK_STATUS_SUCCESS };
    return Mhook_UnhookBatch(&hook, 1);
}

//=========================================================================
PVOID Mhook_GetTarget(PVOID pHookedFunction) {
	EnterCritSec();
	MHOOKS_TRAMPOLINE* pTrampoline = TrampolineGet((PBYTE)pHookedFunction);
	PVOID pTarget = pTrampoline ? (PVOID)pTrampoline->pSystemFunction : NULL;
	LeaveCritSec();
	if (!pTarget)
		SetLastError(MHOOK_ERROR_NOT_HOOKED);
	return pTarget;
}

//=========================================================================
