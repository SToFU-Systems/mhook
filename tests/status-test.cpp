//================================================================================
// Mhook
//
// Copyright (c) 2026, SToFU Systems (https://stofu.io). All rights reserved.
//
// Licensed under the MIT License.
// See LICENSE in the repository root for the full license text.
//================================================================================

#include "mhook-lib/mhook.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static constexpr uint32_t kTargetBufferSize = 64;
static const BYTE kMovEaxRet[] = { 0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3 };

struct ThreadStatusContext
{
    MHOOK_STATUS initialStatus;
    MHOOK_STATUS finalStatus;
    BOOL unhookResult;
};

static int Fail(const char* message)
{
    fprintf(stderr, "%s\n", message);
    return 1;
}

static int HookTarget(void)
{
    return 42;
}

static int HookReplacement(void)
{
    return 1337;
}


/**
 * @brief Allocates a deterministic executable target for descriptor tests.
 * @return The target buffer, or NULL when allocation fails.
 */
static PBYTE allocateTarget(void)
{
    PBYTE target = static_cast<PBYTE>(VirtualAlloc(NULL, kTargetBufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));

    if (!target)
        return NULL;

    memset(target, 0xCC, kTargetBufferSize);
    memcpy(target, kMovEaxRet, sizeof(kMovEaxRet));
    const BOOL flushResult = FlushInstructionCache(GetCurrentProcess(), target, kTargetBufferSize);
    if (!flushResult)
    {
        VirtualFree(target, 0, MEM_RELEASE);
        return NULL;
    }

    return target;
}


/**
 * @brief Stores a pointer in storage that may not satisfy pointer alignment.
 * @param[out] destination Storage receiving the pointer bytes.
 * @param[in] value Pointer value to store.
 */
static void storePointer(OUT void* destination, PVOID value)
{
    memcpy(destination, &value, sizeof(value));
}


/**
 * @brief Loads a pointer from storage that may not satisfy pointer alignment.
 * @param[in] source Storage containing the pointer bytes.
 * @return The stored pointer.
 */
static PVOID loadPointer(const void* source)
{
    PVOID value = NULL;

    memcpy(&value, source, sizeof(value));
    return value;
}


/**
 * @brief Makes a test buffer executable after its bytes have been initialized.
 * @param[in] memory Buffer to protect.
 * @param[in] size Size of the buffer.
 * @return TRUE when protection and instruction-cache synchronization succeed.
 */
static BOOL makeMemoryExecutable(PVOID memory, SIZE_T size)
{
    DWORD oldProtection = 0;
    const BOOL protectionResult = VirtualProtect(memory, size, PAGE_EXECUTE_READ, &oldProtection);
    if (!protectionResult)
        return FALSE;

    return FlushInstructionCache(GetCurrentProcess(), memory, size);
}


/**
 * @brief Verifies that an invalid set request fails without changing caller or target state.
 * @param[in] systemFunction Requested system-function address.
 * @param[in] hookFunction Requested hook-function address.
 * @param[in] expectedStatus Status expected from the rejected request.
 * @param[in] observedMemory Target memory to compare, or NULL when it is inaccessible.
 * @param[in] expectedMemory Snapshot of the target memory, or NULL when it is inaccessible.
 * @param[in] memorySize Number of target bytes in the snapshot.
 * @return Zero on success; otherwise a test failure code.
 */
static int expectInvalidSet(PVOID systemFunction, PVOID hookFunction, MHOOK_STATUS expectedStatus, const void* observedMemory, const BYTE* expectedMemory, SIZE_T memorySize)
{
    PVOID descriptor = systemFunction;
    const BOOL result = Mhook_SetHook(&descriptor, hookFunction);
    const MHOOK_STATUS status = Mhook_GetLastStatus();
    const BOOL descriptorChanged = descriptor != systemFunction;
    const BOOL targetChanged = expectedMemory && memcmp(observedMemory, expectedMemory, memorySize) != 0;

    if (result)
    {
        PVOID trampoline = descriptor;
        Mhook_Unhook(&trampoline);
    }

    if (result)
        return Fail("Mhook_SetHook accepted an invalid function address");
    if (status != expectedStatus)
        return Fail("an invalid function address reported the wrong status");
    if (descriptorChanged)
        return Fail("a rejected function address changed the caller's descriptor");
    if (targetChanged)
        return Fail("a rejected function address modified target code");

    return 0;
}


/**
 * @brief Verifies that Mhook_SetHook rejects a pointer slot without changing readable state.
 * @param[in,out] slot Pointer slot supplied to Mhook_SetHook.
 * @param[in] expectedPointer Expected pointer value, or NULL when the slot cannot be read.
 * @param[in] target Target bytes to compare, or NULL when no target is available.
 * @param[in] snapshot Expected target bytes, or NULL when no target is available.
 * @return Zero on success; otherwise a test failure code.
 */
static int expectInvalidSetSlot(PVOID* slot, PVOID expectedPointer, const BYTE* target, const BYTE* snapshot)
{
    assert((target == NULL) == (snapshot == NULL));

    const BOOL result = Mhook_SetHook(slot, reinterpret_cast<PVOID>(&HookReplacement));
    const MHOOK_STATUS status = Mhook_GetLastStatus();
    const PVOID storedPointer = expectedPointer ? loadPointer(slot) : NULL;
    const BOOL slotChanged = expectedPointer && storedPointer != expectedPointer;
    const BOOL targetChanged = snapshot && memcmp(target, snapshot, kTargetBufferSize) != 0;

    if (result && storedPointer)
    {
        PVOID trampoline = storedPointer;
        Mhook_Unhook(&trampoline);
    }

    if (result)
        return Fail("Mhook_SetHook accepted an invalid function-pointer slot");
    if (status != MHOOK_STATUS_INVALID_DESCRIPTOR)
        return Fail("an invalid function-pointer slot did not report INVALID_DESCRIPTOR");
    if (slotChanged)
        return Fail("a rejected function-pointer slot was modified");
    if (targetChanged)
        return Fail("a rejected function-pointer slot modified target code");

    return 0;
}


/**
 * @brief Verifies that Mhook_Unhook rejects a pointer slot without changing readable state.
 * @param[in,out] slot Pointer slot supplied to Mhook_Unhook.
 * @param[in] expectedPointer Expected pointer value, or NULL when the slot cannot be read.
 * @param[in] target Target bytes to compare, or NULL when no target is available.
 * @param[in] snapshot Expected target bytes, or NULL when no target is available.
 * @return Zero on success; otherwise a test failure code.
 */
static int expectInvalidUnhookSlot(PVOID* slot, PVOID expectedPointer, const BYTE* target, const BYTE* snapshot)
{
    assert((target == NULL) == (snapshot == NULL));

    const BOOL result = Mhook_Unhook(slot);
    const MHOOK_STATUS status = Mhook_GetLastStatus();
    const BOOL slotChanged = expectedPointer && loadPointer(slot) != expectedPointer;
    const BOOL targetChanged = snapshot && memcmp(target, snapshot, kTargetBufferSize) != 0;

    if (result)
        return Fail("Mhook_Unhook accepted an invalid function-pointer slot");
    if (status != MHOOK_STATUS_INVALID_DESCRIPTOR)
        return Fail("an invalid function-pointer slot did not report INVALID_DESCRIPTOR");
    if (slotChanged)
        return Fail("a rejected function-pointer slot was modified");
    if (targetChanged)
        return Fail("a rejected function-pointer slot modified target code");

    return 0;
}


/**
 * @brief Verifies that an inaccessible system-function address is rejected safely.
 * @return Zero on success; otherwise a test failure code.
 */
static int caseInvalidSetTargetAccess(void)
{
    PVOID target = VirtualAlloc(NULL, kTargetBufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS);

    if (!target)
        return Fail("VirtualAlloc for the inaccessible target failed");

    const int result = expectInvalidSet(target, reinterpret_cast<PVOID>(&HookReplacement), MHOOK_STATUS_INVALID_TARGET, NULL, NULL, 0);
    VirtualFree(target, 0, MEM_RELEASE);
    return result;
}


/**
 * @brief Verifies that a readable but non-executable system-function address is rejected.
 * @return Zero on success; otherwise a test failure code.
 */
static int caseInvalidSetTargetExecute(void)
{
    PBYTE target = static_cast<PBYTE>(VirtualAlloc(NULL, kTargetBufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));

    if (!target)
        return Fail("VirtualAlloc for the non-executable target failed");

    memset(target, 0xCC, kTargetBufferSize);
    memcpy(target, kMovEaxRet, sizeof(kMovEaxRet));
    BYTE snapshot[kTargetBufferSize] = {};
    memcpy(snapshot, target, sizeof(snapshot));

    const int result = expectInvalidSet(target, reinterpret_cast<PVOID>(&HookReplacement), MHOOK_STATUS_INVALID_TARGET, target, snapshot, sizeof(snapshot));
    VirtualFree(target, 0, MEM_RELEASE);
    return result;
}


/**
 * @brief Verifies that an inaccessible hook-function address is rejected safely.
 * @return Zero on success; otherwise a test failure code.
 */
static int caseInvalidSetHookAccess(void)
{
    PBYTE target = allocateTarget();
    PVOID hook = VirtualAlloc(NULL, kTargetBufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS);

    if (!target || !hook)
    {
        if (hook)
            VirtualFree(hook, 0, MEM_RELEASE);
        if (target)
            VirtualFree(target, 0, MEM_RELEASE);
        return Fail("VirtualAlloc for the inaccessible hook test failed");
    }

    BYTE snapshot[kTargetBufferSize] = {};
    memcpy(snapshot, target, sizeof(snapshot));
    const int result = expectInvalidSet(target, hook, MHOOK_STATUS_INVALID_TARGET, target, snapshot, sizeof(snapshot));
    VirtualFree(hook, 0, MEM_RELEASE);
    VirtualFree(target, 0, MEM_RELEASE);
    return result;
}


/**
 * @brief Verifies that a thunk truncated by inaccessible memory is rejected safely.
 * @return Zero on success; otherwise a test failure code.
 */
static int caseInvalidSetThunkBoundary(void)
{
    SYSTEM_INFO systemInfo = {};
    GetSystemInfo(&systemInfo);
    const SIZE_T pageSize = systemInfo.dwPageSize;
    const SIZE_T allocationSize = pageSize * 2;
    PBYTE memory = static_cast<PBYTE>(VirtualAlloc(NULL, allocationSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));

    if (!memory)
        return Fail("VirtualAlloc for the truncated thunk failed");

    PBYTE thunk = memory + pageSize - 1;
    thunk[0] = 0xE9;
    const BYTE snapshot[] = { 0xE9 };
    DWORD oldProtection = 0;
    const BOOL executableResult = makeMemoryExecutable(memory, pageSize);
    const BOOL inaccessibleResult = VirtualProtect(memory + pageSize, pageSize, PAGE_NOACCESS, &oldProtection);

    if (!executableResult || !inaccessibleResult)
    {
        VirtualFree(memory, 0, MEM_RELEASE);
        return Fail("protecting the truncated thunk failed");
    }

    const int result = expectInvalidSet(thunk, reinterpret_cast<PVOID>(&HookReplacement), MHOOK_STATUS_INVALID_TARGET, thunk, snapshot, sizeof(snapshot));
    VirtualFree(memory, 0, MEM_RELEASE);
    return result;
}


/**
 * @brief Verifies that an instruction truncated by inaccessible memory is rejected safely.
 * @return Zero on success; otherwise a test failure code.
 */
static int caseInvalidSetDecodeBoundary(void)
{
    const uint8_t kMoveImmediateOpcode = 0xB8;
    SYSTEM_INFO systemInfo = {};
    GetSystemInfo(&systemInfo);
    const SIZE_T pageSize = systemInfo.dwPageSize;
    const SIZE_T allocationSize = pageSize * 2;
    PBYTE memory = static_cast<PBYTE>(VirtualAlloc(NULL, allocationSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));

    if (!memory)
        return Fail("VirtualAlloc for the truncated instruction failed");

    PBYTE instruction = memory + pageSize - 1;
    instruction[0] = kMoveImmediateOpcode;
    const BYTE snapshot[] = { kMoveImmediateOpcode };
    DWORD oldProtection = 0;
    const BOOL executableResult = makeMemoryExecutable(memory, pageSize);
    const BOOL inaccessibleResult = VirtualProtect(memory + pageSize, pageSize, PAGE_NOACCESS, &oldProtection);

    if (!executableResult || !inaccessibleResult)
    {
        VirtualFree(memory, 0, MEM_RELEASE);
        return Fail("protecting the truncated instruction failed");
    }

    const int result = expectInvalidSet(instruction, reinterpret_cast<PVOID>(&HookReplacement), MHOOK_STATUS_INVALID_TARGET, instruction, snapshot, sizeof(snapshot));
    VirtualFree(memory, 0, MEM_RELEASE);
    return result;
}


/**
 * @brief Verifies that an inaccessible indirect thunk slot is rejected safely.
 * @return Zero on success; otherwise a test failure code.
 */
static int caseInvalidSetThunkIndirect(void)
{
    const SIZE_T kThunkSize = 6;
    SYSTEM_INFO systemInfo = {};
    GetSystemInfo(&systemInfo);
    const SIZE_T pageSize = systemInfo.dwPageSize;
    const SIZE_T allocationSize = pageSize * 2;
    PBYTE memory = static_cast<PBYTE>(VirtualAlloc(NULL, allocationSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));

    if (!memory)
        return Fail("VirtualAlloc for the indirect thunk failed");

    PBYTE thunk = memory;
    PBYTE pointerSlot = memory + pageSize;
    thunk[0] = 0xFF;
    thunk[1] = 0x25;
#ifdef _M_IX86
    const DWORD slotAddress = static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(pointerSlot));
    memcpy(thunk + 2, &slotAddress, sizeof(slotAddress));
#elif defined _M_X64
    const INT32 slotOffset = static_cast<INT32>(pointerSlot - (thunk + kThunkSize));
    memcpy(thunk + 2, &slotOffset, sizeof(slotOffset));
#else // !_M_IX86 && !_M_X64
#error unsupported platform
#endif // _M_IX86 || _M_X64
    BYTE snapshot[kThunkSize] = {};
    memcpy(snapshot, thunk, sizeof(snapshot));

    DWORD oldProtection = 0;
    const BOOL executableResult = makeMemoryExecutable(memory, pageSize);
    const BOOL inaccessibleResult = VirtualProtect(pointerSlot, pageSize, PAGE_NOACCESS, &oldProtection);

    if (!executableResult || !inaccessibleResult)
    {
        VirtualFree(memory, 0, MEM_RELEASE);
        return Fail("protecting the indirect thunk failed");
    }

    const int result = expectInvalidSet(thunk, reinterpret_cast<PVOID>(&HookReplacement), MHOOK_STATUS_INVALID_TARGET, thunk, snapshot, sizeof(snapshot));
    VirtualFree(memory, 0, MEM_RELEASE);
    return result;
}


/**
 * @brief Verifies that a cyclic thunk is rejected without unbounded recursion.
 * @return Zero on success; otherwise a test failure code.
 */
static int caseInvalidSetThunkCycle(void)
{
    const INT32 kSelfOffset = -5;
    PBYTE thunk = static_cast<PBYTE>(VirtualAlloc(NULL, kTargetBufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));

    if (!thunk)
        return Fail("VirtualAlloc for the cyclic thunk failed");

    memset(thunk, 0xCC, kTargetBufferSize);
    thunk[0] = 0xE9;
    memcpy(thunk + 1, &kSelfOffset, sizeof(kSelfOffset));
    BYTE snapshot[kTargetBufferSize] = {};
    memcpy(snapshot, thunk, sizeof(snapshot));

    if (!makeMemoryExecutable(thunk, kTargetBufferSize))
    {
        VirtualFree(thunk, 0, MEM_RELEASE);
        return Fail("protecting the cyclic thunk failed");
    }

    const int result = expectInvalidSet(thunk, reinterpret_cast<PVOID>(&HookReplacement), MHOOK_STATUS_JUMP_CYCLE, thunk, snapshot, sizeof(snapshot));
    VirtualFree(thunk, 0, MEM_RELEASE);
    return result;
}


/**
 * @brief Verifies that an excessive acyclic thunk chain is rejected.
 * @return Zero on success; otherwise a test failure code.
 */
static int caseInvalidSetThunkDepth(void)
{
    const SIZE_T kThunkSize = 5;
    const SIZE_T kThunkStride = 8;
    const SIZE_T kThunkCount = 17;
    const SIZE_T kBufferSize = kThunkStride * kThunkCount + kTargetBufferSize;
    const INT32 kNextThunkOffset = static_cast<INT32>(kThunkStride - kThunkSize);
    PBYTE memory = static_cast<PBYTE>(VirtualAlloc(NULL, kBufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));

    if (!memory)
        return Fail("VirtualAlloc for the deep thunk chain failed");

    memset(memory, 0xCC, kBufferSize);
    for (SIZE_T index = 0; index < kThunkCount; ++index)
    {
        PBYTE thunk = memory + index * kThunkStride;
        thunk[0] = 0xE9;
        memcpy(thunk + 1, &kNextThunkOffset, sizeof(kNextThunkOffset));
    }
    memcpy(memory + kThunkCount * kThunkStride, kMovEaxRet, sizeof(kMovEaxRet));

    BYTE snapshot[kBufferSize] = {};
    memcpy(snapshot, memory, sizeof(snapshot));
    if (!makeMemoryExecutable(memory, kBufferSize))
    {
        VirtualFree(memory, 0, MEM_RELEASE);
        return Fail("protecting the deep thunk chain failed");
    }

    const int result = expectInvalidSet(memory, reinterpret_cast<PVOID>(&HookReplacement), MHOOK_STATUS_JUMP_DEPTH_EXCEEDED, memory, snapshot, sizeof(snapshot));
    VirtualFree(memory, 0, MEM_RELEASE);
    return result;
}


/**
 * @brief Verifies that Mhook_SetHook rejects a misaligned pointer slot.
 * @return Zero on success; otherwise a test failure code.
 */
static int caseInvalidSetSlotAlignment(void)
{
    alignas(PVOID) BYTE storage[sizeof(PVOID) + 1] = {};
    PVOID* slot = reinterpret_cast<PVOID*>(storage + 1);
    PBYTE target = allocateTarget();

    if (!target)
        return Fail("VirtualAlloc for the target buffer failed");

    BYTE snapshot[kTargetBufferSize] = {};
    memcpy(snapshot, target, sizeof(snapshot));
    storePointer(slot, target);

    const int result = expectInvalidSetSlot(slot, target, target, snapshot);
    VirtualFree(target, 0, MEM_RELEASE);
    return result;
}


/**
 * @brief Verifies that Mhook_SetHook rejects an inaccessible pointer slot.
 * @return Zero on success; otherwise a test failure code.
 */
static int caseInvalidSetSlotAccess(void)
{
    PVOID* slot = static_cast<PVOID*>(VirtualAlloc(NULL, sizeof(PVOID), MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS));

    if (!slot)
        return Fail("VirtualAlloc for the inaccessible slot failed");

    const int result = expectInvalidSetSlot(slot, NULL, NULL, NULL);
    VirtualFree(slot, 0, MEM_RELEASE);
    return result;
}


/**
 * @brief Verifies that Mhook_SetHook rejects a read-only pointer slot.
 * @return Zero on success; otherwise a test failure code.
 */
static int caseInvalidSetSlotWrite(void)
{
    PBYTE target = allocateTarget();
    PVOID* slot = static_cast<PVOID*>(VirtualAlloc(NULL, sizeof(PVOID), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));

    if (!target || !slot)
    {
        if (slot)
            VirtualFree(slot, 0, MEM_RELEASE);
        if (target)
            VirtualFree(target, 0, MEM_RELEASE);
        return Fail("VirtualAlloc for the read-only slot test failed");
    }

    BYTE snapshot[kTargetBufferSize] = {};
    memcpy(snapshot, target, sizeof(snapshot));
    *slot = target;
    DWORD oldProtection = 0;
    const BOOL protectedSlot = VirtualProtect(slot, sizeof(PVOID), PAGE_READONLY, &oldProtection);

    if (!protectedSlot)
    {
        VirtualFree(slot, 0, MEM_RELEASE);
        VirtualFree(target, 0, MEM_RELEASE);
        return Fail("VirtualProtect for the read-only slot failed");
    }

    const int result = expectInvalidSetSlot(slot, target, target, snapshot);
    VirtualFree(slot, 0, MEM_RELEASE);
    VirtualFree(target, 0, MEM_RELEASE);
    return result;
}


/**
 * @brief Verifies that Mhook_Unhook rejects a misaligned pointer slot.
 * @return Zero on success; otherwise a test failure code.
 */
static int caseInvalidUnhookSlotAlignment(void)
{
    alignas(PVOID) BYTE storage[sizeof(PVOID) + 1] = {};
    PVOID* slot = reinterpret_cast<PVOID*>(storage + 1);
    PBYTE target = allocateTarget();

    if (!target)
        return Fail("VirtualAlloc for the target buffer failed");

    PVOID trampoline = target;
    if (!Mhook_SetHook(&trampoline, reinterpret_cast<PVOID>(&HookReplacement)))
    {
        VirtualFree(target, 0, MEM_RELEASE);
        return Fail("Mhook_SetHook failed while preparing the misaligned unhook test");
    }

    BYTE snapshot[kTargetBufferSize] = {};
    memcpy(snapshot, target, sizeof(snapshot));
    storePointer(slot, trampoline);
    const PVOID expectedPointer = trampoline;

    const int result = expectInvalidUnhookSlot(slot, expectedPointer, target, snapshot);
    Mhook_Unhook(&trampoline);
    VirtualFree(target, 0, MEM_RELEASE);
    return result;
}


/**
 * @brief Verifies that Mhook_Unhook rejects an inaccessible pointer slot.
 * @return Zero on success; otherwise a test failure code.
 */
static int caseInvalidUnhookSlotAccess(void)
{
    PVOID* slot = static_cast<PVOID*>(VirtualAlloc(NULL, sizeof(PVOID), MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS));

    if (!slot)
        return Fail("VirtualAlloc for the inaccessible slot failed");

    const int result = expectInvalidUnhookSlot(slot, NULL, NULL, NULL);
    VirtualFree(slot, 0, MEM_RELEASE);
    return result;
}


/**
 * @brief Verifies that Mhook_Unhook rejects a read-only pointer slot.
 * @return Zero on success; otherwise a test failure code.
 */
static int caseInvalidUnhookSlotWrite(void)
{
    PBYTE target = allocateTarget();
    PVOID* slot = static_cast<PVOID*>(VirtualAlloc(NULL, sizeof(PVOID), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));

    if (!target || !slot)
    {
        if (slot)
            VirtualFree(slot, 0, MEM_RELEASE);
        if (target)
            VirtualFree(target, 0, MEM_RELEASE);
        return Fail("VirtualAlloc for the read-only unhook slot test failed");
    }

    PVOID trampoline = target;
    if (!Mhook_SetHook(&trampoline, reinterpret_cast<PVOID>(&HookReplacement)))
    {
        VirtualFree(slot, 0, MEM_RELEASE);
        VirtualFree(target, 0, MEM_RELEASE);
        return Fail("Mhook_SetHook failed while preparing the read-only unhook test");
    }

    BYTE snapshot[kTargetBufferSize] = {};
    memcpy(snapshot, target, sizeof(snapshot));
    *slot = trampoline;
    DWORD oldProtection = 0;
    const BOOL protectedSlot = VirtualProtect(slot, sizeof(PVOID), PAGE_READONLY, &oldProtection);

    if (!protectedSlot)
    {
        Mhook_Unhook(&trampoline);
        VirtualFree(slot, 0, MEM_RELEASE);
        VirtualFree(target, 0, MEM_RELEASE);
        return Fail("VirtualProtect for the read-only unhook slot failed");
    }

    const int result = expectInvalidUnhookSlot(slot, trampoline, target, snapshot);
    Mhook_Unhook(&trampoline);
    VirtualFree(slot, 0, MEM_RELEASE);
    VirtualFree(target, 0, MEM_RELEASE);
    return result;
}

static int CaseInitial(void)
{
    if (Mhook_GetLastStatus() != MHOOK_STATUS_SUCCESS)
        return Fail("a new thread did not begin with MHOOK_STATUS_SUCCESS");

    return 0;
}

static int CaseInvalidSet(void)
{
    if (Mhook_SetHook(NULL, reinterpret_cast<PVOID>(&HookReplacement)))
        return Fail("Mhook_SetHook accepted a null system-function pointer");
    if (Mhook_GetLastStatus() != MHOOK_STATUS_INVALID_ARGUMENT)
        return Fail("a null system-function pointer did not report INVALID_ARGUMENT");

    PVOID target = NULL;
    if (Mhook_SetHook(&target, reinterpret_cast<PVOID>(&HookReplacement)))
        return Fail("Mhook_SetHook accepted a null system function");
    if (Mhook_GetLastStatus() != MHOOK_STATUS_INVALID_ARGUMENT)
        return Fail("a null system function did not report INVALID_ARGUMENT");

    target = reinterpret_cast<PVOID>(&HookTarget);
    if (Mhook_SetHook(&target, NULL))
        return Fail("Mhook_SetHook accepted a null hook function");
    if (Mhook_GetLastStatus() != MHOOK_STATUS_INVALID_ARGUMENT)
        return Fail("a null hook function did not report INVALID_ARGUMENT");

    return 0;
}

static int CaseInvalidUnhook(void)
{
    if (Mhook_Unhook(NULL))
        return Fail("Mhook_Unhook accepted a null hooked-function pointer");
    if (Mhook_GetLastStatus() != MHOOK_STATUS_INVALID_ARGUMENT)
        return Fail("a null hooked-function pointer did not report INVALID_ARGUMENT");

    PVOID target = NULL;
    if (Mhook_Unhook(&target))
        return Fail("Mhook_Unhook accepted a null hooked function");
    if (Mhook_GetLastStatus() != MHOOK_STATUS_INVALID_ARGUMENT)
        return Fail("a null hooked function did not report INVALID_ARGUMENT");

    return 0;
}

static int CaseNotFound(void)
{
    PVOID target = reinterpret_cast<PVOID>(&HookTarget);

    if (Mhook_Unhook(&target))
        return Fail("Mhook_Unhook accepted a function that was never hooked");
    if (Mhook_GetLastStatus() != MHOOK_STATUS_HOOK_NOT_FOUND)
        return Fail("an unknown hook did not report HOOK_NOT_FOUND");
    if (Mhook_GetLastStatus() != MHOOK_STATUS_HOOK_NOT_FOUND)
        return Fail("Mhook_GetLastStatus cleared the stored status");
    if (target != reinterpret_cast<PVOID>(&HookTarget))
        return Fail("a failed Mhook_Unhook changed the caller's pointer");

    return 0;
}

static DWORD WINAPI ReadStatusOnWorker(LPVOID parameter)
{
    ThreadStatusContext* context = static_cast<ThreadStatusContext*>(parameter);
    PVOID target = reinterpret_cast<PVOID>(&HookTarget);

    context->initialStatus = Mhook_GetLastStatus();
    context->unhookResult = Mhook_Unhook(&target);
    context->finalStatus = Mhook_GetLastStatus();
    return 0;
}

static int CaseThreadLocal(void)
{
    if (Mhook_SetHook(NULL, reinterpret_cast<PVOID>(&HookReplacement)))
        return Fail("Mhook_SetHook accepted invalid input on the main thread");
    if (Mhook_GetLastStatus() != MHOOK_STATUS_INVALID_ARGUMENT)
        return Fail("the main thread did not store INVALID_ARGUMENT");

    ThreadStatusContext context = {};
    HANDLE thread = CreateThread(NULL, 0, ReadStatusOnWorker, &context, 0, NULL);

    if (!thread)
        return Fail("CreateThread failed");

    const DWORD waitResult = WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);

    if (waitResult != WAIT_OBJECT_0)
        return Fail("waiting for the status worker failed");
    if (context.initialStatus != MHOOK_STATUS_SUCCESS)
        return Fail("the worker thread inherited the main thread's status");
    if (context.unhookResult)
        return Fail("the worker thread unhooked an unknown function");
    if (context.finalStatus != MHOOK_STATUS_HOOK_NOT_FOUND)
        return Fail("the worker thread did not store HOOK_NOT_FOUND");
    if (Mhook_GetLastStatus() != MHOOK_STATUS_INVALID_ARGUMENT)
        return Fail("the worker thread overwrote the main thread's status");

    return 0;
}

static int CaseSuccess(void)
{
    PVOID unknownTarget = reinterpret_cast<PVOID>(&HookTarget);

    if (Mhook_Unhook(&unknownTarget))
        return Fail("Mhook_Unhook accepted a function that was never hooked");
    if (Mhook_GetLastStatus() != MHOOK_STATUS_HOOK_NOT_FOUND)
        return Fail("the setup failure did not report HOOK_NOT_FOUND");

    PBYTE target = static_cast<PBYTE>(VirtualAlloc(NULL, kTargetBufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));

    if (!target)
        return Fail("VirtualAlloc for the target buffer failed");

    memset(target, 0xCC, kTargetBufferSize);
    memcpy(target, kMovEaxRet, sizeof(kMovEaxRet));
    PVOID trampoline = target;

    if (!Mhook_SetHook(&trampoline, reinterpret_cast<PVOID>(&HookReplacement)))
        return Fail("Mhook_SetHook failed for a valid target");
    if (Mhook_GetLastStatus() != MHOOK_STATUS_SUCCESS)
        return Fail("a successful hook did not replace the prior failure status");

    return 0;
}

struct StatusTestCase
{
    const char* name;
    int (*run)(void);
};

static const StatusTestCase kStatusTestCases[] = {
    { "initial", CaseInitial },
    { "invalid_set", CaseInvalidSet },
    { "invalid_set_target_access", caseInvalidSetTargetAccess },
    { "invalid_set_target_execute", caseInvalidSetTargetExecute },
    { "invalid_set_hook_access", caseInvalidSetHookAccess },
    { "invalid_set_thunk_boundary", caseInvalidSetThunkBoundary },
    { "invalid_set_decode_boundary", caseInvalidSetDecodeBoundary },
    { "invalid_set_thunk_indirect", caseInvalidSetThunkIndirect },
    { "invalid_set_thunk_cycle", caseInvalidSetThunkCycle },
    { "invalid_set_thunk_depth", caseInvalidSetThunkDepth },
    { "invalid_set_slot_alignment", caseInvalidSetSlotAlignment },
    { "invalid_set_slot_access", caseInvalidSetSlotAccess },
    { "invalid_set_slot_write", caseInvalidSetSlotWrite },
    { "invalid_unhook", CaseInvalidUnhook },
    { "invalid_unhook_slot_alignment", caseInvalidUnhookSlotAlignment },
    { "invalid_unhook_slot_access", caseInvalidUnhookSlotAccess },
    { "invalid_unhook_slot_write", caseInvalidUnhookSlotWrite },
    { "not_found", CaseNotFound },
    { "thread_local", CaseThreadLocal },
    { "success", CaseSuccess }
};

int main(int argc, char** argv)
{
    if (argc != 2)
        return Fail("usage: mhook-status-test <case>");

    for (size_t index = 0; index < sizeof(kStatusTestCases) / sizeof(kStatusTestCases[0]); ++index)
    {
        if (strcmp(argv[1], kStatusTestCases[index].name) == 0)
            return kStatusTestCases[index].run();
    }

    return Fail("unknown status test case");
}
