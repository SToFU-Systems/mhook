//================================================================================
// Mhook
//
// Copyright (c) 2026, SToFU Systems (https://stofu.io). All rights reserved.
//
// Licensed under the MIT License.
// See LICENSE in the repository root for the full license text.
//================================================================================

#include "mhook-lib/mhook.h"

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

    const BOOL result = Mhook_SetHook(slot, reinterpret_cast<PVOID>(&HookReplacement));
    const MHOOK_STATUS status = Mhook_GetLastStatus();
    const PVOID storedPointer = loadPointer(slot);

    if (result)
    {
        PVOID trampoline = storedPointer;
        Mhook_Unhook(&trampoline);
    }

    const BOOL targetChanged = memcmp(snapshot, target, sizeof(snapshot)) != 0;
    const BOOL slotChanged = storedPointer != target;
    VirtualFree(target, 0, MEM_RELEASE);

    if (result)
        return Fail("Mhook_SetHook accepted a misaligned system-function slot");
    if (status != MHOOK_STATUS_INVALID_DESCRIPTOR)
        return Fail("a misaligned system-function slot did not report INVALID_DESCRIPTOR");
    if (slotChanged)
        return Fail("a rejected misaligned system-function slot was modified");
    if (targetChanged)
        return Fail("a rejected misaligned system-function slot modified target code");

    return 0;
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

    const BOOL result = Mhook_SetHook(slot, reinterpret_cast<PVOID>(&HookReplacement));
    const MHOOK_STATUS status = Mhook_GetLastStatus();
    VirtualFree(slot, 0, MEM_RELEASE);

    if (result)
        return Fail("Mhook_SetHook accepted an inaccessible system-function slot");
    if (status != MHOOK_STATUS_INVALID_DESCRIPTOR)
        return Fail("an inaccessible system-function slot did not report INVALID_DESCRIPTOR");

    return 0;
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

    const BOOL result = Mhook_SetHook(slot, reinterpret_cast<PVOID>(&HookReplacement));
    const MHOOK_STATUS status = Mhook_GetLastStatus();
    const BOOL targetChanged = memcmp(snapshot, target, sizeof(snapshot)) != 0;
    const BOOL slotChanged = loadPointer(slot) != target;
    VirtualFree(slot, 0, MEM_RELEASE);
    VirtualFree(target, 0, MEM_RELEASE);

    if (result)
        return Fail("Mhook_SetHook accepted a read-only system-function slot");
    if (status != MHOOK_STATUS_INVALID_DESCRIPTOR)
        return Fail("a read-only system-function slot did not report INVALID_DESCRIPTOR");
    if (slotChanged)
        return Fail("a rejected read-only system-function slot was modified");
    if (targetChanged)
        return Fail("a rejected read-only system-function slot modified target code");

    return 0;
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

    const BOOL result = Mhook_Unhook(slot);
    const MHOOK_STATUS status = Mhook_GetLastStatus();
    const PVOID storedPointer = loadPointer(slot);
    const BOOL targetChanged = memcmp(snapshot, target, sizeof(snapshot)) != 0;
    const BOOL slotChanged = storedPointer != expectedPointer;

    if (!result)
        Mhook_Unhook(&trampoline);
    VirtualFree(target, 0, MEM_RELEASE);

    if (result)
        return Fail("Mhook_Unhook accepted a misaligned hooked-function slot");
    if (status != MHOOK_STATUS_INVALID_DESCRIPTOR)
        return Fail("a misaligned hooked-function slot did not report INVALID_DESCRIPTOR");
    if (slotChanged)
        return Fail("a rejected misaligned hooked-function slot was modified");
    if (targetChanged)
        return Fail("a rejected misaligned hooked-function slot modified target code");

    return 0;
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

    const BOOL result = Mhook_Unhook(slot);
    const MHOOK_STATUS status = Mhook_GetLastStatus();
    VirtualFree(slot, 0, MEM_RELEASE);

    if (result)
        return Fail("Mhook_Unhook accepted an inaccessible hooked-function slot");
    if (status != MHOOK_STATUS_INVALID_DESCRIPTOR)
        return Fail("an inaccessible hooked-function slot did not report INVALID_DESCRIPTOR");

    return 0;
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

    const BOOL result = Mhook_Unhook(slot);
    const MHOOK_STATUS status = Mhook_GetLastStatus();
    const BOOL targetChanged = memcmp(snapshot, target, sizeof(snapshot)) != 0;
    const BOOL slotChanged = loadPointer(slot) != trampoline;

    if (!result)
        Mhook_Unhook(&trampoline);
    VirtualFree(slot, 0, MEM_RELEASE);
    VirtualFree(target, 0, MEM_RELEASE);

    if (result)
        return Fail("Mhook_Unhook accepted a read-only hooked-function slot");
    if (status != MHOOK_STATUS_INVALID_DESCRIPTOR)
        return Fail("a read-only hooked-function slot did not report INVALID_DESCRIPTOR");
    if (slotChanged)
        return Fail("a rejected read-only hooked-function slot was modified");
    if (targetChanged)
        return Fail("a rejected read-only hooked-function slot modified target code");

    return 0;
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
