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
    { "invalid_unhook", CaseInvalidUnhook },
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
