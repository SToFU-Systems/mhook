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
// Copyright (c) 2026, SToFU Systems (https://stofu.io). All rights reserved.
//
// Licensed under the MIT License.
// See LICENSE in the repository root for the full license text.
//================================================================================

#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <vector>
#include "mhook-lib/mhook.h"

typedef int (*TargetFn)(void);

static int Fail(const char* message)
{
    fprintf(stderr, "%s\n", message);
    return 1;
}

// Targets live in a 64 byte buffer whose tail is filled with int3, so that
// execution running off the end of a short prologue traps instead of falling
// into zero bytes, which would decode as a harmless-looking add and run on.
#define TARGET_BUFFER_SIZE 64
#define TARGET_RESULT 42
#define HOOK_RESULT 1337

// mov eax, 42; ret - exactly five bytes before the ret, which is the minimum
// DisassembleAndSkip can accept for MHOOK_JMPSIZE.
static const BYTE kMovEaxRet[] = {0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3};

// Every hook and unhook pair costs at least two system wide thread snapshots in
// suspendOtherThreads, which dominates the runtime of the bulk cases. CI cannot
// afford the exhaustive versions, so they sample deterministically by default
// and run in full when MHOOK_TEST_EXHAUSTIVE is set in the environment.
static bool Exhaustive(void)
{
    return GetEnvironmentVariableA("MHOOK_TEST_EXHAUSTIVE", NULL, 0) != 0;
}

static volatile LONG g_hookCalls = 0;
// CaseTrampoline is the only case that uses this global, and HookChaining is
// the only function that reads it: HookChaining takes zero arguments, so it
// has no other way to reach the trampoline it calls through.
static PVOID g_trampoline = NULL;

static PBYTE AllocCodeBuffer(const BYTE* code, size_t length, PVOID address = NULL)
{
    PBYTE buffer = (PBYTE)VirtualAlloc(address, TARGET_BUFFER_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (buffer)
    {
        memset(buffer, 0xCC, TARGET_BUFFER_SIZE);
        memcpy(buffer, code, length);
        FlushInstructionCache(GetCurrentProcess(), buffer, TARGET_BUFFER_SIZE);
    }
    return buffer;
}

/**
 * @brief Creates executable code in a writable mapped view that can be remapped at the same address.
 * @param[in] code Bytes copied into the mapped target.
 * @param[in] length Number of bytes copied from code.
 * @param[out] mapping Mapping handle that owns the returned view.
 * @return Executable writable view, or NULL when setup fails.
 */
static PBYTE allocateMappedCodeBuffer(const BYTE* code, size_t length, OUT HANDLE* mapping)
{
    *mapping = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, TARGET_BUFFER_SIZE, NULL);
    if (!*mapping)
        return NULL;

    PBYTE buffer = static_cast<PBYTE>(
        MapViewOfFile(*mapping, FILE_MAP_READ | FILE_MAP_WRITE | FILE_MAP_EXECUTE, 0, 0, TARGET_BUFFER_SIZE)
    );
    if (!buffer)
    {
        CloseHandle(*mapping);
        *mapping = NULL;
        return NULL;
    }

    memset(buffer, 0xCC, TARGET_BUFFER_SIZE);
    memcpy(buffer, code, length);
    if (!FlushInstructionCache(GetCurrentProcess(), buffer, TARGET_BUFFER_SIZE))
    {
        UnmapViewOfFile(buffer);
        CloseHandle(*mapping);
        *mapping = NULL;
        return NULL;
    }

    return buffer;
}

/**
 * @brief Creates executable code whose mapped view cannot be made writable.
 * @param[in] code Bytes copied into the mapped target.
 * @param[in] length Number of bytes copied from code.
 * @param[out] mapping Mapping handle that owns the returned view.
 * @return Executable read-only view, or NULL when setup fails.
 */
static PBYTE allocateReadOnlyCodeBuffer(const BYTE* code, size_t length, OUT HANDLE* mapping)
{
    PBYTE writableView = allocateMappedCodeBuffer(code, length, mapping);
    if (!writableView)
        return NULL;

    // Exclude write access from the target view so hook commit cannot change its protection.
    PBYTE executableView =
        static_cast<PBYTE>(MapViewOfFile(*mapping, FILE_MAP_READ | FILE_MAP_EXECUTE, 0, 0, TARGET_BUFFER_SIZE));
    UnmapViewOfFile(writableView);

    if (!executableView)
    {
        CloseHandle(*mapping);
        *mapping = NULL;
        return NULL;
    }

    return executableView;
}

static bool IsJumpPatched(const BYTE* code)
{
    return code[0] == 0xE9 || (code[0] == 0xFF && code[1] == 0x25);
}

static int HookCounting(void)
{
    InterlockedIncrement(&g_hookCalls);
    return HOOK_RESULT;
}

static int CaseBasic(void)
{
    PBYTE target = AllocCodeBuffer(kMovEaxRet, sizeof(kMovEaxRet));
    if (!target)
        return Fail("VirtualAlloc for the target buffer failed");

    g_hookCalls = 0;
    PVOID trampoline = target;
    if (!Mhook_SetHook(&trampoline, (PVOID)&HookCounting))
        return Fail("Mhook_SetHook failed on a five byte prologue");
    if (trampoline == (PVOID)target)
        return Fail("Mhook_SetHook left the pointer unchanged instead of writing the trampoline");
    if (!IsJumpPatched(target))
        return Fail("the target prologue does not start with a jump");
    if (((TargetFn)target)() != HOOK_RESULT)
        return Fail("calling the target did not reach the hook");
    if (g_hookCalls != 1)
        return Fail("the hook ran a number of times other than once");

    Mhook_Unhook(&trampoline);
    return 0;
}

static int HookChaining(void)
{
    InterlockedIncrement(&g_hookCalls);
    return ((TargetFn)g_trampoline)() + 1;
}

static int CaseTrampoline(void)
{
    PBYTE target = AllocCodeBuffer(kMovEaxRet, sizeof(kMovEaxRet));
    if (!target)
        return Fail("VirtualAlloc for the target buffer failed");

    g_hookCalls = 0;
    g_trampoline = target;
    if (!Mhook_SetHook(&g_trampoline, (PVOID)&HookChaining))
        return Fail("Mhook_SetHook failed on a five byte prologue");
    if (((TargetFn)g_trampoline)() != TARGET_RESULT)
        return Fail("calling the trampoline did not produce the original result");
    if (g_hookCalls != 0)
        return Fail("calling the trampoline re-entered the hook");
    if (((TargetFn)target)() != TARGET_RESULT + 1)
        return Fail("the hook did not receive the original result through the trampoline");
    if (g_hookCalls != 1)
        return Fail("the hook ran a number of times other than once");

    Mhook_Unhook(&g_trampoline);
    return 0;
}

static int CaseRestore(void)
{
    PBYTE target = AllocCodeBuffer(kMovEaxRet, sizeof(kMovEaxRet));
    if (!target)
        return Fail("VirtualAlloc for the target buffer failed");

    BYTE snapshot[TARGET_BUFFER_SIZE];
    memcpy(snapshot, target, TARGET_BUFFER_SIZE);

    g_hookCalls = 0;
    PVOID trampoline = target;
    if (!Mhook_SetHook(&trampoline, (PVOID)&HookCounting))
        return Fail("Mhook_SetHook failed on a five byte prologue");
    if (memcmp(target, snapshot, TARGET_BUFFER_SIZE) == 0)
        return Fail("Mhook_SetHook did not modify the target bytes");
    if (!Mhook_Unhook(&trampoline))
        return Fail("Mhook_Unhook failed");
    if (memcmp(target, snapshot, TARGET_BUFFER_SIZE) != 0)
        return Fail("Mhook_Unhook did not restore the original bytes");
    if (trampoline != (PVOID)target)
        return Fail("Mhook_Unhook did not write the original address back");
    if (((TargetFn)target)() != TARGET_RESULT)
        return Fail("the unhooked target did not produce the original result");
    if (g_hookCalls != 0)
        return Fail("the hook ran after unhooking");
    return 0;
}

/**
 * @brief Verifies that the batch API installs and removes multiple hooks through shared descriptors.
 * @return Zero on success; otherwise a test failure code.
 */
static int caseBatch(void)
{
    const DWORD kInstallLastError = ERROR_ACCESS_DENIED;
    const DWORD kUnhookLastError = ERROR_BUSY;
    PBYTE firstTarget = AllocCodeBuffer(kMovEaxRet, sizeof(kMovEaxRet));
    PBYTE secondTarget = AllocCodeBuffer(kMovEaxRet, sizeof(kMovEaxRet));

    if (!firstTarget || !secondTarget)
        return Fail("VirtualAlloc for a batch target failed");

    BYTE firstSnapshot[TARGET_BUFFER_SIZE] = {};
    BYTE secondSnapshot[TARGET_BUFFER_SIZE] = {};
    memcpy(firstSnapshot, firstTarget, sizeof(firstSnapshot));
    memcpy(secondSnapshot, secondTarget, sizeof(secondSnapshot));

    PVOID firstTrampoline = firstTarget;
    PVOID secondTrampoline = secondTarget;
    MHOOK_HOOK_INFO hooks[] = {
        {&firstTrampoline, reinterpret_cast<PVOID>(&HookCounting), MHOOK_STATUS_INVALID_ARGUMENT},
        {&secondTrampoline, reinterpret_cast<PVOID>(&HookCounting), MHOOK_STATUS_INVALID_ARGUMENT}
    };

    SetLastError(kInstallLastError);
    const BOOL installResult = Mhook_SetHookBatch(hooks, ARRAYSIZE(hooks));
    const DWORD installLastError = GetLastError();

    if (!installResult)
        return Fail("Mhook_SetHookBatch failed for valid hooks");
    if (installLastError != kInstallLastError)
        return Fail("Mhook_SetHookBatch did not preserve the caller's last error");
    if (Mhook_GetLastStatus() != MHOOK_STATUS_SUCCESS)
        return Fail("Mhook_SetHookBatch did not report overall success");
    if (hooks[0].status != MHOOK_STATUS_SUCCESS || hooks[1].status != MHOOK_STATUS_SUCCESS)
        return Fail("Mhook_SetHookBatch did not report per-hook success");
    if (firstTrampoline == firstTarget || secondTrampoline == secondTarget)
        return Fail("Mhook_SetHookBatch did not publish every trampoline");
    if (((TargetFn)firstTarget)() != HOOK_RESULT || ((TargetFn)secondTarget)() != HOOK_RESULT)
        return Fail("a batch target did not reach the hook");

    SetLastError(kUnhookLastError);
    const BOOL unhookResult = Mhook_UnhookBatch(hooks, ARRAYSIZE(hooks));
    const DWORD unhookLastError = GetLastError();

    if (!unhookResult)
        return Fail("Mhook_UnhookBatch failed for valid hooks");
    if (unhookLastError != kUnhookLastError)
        return Fail("Mhook_UnhookBatch did not preserve the caller's last error");
    if (Mhook_GetLastStatus() != MHOOK_STATUS_SUCCESS)
        return Fail("Mhook_UnhookBatch did not report overall success");
    if (hooks[0].status != MHOOK_STATUS_SUCCESS || hooks[1].status != MHOOK_STATUS_SUCCESS)
        return Fail("Mhook_UnhookBatch did not report per-hook success");
    if (firstTrampoline != firstTarget || secondTrampoline != secondTarget)
        return Fail("Mhook_UnhookBatch did not restore every target pointer");
    if (memcmp(firstTarget, firstSnapshot, sizeof(firstSnapshot)) != 0 ||
        memcmp(secondTarget, secondSnapshot, sizeof(secondSnapshot)) != 0)
        return Fail("Mhook_UnhookBatch did not restore every target prologue");

    VirtualFree(firstTarget, 0, MEM_RELEASE);
    VirtualFree(secondTarget, 0, MEM_RELEASE);
    return 0;
}

static int CaseConflict(void)
{
    PBYTE target = AllocCodeBuffer(kMovEaxRet, sizeof(kMovEaxRet));
    if (!target)
        return Fail("VirtualAlloc for the target buffer failed");

    PVOID trampoline = target;
    if (!Mhook_SetHook(&trampoline, (PVOID)&HookCounting))
        return Fail("Mhook_SetHook failed on a five byte prologue");
    if (Mhook_GetTarget(trampoline) != (PVOID)target)
        return Fail("Mhook_GetTarget did not report the patched address");

    // Stand in for a second hooking engine patching the same prologue after we
    // did. Byte one is inside the relative displacement of our own jump, so it
    // is squarely within the overwrite zone Mhook recorded.
    target[1] ^= 0xFF;
    FlushInstructionCache(GetCurrentProcess(), target, TARGET_BUFFER_SIZE);

    BYTE patched[TARGET_BUFFER_SIZE];
    memcpy(patched, target, TARGET_BUFFER_SIZE);

    PVOID const before = trampoline;
    SetLastError(ERROR_SUCCESS);
    if (Mhook_Unhook(&trampoline))
        return Fail("Mhook_Unhook restored a target somebody else had patched");
    if (GetLastError() != MHOOK_ERROR_TARGET_MODIFIED)
        return Fail("Mhook_Unhook did not report the conflict through GetLastError");
    if (Mhook_GetLastStatus() != MHOOK_STATUS_TARGET_MODIFIED)
        return Fail("Mhook_Unhook reported the wrong status for a modified target");
    if (trampoline != before)
        return Fail("the refused Mhook_Unhook still overwrote the pointer");
    if (memcmp(target, patched, TARGET_BUFFER_SIZE) != 0)
        return Fail("the refused Mhook_Unhook modified the target bytes");
    // The conflict has to leave the caller something actionable to log.
    if (Mhook_GetTarget(trampoline) != (PVOID)target)
        return Fail("Mhook_GetTarget did not report the contested address after the conflict");

    // The hook is still registered, so putting the prologue back the way Mhook
    // left it must let a second attempt through.
    target[1] ^= 0xFF;
    FlushInstructionCache(GetCurrentProcess(), target, TARGET_BUFFER_SIZE);
    if (!Mhook_Unhook(&trampoline))
        return Fail("Mhook_Unhook failed after the conflicting patch was reverted");
    if (trampoline != (PVOID)target)
        return Fail("Mhook_Unhook did not write the original address back");
    if (((TargetFn)target)() != TARGET_RESULT)
        return Fail("the unhooked target did not produce the original result");

    SetLastError(ERROR_SUCCESS);
    if (Mhook_GetTarget(trampoline) != NULL)
        return Fail("Mhook_GetTarget reported a target for a function that is not hooked");
    if (GetLastError() != MHOOK_ERROR_NOT_HOOKED)
        return Fail("Mhook_GetTarget did not report MHOOK_ERROR_NOT_HOOKED");
    SetLastError(ERROR_SUCCESS);
    if (Mhook_Unhook(&trampoline))
        return Fail("Mhook_Unhook succeeded for a function that is not hooked");
    if (GetLastError() != MHOOK_ERROR_NOT_HOOKED)
        return Fail("Mhook_Unhook did not report MHOOK_ERROR_NOT_HOOKED");
    return 0;
}

typedef int(__stdcall* Sum5Fn)(int, int, int, int, int);

__declspec(noinline) static int __stdcall Sum5(int a, int b, int c, int d, int e)
{
    volatile int accumulator = a;
    accumulator += b;
    accumulator += c;
    accumulator += d;
    accumulator += e;
    return accumulator;
}

static Sum5Fn g_trueSum5 = NULL;
static volatile LONG g_sum5HookCalls = 0;

__declspec(noinline) static int __stdcall HookSum5(int a, int b, int c, int d, int e)
{
    InterlockedIncrement(&g_sum5HookCalls);
    return g_trueSum5(a, b, c, d, e) + 1;
}

static int CasePassthrough(void)
{
    const DWORD kInstallLastError = ERROR_ACCESS_DENIED;
    const DWORD kCallThroughLastError = ERROR_BAD_COMMAND;
    const DWORD kUnhookLastError = ERROR_BUSY;
    static Sum5Fn volatile callSum5 = &Sum5;
    int result = 0;

    if (callSum5(1, 2, 3, 4, 5) != 15)
        return Fail("the unhooked target does not sum its arguments");

    PVOID original = (PVOID)&Sum5;
    SetLastError(kInstallLastError);
    const BOOL hookInstalled = Mhook_SetHook(&original, (PVOID)&HookSum5);
    const DWORD installLastError = GetLastError();
    if (!hookInstalled)
        return Fail("Mhook_SetHook failed on the compiled target");
    if (installLastError != kInstallLastError)
        result = Fail("Mhook_SetHook did not preserve the caller's last error");
    g_trueSum5 = (Sum5Fn)original;

    g_sum5HookCalls = 0;
    SetLastError(kCallThroughLastError);
    const int hooked = callSum5(1, 2, 3, 4, 5);
    const DWORD callThroughLastError = GetLastError();
    if (g_sum5HookCalls != 1)
        return Fail("the hook ran a number of times other than once");
    if (hooked != 16)
        return Fail("arguments or the return value were corrupted passing through the hook");
    if (!result && callThroughLastError != kCallThroughLastError)
        result = Fail("calling through the trampoline changed the caller's last error");

    SetLastError(kUnhookLastError);
    const BOOL hookRemoved = Mhook_Unhook(&original);
    const DWORD unhookLastError = GetLastError();
    if (!hookRemoved)
        return Fail("Mhook_Unhook failed");
    if (!result && unhookLastError != kUnhookLastError)
        result = Fail("Mhook_Unhook did not preserve the caller's last error");
    if (callSum5(1, 2, 3, 4, 5) != 15)
        return Fail("the unhooked target no longer sums its arguments");
    return result;
}

static int CaseThunk(void)
{
    const SIZE_T kPageSize = 4096;
    const SIZE_T kThunkCount = 16;
    const SIZE_T kThunkStride = 16;
    const SIZE_T kShortJumpIndex = 1;
    const SIZE_T kPointerSlotOffset = 320;
    const SIZE_T kTargetOffset = 384;
    const SIZE_T kNearJumpSize = 5;
    const SIZE_T kShortJumpSize = 2;
    const SIZE_T kSnapshotSize = kThunkCount * kThunkStride;
#ifdef _M_IX86
    const SIZE_T kDirectThunkCount = 15;
#elif defined _M_X64
    const SIZE_T kDirectThunkCount = 14;
    const SIZE_T kIndirectJumpSize = 6;
    const SIZE_T kSecondPointerSlotOffset = 336;
    const SIZE_T kRexIndirectJumpSize = 7;
#else // !_M_IX86 && !_M_X64
#error unsupported platform
#endif // _M_IX86 || _M_X64

    PBYTE page = static_cast<PBYTE>(VirtualAlloc(NULL, kPageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (!page)
        return Fail("VirtualAlloc for the thunk page failed");
    memset(page, 0xCC, kPageSize);

    PBYTE firstThunk = page;
    PBYTE indirectThunk = page + kDirectThunkCount * kThunkStride;
    PBYTE pointerSlot = page + kPointerSlotOffset;
    PBYTE target = page + kTargetOffset;
#ifdef _M_X64
    PBYTE secondPointerSlot = page + kSecondPointerSlotOffset;
#endif // _M_X64
    memcpy(target, kMovEaxRet, sizeof(kMovEaxRet));

    // Mix every relative jump form with the x86 entry prefixes.
    for (SIZE_T index = 0; index < kDirectThunkCount; ++index)
    {
        PBYTE thunk = page + index * kThunkStride;
        PBYTE instruction = thunk;
        PBYTE nextThunk = page + (index + 1) * kThunkStride;
#ifdef _M_IX86
        if (index == 0)
        {
            instruction[0] = 0x8B;
            instruction[1] = 0xFF;
            instruction += 2;
        }
        else if (index == 1)
        {
            instruction[0] = 0x55;
            instruction[1] = 0x8B;
            instruction[2] = 0xEC;
            instruction[3] = 0x5D;
            instruction += 4;
        }
#endif // _M_IX86

        if (index == kShortJumpIndex)
        {
            const int8_t offset = static_cast<int8_t>(nextThunk - (instruction + kShortJumpSize));
            instruction[0] = 0xEB;
            memcpy(instruction + 1, &offset, sizeof(offset));
        }
        else
        {
            const int32_t offset = static_cast<int32_t>(nextThunk - (instruction + kNearJumpSize));
            instruction[0] = 0xE9;
            memcpy(instruction + 1, &offset, sizeof(offset));
        }
    }

    // End the chain through each architecture's supported indirect forms.
    indirectThunk[0] = 0xFF;
    indirectThunk[1] = 0x25;
#ifdef _M_IX86
    const uint32_t slotAddress = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(pointerSlot));
    memcpy(indirectThunk + 2, &slotAddress, sizeof(slotAddress));
#elif defined _M_X64
    const int32_t slotOffset = static_cast<int32_t>(pointerSlot - (indirectThunk + kIndirectJumpSize));
    memcpy(indirectThunk + 2, &slotOffset, sizeof(slotOffset));

    PBYTE rexIndirectThunk = indirectThunk + kThunkStride;
    rexIndirectThunk[0] = 0x48;
    rexIndirectThunk[1] = 0xFF;
    rexIndirectThunk[2] = 0x25;
    const int32_t secondSlotOffset =
        static_cast<int32_t>(secondPointerSlot - (rexIndirectThunk + kRexIndirectJumpSize));
    memcpy(rexIndirectThunk + 3, &secondSlotOffset, sizeof(secondSlotOffset));
    memcpy(pointerSlot, &rexIndirectThunk, sizeof(rexIndirectThunk));
    memcpy(secondPointerSlot, &target, sizeof(target));
#else // !_M_IX86 && !_M_X64
#error unsupported platform
#endif // _M_IX86 || _M_X64
#ifdef _M_IX86
    memcpy(pointerSlot, &target, sizeof(target));
#endif // _M_IX86

    if (!FlushInstructionCache(GetCurrentProcess(), page, kPageSize))
    {
        VirtualFree(page, 0, MEM_RELEASE);
        return Fail("FlushInstructionCache failed for the thunk chain");
    }

    BYTE thunkSnapshot[kSnapshotSize] = {};
    memcpy(thunkSnapshot, firstThunk, sizeof(thunkSnapshot));

    if ((reinterpret_cast<TargetFn>(firstThunk))() != TARGET_RESULT)
        return Fail("the thunk chain does not reach the target before hooking");

    g_hookCalls = 0;
    PVOID trampoline = firstThunk;
    if (!Mhook_SetHook(&trampoline, reinterpret_cast<PVOID>(&HookCounting)))
        return Fail("Mhook_SetHook failed on a target behind a thunk chain");
    if (memcmp(firstThunk, thunkSnapshot, sizeof(thunkSnapshot)) != 0)
        return Fail("jump resolution patched a thunk instead of the final target");
    if (!IsJumpPatched(target))
        return Fail("the final target was not patched");
    if ((reinterpret_cast<TargetFn>(firstThunk))() != HOOK_RESULT)
        return Fail("calling through the thunk chain did not reach the hook");
    if (g_hookCalls != 1)
        return Fail("the hook ran a number of times other than once");

    if (!Mhook_Unhook(&trampoline))
        return Fail("Mhook_Unhook failed for the thunk chain");
    if ((reinterpret_cast<TargetFn>(firstThunk))() != TARGET_RESULT)
        return Fail("the thunk chain does not reach the restored target");

    VirtualFree(page, 0, MEM_RELEASE);
    return 0;
}

/**
 * @brief Verifies that a complete prologue at an executable-page boundary remains hookable.
 * @return Zero on success; otherwise a test failure code.
 */
static int CaseSnapshotBoundary(void)
{
    SYSTEM_INFO systemInfo = {};
    GetSystemInfo(&systemInfo);
    const SIZE_T pageSize = systemInfo.dwPageSize;
    const SIZE_T allocationSize = pageSize * 2;
    PBYTE memory = static_cast<PBYTE>(VirtualAlloc(NULL, allocationSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));

    if (!memory)
        return Fail("VirtualAlloc for the boundary prologue failed");

    PBYTE target = memory + pageSize - sizeof(kMovEaxRet);
    memcpy(target, kMovEaxRet, sizeof(kMovEaxRet));
    DWORD oldProtection = 0;
    const BOOL executableResult = VirtualProtect(memory, pageSize, PAGE_EXECUTE_READ, &oldProtection);
    const BOOL inaccessibleResult = VirtualProtect(memory + pageSize, pageSize, PAGE_NOACCESS, &oldProtection);
    const BOOL flushResult = FlushInstructionCache(GetCurrentProcess(), target, sizeof(kMovEaxRet));

    if (!executableResult || !inaccessibleResult || !flushResult)
    {
        VirtualFree(memory, 0, MEM_RELEASE);
        return Fail("protecting the boundary prologue failed");
    }

    g_hookCalls = 0;
    PVOID trampoline = target;
    const BOOL hookResult = Mhook_SetHook(&trampoline, reinterpret_cast<PVOID>(&HookCounting));
    const int hookedValue = hookResult ? (reinterpret_cast<TargetFn>(target))() : 0;
    const LONG hookCalls = g_hookCalls;
    const BOOL unhookResult = hookResult && Mhook_Unhook(&trampoline);
    const int restoredValue = unhookResult ? (reinterpret_cast<TargetFn>(target))() : 0;
    VirtualFree(memory, 0, MEM_RELEASE);

    if (!hookResult)
        return Fail("Mhook_SetHook rejected a complete boundary prologue");
    if (hookedValue != HOOK_RESULT || hookCalls != 1)
        return Fail("the boundary prologue did not reach the hook");
    if (!unhookResult)
        return Fail("Mhook_Unhook failed for the boundary prologue");
    if (restoredValue != TARGET_RESULT)
        return Fail("the boundary prologue was not restored");

    return 0;
}

static const BYTE kRetOnly[] = {0xC3};

static int CaseShortFunc(void)
{
    PBYTE target = AllocCodeBuffer(kRetOnly, sizeof(kRetOnly));
    if (!target)
        return Fail("VirtualAlloc for the target buffer failed");

    BYTE snapshot[TARGET_BUFFER_SIZE];
    memcpy(snapshot, target, TARGET_BUFFER_SIZE);

    PVOID trampoline = target;
    if (Mhook_SetHook(&trampoline, (PVOID)&HookCounting))
        return Fail("Mhook_SetHook accepted a function shorter than MHOOK_JMPSIZE");
    if (Mhook_GetLastStatus() != MHOOK_STATUS_UNSUPPORTED_PROLOGUE)
        return Fail("Mhook_SetHook reported the wrong status for a short prologue");
    if (trampoline != (PVOID)target)
        return Fail("the failed Mhook_SetHook still overwrote the pointer");
    if (memcmp(target, snapshot, TARGET_BUFFER_SIZE) != 0)
        return Fail("the failed Mhook_SetHook modified the target bytes");
    return 0;
}

static volatile LONG g_stopThreads = 0;
static volatile LONG g_badResults = 0;

static DWORD WINAPI SpinCallingTarget(LPVOID parameter)
{
    TargetFn target = (TargetFn)parameter;
    while (!g_stopThreads)
    {
        const int result = target();
        if (result != TARGET_RESULT && result != HOOK_RESULT)
            InterlockedIncrement(&g_badResults);
    }
    return 0;
}

/**
 * @brief Verifies that a preparation failure leaves every batch hook unpublished.
 * @return Zero on success; otherwise a test failure code.
 */
static int caseBatchPrepareFailure(void)
{
    PBYTE target = AllocCodeBuffer(kMovEaxRet, sizeof(kMovEaxRet));
    if (!target)
        return Fail("VirtualAlloc for the batch preparation target failed");

    BYTE snapshot[TARGET_BUFFER_SIZE] = {};
    memcpy(snapshot, target, sizeof(snapshot));

    // Place a valid request before an invalid one to detect eager installation.
    PVOID firstTrampoline = target;
    PVOID invalidTarget = NULL;
    MHOOK_HOOK_INFO hooks[] = {
        {&firstTrampoline, reinterpret_cast<PVOID>(&HookCounting), MHOOK_STATUS_INVALID_ARGUMENT},
        {&invalidTarget, reinterpret_cast<PVOID>(&HookCounting), MHOOK_STATUS_SUCCESS}
    };

    if (Mhook_SetHookBatch(hooks, ARRAYSIZE(hooks)))
        return Fail("Mhook_SetHookBatch accepted an invalid request");
    if (hooks[0].status != MHOOK_STATUS_SUCCESS || hooks[1].status != MHOOK_STATUS_INVALID_ARGUMENT)
        return Fail("a preparation failure did not identify the invalid request");
    if (Mhook_GetLastStatus() != MHOOK_STATUS_INVALID_ARGUMENT)
        return Fail("a preparation failure reported the wrong overall status");
    if (firstTrampoline != target)
        return Fail("a preparation failure published an earlier trampoline");
    if (memcmp(target, snapshot, sizeof(snapshot)) != 0)
        return Fail("a preparation failure patched an earlier target");

    VirtualFree(target, 0, MEM_RELEASE);
    return 0;
}

/**
 * @brief Verifies that conflicting prepared requests abort the whole batch.
 * @return Zero on success; otherwise a test failure code.
 */
static int caseBatchConflict(void)
{
    PBYTE duplicateTarget = AllocCodeBuffer(kMovEaxRet, sizeof(kMovEaxRet));
    if (!duplicateTarget)
        return Fail("VirtualAlloc for the duplicate batch target failed");

    BYTE duplicateSnapshot[TARGET_BUFFER_SIZE] = {};
    memcpy(duplicateSnapshot, duplicateTarget, sizeof(duplicateSnapshot));

    // A replacement inside its own overwritten prologue would be destroyed by installation.
    PVOID selfConflictTrampoline = duplicateTarget;
    MHOOK_HOOK_INFO selfConflictHook = {&selfConflictTrampoline, duplicateTarget + 1, MHOOK_STATUS_INVALID_ARGUMENT};

    if (Mhook_SetHookBatch(&selfConflictHook, 1))
        return Fail("Mhook_SetHookBatch accepted a replacement inside its own target");
    if (selfConflictHook.status != MHOOK_STATUS_ALREADY_HOOKED)
        return Fail("a self-range conflict reported the wrong status");
    if (selfConflictTrampoline != duplicateTarget)
        return Fail("a self-range conflict published a trampoline");
    if (memcmp(duplicateTarget, duplicateSnapshot, sizeof(duplicateSnapshot)) != 0)
        return Fail("a self-range conflict changed the target bytes");

    // Two caller slots that resolve to the same target cannot be installed atomically.
    PVOID firstDuplicateTrampoline = duplicateTarget;
    PVOID secondDuplicateTrampoline = duplicateTarget;
    MHOOK_HOOK_INFO duplicateHooks[] = {
        {&firstDuplicateTrampoline, reinterpret_cast<PVOID>(&HookCounting), MHOOK_STATUS_INVALID_ARGUMENT},
        {&secondDuplicateTrampoline, reinterpret_cast<PVOID>(&HookCounting), MHOOK_STATUS_INVALID_ARGUMENT}
    };

    if (Mhook_SetHookBatch(duplicateHooks, ARRAYSIZE(duplicateHooks)))
        return Fail("Mhook_SetHookBatch accepted duplicate resolved targets");
    if (duplicateHooks[0].status != MHOOK_STATUS_SUCCESS || duplicateHooks[1].status != MHOOK_STATUS_ALREADY_HOOKED)
        return Fail("a duplicate batch target did not identify the conflicting request");
    if (firstDuplicateTrampoline != duplicateTarget || secondDuplicateTrampoline != duplicateTarget)
        return Fail("a duplicate batch target published a trampoline");
    if (memcmp(duplicateTarget, duplicateSnapshot, sizeof(duplicateSnapshot)) != 0)
        return Fail("a duplicate batch target changed the target bytes");

    PBYTE firstTarget = AllocCodeBuffer(kMovEaxRet, sizeof(kMovEaxRet));
    PBYTE secondTarget = AllocCodeBuffer(kMovEaxRet, sizeof(kMovEaxRet));
    if (!firstTarget || !secondTarget)
        return Fail("VirtualAlloc for replacement-conflict targets failed");

    BYTE firstSnapshot[TARGET_BUFFER_SIZE] = {};
    BYTE secondSnapshot[TARGET_BUFFER_SIZE] = {};
    memcpy(firstSnapshot, firstTarget, sizeof(firstSnapshot));
    memcpy(secondSnapshot, secondTarget, sizeof(secondSnapshot));

    // A replacement cannot point into code that another request will overwrite.
    PVOID firstTrampoline = firstTarget;
    PVOID secondTrampoline = secondTarget;
    MHOOK_HOOK_INFO replacementHooks[] = {
        {&firstTrampoline, secondTarget, MHOOK_STATUS_INVALID_ARGUMENT},
        {&secondTrampoline, reinterpret_cast<PVOID>(&HookCounting), MHOOK_STATUS_INVALID_ARGUMENT}
    };

    if (Mhook_SetHookBatch(replacementHooks, ARRAYSIZE(replacementHooks)))
        return Fail("Mhook_SetHookBatch accepted a replacement inside another target");
    if (replacementHooks[0].status != MHOOK_STATUS_SUCCESS || replacementHooks[1].status != MHOOK_STATUS_ALREADY_HOOKED)
        return Fail("a replacement conflict did not identify the conflicting request");
    if (firstTrampoline != firstTarget || secondTrampoline != secondTarget)
        return Fail("a replacement conflict published a trampoline");
    if (memcmp(firstTarget, firstSnapshot, sizeof(firstSnapshot)) != 0 ||
        memcmp(secondTarget, secondSnapshot, sizeof(secondSnapshot)) != 0)
        return Fail("a replacement conflict changed target bytes");

    VirtualFree(secondTarget, 0, MEM_RELEASE);
    VirtualFree(firstTarget, 0, MEM_RELEASE);
    VirtualFree(duplicateTarget, 0, MEM_RELEASE);
    return 0;
}

/**
 * @brief Verifies that a commit failure restores every earlier hook in the batch.
 * @return Zero on success; otherwise a test failure code.
 */
static int caseBatchCommitFailure(void)
{
    PBYTE firstTarget = AllocCodeBuffer(kMovEaxRet, sizeof(kMovEaxRet));
    HANDLE secondMapping = NULL;
    PBYTE secondTarget = allocateReadOnlyCodeBuffer(kMovEaxRet, sizeof(kMovEaxRet), &secondMapping);

    if (!firstTarget || !secondTarget)
        return Fail("mapped target setup for the batch commit test failed");

    BYTE firstSnapshot[TARGET_BUFFER_SIZE] = {};
    BYTE secondSnapshot[TARGET_BUFFER_SIZE] = {};
    memcpy(firstSnapshot, firstTarget, sizeof(firstSnapshot));
    memcpy(secondSnapshot, secondTarget, sizeof(secondSnapshot));

    // Force the second commit to fail after the first request is ready to install.
    PVOID firstTrampoline = firstTarget;
    PVOID secondTrampoline = secondTarget;
    MHOOK_HOOK_INFO hooks[] = {
        {&firstTrampoline, reinterpret_cast<PVOID>(&HookCounting), MHOOK_STATUS_INVALID_ARGUMENT},
        {&secondTrampoline, reinterpret_cast<PVOID>(&HookCounting), MHOOK_STATUS_INVALID_ARGUMENT}
    };

    if (Mhook_SetHookBatch(hooks, ARRAYSIZE(hooks)))
        return Fail("Mhook_SetHookBatch installed a read-only mapped target");
    if (hooks[0].status != MHOOK_STATUS_SUCCESS || hooks[1].status != MHOOK_STATUS_MEMORY_PROTECTION_FAILED)
        return Fail("a commit failure did not identify the unwritable request");
    if (Mhook_GetLastStatus() != MHOOK_STATUS_MEMORY_PROTECTION_FAILED)
        return Fail("a commit failure reported the wrong overall status");
    if (firstTrampoline != firstTarget || secondTrampoline != secondTarget)
        return Fail("a commit failure published a batch trampoline");
    if (memcmp(firstTarget, firstSnapshot, sizeof(firstSnapshot)) != 0 ||
        memcmp(secondTarget, secondSnapshot, sizeof(secondSnapshot)) != 0)
        return Fail("a commit failure left a batch target patched");

    UnmapViewOfFile(secondTarget);
    CloseHandle(secondMapping);
    VirtualFree(firstTarget, 0, MEM_RELEASE);
    return 0;
}

/**
 * @brief Verifies that an invalid live patch prevents every batch removal.
 * @return Zero on success; otherwise a test failure code.
 */
static int caseBatchUnhookPrepareFailure(void)
{
    const DWORD kCallerLastError = ERROR_BUSY;
    PBYTE firstTarget = AllocCodeBuffer(kMovEaxRet, sizeof(kMovEaxRet));
    PBYTE secondTarget = AllocCodeBuffer(kMovEaxRet, sizeof(kMovEaxRet));
    if (!firstTarget || !secondTarget)
        return Fail("VirtualAlloc for batch unhook preparation targets failed");

    BYTE firstOriginal[TARGET_BUFFER_SIZE] = {};
    BYTE secondOriginal[TARGET_BUFFER_SIZE] = {};
    memcpy(firstOriginal, firstTarget, sizeof(firstOriginal));
    memcpy(secondOriginal, secondTarget, sizeof(secondOriginal));

    PVOID firstTrampoline = firstTarget;
    PVOID secondTrampoline = secondTarget;
    MHOOK_HOOK_INFO hooks[] = {
        {&firstTrampoline, reinterpret_cast<PVOID>(&HookCounting), MHOOK_STATUS_INVALID_ARGUMENT},
        {&secondTrampoline, reinterpret_cast<PVOID>(&HookCounting), MHOOK_STATUS_INVALID_ARGUMENT}
    };

    if (!Mhook_SetHookBatch(hooks, ARRAYSIZE(hooks)))
        return Fail("Mhook_SetHookBatch failed before the batch unhook preparation test");

    const PVOID firstInstalledTrampoline = firstTrampoline;
    const PVOID secondInstalledTrampoline = secondTrampoline;
    BYTE firstInstalled[TARGET_BUFFER_SIZE] = {};
    BYTE secondModified[TARGET_BUFFER_SIZE] = {};
    memcpy(firstInstalled, firstTarget, sizeof(firstInstalled));

    // Simulate another writer changing the second installed patch before preflight.
    secondTarget[1] ^= 0xFF;
    if (!FlushInstructionCache(GetCurrentProcess(), secondTarget, TARGET_BUFFER_SIZE))
        return Fail("flushing the modified batch unhook target failed");
    memcpy(secondModified, secondTarget, sizeof(secondModified));

    SetLastError(kCallerLastError);
    if (Mhook_UnhookBatch(hooks, ARRAYSIZE(hooks)))
        return Fail("Mhook_UnhookBatch accepted a modified target");
    if (hooks[0].status != MHOOK_STATUS_SUCCESS || hooks[1].status != MHOOK_STATUS_TARGET_MODIFIED)
        return Fail("batch unhook preparation did not identify the modified target");
    if (Mhook_GetLastStatus() != MHOOK_STATUS_TARGET_MODIFIED)
        return Fail("batch unhook preparation reported the wrong overall status");
    if (GetLastError() != MHOOK_ERROR_TARGET_MODIFIED)
        return Fail("batch unhook preparation reported the wrong Win32 error");
    if (firstTrampoline != firstInstalledTrampoline || secondTrampoline != secondInstalledTrampoline)
        return Fail("batch unhook preparation failure changed a caller slot");
    if (memcmp(firstTarget, firstInstalled, sizeof(firstInstalled)) != 0 ||
        memcmp(secondTarget, secondModified, sizeof(secondModified)) != 0)
        return Fail("batch unhook preparation failure changed target bytes");
    if (Mhook_GetTarget(firstTrampoline) != firstTarget || Mhook_GetTarget(secondTrampoline) != secondTarget)
        return Fail("batch unhook preparation failure retired an active hook");

    // Repair the contested patch and prove the unchanged descriptors can be retried.
    secondTarget[1] ^= 0xFF;
    if (!FlushInstructionCache(GetCurrentProcess(), secondTarget, TARGET_BUFFER_SIZE))
        return Fail("flushing the repaired batch unhook target failed");
    if (!Mhook_UnhookBatch(hooks, ARRAYSIZE(hooks)))
        return Fail("Mhook_UnhookBatch could not retry after the target was repaired");
    if (firstTrampoline != firstTarget || secondTrampoline != secondTarget)
        return Fail("the retried batch unhook did not restore caller slots");
    if (memcmp(firstTarget, firstOriginal, sizeof(firstOriginal)) != 0 ||
        memcmp(secondTarget, secondOriginal, sizeof(secondOriginal)) != 0)
        return Fail("the retried batch unhook did not restore target bytes");

    VirtualFree(secondTarget, 0, MEM_RELEASE);
    VirtualFree(firstTarget, 0, MEM_RELEASE);
    return 0;
}

/**
 * @brief Verifies that one trampoline cannot be removed twice by the same batch.
 * @return Zero on success; otherwise a test failure code.
 */
static int caseBatchUnhookConflict(void)
{
    const DWORD kCallerLastError = ERROR_BUSY;
    PBYTE target = AllocCodeBuffer(kMovEaxRet, sizeof(kMovEaxRet));
    if (!target)
        return Fail("VirtualAlloc for the duplicate batch unhook target failed");

    BYTE original[TARGET_BUFFER_SIZE] = {};
    memcpy(original, target, sizeof(original));

    PVOID trampoline = target;
    if (!Mhook_SetHook(&trampoline, reinterpret_cast<PVOID>(&HookCounting)))
        return Fail("Mhook_SetHook failed before the duplicate batch unhook test");

    const PVOID installedTrampoline = trampoline;
    PVOID duplicateTrampoline = trampoline;
    BYTE installed[TARGET_BUFFER_SIZE] = {};
    memcpy(installed, target, sizeof(installed));

    MHOOK_HOOK_INFO hooks[] = {
        {&trampoline, NULL, MHOOK_STATUS_INVALID_ARGUMENT},
        {&duplicateTrampoline, NULL, MHOOK_STATUS_INVALID_ARGUMENT}
    };

    SetLastError(kCallerLastError);
    if (Mhook_UnhookBatch(hooks, ARRAYSIZE(hooks)))
        return Fail("Mhook_UnhookBatch accepted the same trampoline twice");
    if (hooks[0].status != MHOOK_STATUS_SUCCESS || hooks[1].status != MHOOK_STATUS_INVALID_ARGUMENT)
        return Fail("a duplicate batch unhook did not identify the repeated request");
    if (Mhook_GetLastStatus() != MHOOK_STATUS_INVALID_ARGUMENT)
        return Fail("a duplicate batch unhook reported the wrong overall status");
    if (GetLastError() != kCallerLastError)
        return Fail("a duplicate batch unhook changed the caller's last error");
    if (trampoline != installedTrampoline || duplicateTrampoline != installedTrampoline)
        return Fail("a duplicate batch unhook changed a caller slot");
    if (memcmp(target, installed, sizeof(installed)) != 0)
        return Fail("a duplicate batch unhook changed the target bytes");
    if (Mhook_GetTarget(trampoline) != target)
        return Fail("a duplicate batch unhook retired the active hook");

    if (!Mhook_Unhook(&trampoline))
        return Fail("cleaning up the duplicate batch unhook target failed");
    if (memcmp(target, original, sizeof(original)) != 0)
        return Fail("cleanup did not restore the duplicate batch unhook target");

    VirtualFree(target, 0, MEM_RELEASE);
    return 0;
}

/**
 * @brief Verifies that a removal failure reinstalls every earlier batch hook.
 * @return Zero on success; otherwise a test failure code.
 */
static int caseBatchUnhookCommitFailure(void)
{
    const DWORD kCallerLastError = ERROR_BUSY;

    PBYTE firstTarget = AllocCodeBuffer(kMovEaxRet, sizeof(kMovEaxRet));
    HANDLE secondMapping = NULL;
    PBYTE secondTarget = allocateMappedCodeBuffer(kMovEaxRet, sizeof(kMovEaxRet), &secondMapping);
    if (!firstTarget || !secondTarget)
        return Fail("mapped target setup for the batch unhook commit test failed");

    BYTE firstOriginal[TARGET_BUFFER_SIZE] = {};
    BYTE secondOriginal[TARGET_BUFFER_SIZE] = {};
    memcpy(firstOriginal, firstTarget, sizeof(firstOriginal));
    memcpy(secondOriginal, secondTarget, sizeof(secondOriginal));

    PVOID firstTrampoline = firstTarget;
    PVOID secondTrampoline = secondTarget;
    MHOOK_HOOK_INFO hooks[] = {
        {&firstTrampoline, reinterpret_cast<PVOID>(&HookCounting), MHOOK_STATUS_INVALID_ARGUMENT},
        {&secondTrampoline, reinterpret_cast<PVOID>(&HookCounting), MHOOK_STATUS_INVALID_ARGUMENT}
    };

    if (!Mhook_SetHookBatch(hooks, ARRAYSIZE(hooks)))
        return Fail("Mhook_SetHookBatch failed before the batch unhook commit test");

    const PVOID firstInstalledTrampoline = firstTrampoline;
    const PVOID secondInstalledTrampoline = secondTrampoline;
    BYTE firstInstalled[TARGET_BUFFER_SIZE] = {};
    BYTE secondInstalled[TARGET_BUFFER_SIZE] = {};
    memcpy(firstInstalled, firstTarget, sizeof(firstInstalled));
    memcpy(secondInstalled, secondTarget, sizeof(secondInstalled));

    // Remap the installed patch without write access so commit fails after preflight.
    PBYTE secondAddress = secondTarget;
    if (!UnmapViewOfFile(secondTarget))
        return Fail("unmapping the writable batch unhook target failed");
    secondTarget = static_cast<PBYTE>(
        MapViewOfFileEx(secondMapping, FILE_MAP_READ | FILE_MAP_EXECUTE, 0, 0, TARGET_BUFFER_SIZE, secondAddress)
    );
    if (secondTarget != secondAddress)
        return Fail("remapping the batch unhook target read-only failed");

    DWORD ignoredProtection = 0;
    SetLastError(kCallerLastError);
    if (VirtualProtect(secondTarget, TARGET_BUFFER_SIZE, PAGE_EXECUTE_READWRITE, &ignoredProtection))
        return Fail("the read-only batch unhook target unexpectedly accepted writable protection");
    const DWORD expectedLastError = GetLastError();

    SetLastError(kCallerLastError);
    if (Mhook_UnhookBatch(hooks, ARRAYSIZE(hooks)))
        return Fail("Mhook_UnhookBatch removed a read-only mapped target");
    const DWORD actualLastError = GetLastError();
    if (hooks[0].status != MHOOK_STATUS_SUCCESS || hooks[1].status != MHOOK_STATUS_MEMORY_PROTECTION_FAILED)
        return Fail("batch unhook commit failure did not identify the unwritable target");
    if (Mhook_GetLastStatus() != MHOOK_STATUS_MEMORY_PROTECTION_FAILED)
        return Fail("batch unhook commit failure reported the wrong overall status");
    if (actualLastError != expectedLastError)
        return Fail("batch unhook commit failure reported the wrong Win32 error");
    if (firstTrampoline != firstInstalledTrampoline || secondTrampoline != secondInstalledTrampoline)
        return Fail("batch unhook commit failure changed a caller slot");
    if (memcmp(firstTarget, firstInstalled, sizeof(firstInstalled)) != 0 ||
        memcmp(secondTarget, secondInstalled, sizeof(secondInstalled)) != 0)
        return Fail("batch unhook commit failure did not preserve installed patches");
    if (Mhook_GetTarget(firstTrampoline) != firstTarget || Mhook_GetTarget(secondTrampoline) != secondTarget)
        return Fail("batch unhook commit failure retired an active hook");

    // Restore writable target storage and verify the original batch can be retried.
    UnmapViewOfFile(secondTarget);
    secondTarget = static_cast<PBYTE>(MapViewOfFileEx(
        secondMapping,
        FILE_MAP_READ | FILE_MAP_WRITE | FILE_MAP_EXECUTE,
        0,
        0,
        TARGET_BUFFER_SIZE,
        secondAddress
    ));
    if (secondTarget != secondAddress)
        return Fail("restoring writable storage for the batch unhook retry failed");
    if (!Mhook_UnhookBatch(hooks, ARRAYSIZE(hooks)))
        return Fail("Mhook_UnhookBatch could not retry after commit failure");
    if (firstTrampoline != firstTarget || secondTrampoline != secondTarget)
        return Fail("the retried batch unhook did not restore caller slots");
    if (memcmp(firstTarget, firstOriginal, sizeof(firstOriginal)) != 0 ||
        memcmp(secondTarget, secondOriginal, sizeof(secondOriginal)) != 0)
        return Fail("the retried batch unhook did not restore target bytes");

    UnmapViewOfFile(secondTarget);
    CloseHandle(secondMapping);
    VirtualFree(firstTarget, 0, MEM_RELEASE);
    return 0;
}

/**
 * @brief Keeps a peer alive without entering the target code used by suspension tests.
 * @return Zero after the test requests worker shutdown.
 */
static DWORD WINAPI waitForStop(LPVOID)
{
    while (!g_stopThreads)
        Sleep(1);
    return 0;
}

/**
 * @brief Checks and clears suspension counts left by a failed hook transaction.
 * @param[in] threads Worker handles created by the test.
 * @param[in] threadCount Number of handles in threads.
 * @return TRUE when every worker was running before the check.
 */
static BOOL peerSuspensionsWereReleased(const HANDLE* threads, SIZE_T threadCount)
{
    BOOL allThreadsWereRunning = TRUE;

    for (SIZE_T index = 0; index < threadCount; ++index)
    {
        const DWORD previousSuspendCount = SuspendThread(threads[index]);
        if (previousSuspendCount == (DWORD)-1)
        {
            allThreadsWereRunning = FALSE;
            continue;
        }

        for (DWORD resumeIndex = 0; resumeIndex <= previousSuspendCount; ++resumeIndex)
        {
            if (ResumeThread(threads[index]) == (DWORD)-1)
                allThreadsWereRunning = FALSE;
        }

        if (previousSuspendCount != 0)
            allThreadsWereRunning = FALSE;
    }

    return allThreadsWereRunning;
}

/**
 * @brief Disables the privilege that bypasses thread DACL checks on elevated runners.
 * @return TRUE when the privilege is disabled or absent from the process token.
 */
static BOOL disableDebugPrivilege(void)
{
    HANDLE processToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &processToken))
        return FALSE;

    BOOL result = FALSE;
    LUID debugPrivilege = {};
    if (LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &debugPrivilege))
    {
        TOKEN_PRIVILEGES privileges = {};
        privileges.PrivilegeCount = 1;
        privileges.Privileges[0].Luid = debugPrivilege;

        SetLastError(ERROR_SUCCESS);
        result = AdjustTokenPrivileges(processToken, FALSE, &privileges, 0, NULL, NULL);
        const DWORD privilegeError = GetLastError();
        if (result)
            result = privilegeError == ERROR_SUCCESS || privilegeError == ERROR_NOT_ALL_ASSIGNED;
    }

    if (!CloseHandle(processToken))
        result = FALSE;

    return result;
}

static int CaseThreads(void)
{
    const int kWorkerCount = 4;
    const int kRoundCount = 25;
    const int kOperationRetryCount = 16;

    PBYTE target = AllocCodeBuffer(kMovEaxRet, sizeof(kMovEaxRet));
    if (!target)
        return Fail("VirtualAlloc for the target buffer failed");

    g_stopThreads = 0;
    g_badResults = 0;

    HANDLE threads[kWorkerCount] = {};
    for (int i = 0; i < kWorkerCount; ++i)
    {
        threads[i] = CreateThread(NULL, 0, SpinCallingTarget, target, 0, NULL);
        if (!threads[i])
        {
            // Stop and join whatever already started before bailing out, so the
            // case never returns while threads are still running on the buffer.
            InterlockedExchange(&g_stopThreads, 1);
            if (i > 0)
            {
                WaitForMultipleObjects((DWORD)i, threads, TRUE, INFINITE);
                for (int j = 0; j < i; ++j)
                    CloseHandle(threads[j]);
            }
            return Fail("CreateThread failed");
        }
    }

    int status = 0;
    PVOID trampoline = target;
    const int rounds = Exhaustive() ? 100 : kRoundCount;

    // Complete every round while workers repeatedly enter the patch range.
    for (int round = 0; round < rounds && status == 0; ++round)
    {
        BOOL hookResult = FALSE;
        for (int attempt = 0; attempt < kOperationRetryCount && !hookResult; ++attempt)
        {
            hookResult = Mhook_SetHook(&trampoline, (PVOID)&HookCounting);
            if (!hookResult && Mhook_GetLastStatus() != MHOOK_STATUS_THREAD_BUSY)
                status = Fail("Mhook_SetHook failed unexpectedly while other threads were running");
            else if (!hookResult && trampoline != target)
                status = Fail("a suspended-thread collision changed the caller slot");

            if (status != 0)
                break;
        }

        if (status != 0)
            break;
        if (!hookResult)
        {
            status = Fail("Mhook_SetHook could not safely suspend all peer threads");
            break;
        }

        BOOL unhookResult = FALSE;
        for (int attempt = 0; attempt < kOperationRetryCount && !unhookResult; ++attempt)
        {
            unhookResult = Mhook_Unhook(&trampoline);
            if (!unhookResult && Mhook_GetLastStatus() != MHOOK_STATUS_THREAD_BUSY)
                status = Fail("Mhook_Unhook failed unexpectedly while other threads were running");
            else if (!unhookResult && trampoline == target)
                status = Fail("a suspended-thread collision published a failed unhook");

            if (status != 0)
                break;
        }

        if (status == 0 && !unhookResult)
            status = Fail("Mhook_Unhook could not safely suspend all peer threads");
    }

    InterlockedExchange(&g_stopThreads, 1);
    WaitForMultipleObjects(kWorkerCount, threads, TRUE, INFINITE);
    for (int i = 0; i < kWorkerCount; ++i)
        CloseHandle(threads[i]);

    // Restore a hook left installed only because the stress case itself failed.
    if (trampoline != target)
        Mhook_Unhook(&trampoline);

    if (status != 0)
        return status;
    if (g_badResults != 0)
        return Fail("a thread observed a result from neither the target nor the hook");
    return 0;
}

/**
 * @brief Verifies that peer access failures cannot publish an install or removal.
 * @return Zero on success; otherwise a test failure code.
 */
static int caseSuspensionFailure(void)
{
    const SIZE_T kWorkerCount = 2;
    const SIZE_T kRestrictedWorkerIndex = 1;

    // Make the worker DACL effective even when CI enables SeDebugPrivilege.
    if (!disableDebugPrivilege())
        return Fail("disabling SeDebugPrivilege for the suspension failure case failed");

    PBYTE target = AllocCodeBuffer(kMovEaxRet, sizeof(kMovEaxRet));
    if (!target)
        return Fail("VirtualAlloc for the suspension failure target failed");

    BYTE targetSnapshot[TARGET_BUFFER_SIZE] = {};
    memcpy(targetSnapshot, target, TARGET_BUFFER_SIZE);

    ACL emptyAcl = {};
    SECURITY_DESCRIPTOR restrictedSecurityDescriptor = {};
    SECURITY_DESCRIPTOR permissiveSecurityDescriptor = {};
    SECURITY_ATTRIBUTES restrictedAttributes = {};
    const char* failure = NULL;

    if (!InitializeAcl(&emptyAcl, sizeof(emptyAcl), ACL_REVISION))
        failure = "InitializeAcl for the restricted worker failed";
    else if (!InitializeSecurityDescriptor(&restrictedSecurityDescriptor, SECURITY_DESCRIPTOR_REVISION))
        failure = "InitializeSecurityDescriptor for the restricted worker failed";
    else if (!SetSecurityDescriptorDacl(&restrictedSecurityDescriptor, TRUE, &emptyAcl, FALSE))
        failure = "SetSecurityDescriptorDacl for the restricted worker failed";
    else if (!InitializeSecurityDescriptor(&permissiveSecurityDescriptor, SECURITY_DESCRIPTOR_REVISION))
        failure = "InitializeSecurityDescriptor for the permissive worker failed";
    else if (!SetSecurityDescriptorDacl(&permissiveSecurityDescriptor, TRUE, NULL, FALSE))
        failure = "SetSecurityDescriptorDacl for the permissive worker failed";

    restrictedAttributes.nLength = sizeof(restrictedAttributes);
    restrictedAttributes.lpSecurityDescriptor = &restrictedSecurityDescriptor;

    HANDLE threads[kWorkerCount] = {};
    DWORD threadIds[kWorkerCount] = {};
    LPSECURITY_ATTRIBUTES threadAttributes[kWorkerCount] = {NULL, &restrictedAttributes};
    g_stopThreads = 0;

    SIZE_T createdThreadCount = 0;
    for (; !failure && createdThreadCount < kWorkerCount; ++createdThreadCount)
    {
        threads[createdThreadCount] =
            CreateThread(threadAttributes[createdThreadCount], 0, waitForStop, NULL, 0, &threadIds[createdThreadCount]);
        if (!threads[createdThreadCount])
            failure = "CreateThread for the suspension failure case failed";
    }

    if (!failure)
    {
        HANDLE probe = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT, FALSE, threadIds[kRestrictedWorkerIndex]);
        if (probe)
        {
            CloseHandle(probe);
            failure = "the restricted worker still allowed the access requested by Mhook";
        }
        else if (GetLastError() != ERROR_ACCESS_DENIED)
        {
            failure = "the restricted worker failed with an unexpected error";
        }
    }

    PVOID trampoline = target;
    BOOL hookResult = FALSE;
    if (!failure)
    {
        hookResult = Mhook_SetHook(&trampoline, reinterpret_cast<PVOID>(&HookCounting));

        if (hookResult)
            failure = "Mhook_SetHook succeeded when a peer thread could not be opened";
        else if (Mhook_GetLastStatus() != MHOOK_STATUS_THREAD_ACCESS_DENIED)
            failure = "Mhook_SetHook reported the wrong suspension failure status";
        else if (trampoline != target)
            failure = "the failed Mhook_SetHook changed the caller slot";
        else if (memcmp(target, targetSnapshot, TARGET_BUFFER_SIZE) != 0)
            failure = "the failed Mhook_SetHook changed the target bytes";
    }

    if (!failure && !peerSuspensionsWereReleased(threads, createdThreadCount))
        failure = "a peer thread remained suspended after hook rollback";

    // Permit installation so the same real access failure can exercise removal.
    if (!failure && !SetKernelObjectSecurity(
                        threads[kRestrictedWorkerIndex],
                        DACL_SECURITY_INFORMATION,
                        &permissiveSecurityDescriptor
                    ))
        failure = "making the restricted worker accessible failed";

    if (!failure)
    {
        hookResult = Mhook_SetHook(&trampoline, reinterpret_cast<PVOID>(&HookCounting));
        if (!hookResult)
            failure = "Mhook_SetHook failed after restoring peer access";
    }

    BYTE installedSnapshot[TARGET_BUFFER_SIZE] = {};
    if (!failure)
        memcpy(installedSnapshot, target, TARGET_BUFFER_SIZE);

    if (!failure && !SetKernelObjectSecurity(
                        threads[kRestrictedWorkerIndex],
                        DACL_SECURITY_INFORMATION,
                        &restrictedSecurityDescriptor
                    ))
        failure = "restricting the worker before unhooking failed";

    if (!failure)
    {
        const BOOL unhookResult = Mhook_Unhook(&trampoline);
        if (unhookResult)
            failure = "Mhook_Unhook succeeded when a peer thread could not be opened";
        else if (Mhook_GetLastStatus() != MHOOK_STATUS_THREAD_ACCESS_DENIED)
            failure = "Mhook_Unhook reported the wrong suspension failure status";
        else if (trampoline == target)
            failure = "the failed Mhook_Unhook changed the caller slot";
        else if (memcmp(target, installedSnapshot, TARGET_BUFFER_SIZE) != 0)
            failure = "the failed Mhook_Unhook changed the target bytes";
    }

    if (!failure && !peerSuspensionsWereReleased(threads, createdThreadCount))
        failure = "a peer thread remained suspended after unhook rollback";

    InterlockedExchange(&g_stopThreads, 1);
    if (createdThreadCount != 0)
        WaitForMultipleObjects((DWORD)createdThreadCount, threads, TRUE, INFINITE);
    for (SIZE_T index = 0; index < createdThreadCount; ++index)
        CloseHandle(threads[index]);

    if (trampoline != target && !Mhook_Unhook(&trampoline) && !failure)
        failure = "cleaning up the installed hook failed";

    if (failure)
        return Fail(failure);
    return 0;
}

/**
 * @brief Shared state for workers racing to make the first hook calls in the process.
 */
struct FirstUseRace
{
    HANDLE start;
    HANDLE allDone;
    HANDLE finish;
    volatile LONG* pending;
    PBYTE target;
    BOOL hooked;
    BOOL called;
    BOOL unhooked;
};

/**
 * @brief Installs, calls, and removes a hook on the worker's own target once released.
 * @param[in,out] parameter The worker's FirstUseRace entry.
 * @return Zero after the finish event is signalled.
 */
static DWORD WINAPI raceFirstUse(LPVOID parameter)
{
    FirstUseRace* race = static_cast<FirstUseRace*>(parameter);
    PVOID trampoline = race->target;

    WaitForSingleObject(race->start, INFINITE);

    race->hooked = Mhook_SetHook(&trampoline, reinterpret_cast<PVOID>(&HookCounting));
    if (race->hooked)
    {
        race->called = reinterpret_cast<int (*)(void)>(race->target)() == HOOK_RESULT;
        race->unhooked = Mhook_Unhook(&trampoline) && trampoline == race->target;
    }

    if (InterlockedDecrement(race->pending) == 0)
        SetEvent(race->allDone);

    // Stay alive until every worker is done, so a peer never exits while another
    // worker's operation is suspending it.
    WaitForSingleObject(race->finish, INFINITE);
    return 0;
}

/**
 * @brief Verifies that concurrent first calls into a fresh process share one registry lock.
 * @return Zero on success; otherwise a test failure code.
 */
static int caseFirstUseRace(void)
{
    const SIZE_T kWorkerCount = 8;

    HANDLE start = CreateEventW(NULL, TRUE, FALSE, NULL);
    HANDLE allDone = CreateEventW(NULL, TRUE, FALSE, NULL);
    HANDLE finish = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!start || !allDone || !finish)
        return Fail("CreateEvent for the first use race failed");

    volatile LONG pending = (LONG)kWorkerCount;

    FirstUseRace races[kWorkerCount] = {};
    HANDLE threads[kWorkerCount] = {};
    SIZE_T createdThreadCount = 0;
    const char* failure = NULL;

    for (; createdThreadCount < kWorkerCount; ++createdThreadCount)
    {
        FirstUseRace* race = &races[createdThreadCount];
        race->start = start;
        race->allDone = allDone;
        race->finish = finish;
        race->pending = &pending;
        race->target = AllocCodeBuffer(kMovEaxRet, sizeof(kMovEaxRet));
        if (!race->target)
        {
            failure = "VirtualAlloc for a first use race target failed";
            break;
        }

        threads[createdThreadCount] = CreateThread(NULL, 0, raceFirstUse, race, 0, NULL);
        if (!threads[createdThreadCount])
        {
            failure = "CreateThread for the first use race failed";
            break;
        }
    }

    // Release every worker at once so their first library calls overlap, and
    // let none exit before all have finished.
    SetEvent(start);
    if (!failure)
        WaitForSingleObject(allDone, INFINITE);
    SetEvent(finish);
    if (createdThreadCount != 0)
        WaitForMultipleObjects((DWORD)createdThreadCount, threads, TRUE, INFINITE);

    for (SIZE_T index = 0; index < createdThreadCount; ++index)
    {
        const FirstUseRace* race = &races[index];
        if (failure)
            break;
        if (!race->hooked)
            failure = "a concurrent first Mhook_SetHook failed";
        else if (!race->called)
            failure = "a concurrently installed hook did not redirect its target";
        else if (!race->unhooked)
            failure = "a concurrent Mhook_Unhook failed";
        else if (memcmp(race->target, kMovEaxRet, sizeof(kMovEaxRet)) != 0)
            failure = "a concurrent Mhook_Unhook did not restore its target";
    }

    for (SIZE_T index = 0; index < createdThreadCount; ++index)
        CloseHandle(threads[index]);
    for (SIZE_T index = 0; index < kWorkerCount; ++index)
    {
        if (races[index].target)
            VirtualFree(races[index].target, 0, MEM_RELEASE);
    }
    CloseHandle(start);
    CloseHandle(allDone);
    CloseHandle(finish);

    if (failure)
        return Fail(failure);
    return 0;
}

typedef HANDLE(WINAPI* SnapshotFunction)(DWORD flags, DWORD processId);
typedef HANDLE (*SnapshotObserver)(DWORD call, DWORD flags, DWORD processId);

static SnapshotFunction g_originalSnapshot = NULL;
static SnapshotObserver g_snapshotObserver = NULL;
static DWORD g_snapshotCalls = 0;

/**
 * @brief Hands each thread snapshot the engine takes to the active observer, if any.
 * @param[in] flags Snapshot flags.
 * @param[in] processId Process to snapshot.
 * @return The observer's snapshot, or the original function's when no observer is active.
 */
static HANDLE WINAPI observeSnapshot(DWORD flags, DWORD processId)
{
    const SnapshotObserver observer = g_snapshotObserver;
    if (!observer)
        return g_originalSnapshot(flags, processId);

    return observer(++g_snapshotCalls, flags, processId);
}

/**
 * @brief Routes every CreateToolhelp32Snapshot call in the process through observeSnapshot.
 * @return TRUE when the hook is installed.
 */
static BOOL hookSnapshots(void)
{
    g_originalSnapshot = reinterpret_cast<SnapshotFunction>(
        reinterpret_cast<void (*)(void)>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "CreateToolhelp32Snapshot"))
    );

    // The slot is published before peers resume, so a resumed call already reaches the trampoline.
    return g_originalSnapshot &&
           Mhook_SetHook(reinterpret_cast<PVOID*>(&g_originalSnapshot), reinterpret_cast<PVOID>(&observeSnapshot));
}

/**
 * @brief Runs one hook installation with an observer watching the engine's snapshots.
 * @param[in] observer Observer active for the duration of the call.
 * @param[in,out] slot Hook slot passed to Mhook_SetHook.
 * @return The Mhook_SetHook result.
 */
static BOOL setHookObserved(SnapshotObserver observer, PVOID* slot)
{
    g_snapshotCalls = 0;
    g_snapshotObserver = observer;
    const BOOL result = Mhook_SetHook(slot, reinterpret_cast<PVOID>(&HookCounting));
    g_snapshotObserver = NULL;
    return result;
}

static HANDLE g_lateThread = NULL;
static BOOL g_lateThreadSeenSuspended = FALSE;

/**
 * @brief Starts a thread just after the engine's first snapshot, then watches whether it is held.
 */
static HANDLE startLateThread(DWORD call, DWORD flags, DWORD processId)
{
    HANDLE snapshot = g_originalSnapshot(flags, processId);

    if (call == 1)
    {
        // Nothing is suspended yet, and this snapshot cannot list the new thread.
        g_lateThread = CreateThread(NULL, 0, waitForStop, NULL, 0, NULL);
    }
    else if (g_lateThread)
    {
        // A later snapshot that finds the thread already suspended proves the engine went back for it.
        const DWORD previousSuspendCount = SuspendThread(g_lateThread);
        if (previousSuspendCount != (DWORD)-1)
        {
            if (previousSuspendCount != 0)
                g_lateThreadSeenSuspended = TRUE;
            ResumeThread(g_lateThread);
        }
    }

    return snapshot;
}

/**
 * @brief Verifies that a thread started after the first snapshot is suspended before code is patched.
 * @return Zero on success; otherwise a test failure code.
 */
static int caseLateThread(void)
{
    if (!hookSnapshots())
        return Fail("hooking CreateToolhelp32Snapshot failed");

    PBYTE target = AllocCodeBuffer(kMovEaxRet, sizeof(kMovEaxRet));
    const char* failure = target ? NULL : "VirtualAlloc for the late thread target failed";

    g_stopThreads = 0;
    PVOID trampoline = target;
    if (!failure)
    {
        if (!setHookObserved(startLateThread, &trampoline))
            failure = "Mhook_SetHook failed while a thread started during suspension";
        else if (!g_lateThread)
            failure = "CreateThread for the late thread failed";
        else if (!g_lateThreadSeenSuspended)
            failure = "a thread started after the first snapshot was never suspended";
        else if (!peerSuspensionsWereReleased(&g_lateThread, 1))
            failure = "the late thread remained suspended after the hook was installed";
    }

    InterlockedExchange(&g_stopThreads, 1);
    if (g_lateThread)
    {
        WaitForSingleObject(g_lateThread, INFINITE);
        CloseHandle(g_lateThread);
    }

    if (trampoline != target && !Mhook_Unhook(&trampoline) && !failure)
        failure = "removing the target hook failed";
    if (!Mhook_Unhook(reinterpret_cast<PVOID*>(&g_originalSnapshot)) && !failure)
        failure = "removing the CreateToolhelp32Snapshot hook failed";
    if (target)
        VirtualFree(target, 0, MEM_RELEASE);

    if (failure)
        return Fail(failure);
    return 0;
}

static const SIZE_T kChurnThreadLimit = 16;
static HANDLE g_churnThreads[kChurnThreadLimit] = {};
static SIZE_T g_churnThreadCount = 0;

/**
 * @brief Starts another thread after every snapshot, so the thread set never settles.
 */
static HANDLE startThreadPerSnapshot(DWORD, DWORD flags, DWORD processId)
{
    HANDLE snapshot = g_originalSnapshot(flags, processId);

    if (g_churnThreadCount < kChurnThreadLimit)
    {
        HANDLE thread = CreateThread(NULL, 0, waitForStop, NULL, 0, NULL);
        if (thread)
            g_churnThreads[g_churnThreadCount++] = thread;
    }

    return snapshot;
}

/**
 * @brief Verifies that a thread set which never settles fails as busy and releases every thread.
 * @return Zero on success; otherwise a test failure code.
 */
static int caseThreadChurn(void)
{
    if (!hookSnapshots())
        return Fail("hooking CreateToolhelp32Snapshot failed");

    PBYTE target = AllocCodeBuffer(kMovEaxRet, sizeof(kMovEaxRet));
    const char* failure = target ? NULL : "VirtualAlloc for the thread churn target failed";

    g_stopThreads = 0;
    PVOID trampoline = target;
    if (!failure)
    {
        const BOOL hookResult = setHookObserved(startThreadPerSnapshot, &trampoline);
        const MHOOK_STATUS status = Mhook_GetLastStatus();

        if (hookResult)
            failure = "Mhook_SetHook succeeded although threads kept starting";
        else if (status != MHOOK_STATUS_THREAD_BUSY)
            failure = "a thread set that never settled was not reported as busy";
        else if (trampoline != target)
            failure = "the failed Mhook_SetHook changed the caller slot";
        else if (memcmp(target, kMovEaxRet, sizeof(kMovEaxRet)) != 0)
            failure = "the failed Mhook_SetHook changed the target bytes";
        else if (!peerSuspensionsWereReleased(g_churnThreads, g_churnThreadCount))
            failure = "a thread remained suspended after the busy failure";
    }

    InterlockedExchange(&g_stopThreads, 1);
    for (SIZE_T index = 0; index < g_churnThreadCount; ++index)
    {
        WaitForSingleObject(g_churnThreads[index], INFINITE);
        CloseHandle(g_churnThreads[index]);
    }

    if (trampoline != target && !Mhook_Unhook(&trampoline) && !failure)
        failure = "removing the target hook failed";
    if (!Mhook_Unhook(reinterpret_cast<PVOID*>(&g_originalSnapshot)) && !failure)
        failure = "removing the CreateToolhelp32Snapshot hook failed";
    if (target)
        VirtualFree(target, 0, MEM_RELEASE);

    if (failure)
        return Fail(failure);
    return 0;
}

/**
 * @brief Lets the first snapshot through and fails the second, after peers are already suspended.
 */
static HANDLE failSecondSnapshot(DWORD call, DWORD flags, DWORD processId)
{
    if (call < 2)
        return g_originalSnapshot(flags, processId);

    SetLastError(ERROR_NOT_ENOUGH_MEMORY);
    return INVALID_HANDLE_VALUE;
}

/**
 * @brief Verifies that a failed snapshot is reported as such and releases the peers already suspended.
 * @return Zero on success; otherwise a test failure code.
 */
static int caseEnumerationFailure(void)
{
    if (!hookSnapshots())
        return Fail("hooking CreateToolhelp32Snapshot failed");

    PBYTE target = AllocCodeBuffer(kMovEaxRet, sizeof(kMovEaxRet));
    const char* failure = target ? NULL : "VirtualAlloc for the enumeration failure target failed";

    g_stopThreads = 0;
    HANDLE peer = CreateThread(NULL, 0, waitForStop, NULL, 0, NULL);
    if (!failure && !peer)
        failure = "CreateThread for the enumeration failure peer failed";

    PVOID trampoline = target;
    if (!failure)
    {
        const BOOL hookResult = setHookObserved(failSecondSnapshot, &trampoline);
        const MHOOK_STATUS status = Mhook_GetLastStatus();

        if (hookResult)
            failure = "Mhook_SetHook succeeded although a thread snapshot failed";
        else if (status != MHOOK_STATUS_THREAD_ENUMERATION_FAILED)
            failure = "Mhook_SetHook did not report the failed thread snapshot";
        else if (trampoline != target)
            failure = "the failed Mhook_SetHook changed the caller slot";
        else if (memcmp(target, kMovEaxRet, sizeof(kMovEaxRet)) != 0)
            failure = "the failed Mhook_SetHook changed the target bytes";
        else if (!peerSuspensionsWereReleased(&peer, 1))
            failure = "a peer remained suspended after the failed installation";
    }

    // Removal reports the snapshot's own error through GetLastError.
    if (!failure && !Mhook_SetHook(&trampoline, reinterpret_cast<PVOID>(&HookCounting)))
        failure = "Mhook_SetHook failed without an observer";

    if (!failure)
    {
        g_snapshotCalls = 0;
        g_snapshotObserver = failSecondSnapshot;
        const BOOL unhookResult = Mhook_Unhook(&trampoline);
        const DWORD unhookError = GetLastError();
        g_snapshotObserver = NULL;

        if (unhookResult)
            failure = "Mhook_Unhook succeeded although a thread snapshot failed";
        else if (Mhook_GetLastStatus() != MHOOK_STATUS_THREAD_ENUMERATION_FAILED)
            failure = "Mhook_Unhook did not report the failed thread snapshot";
        else if (unhookError != ERROR_NOT_ENOUGH_MEMORY)
            failure = "Mhook_Unhook did not report the snapshot's error";
        else if (trampoline == target)
            failure = "the failed Mhook_Unhook changed the caller slot";
        else if (!peerSuspensionsWereReleased(&peer, 1))
            failure = "a peer remained suspended after the failed removal";
    }

    InterlockedExchange(&g_stopThreads, 1);
    if (peer)
    {
        WaitForSingleObject(peer, INFINITE);
        CloseHandle(peer);
    }

    if (trampoline != target && !Mhook_Unhook(&trampoline) && !failure)
        failure = "removing the target hook failed";
    if (!Mhook_Unhook(reinterpret_cast<PVOID*>(&g_originalSnapshot)) && !failure)
        failure = "removing the CreateToolhelp32Snapshot hook failed";
    if (target)
        VirtualFree(target, 0, MEM_RELEASE);

    if (failure)
        return Fail(failure);
    return 0;
}

static HANDLE g_exitNow = NULL;
static HANDLE g_releasedExitingThread = NULL;
static HANDLE g_heldExitingThread = NULL;

/**
 * @brief Waits for the signal to exit, so the test controls exactly when the thread ends.
 * @return Zero once signalled.
 */
static DWORD WINAPI exitWhenSignalled(LPVOID)
{
    WaitForSingleObject(g_exitNow, INFINITE);
    return 0;
}

/**
 * @brief Lets both exiting threads end after the first snapshot has listed them.
 */
static HANDLE endThreadsAfterFirstSnapshot(DWORD call, DWORD flags, DWORD processId)
{
    HANDLE snapshot = g_originalSnapshot(flags, processId);
    if (call != 1)
        return snapshot;

    SetEvent(g_exitNow);
    WaitForSingleObject(g_releasedExitingThread, INFINITE);
    WaitForSingleObject(g_heldExitingThread, INFINITE);

    // Closing the only handle deletes the thread object, so its ID no longer opens at all.
    CloseHandle(g_releasedExitingThread);
    g_releasedExitingThread = NULL;
    return snapshot;
}

/**
 * @brief Verifies that threads which exit after the snapshot lists them do not fail the operation.
 * @return Zero on success; otherwise a test failure code.
 */
static int caseExitedThread(void)
{
    if (!hookSnapshots())
        return Fail("hooking CreateToolhelp32Snapshot failed");

    PBYTE target = AllocCodeBuffer(kMovEaxRet, sizeof(kMovEaxRet));
    const char* failure = target ? NULL : "VirtualAlloc for the exited thread target failed";

    // One thread's object is deleted before the engine opens it; the other stays alive through
    // this test's handle, so the engine opens it but cannot suspend it.
    g_exitNow = CreateEventW(NULL, TRUE, FALSE, NULL);
    g_releasedExitingThread = CreateThread(NULL, 0, exitWhenSignalled, NULL, 0, NULL);
    g_heldExitingThread = CreateThread(NULL, 0, exitWhenSignalled, NULL, 0, NULL);
    if (!failure && (!g_exitNow || !g_releasedExitingThread || !g_heldExitingThread))
        failure = "creating the exiting threads failed";

    PVOID trampoline = target;
    if (!failure)
    {
        if (!setHookObserved(endThreadsAfterFirstSnapshot, &trampoline))
            failure = "Mhook_SetHook failed because listed threads exited before suspension";
        else if (Mhook_GetLastStatus() != MHOOK_STATUS_SUCCESS)
            failure = "Mhook_SetHook reported a failure for threads that had exited";
    }

    if (g_exitNow)
        SetEvent(g_exitNow);
    if (g_releasedExitingThread)
    {
        WaitForSingleObject(g_releasedExitingThread, INFINITE);
        CloseHandle(g_releasedExitingThread);
    }
    if (g_heldExitingThread)
    {
        WaitForSingleObject(g_heldExitingThread, INFINITE);
        CloseHandle(g_heldExitingThread);
    }
    if (g_exitNow)
        CloseHandle(g_exitNow);

    if (trampoline != target && !Mhook_Unhook(&trampoline) && !failure)
        failure = "removing the target hook failed";
    if (!Mhook_Unhook(reinterpret_cast<PVOID*>(&g_originalSnapshot)) && !failure)
        failure = "removing the CreateToolhelp32Snapshot hook failed";
    if (target)
        VirtualFree(target, 0, MEM_RELEASE);

    if (failure)
        return Fail(failure);
    return 0;
}

/**
 * @brief Verifies that a peer parked inside the patch range fails the operation as busy.
 * @return Zero on success; otherwise a test failure code.
 */
static int caseThreadBusy(void)
{
    PBYTE target = AllocCodeBuffer(kMovEaxRet, sizeof(kMovEaxRet));
    if (!target)
        return Fail("VirtualAlloc for the busy thread target failed");

    // A thread that never ran can be moved anywhere; this test's own suspension keeps it there.
    g_stopThreads = 0;
    HANDLE parked = CreateThread(NULL, 0, waitForStop, NULL, CREATE_SUSPENDED, NULL);
    const char* failure = parked ? NULL : "CreateThread for the parked thread failed";

    CONTEXT original = {};
    original.ContextFlags = CONTEXT_CONTROL;
    if (!failure && !GetThreadContext(parked, &original))
        failure = "reading the parked thread's context failed";

    if (!failure)
    {
        CONTEXT insideTarget = original;
#ifdef _M_X64
        insideTarget.Rip = reinterpret_cast<DWORD64>(target + 1);
#else
        insideTarget.Eip = reinterpret_cast<DWORD>(target + 1);
#endif
        if (!SetThreadContext(parked, &insideTarget))
            failure = "moving the parked thread into the target failed";
    }

    PVOID trampoline = target;
    if (!failure)
    {
        const BOOL hookResult = Mhook_SetHook(&trampoline, reinterpret_cast<PVOID>(&HookCounting));

        if (hookResult)
            failure = "Mhook_SetHook succeeded with a thread stopped inside the target";
        else if (Mhook_GetLastStatus() != MHOOK_STATUS_THREAD_BUSY)
            failure = "a thread stopped inside the target was not reported as busy";
        else if (trampoline != target)
            failure = "the failed Mhook_SetHook changed the caller slot";
        else if (memcmp(target, kMovEaxRet, sizeof(kMovEaxRet)) != 0)
            failure = "the failed Mhook_SetHook changed the target bytes";
    }

    // The engine must leave exactly this test's own suspension behind.
    if (!failure)
    {
        const DWORD previousSuspendCount = SuspendThread(parked);
        if (previousSuspendCount != 1)
            failure = "the engine did not release its suspension of the parked thread";
        if (previousSuspendCount != (DWORD)-1)
            ResumeThread(parked);
    }

    if (parked)
    {
        InterlockedExchange(&g_stopThreads, 1);
        if (!SetThreadContext(parked, &original) && !failure)
            failure = "restoring the parked thread's context failed";
        ResumeThread(parked);
        WaitForSingleObject(parked, INFINITE);
        CloseHandle(parked);
    }

    if (trampoline != target && !Mhook_Unhook(&trampoline) && !failure)
        failure = "removing the target hook failed";
    VirtualFree(target, 0, MEM_RELEASE);

    if (failure)
        return Fail(failure);
    return 0;
}

typedef DWORD(WINAPI* ResumeFunction)(HANDLE thread);

static ResumeFunction g_originalResume = NULL;
static volatile LONG g_reportResumeFailure = 0;

/**
 * @brief Resumes the thread, then reports failure while the test asks it to.
 * @param[in] thread Thread to resume.
 * @return The previous suspend count, or (DWORD)-1 while failures are being reported.
 */
static DWORD WINAPI resumeReportingFailure(HANDLE thread)
{
    const DWORD previousSuspendCount = g_originalResume(thread);
    if (!g_reportResumeFailure)
        return previousSuspendCount;

    SetLastError(ERROR_INVALID_HANDLE);
    return (DWORD)-1;
}

/**
 * @brief Verifies that a failed resume is reported without undoing a completed operation.
 * @return Zero on success; otherwise a test failure code.
 */
static int caseResumeFailure(void)
{
    g_originalResume = reinterpret_cast<ResumeFunction>(
        reinterpret_cast<void (*)(void)>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "ResumeThread"))
    );
    if (!g_originalResume ||
        !Mhook_SetHook(reinterpret_cast<PVOID*>(&g_originalResume), reinterpret_cast<PVOID>(&resumeReportingFailure)))
        return Fail("hooking ResumeThread failed");

    PBYTE target = AllocCodeBuffer(kMovEaxRet, sizeof(kMovEaxRet));
    const char* failure = target ? NULL : "VirtualAlloc for the resume failure target failed";

    g_stopThreads = 0;
    HANDLE peer = CreateThread(NULL, 0, waitForStop, NULL, 0, NULL);
    if (!failure && !peer)
        failure = "CreateThread for the resume failure peer failed";

    PVOID trampoline = target;
    if (!failure)
    {
        InterlockedExchange(&g_reportResumeFailure, 1);
        const BOOL hookResult = Mhook_SetHook(&trampoline, reinterpret_cast<PVOID>(&HookCounting));
        InterlockedExchange(&g_reportResumeFailure, 0);

        if (!hookResult)
            failure = "Mhook_SetHook failed although only resuming a peer failed";
        else if (Mhook_GetLastStatus() != MHOOK_STATUS_THREAD_RESUME_FAILED)
            failure = "Mhook_SetHook did not report the failed resume";
        else if (trampoline == target)
            failure = "the completed Mhook_SetHook did not publish its trampoline";
        else if (reinterpret_cast<int (*)(void)>(target)() != HOOK_RESULT)
            failure = "the completed Mhook_SetHook did not redirect the target";
        else if (!peerSuspensionsWereReleased(&peer, 1))
            failure = "the peer was left suspended";
    }

    if (!failure)
    {
        InterlockedExchange(&g_reportResumeFailure, 1);
        const BOOL unhookResult = Mhook_Unhook(&trampoline);
        InterlockedExchange(&g_reportResumeFailure, 0);

        if (!unhookResult)
            failure = "Mhook_Unhook failed although only resuming a peer failed";
        else if (Mhook_GetLastStatus() != MHOOK_STATUS_THREAD_RESUME_FAILED)
            failure = "Mhook_Unhook did not report the failed resume";
        else if (trampoline != target)
            failure = "the completed Mhook_Unhook did not restore the caller slot";
        else if (memcmp(target, kMovEaxRet, sizeof(kMovEaxRet)) != 0)
            failure = "the completed Mhook_Unhook did not restore the target";
    }

    InterlockedExchange(&g_stopThreads, 1);
    if (peer)
    {
        WaitForSingleObject(peer, INFINITE);
        CloseHandle(peer);
    }

    if (trampoline != target && !Mhook_Unhook(&trampoline) && !failure)
        failure = "removing the target hook failed";
    if (!Mhook_Unhook(reinterpret_cast<PVOID*>(&g_originalResume)) && !failure)
        failure = "removing the ResumeThread hook failed";
    if (target)
        VirtualFree(target, 0, MEM_RELEASE);

    if (failure)
        return Fail(failure);
    return 0;
}

static int CaseReuse(void)
{
    PBYTE target = AllocCodeBuffer(kMovEaxRet, sizeof(kMovEaxRet));
    if (!target)
        return Fail("VirtualAlloc for the target buffer failed");

    BYTE snapshot[TARGET_BUFFER_SIZE];
    memcpy(snapshot, target, TARGET_BUFFER_SIZE);

    const int cycles = Exhaustive() ? 1000 : 100;
    for (int i = 0; i < cycles; ++i)
    {
        PVOID trampoline = target;
        if (!Mhook_SetHook(&trampoline, (PVOID)&HookCounting))
            return Fail("Mhook_SetHook failed during repeated hook and unhook cycles");
        if (!Mhook_Unhook(&trampoline))
            return Fail("Mhook_Unhook failed during repeated hook and unhook cycles");
    }
    if (memcmp(target, snapshot, TARGET_BUFFER_SIZE) != 0)
        return Fail("the target bytes drifted over repeated hook and unhook cycles");
    return 0;
}


#ifdef _M_X64
/**
 * @brief Verifies distant routing and prevents active trampolines from reentering the free list.
 * @return Zero on success; otherwise a test failure code.
 */
static int caseTrampolinePoolBookkeeping(void)
{
    static const uintptr_t kNearbyTargetOffset = UINT64_C(0x0000000000020000);
    static const uintptr_t kTargetAddressPairs[][2] = {
        {UINT64_C(0x0000000200000000), UINT64_C(0x0000000600000000)},
        {UINT64_C(0x0000000A00000000), UINT64_C(0x0000000E00000000)},
        {UINT64_C(0x0000001200000000), UINT64_C(0x0000001600000000)}
    };

    PBYTE firstTarget = NULL;
    PBYTE nearbyTarget = NULL;
    PBYTE secondTarget = NULL;

    for (size_t index = 0; index < ARRAYSIZE(kTargetAddressPairs); ++index)
    {
        firstTarget =
            AllocCodeBuffer(kMovEaxRet, sizeof(kMovEaxRet), reinterpret_cast<PVOID>(kTargetAddressPairs[index][0]));

        if (!firstTarget)
            continue;

        nearbyTarget = AllocCodeBuffer(
            kMovEaxRet,
            sizeof(kMovEaxRet),
            reinterpret_cast<PVOID>(kTargetAddressPairs[index][0] + kNearbyTargetOffset)
        );
        secondTarget =
            AllocCodeBuffer(kMovEaxRet, sizeof(kMovEaxRet), reinterpret_cast<PVOID>(kTargetAddressPairs[index][1]));

        if (nearbyTarget && secondTarget)
            break;

        VirtualFree(firstTarget, 0, MEM_RELEASE);
        if (nearbyTarget)
            VirtualFree(nearbyTarget, 0, MEM_RELEASE);
        if (secondTarget)
            VirtualFree(secondTarget, 0, MEM_RELEASE);

        firstTarget = NULL;
        nearbyTarget = NULL;
        secondTarget = NULL;
    }

    if (!firstTarget || !nearbyTarget || !secondTarget)
        return Fail("VirtualAlloc could not reserve distant trampoline-pool targets");

    PBYTE initialTargets[] = {firstTarget, secondTarget};

    for (size_t index = 0; index < ARRAYSIZE(initialTargets); ++index)
    {
        PVOID trampoline = initialTargets[index];

        if (!Mhook_SetHook(&trampoline, reinterpret_cast<PVOID>(&HookCounting)))
            return Fail("Mhook_SetHook failed while exercising distant trampoline pools");

        // Execute the distant route through its nearby stub before removing the hook.
        g_hookCalls = 0;
        if (reinterpret_cast<TargetFn>(initialTargets[index])() != HOOK_RESULT)
            return Fail("calling a distant target did not reach the hook");
        if (g_hookCalls != 1)
            return Fail("the distant target called the hook an unexpected number of times");

        if (!Mhook_Unhook(&trampoline))
            return Fail("Mhook_Unhook failed while exercising distant trampoline pools");
    }

    PVOID firstTrampoline = firstTarget;
    if (!Mhook_SetHook(&firstTrampoline, reinterpret_cast<PVOID>(&HookCounting)))
        return Fail("Mhook_SetHook failed while reserving the first nearby trampoline");

    PVOID nearbyTrampoline = nearbyTarget;
    if (!Mhook_SetHook(&nearbyTrampoline, reinterpret_cast<PVOID>(&HookCounting)))
        return Fail("Mhook_SetHook failed while reserving the second nearby trampoline");

    if (firstTrampoline == nearbyTrampoline)
        return Fail("the same trampoline was reserved for two active hooks");

    if (!Mhook_Unhook(&nearbyTrampoline) || !Mhook_Unhook(&firstTrampoline))
        return Fail("Mhook_Unhook failed while cleaning up the trampoline pool test");

    VirtualFree(firstTarget, 0, MEM_RELEASE);
    VirtualFree(nearbyTarget, 0, MEM_RELEASE);
    VirtualFree(secondTarget, 0, MEM_RELEASE);

    return 0;
}
#endif // _M_X64

// Mirrors the patterns the entry-point resolver follows, without following them.
static bool PrologueJumpsElsewhere(const BYTE* code)
{
#ifdef _M_IX86
    if (code[0] == 0x8B && code[1] == 0xFF)
        code += 2;
    if (code[0] == 0x55 && code[1] == 0x8B && code[2] == 0xEC && code[3] == 0x5D)
        code += 4;
#endif
    if (code[0] == 0xE9 || code[0] == 0xEB)
        return true;
    if (code[0] == 0xFF && code[1] == 0x25)
        return true;
    if (code[0] == 0x48 && code[1] == 0xFF && code[2] == 0x25)
        return true;
    return false;
}

static int SweepModule(
    const wchar_t* moduleName,
    PBYTE scratch,
    int* hooked,
    int* skipped,
    int* refused,
    int* sampledOut
)
{
    // Taking every Nth name keeps the sweep spread across the whole export
    // table, and keeps it reproducible from run to run, which random sampling
    // would not.
    const DWORD stride = Exhaustive() ? 1 : 10;

    HMODULE module = LoadLibraryW(moduleName);
    if (!module)
        return Fail("LoadLibraryW failed for a system module the sweep needs");

    PBYTE base = (PBYTE)module;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    const IMAGE_DATA_DIRECTORY directory = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (directory.VirtualAddress == 0)
        return Fail("a system module unexpectedly has no export directory");

    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)(base + directory.VirtualAddress);
    const DWORD* nameRvas = (const DWORD*)(base + exports->AddressOfNames);
    const WORD* ordinals = (const WORD*)(base + exports->AddressOfNameOrdinals);
    const DWORD* functionRvas = (const DWORD*)(base + exports->AddressOfFunctions);

    for (DWORD i = 0; i < exports->NumberOfNames; ++i)
    {
        if (i % stride != 0)
        {
            (*sampledOut)++;
            continue;
        }
        const char* name = (const char*)(base + nameRvas[i]);
        const DWORD functionRva = functionRvas[ordinals[i]];

        // A forwarder stores a string inside the export directory, not code.
        if (functionRva >= directory.VirtualAddress && functionRva < directory.VirtualAddress + directory.Size)
        {
            (*skipped)++;
            continue;
        }

        PBYTE function = base + functionRva;
        MEMORY_BASIC_INFORMATION info;
        if (!VirtualQuery(function, &info, sizeof(info)) || info.State != MEM_COMMIT)
        {
            (*skipped)++;
            continue;
        }
        // Never read past the committed region the prologue lives in.
        if (function + TARGET_BUFFER_SIZE > (PBYTE)info.BaseAddress + info.RegionSize)
        {
            (*skipped)++;
            continue;
        }
        if (PrologueJumpsElsewhere(function))
        {
            (*skipped)++;
            continue;
        }

        memset(scratch, 0xCC, TARGET_BUFFER_SIZE);
        memcpy(scratch, function, TARGET_BUFFER_SIZE);
        FlushInstructionCache(GetCurrentProcess(), scratch, TARGET_BUFFER_SIZE);

        BYTE snapshot[TARGET_BUFFER_SIZE];
        memcpy(snapshot, scratch, TARGET_BUFFER_SIZE);

        PVOID trampoline = scratch;
        if (!Mhook_SetHook(&trampoline, (PVOID)&HookCounting))
        {
            (*refused)++;
            continue;
        }
        if (!Mhook_Unhook(&trampoline))
        {
            fprintf(stderr, "Mhook_Unhook failed for the prologue of %s\n", name);
            return 1;
        }
        if (memcmp(scratch, snapshot, TARGET_BUFFER_SIZE) != 0)
        {
            fprintf(stderr, "prologue bytes were not restored for %s\n", name);
            return 1;
        }
        (*hooked)++;
    }
    return 0;
}

static int CaseSweep(void)
{
    // A copy of each prologue is hooked, never the live function. Hooking live
    // ntdll would be re-entrant: other threads enter the hooked function, and
    // Mhook_Unhook itself calls VirtualProtect, which reaches
    // NtProtectVirtualMemory. The copy is never executed, so RIP-relative
    // operands inside it pointing at the wrong data does not matter.
    PBYTE scratch = (PBYTE)VirtualAlloc(NULL, TARGET_BUFFER_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!scratch)
        return Fail("VirtualAlloc for the scratch buffer failed");

    static const wchar_t* const kModules[] = {L"ntdll.dll", L"kernel32.dll", L"gdi32.dll"};
    int hooked = 0;
    int skipped = 0;
    int refused = 0;
    int sampledOut = 0;
    for (size_t i = 0; i < sizeof(kModules) / sizeof(kModules[0]); ++i)
    {
        const int status = SweepModule(kModules[i], scratch, &hooked, &skipped, &refused, &sampledOut);
        if (status != 0)
            return status;
    }

    printf(
        "sweep: %d prologues hooked and restored, %d skipped by the harness, "
        "%d refused by Mhook_SetHook, %d not sampled%s\n",
        hooked,
        skipped,
        refused,
        sampledOut,
        Exhaustive() ? "" : " (set MHOOK_TEST_EXHAUSTIVE for the full sweep)"
    );
    if (hooked == 0)
        return Fail("no prologue could be hooked at all, so the sweep proved nothing");
    return 0;
}

/**
 * @brief Reads the pool statistics, treating failure as an empty read the caller reports.
 * @param[out] statistics Receives the counts.
 * @return TRUE when the statistics were read.
 */
static BOOL readPool(MHOOK_POOL_STATISTICS* statistics)
{
    *statistics = MHOOK_POOL_STATISTICS{};
    return Mhook_GetPoolStatistics(statistics);
}

/**
 * @brief Verifies that pool statistics follow installation and removal, and that removal keeps the slot.
 * @return Zero on success; otherwise a test failure code.
 */
static int casePoolStatistics(void)
{
    SetLastError(ERROR_SUCCESS);
    if (Mhook_GetPoolStatistics(NULL) || GetLastError() != ERROR_INVALID_PARAMETER)
        return Fail("Mhook_GetPoolStatistics accepted a NULL argument");

    MHOOK_POOL_STATISTICS initial = {};
    if (!readPool(&initial))
        return Fail("reading the initial pool statistics failed");
    if (initial.activeTrampolines || initial.retiredTrampolines || initial.strandedTrampolines ||
        initial.freeTrampolines || initial.blockCount || initial.reservedBytes)
        return Fail("a fresh process reported a non-empty trampoline pool");

    PBYTE target = AllocCodeBuffer(kMovEaxRet, sizeof(kMovEaxRet));
    if (!target)
        return Fail("VirtualAlloc for the target buffer failed");

    PVOID trampoline = target;
    if (!Mhook_SetHook(&trampoline, reinterpret_cast<PVOID>(&HookCounting)))
        return Fail("Mhook_SetHook failed");

    MHOOK_POOL_STATISTICS installed = {};
    if (!readPool(&installed))
        return Fail("reading the pool statistics after installation failed");
    if (installed.activeTrampolines != 1 || installed.retiredTrampolines != 0)
        return Fail("an installed hook was not counted as active");
    if (installed.blockCount != 1 || installed.reservedBytes == 0 || installed.freeTrampolines == 0)
        return Fail("the first hook did not allocate exactly one pool block");

    const PVOID retiredTrampoline = trampoline;
    if (!Mhook_Unhook(&trampoline))
        return Fail("Mhook_Unhook failed");

    MHOOK_POOL_STATISTICS removed = {};
    if (!readPool(&removed))
        return Fail("reading the pool statistics after removal failed");
    if (removed.activeTrampolines != 0 || removed.retiredTrampolines != 1)
        return Fail("a removed hook was not counted as retired");
    if (removed.freeTrampolines != installed.freeTrampolines)
        return Fail("removal returned the retired slot to the free slots");
    if (removed.blockCount != installed.blockCount || removed.reservedBytes != installed.reservedBytes)
        return Fail("removal released pool memory");

    // A new hook on the same target must not reuse the retired slot.
    PVOID reinstalled = target;
    if (!Mhook_SetHook(&reinstalled, reinterpret_cast<PVOID>(&HookCounting)))
        return Fail("reinstalling the hook failed");
    if (reinstalled == retiredTrampoline)
        return Fail("a retired trampoline was handed out again");
    if (!Mhook_Unhook(&reinstalled))
        return Fail("removing the reinstalled hook failed");

    SetLastError(ERROR_BAD_COMMAND);
    if (!Mhook_ReclaimRetired() || Mhook_GetLastStatus() != MHOOK_STATUS_SUCCESS)
        return Fail("Mhook_ReclaimRetired failed with no thread inside a retired trampoline");
    if (GetLastError() != ERROR_BAD_COMMAND)
        return Fail("a successful reclaim changed the caller's last error");

    MHOOK_POOL_STATISTICS reclaimed = {};
    if (!readPool(&reclaimed))
        return Fail("reading the pool statistics after reclaim failed");
    if (reclaimed.activeTrampolines || reclaimed.retiredTrampolines || reclaimed.freeTrampolines ||
        reclaimed.blockCount || reclaimed.reservedBytes)
        return Fail("reclaim with no installed hooks did not release the whole pool");

    SetLastError(ERROR_BAD_COMMAND);
    if (!Mhook_ReclaimRetired() || Mhook_GetLastStatus() != MHOOK_STATUS_SUCCESS)
        return Fail("Mhook_ReclaimRetired failed on an empty pool");
    if (GetLastError() != ERROR_BAD_COMMAND)
        return Fail("a successful reclaim of an empty pool changed the caller's last error");

    VirtualFree(target, 0, MEM_RELEASE);
    return 0;
}

typedef BOOL(WINAPI* ProtectFunction)(LPVOID address, SIZE_T size, DWORD newProtection, PDWORD oldProtection);
typedef bool (*ProtectRefusal)(PBYTE address, DWORD newProtection);

static ProtectFunction g_originalProtect = NULL;
static ProtectRefusal g_protectRefusal = NULL;
static volatile LONG g_refusedProtects = 0;

/**
 * @brief Refuses the protection changes the active refusal names and forwards every other call.
 * @param[in] address Start of the range.
 * @param[in] size Size of the range.
 * @param[in] newProtection Requested protection.
 * @param[out] oldProtection Receives the previous protection.
 * @return The original function's result, or FALSE with ERROR_ACCESS_DENIED when refused.
 */
static BOOL WINAPI protectRefusing(LPVOID address, SIZE_T size, DWORD newProtection, PDWORD oldProtection)
{
    const ProtectRefusal refusal = g_protectRefusal;
    if (refusal && refusal(static_cast<PBYTE>(address), newProtection))
    {
        InterlockedIncrement(&g_refusedProtects);
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }

    // Installing this very hook calls VirtualProtect on the patched target before the trampoline
    // is published, and the unpublished slot would lead straight back here.
    const ProtectFunction original = g_originalProtect;
    if (!original)
        return VirtualProtectEx(GetCurrentProcess(), address, size, newProtection, oldProtection);

    return original(address, size, newProtection, oldProtection);
}

/**
 * @brief Routes every VirtualProtect call in the process through protectRefusing.
 * @return TRUE when the hook is installed.
 */
static BOOL hookProtect(void)
{
    PVOID original = reinterpret_cast<PVOID>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "VirtualProtect"));

    // g_originalProtect stays NULL until the trampoline exists; see protectRefusing.
    g_originalProtect = NULL;
    if (!original || !Mhook_SetHook(&original, reinterpret_cast<PVOID>(&protectRefusing)))
        return FALSE;

    g_originalProtect = reinterpret_cast<ProtectFunction>(original);
    return TRUE;
}

/**
 * @brief Reports whether two addresses share a page.
 * @param[in] first First address.
 * @param[in] second Second address.
 * @return true when both lie in the same page.
 */
static bool samePage(const void* first, const void* second)
{
    SYSTEM_INFO info = {};
    GetSystemInfo(&info);
    const uintptr_t mask = ~static_cast<uintptr_t>(info.dwPageSize - 1);
    return (reinterpret_cast<uintptr_t>(first) & mask) == (reinterpret_cast<uintptr_t>(second) & mask);
}

static PBYTE g_strandedTarget = NULL;
static LONG g_strandedTargetWrites = 0;

/**
 * @brief Lets installation make the stranded target writable, then refuses the rollback's attempt.
 * @param[in] address Start of the range.
 * @param[in] newProtection Requested protection.
 * @return true for the second request to make the stranded target's page writable.
 */
static bool refuseStrandedRollback(PBYTE address, DWORD newProtection)
{
    if (newProtection != PAGE_EXECUTE_READWRITE || !samePage(address, g_strandedTarget))
        return false;

    return ++g_strandedTargetWrites > 1;
}

/**
 * @brief Verifies that an entry whose target a failed rollback could not restore is kept as stranded.
 * @return Zero on success; otherwise a test failure code.
 */
static int caseStrandedRollback(void)
{
    PBYTE firstTarget = AllocCodeBuffer(kMovEaxRet, sizeof(kMovEaxRet));
    HANDLE mapping = NULL;
    PBYTE secondTarget = allocateReadOnlyCodeBuffer(kMovEaxRet, sizeof(kMovEaxRet), &mapping);
    if (!firstTarget || !secondTarget)
        return Fail("allocating the stranded rollback targets failed");

    // Execute-read, so installation restores a protection the refusal does not match.
    DWORD ignoredProtection = 0;
    if (!VirtualProtect(firstTarget, TARGET_BUFFER_SIZE, PAGE_EXECUTE_READ, &ignoredProtection))
        return Fail("making the first target execute-read failed");

    if (!hookProtect())
        return Fail("hooking VirtualProtect failed");

    MHOOK_POOL_STATISTICS before = {};
    if (!readPool(&before))
        return Fail("reading the pool statistics before the batch failed");

    PVOID firstSlot = firstTarget;
    PVOID secondSlot = secondTarget;
    MHOOK_HOOK_INFO hooks[] = {
        {&firstSlot, reinterpret_cast<PVOID>(&HookCounting), MHOOK_STATUS_SUCCESS},
        {&secondSlot, reinterpret_cast<PVOID>(&HookCounting), MHOOK_STATUS_SUCCESS}
    };

    g_strandedTarget = firstTarget;
    g_strandedTargetWrites = 0;
    g_protectRefusal = refuseStrandedRollback;
    const BOOL result = Mhook_SetHookBatch(hooks, ARRAYSIZE(hooks));
    g_protectRefusal = NULL;

    MHOOK_POOL_STATISTICS after = {};
    const char* failure = NULL;
    if (!readPool(&after))
        failure = "reading the pool statistics after the batch failed";
    else if (result)
        failure = "a batch with a read-only target succeeded";
    else if (hooks[0].status != MHOOK_STATUS_MEMORY_PROTECTION_FAILED)
        failure = "the failed rollback was not reported on its descriptor";
    else if (after.strandedTrampolines != before.strandedTrampolines + 1)
        failure = "the entry the rollback could not restore was not counted as stranded";
    else if (after.activeTrampolines != before.activeTrampolines)
        failure = "the failed batch changed the number of active hooks";
    else if (firstSlot != firstTarget || secondSlot != secondTarget)
        failure = "the failed batch changed a caller slot";

    // The first target stays patched: it belongs to the stranded entry and is never freed or called.
    if (!Mhook_Unhook(reinterpret_cast<PVOID*>(&g_originalProtect)) && !failure)
        failure = "removing the VirtualProtect hook failed";
    UnmapViewOfFile(secondTarget);
    CloseHandle(mapping);

    if (failure)
        return Fail(failure);
    return 0;
}

/**
 * @brief Reports whether the page holding an address has exactly one protection.
 * @param[in] address Address to query.
 * @param[in] protection Expected protection.
 * @return true when VirtualQuery reports exactly that protection.
 */
static bool hasProtection(const void* address, DWORD protection)
{
    MEMORY_BASIC_INFORMATION info = {};
    return VirtualQuery(address, &info, sizeof(info)) == sizeof(info) && info.Protect == protection;
}

/**
 * @brief Places a second copy of kMovEaxRet in the upper half of a target buffer.
 * @param[in,out] buffer Buffer from AllocCodeBuffer.
 * @return The second target, which shares the first target's page and trampoline range.
 */
static PBYTE addSecondTarget(PBYTE buffer)
{
    PBYTE second = buffer + TARGET_BUFFER_SIZE / 2;
    memcpy(second, kMovEaxRet, sizeof(kMovEaxRet));
    FlushInstructionCache(GetCurrentProcess(), second, sizeof(kMovEaxRet));
    return second;
}

/**
 * @brief Verifies that installed and retired trampolines live on execute-read pages and keep working.
 * @return Zero on success; otherwise a test failure code.
 */
static int caseTrampolineProtection(void)
{
    PBYTE target = AllocCodeBuffer(kMovEaxRet, sizeof(kMovEaxRet));
    if (!target)
        return Fail("VirtualAlloc for the target buffer failed");

    PVOID trampoline = target;
    if (!Mhook_SetHook(&trampoline, reinterpret_cast<PVOID>(&HookCounting)))
        return Fail("Mhook_SetHook failed");
    if (!hasProtection(trampoline, PAGE_EXECUTE_READ))
        return Fail("an installed trampoline page is not PAGE_EXECUTE_READ");
    if (reinterpret_cast<TargetFn>(target)() != HOOK_RESULT)
        return Fail("calling the target did not reach the hook");
    if (reinterpret_cast<TargetFn>(trampoline)() != TARGET_RESULT)
        return Fail("calling the trampoline did not reach the original");

    const PVOID retired = trampoline;
    if (!Mhook_Unhook(&trampoline))
        return Fail("Mhook_Unhook failed");
    if (!hasProtection(retired, PAGE_EXECUTE_READ))
        return Fail("a retired trampoline page is not PAGE_EXECUTE_READ");
    if (reinterpret_cast<TargetFn>(retired)() != TARGET_RESULT)
        return Fail("a retired trampoline no longer reaches the original");

    VirtualFree(target, 0, MEM_RELEASE);
    return 0;
}

static PBYTE g_refusalTarget = NULL;
static DWORD g_refusedProtection = 0;

/**
 * @brief Refuses one protection value everywhere except the test targets' page, so only pool pages are affected.
 * @param[in] address Start of the range.
 * @param[in] newProtection Requested protection.
 * @return true when the request must be refused.
 */
static bool refusePoolProtection(PBYTE address, DWORD newProtection)
{
    return newProtection == g_refusedProtection && !samePage(address, g_refusalTarget);
}

/**
 * @brief Installs a hook while one pool protection change is refused.
 * @param[in] protection Protection value to refuse.
 * @param[in,out] slot Hook slot passed to Mhook_SetHook.
 * @param[out] status Status reported for the installation.
 * @return The Mhook_SetHook result.
 */
static BOOL setHookRefusing(DWORD protection, PVOID* slot, MHOOK_STATUS* status)
{
    g_refusedProtection = protection;
    g_refusedProtects = 0;
    g_protectRefusal = refusePoolProtection;
    const BOOL result = Mhook_SetHook(slot, reinterpret_cast<PVOID>(&HookCounting));
    *status = Mhook_GetLastStatus();
    g_protectRefusal = NULL;
    return result;
}

/**
 * @brief Verifies that a failed pool protection change prevents activation and leaves neighbours running.
 * @return Zero on success; otherwise a test failure code.
 */
static int caseProtectionFailure(void)
{
    PBYTE firstTarget = AllocCodeBuffer(kMovEaxRet, sizeof(kMovEaxRet));
    if (!firstTarget)
        return Fail("VirtualAlloc for the target buffer failed");
    PBYTE secondTarget = addSecondTarget(firstTarget);
    g_refusalTarget = firstTarget;

    if (!hookProtect())
        return Fail("hooking VirtualProtect failed");

    // The first hook's slot and the second's end up in the same block and page.
    PVOID firstTrampoline = firstTarget;
    if (!Mhook_SetHook(&firstTrampoline, reinterpret_cast<PVOID>(&HookCounting)))
        return Fail("installing the first hook failed");

    MHOOK_POOL_STATISTICS before = {};
    if (!readPool(&before))
        return Fail("reading the pool statistics failed");

    const char* failure = NULL;
    const DWORD refusals[] = {PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_READ};
    for (size_t index = 0; index < ARRAYSIZE(refusals) && !failure; ++index)
    {
        PVOID secondTrampoline = secondTarget;
        MHOOK_STATUS status = MHOOK_STATUS_SUCCESS;
        const BOOL result = setHookRefusing(refusals[index], &secondTrampoline, &status);

        MHOOK_POOL_STATISTICS after = {};
        if (!readPool(&after))
            failure = "reading the pool statistics failed";
        else if (!g_refusedProtects)
            failure = "the installation never changed a pool page's protection";
        else if (result)
            failure = "an installation succeeded although its slot protection could not be set";
        else if (status != MHOOK_STATUS_MEMORY_PROTECTION_FAILED)
            failure = "a refused slot protection was not reported as MEMORY_PROTECTION_FAILED";
        else if (secondTrampoline != secondTarget)
            failure = "the failed installation changed the caller slot";
        else if (memcmp(secondTarget, kMovEaxRet, sizeof(kMovEaxRet)) != 0)
            failure = "the failed installation changed the target";
        else if (after.activeTrampolines != before.activeTrampolines ||
                 after.freeTrampolines != before.freeTrampolines || after.blockCount != before.blockCount)
            failure = "the failed installation changed the pool";
        else if (reinterpret_cast<TargetFn>(firstTrampoline)() != TARGET_RESULT)
            failure = "an active neighbour trampoline stopped working";
        else if (refusals[index] == PAGE_EXECUTE_READ && !hasProtection(firstTrampoline, PAGE_EXECUTE_READWRITE))
            failure = "a page that could not return to execute-read was not left PAGE_EXECUTE_READWRITE";
    }

    // A later successful write makes the pool pages execute-read again.
    PVOID secondTrampoline = secondTarget;
    if (!failure && !Mhook_SetHook(&secondTrampoline, reinterpret_cast<PVOID>(&HookCounting)))
        failure = "installing the second hook without refusals failed";
    else if (!failure && !samePage(firstTrampoline, secondTrampoline))
        failure = "the test's two trampolines do not share a page, so it proves nothing about neighbours";
    else if (!failure && (!hasProtection(secondTrampoline, PAGE_EXECUTE_READ) ||
                          !hasProtection(firstTrampoline, PAGE_EXECUTE_READ)))
        failure = "a successful installation left a pool page writable";

    if (secondTrampoline != secondTarget && !Mhook_Unhook(&secondTrampoline) && !failure)
        failure = "removing the second hook failed";
    if (!Mhook_Unhook(&firstTrampoline) && !failure)
        failure = "removing the first hook failed";
    if (!Mhook_Unhook(reinterpret_cast<PVOID*>(&g_originalProtect)) && !failure)
        failure = "removing the VirtualProtect hook failed";
    VirtualFree(firstTarget, 0, MEM_RELEASE);

    if (failure)
        return Fail(failure);
    return 0;
}

#ifdef _M_X64
/**
 * @brief Verifies that the block search stops at the first new block that cannot be made execute-read.
 * @return Zero on success; otherwise a test failure code.
 */
static int caseBlockProtectionRefused(void)
{
    // Far from every module, so no existing block is in range and the search must allocate one.
    static const uintptr_t kTargetAddresses[] =
        {UINT64_C(0x0000000200000000), UINT64_C(0x0000000A00000000), UINT64_C(0x0000001200000000)};

    PBYTE target = NULL;
    for (size_t index = 0; index < ARRAYSIZE(kTargetAddresses) && !target; ++index)
        target = AllocCodeBuffer(kMovEaxRet, sizeof(kMovEaxRet), reinterpret_cast<PVOID>(kTargetAddresses[index]));
    if (!target)
        return Fail("VirtualAlloc could not reserve a distant target");
    g_refusalTarget = target;

    if (!hookProtect())
        return Fail("hooking VirtualProtect failed");

    MHOOK_POOL_STATISTICS before = {};
    if (!readPool(&before))
        return Fail("reading the pool statistics failed");

    PVOID trampoline = target;
    MHOOK_STATUS status = MHOOK_STATUS_SUCCESS;
    const BOOL result = setHookRefusing(PAGE_EXECUTE_READ, &trampoline, &status);
    const LONG refusedProtects = g_refusedProtects;

    MHOOK_POOL_STATISTICS after = {};
    const char* failure = NULL;
    if (!readPool(&after))
        failure = "reading the pool statistics failed";
    else if (result)
        failure = "an installation succeeded although no new block could be made execute-read";
    else if (status != MHOOK_STATUS_TRAMPOLINE_ALLOCATION_FAILED)
        failure = "a refused block protection was not reported as TRAMPOLINE_ALLOCATION_FAILED";
    else if (refusedProtects != 1)
        failure = "the block search went on after the process refused executable memory";
    else if (after.blockCount != before.blockCount)
        failure = "the failed installation changed the number of blocks";
    else if (trampoline != target)
        failure = "the failed installation changed the caller slot";

    if (result && !Mhook_Unhook(&trampoline) && !failure)
        failure = "removing the unexpected hook failed";
    if (!Mhook_Unhook(reinterpret_cast<PVOID*>(&g_originalProtect)) && !failure)
        failure = "removing the VirtualProtect hook failed";
    VirtualFree(target, 0, MEM_RELEASE);

    if (failure)
    {
        fprintf(stderr, "refused protection changes: %ld\n", refusedProtects);
        return Fail(failure);
    }
    return 0;
}
#endif // _M_X64

/**
 * @brief Verifies that reclaim frees a retired neighbour but keeps an active trampoline and its block.
 * @return Zero on success; otherwise a test failure code.
 */
static int caseReclaimKeepsActive(void)
{
    PBYTE firstTarget = AllocCodeBuffer(kMovEaxRet, sizeof(kMovEaxRet));
    if (!firstTarget)
        return Fail("VirtualAlloc for the target buffer failed");
    PBYTE secondTarget = addSecondTarget(firstTarget);

    PVOID firstTrampoline = firstTarget;
    PVOID secondTrampoline = secondTarget;
    if (!Mhook_SetHook(&firstTrampoline, reinterpret_cast<PVOID>(&HookCounting)) ||
        !Mhook_SetHook(&secondTrampoline, reinterpret_cast<PVOID>(&HookCounting)))
        return Fail("installing the two hooks failed");
    if (!Mhook_Unhook(&secondTrampoline))
        return Fail("removing the second hook failed");
    if (!Mhook_ReclaimRetired())
        return Fail("Mhook_ReclaimRetired failed");

    MHOOK_POOL_STATISTICS statistics = {};
    if (!readPool(&statistics))
        return Fail("reading the pool statistics failed");
    if (statistics.activeTrampolines != 1 || statistics.retiredTrampolines != 0)
        return Fail("reclaim did not leave exactly the active hook");
    if (statistics.blockCount != 1)
        return Fail("reclaim released the block of an active hook");

    g_hookCalls = 0;
    if (reinterpret_cast<TargetFn>(firstTarget)() != HOOK_RESULT || g_hookCalls != 1)
        return Fail("the active hook stopped routing to its replacement");
    if (reinterpret_cast<TargetFn>(firstTrampoline)() != TARGET_RESULT)
        return Fail("the active trampoline stopped reaching the original");

    if (!Mhook_Unhook(&firstTrampoline) || !Mhook_ReclaimRetired())
        return Fail("removing and reclaiming the first hook failed");
    if (!readPool(&statistics) || statistics.blockCount != 0)
        return Fail("reclaiming the last hook did not release its block");

    VirtualFree(firstTarget, 0, MEM_RELEASE);
    return 0;
}

/**
 * @brief Verifies that a thread stopped inside a retired trampoline makes reclaim fail as busy and change nothing.
 * @return Zero on success; otherwise a test failure code.
 */
static int caseReclaimBusy(void)
{
    PBYTE target = AllocCodeBuffer(kMovEaxRet, sizeof(kMovEaxRet));
    if (!target)
        return Fail("VirtualAlloc for the target buffer failed");

    PVOID trampoline = target;
    if (!Mhook_SetHook(&trampoline, reinterpret_cast<PVOID>(&HookCounting)))
        return Fail("Mhook_SetHook failed");
    const PBYTE retired = static_cast<PBYTE>(trampoline);
    if (!Mhook_Unhook(&trampoline))
        return Fail("Mhook_Unhook failed");

    // A thread that never ran can be moved anywhere; this test's own suspension keeps it there.
    g_stopThreads = 0;
    HANDLE parked = CreateThread(NULL, 0, waitForStop, NULL, CREATE_SUSPENDED, NULL);
    const char* failure = parked ? NULL : "CreateThread for the parked thread failed";

    CONTEXT original = {};
    original.ContextFlags = CONTEXT_CONTROL;
    if (!failure && !GetThreadContext(parked, &original))
        failure = "reading the parked thread's context failed";

    if (!failure)
    {
        CONTEXT insideRetired = original;
#ifdef _M_X64
        insideRetired.Rip = reinterpret_cast<DWORD64>(retired + 1);
#else
        insideRetired.Eip = reinterpret_cast<DWORD>(retired + 1);
#endif
        if (!SetThreadContext(parked, &insideRetired))
            failure = "moving the parked thread into the retired trampoline failed";
    }

    MHOOK_POOL_STATISTICS before = {};
    if (!failure && !readPool(&before))
        failure = "reading the pool statistics failed";

    if (!failure)
    {
        const BOOL result = Mhook_ReclaimRetired();
        MHOOK_POOL_STATISTICS after = {};

        if (result)
            failure = "reclaim succeeded with a thread inside a retired trampoline";
        else if (Mhook_GetLastStatus() != MHOOK_STATUS_THREAD_BUSY)
            failure = "a thread inside a retired trampoline was not reported as busy";
        else if (!readPool(&after))
            failure = "reading the pool statistics after the busy reclaim failed";
        else if (after.retiredTrampolines != before.retiredTrampolines || after.blockCount != before.blockCount)
            failure = "a failed reclaim changed the pool";
    }

    if (parked)
    {
        InterlockedExchange(&g_stopThreads, 1);
        if (!SetThreadContext(parked, &original) && !failure)
            failure = "restoring the parked thread's context failed";
    }

    // With the thread moved out, the same reclaim succeeds.
    MHOOK_POOL_STATISTICS reclaimed = {};
    if (!failure && !Mhook_ReclaimRetired())
        failure = "reclaim failed after the thread left the retired trampoline";
    else if (!failure && (!readPool(&reclaimed) || reclaimed.retiredTrampolines != 0 || reclaimed.blockCount != 0))
        failure = "the retried reclaim did not free the retired trampoline and its block";

    if (parked)
    {
        ResumeThread(parked);
        WaitForSingleObject(parked, INFINITE);
        CloseHandle(parked);
    }
    VirtualFree(target, 0, MEM_RELEASE);

    if (failure)
        return Fail(failure);
    return 0;
}

/**
 * @brief Verifies that hook churn with reclaim does not grow the pool without bound.
 * @return Zero on success; otherwise a test failure code.
 */
static int caseReclaimChurn(void)
{
    PBYTE target = AllocCodeBuffer(kMovEaxRet, sizeof(kMovEaxRet));
    if (!target)
        return Fail("VirtualAlloc for the target buffer failed");

    const SIZE_T cycles = Exhaustive() ? 1000 : 50;
    MHOOK_POOL_STATISTICS statistics = {};

    // Reclaiming after every removal keeps no block alive between cycles.
    for (SIZE_T cycle = 0; cycle < cycles; ++cycle)
    {
        PVOID trampoline = target;
        if (!Mhook_SetHook(&trampoline, reinterpret_cast<PVOID>(&HookCounting)) || !Mhook_Unhook(&trampoline))
            return Fail("a hook and unhook cycle failed");
        if (!Mhook_ReclaimRetired())
            return Fail("Mhook_ReclaimRetired failed during churn");
        if (!readPool(&statistics) || statistics.blockCount != 0)
            return Fail("a reclaimed cycle left a pool block allocated");
    }

    // Deferring reclaim lets retired slots accumulate, and one reclaim frees them all.
    for (SIZE_T cycle = 0; cycle < cycles; ++cycle)
    {
        PVOID trampoline = target;
        if (!Mhook_SetHook(&trampoline, reinterpret_cast<PVOID>(&HookCounting)) || !Mhook_Unhook(&trampoline))
            return Fail("a hook and unhook cycle failed");
        if (!readPool(&statistics) || statistics.blockCount > 1)
            return Fail("retired slots spilled into a second block before the first was full");
    }
    if (!readPool(&statistics) || statistics.retiredTrampolines != cycles)
        return Fail("deferred removals were not all counted as retired");

    if (!Mhook_ReclaimRetired())
        return Fail("the deferred Mhook_ReclaimRetired failed");
    if (!readPool(&statistics) || statistics.retiredTrampolines || statistics.blockCount || statistics.reservedBytes)
        return Fail("one reclaim did not free every deferred retired trampoline");

    VirtualFree(target, 0, MEM_RELEASE);
    return 0;
}

/**
 * @brief Verifies that reclaim releases a block a failed batch left empty, with nothing retired.
 * @return Zero on success; otherwise a test failure code.
 */
static int caseReclaimEmptyBlock(void)
{
    PBYTE target = AllocCodeBuffer(kMovEaxRet, sizeof(kMovEaxRet));
    if (!target)
        return Fail("VirtualAlloc for the target buffer failed");

    // The first request allocates a block in prepare; the second fails there, and the batch gives the slot back.
    PVOID firstSlot = target;
    PVOID secondSlot = target;
    MHOOK_HOOK_INFO hooks[] = {
        {&firstSlot, reinterpret_cast<PVOID>(&HookCounting), MHOOK_STATUS_SUCCESS},
        {&secondSlot, NULL, MHOOK_STATUS_SUCCESS}
    };
    if (Mhook_SetHookBatch(hooks, ARRAYSIZE(hooks)))
        return Fail("a batch with a NULL hook function succeeded");
    if (hooks[0].status != MHOOK_STATUS_SUCCESS || hooks[1].status != MHOOK_STATUS_INVALID_ARGUMENT)
        return Fail("the batch did not fail in prepare on its second request");

    MHOOK_POOL_STATISTICS statistics = {};
    if (!readPool(&statistics))
        return Fail("reading the pool statistics after the failed batch failed");
    if (statistics.blockCount != 1 || statistics.activeTrampolines || statistics.retiredTrampolines)
        return Fail("the failed batch did not leave exactly one empty block");

    if (!Mhook_ReclaimRetired() || Mhook_GetLastStatus() != MHOOK_STATUS_SUCCESS)
        return Fail("Mhook_ReclaimRetired failed with nothing retired");
    if (!readPool(&statistics) || statistics.blockCount != 0 || statistics.reservedBytes != 0)
        return Fail("reclaim did not release the empty block");

    VirtualFree(target, 0, MEM_RELEASE);
    return 0;
}

/**
 * @brief Verifies that a target with no free memory below it gets its block from the other side of the search.
 *
 * The target takes the lowest free granule, so every granule below it is in use, and every free granule from
 * there up to twice its address plus one granule is reserved. When the downward half of the search reaches
 * address zero it has made as many steps as the upward half, which by then has only seen reserved granules
 * below twice the target's address. A search that ends when either side leaves the range therefore fails, and
 * one that keeps going on the other side finds a block above twice the target's address. The test builds this
 * layout itself, so the result does not depend on where the loader placed anything.
 *
 * @return Zero on success; otherwise a test failure code.
 */
static int caseLowTarget(void)
{
    SYSTEM_INFO info = {};
    GetSystemInfo(&info);
    const uintptr_t granule = info.dwAllocationGranularity;

    // Stay in the low gigabyte, so twice the target is still a user address on x86.
    static const uintptr_t kSearchLimit = 0x40000000;
    PBYTE target = NULL;
    for (uintptr_t address = granule; address < kSearchLimit && !target; address += granule)
        target = AllocCodeBuffer(kMovEaxRet, sizeof(kMovEaxRet), reinterpret_cast<PVOID>(address));
    if (!target)
        return Fail("no free granule in the low gigabyte could hold the target");

    const uintptr_t targetAddress = reinterpret_cast<uintptr_t>(target);
    std::vector<PVOID> reservations;
    for (uintptr_t address = granule; address <= 2 * targetAddress + granule; address += granule)
    {
        PVOID reservation = VirtualAlloc(reinterpret_cast<PVOID>(address), granule, MEM_RESERVE, PAGE_NOACCESS);
        if (reservation)
            reservations.push_back(reservation);
    }

    const char* failure = NULL;
    PVOID trampoline = target;
    if (!Mhook_SetHook(&trampoline, reinterpret_cast<PVOID>(&HookCounting)))
    {
        failure = "Mhook_SetHook failed for a target with free memory only above it";
    }
    else
    {
        g_hookCalls = 0;
        if (reinterpret_cast<TargetFn>(target)() != HOOK_RESULT || g_hookCalls != 1)
            failure = "calling the low target did not reach the hook";
        else if (reinterpret_cast<TargetFn>(trampoline)() != TARGET_RESULT)
            failure = "calling the trampoline did not reach the original";
        else if (reinterpret_cast<uintptr_t>(trampoline) <= 2 * targetAddress)
            failure = "the trampoline does not lie above the reserved granules";

        if (!Mhook_Unhook(&trampoline) && !failure)
            failure = "Mhook_Unhook failed";
        else if (!Mhook_ReclaimRetired() && !failure)
            failure = "Mhook_ReclaimRetired failed";
    }

    for (size_t index = 0; index < reservations.size(); ++index)
        VirtualFree(reservations[index], 0, MEM_RELEASE);
    VirtualFree(target, 0, MEM_RELEASE);

    if (failure)
        return Fail(failure);
    return 0;
}

struct TestCase
{
    const char* name;
    int (*run)(void);
};

static const TestCase kCases[] = {
    {"basic", CaseBasic},
    {"batch", caseBatch},
    {"batch_prepare_failure", caseBatchPrepareFailure},
    {"batch_conflict", caseBatchConflict},
    {"batch_commit_failure", caseBatchCommitFailure},
    {"batch_unhook_prepare_failure", caseBatchUnhookPrepareFailure},
    {"batch_unhook_conflict", caseBatchUnhookConflict},
    {"batch_unhook_commit_failure", caseBatchUnhookCommitFailure},
    {"trampoline", CaseTrampoline},
    {"restore", CaseRestore},
    {"conflict", CaseConflict},
    {"passthrough", CasePassthrough},
    {"thunk", CaseThunk},
    {"snapshot_boundary", CaseSnapshotBoundary},
    {"short_func", CaseShortFunc},
    {"threads", CaseThreads},
    {"suspend_failure", caseSuspensionFailure},
    {"first_use_race", caseFirstUseRace},
    {"late_thread", caseLateThread},
    {"thread_churn", caseThreadChurn},
    {"enumeration_failure", caseEnumerationFailure},
    {"exited_thread", caseExitedThread},
    {"thread_busy", caseThreadBusy},
    {"resume_failure", caseResumeFailure},
    {"reuse", CaseReuse},
#ifdef _M_X64
    {"pool", caseTrampolinePoolBookkeeping},
    {"block_protection_refused", caseBlockProtectionRefused},
#endif // _M_X64
    {"pool_statistics", casePoolStatistics},
    {"stranded_rollback", caseStrandedRollback},
    {"trampoline_protection", caseTrampolineProtection},
    {"protection_failure", caseProtectionFailure},
    {"reclaim_keeps_active", caseReclaimKeepsActive},
    {"reclaim_busy", caseReclaimBusy},
    {"reclaim_churn", caseReclaimChurn},
    {"reclaim_empty_block", caseReclaimEmptyBlock},
    {"low_target", caseLowTarget},
    {"sweep", CaseSweep},
};

int main(int argc, char** argv)
{
    if (argc != 2)
    {
        fprintf(stderr, "usage: mhook-hook-test <case>\n");
        return 2;
    }
    for (size_t i = 0; i < sizeof(kCases) / sizeof(kCases[0]); ++i)
    {
        if (strcmp(argv[1], kCases[i].name) == 0)
            return kCases[i].run();
    }
    fprintf(stderr, "unknown case: %s\n", argv[1]);
    return 2;
}
