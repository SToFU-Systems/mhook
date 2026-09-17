//================================================================================
// Mhook
//
// Modifications and original additions:
// Copyright (c) 2026, SToFU Systems (https://stofu.io). All rights reserved.
//
// Licensed under the MIT License.
// See LICENSE in the repository root for the full license text.
//================================================================================

#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
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
static const BYTE kMovEaxRet[] = { 0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3 };

// Every hook and unhook pair costs two system wide thread snapshots inside
// SuspendOtherThreads, which dominates the runtime of the bulk cases. CI cannot
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

static PBYTE AllocCodeBuffer(const BYTE* code, size_t length)
{
    PBYTE buffer = (PBYTE)VirtualAlloc(NULL, TARGET_BUFFER_SIZE,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (buffer) {
        memset(buffer, 0xCC, TARGET_BUFFER_SIZE);
        memcpy(buffer, code, length);
        FlushInstructionCache(GetCurrentProcess(), buffer, TARGET_BUFFER_SIZE);
    }
    return buffer;
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

typedef int (__stdcall *Sum5Fn)(int, int, int, int, int);

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
    const SIZE_T kIndirectJumpSize = 6;
    const SIZE_T kSnapshotSize = kThunkCount * kThunkStride;
#ifdef _M_IX86
    const SIZE_T kDirectThunkCount = 15;
#elif defined _M_X64
    const SIZE_T kDirectThunkCount = 14;
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
    const int32_t secondSlotOffset = static_cast<int32_t>(secondPointerSlot - (rexIndirectThunk + kRexIndirectJumpSize));
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

static const BYTE kRetOnly[] = { 0xC3 };

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
    while (!g_stopThreads) {
        const int result = target();
        if (result != TARGET_RESULT && result != HOOK_RESULT)
            InterlockedIncrement(&g_badResults);
    }
    return 0;
}

static int CaseThreads(void)
{
    PBYTE target = AllocCodeBuffer(kMovEaxRet, sizeof(kMovEaxRet));
    if (!target)
        return Fail("VirtualAlloc for the target buffer failed");

    g_stopThreads = 0;
    g_badResults = 0;

    HANDLE threads[4];
    for (int i = 0; i < 4; ++i) {
        threads[i] = CreateThread(NULL, 0, SpinCallingTarget, target, 0, NULL);
        if (!threads[i]) {
            // Stop and join whatever already started before bailing out, so the
            // case never returns while threads are still running on the buffer.
            InterlockedExchange(&g_stopThreads, 1);
            if (i > 0) {
                WaitForMultipleObjects(i, threads, TRUE, INFINITE);
                for (int j = 0; j < i; ++j)
                    CloseHandle(threads[j]);
            }
            return Fail("CreateThread failed");
        }
    }

    int status = 0;
    // Each iteration hooks and unhooks while four threads hammer the target.
    const int rounds = Exhaustive() ? 100 : 25;
    for (int i = 0; i < rounds && status == 0; ++i) {
        PVOID trampoline = target;
        if (!Mhook_SetHook(&trampoline, (PVOID)&HookCounting))
            status = Fail("Mhook_SetHook failed while other threads were running");
        else if (!Mhook_Unhook(&trampoline))
            status = Fail("Mhook_Unhook failed while other threads were running");
    }

    InterlockedExchange(&g_stopThreads, 1);
    WaitForMultipleObjects(4, threads, TRUE, INFINITE);
    for (int i = 0; i < 4; ++i)
        CloseHandle(threads[i]);

    if (status != 0)
        return status;
    if (g_badResults != 0)
        return Fail("a thread observed a result from neither the target nor the hook");
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
    for (int i = 0; i < cycles; ++i) {
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

static int SweepModule(const wchar_t* moduleName, PBYTE scratch, int* hooked, int* skipped, int* refused,
                      int* sampledOut)
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
    const IMAGE_DATA_DIRECTORY directory =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (directory.VirtualAddress == 0)
        return Fail("a system module unexpectedly has no export directory");

    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)(base + directory.VirtualAddress);
    const DWORD* nameRvas = (const DWORD*)(base + exports->AddressOfNames);
    const WORD* ordinals = (const WORD*)(base + exports->AddressOfNameOrdinals);
    const DWORD* functionRvas = (const DWORD*)(base + exports->AddressOfFunctions);

    for (DWORD i = 0; i < exports->NumberOfNames; ++i) {
        if (i % stride != 0) {
            (*sampledOut)++;
            continue;
        }
        const char* name = (const char*)(base + nameRvas[i]);
        const DWORD functionRva = functionRvas[ordinals[i]];

        // A forwarder stores a string inside the export directory, not code.
        if (functionRva >= directory.VirtualAddress &&
            functionRva < directory.VirtualAddress + directory.Size) {
            (*skipped)++;
            continue;
        }

        PBYTE function = base + functionRva;
        MEMORY_BASIC_INFORMATION info;
        if (!VirtualQuery(function, &info, sizeof(info)) || info.State != MEM_COMMIT) {
            (*skipped)++;
            continue;
        }
        // Never read past the committed region the prologue lives in.
        if (function + TARGET_BUFFER_SIZE > (PBYTE)info.BaseAddress + info.RegionSize) {
            (*skipped)++;
            continue;
        }
        if (PrologueJumpsElsewhere(function)) {
            (*skipped)++;
            continue;
        }

        memset(scratch, 0xCC, TARGET_BUFFER_SIZE);
        memcpy(scratch, function, TARGET_BUFFER_SIZE);
        FlushInstructionCache(GetCurrentProcess(), scratch, TARGET_BUFFER_SIZE);

        BYTE snapshot[TARGET_BUFFER_SIZE];
        memcpy(snapshot, scratch, TARGET_BUFFER_SIZE);

        PVOID trampoline = scratch;
        if (!Mhook_SetHook(&trampoline, (PVOID)&HookCounting)) {
            (*refused)++;
            continue;
        }
        if (!Mhook_Unhook(&trampoline)) {
            fprintf(stderr, "Mhook_Unhook failed for the prologue of %s\n", name);
            return 1;
        }
        if (memcmp(scratch, snapshot, TARGET_BUFFER_SIZE) != 0) {
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
    PBYTE scratch = (PBYTE)VirtualAlloc(NULL, TARGET_BUFFER_SIZE,
                                        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!scratch)
        return Fail("VirtualAlloc for the scratch buffer failed");

    static const wchar_t* const kModules[] = { L"ntdll.dll", L"kernel32.dll", L"gdi32.dll" };
    int hooked = 0;
    int skipped = 0;
    int refused = 0;
    int sampledOut = 0;
    for (size_t i = 0; i < sizeof(kModules) / sizeof(kModules[0]); ++i) {
        const int status = SweepModule(kModules[i], scratch, &hooked, &skipped, &refused, &sampledOut);
        if (status != 0)
            return status;
    }

    printf("sweep: %d prologues hooked and restored, %d skipped by the harness, "
           "%d refused by Mhook_SetHook, %d not sampled%s\n",
           hooked, skipped, refused, sampledOut,
           Exhaustive() ? "" : " (set MHOOK_TEST_EXHAUSTIVE for the full sweep)");
    if (hooked == 0)
        return Fail("no prologue could be hooked at all, so the sweep proved nothing");
    return 0;
}

struct TestCase {
    const char* name;
    int (*run)(void);
};

static const TestCase kCases[] = {
    { "basic", CaseBasic },
    { "trampoline", CaseTrampoline },
    { "restore", CaseRestore },
    { "conflict", CaseConflict },
    { "passthrough", CasePassthrough },
    { "thunk", CaseThunk },
    { "snapshot_boundary", CaseSnapshotBoundary },
    { "short_func", CaseShortFunc },
    { "threads", CaseThreads },
    { "reuse", CaseReuse },
    { "sweep", CaseSweep },
};

int main(int argc, char** argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: mhook-hook-test <case>\n");
        return 2;
    }
    for (size_t i = 0; i < sizeof(kCases) / sizeof(kCases[0]); ++i) {
        if (strcmp(argv[1], kCases[i].name) == 0)
            return kCases[i].run();
    }
    fprintf(stderr, "unknown case: %s\n", argv[1]);
    return 2;
}
