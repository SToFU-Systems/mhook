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
    static Sum5Fn volatile callSum5 = &Sum5;

    if (callSum5(1, 2, 3, 4, 5) != 15)
        return Fail("the unhooked target does not sum its arguments");

    PVOID original = (PVOID)&Sum5;
    if (!Mhook_SetHook(&original, (PVOID)&HookSum5))
        return Fail("Mhook_SetHook failed on the compiled target");
    g_trueSum5 = (Sum5Fn)original;

    g_sum5HookCalls = 0;
    const int hooked = callSum5(1, 2, 3, 4, 5);
    if (g_sum5HookCalls != 1)
        return Fail("the hook ran a number of times other than once");
    if (hooked != 16)
        return Fail("arguments or the return value were corrupted passing through the hook");

    if (!Mhook_Unhook(&original))
        return Fail("Mhook_Unhook failed");
    if (callSum5(1, 2, 3, 4, 5) != 15)
        return Fail("the unhooked target no longer sums its arguments");
    return 0;
}

static int CaseThunk(void)
{
    PBYTE page = (PBYTE)VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!page)
        return Fail("VirtualAlloc for the thunk page failed");
    memset(page, 0xCC, 4096);

    PBYTE thunk = page;
    PBYTE target = page + 128;
    memcpy(target, kMovEaxRet, sizeof(kMovEaxRet));
    thunk[0] = 0xE9;
    *(DWORD*)(thunk + 1) = (DWORD)(target - (thunk + 5));
    FlushInstructionCache(GetCurrentProcess(), page, 4096);

    BYTE thunkSnapshot[8];
    memcpy(thunkSnapshot, thunk, sizeof(thunkSnapshot));

    if (((TargetFn)thunk)() != TARGET_RESULT)
        return Fail("the thunk does not reach the target before hooking");

    g_hookCalls = 0;
    PVOID trampoline = thunk;
    if (!Mhook_SetHook(&trampoline, (PVOID)&HookCounting))
        return Fail("Mhook_SetHook failed on a target behind a thunk");
    if (memcmp(thunk, thunkSnapshot, sizeof(thunkSnapshot)) != 0)
        return Fail("SkipJumps patched the thunk instead of the final target");
    if (!IsJumpPatched(target))
        return Fail("the final target was not patched");
    if (((TargetFn)thunk)() != HOOK_RESULT)
        return Fail("calling through the thunk did not reach the hook");
    if (g_hookCalls != 1)
        return Fail("the hook ran a number of times other than once");

    Mhook_Unhook(&trampoline);
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
    for (int i = 0; i < 100 && status == 0; ++i) {
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

    for (int i = 0; i < 1000; ++i) {
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

// Mirrors the patterns SkipJumps follows, without following them.
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

static int SweepModule(const wchar_t* moduleName, PBYTE scratch, int* hooked, int* skipped, int* refused)
{
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
    for (size_t i = 0; i < sizeof(kModules) / sizeof(kModules[0]); ++i) {
        const int status = SweepModule(kModules[i], scratch, &hooked, &skipped, &refused);
        if (status != 0)
            return status;
    }

    printf("sweep: %d prologues hooked and restored, %d skipped by the harness, %d refused by Mhook_SetHook\n",
           hooked, skipped, refused);
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
    { "passthrough", CasePassthrough },
    { "thunk", CaseThunk },
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
