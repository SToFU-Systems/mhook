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

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mhook-lib/mhook.h"

//=========================================================================
// Define _NtOpenProcess so we can dynamically bind to the function
//
typedef struct _CLIENT_ID
{
    DWORD_PTR UniqueProcess;
    DWORD_PTR UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef ULONG(WINAPI* _NtOpenProcess)(
    OUT PHANDLE ProcessHandle,
    IN ACCESS_MASK AccessMask,
    IN PVOID ObjectAttributes,
    IN PCLIENT_ID ClientId
);

//=========================================================================
// Define _SelectObject so we can dynamically bind to the function
typedef HGDIOBJ(WINAPI* _SelectObject)(HDC hdc, HGDIOBJ hgdiobj);

//=========================================================================
// Define _getaddrinfo so we can dynamically bind to the function
typedef int(WSAAPI* _getaddrinfo)(
    const char* nodename,
    const char* servname,
    const struct addrinfo* hints,
    struct addrinfo** res
);

//=========================================================================
// Define _HeapAlloc so we can dynamically bind to the function
typedef LPVOID(WINAPI* _HeapAlloc)(HANDLE, DWORD, SIZE_T);

//=========================================================================
// Define _NtClose so we can dynamically bind to the function
typedef ULONG(WINAPI* _NtClose)(IN HANDLE Handle);

//=========================================================================
// Get the current (original) address to the functions to be hooked
//
_NtOpenProcess TrueNtOpenProcess =
    (_NtOpenProcess)(void (*)(void))GetProcAddress(GetModuleHandle(L"ntdll"), "NtOpenProcess");

_SelectObject TrueSelectObject =
    (_SelectObject)(void (*)(void))GetProcAddress(GetModuleHandle(L"gdi32"), "SelectObject");

_getaddrinfo Truegetaddrinfo = (_getaddrinfo)(void (*)(void))GetProcAddress(GetModuleHandle(L"ws2_32"), "getaddrinfo");

_HeapAlloc TrueHeapAlloc = (_HeapAlloc)(void (*)(void))GetProcAddress(GetModuleHandle(L"kernel32"), "HeapAlloc");

_NtClose TrueNtClose = (_NtClose)(void (*)(void))GetProcAddress(GetModuleHandle(L"ntdll"), "NtClose");

//=========================================================================
// This is the function that will replace NtOpenProcess once the hook
// is in place
//
ULONG WINAPI HookNtOpenProcess(
    OUT PHANDLE ProcessHandle,
    IN ACCESS_MASK AccessMask,
    IN PVOID ObjectAttributes,
    IN PCLIENT_ID ClientId
)
{
    printf("***** Call to open process %lu\n", (unsigned long)ClientId->UniqueProcess);
    return TrueNtOpenProcess(ProcessHandle, AccessMask, ObjectAttributes, ClientId);
}

//=========================================================================
// This is the function that will replace SelectObject once the hook
// is in place
//
HGDIOBJ WINAPI HookSelectobject(HDC hdc, HGDIOBJ hgdiobj)
{
    printf("***** Call to SelectObject(0x%p, 0x%p)\n", static_cast<void*>(hdc), hgdiobj);
    return TrueSelectObject(hdc, hgdiobj);
}

//=========================================================================
// This is the function that will replace SelectObject once the hook
// is in place
//
int WSAAPI
Hookgetaddrinfo(const char* nodename, const char* servname, const struct addrinfo* hints, struct addrinfo** res)
{
    printf(
        "***** Call to getaddrinfo(0x%p, 0x%p, 0x%p, 0x%p)\n",
        nodename,
        servname,
        static_cast<const void*>(hints),
        static_cast<void*>(res)
    );
    return Truegetaddrinfo(nodename, servname, hints, res);
}

//=========================================================================
// This is the function that will replace HeapAlloc once the hook
// is in place
//
LPVOID WINAPI HookHeapAlloc(HANDLE a_Handle, DWORD a_Bla, SIZE_T a_Bla2)
{
    printf("***** Call to HeapAlloc(0x%p, %lu, %zu)\n", a_Handle, a_Bla, (size_t)a_Bla2);
    return TrueHeapAlloc(a_Handle, a_Bla, a_Bla2);
}

//=========================================================================
// This is the function that will replace NtClose once the hook
// is in place
//
ULONG WINAPI HookNtClose(HANDLE hHandle)
{
    printf("***** Call to NtClose(0x%p)\n", hHandle);
    return TrueNtClose(hHandle);
}

//=========================================================================
// Removes a hook and reports what happened.
//
// Mhook_Unhook refuses to restore a prologue that no longer holds Mhook's own
// patch, so that a second hooking engine's work is never silently erased. When
// that happens the hook is still in place, so a real program can either leave
// it alone or come back and retry later - here we just say so and move on.
//
static void UnhookAndReport(PVOID* ppHookedFunction, const char* pszName)
{
    if (Mhook_Unhook(ppHookedFunction))
    {
        printf("Unhooked %s\n", pszName);
        return;
    }
    const DWORD dwError = GetLastError();
    if (dwError == MHOOK_ERROR_TARGET_MODIFIED)
    {
        printf(
            "Could not unhook %s: somebody else patched %p after we did, "
            "leaving our hook in place\n",
            pszName,
            Mhook_GetTarget(*ppHookedFunction)
        );
    }
    else
    {
        printf("Could not unhook %s: error %lu\n", pszName, dwError);
    }
}

//=========================================================================
// This is where the work gets done.
//
int wmain(int, WCHAR*[])
{
    HANDLE hProc = NULL;

    // Set the hook
    if (Mhook_SetHook((PVOID*)&TrueNtOpenProcess, reinterpret_cast<PVOID>(HookNtOpenProcess)))
    {
        // Now call OpenProcess and observe NtOpenProcess being redirected
        // under the hood.
        hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
        if (hProc)
        {
            printf("Successfully opened self: %p\n", hProc);
            CloseHandle(hProc);
        }
        else
        {
            printf("Could not open self: %lu\n", GetLastError());
        }
        // Remove the hook
        UnhookAndReport((PVOID*)&TrueNtOpenProcess, "NtOpenProcess");
    }

    // Call OpenProces again - this time there won't be a redirection as
    // the hook has bee removed.
    hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
    if (hProc)
    {
        printf("Successfully opened self: %p\n", hProc);
        CloseHandle(hProc);
    }
    else
    {
        printf("Could not open self: %lu\n", GetLastError());
    }

    // Test another hook, this time in SelectObject
    // (SelectObject is interesting in that on XP x64, the second instruction
    // in the trampoline uses IP-relative addressing and we need to do some
    // extra work under the hood to make things work properly. This really
    // is more of a test case rather than a demo.)
    printf("Testing SelectObject.\n");
    if (Mhook_SetHook((PVOID*)&TrueSelectObject, reinterpret_cast<PVOID>(HookSelectobject)))
    {
        // error checking omitted for brevity. doesn't matter much
        // in this context anyway.
        HDC hdc = GetDC(NULL);
        HDC hdcMem = CreateCompatibleDC(hdc);
        HBITMAP hbm = CreateCompatibleBitmap(hdc, 32, 32);
        HBITMAP hbmOld = (HBITMAP)SelectObject(hdcMem, hbm);
        SelectObject(hdcMem, hbmOld);
        DeleteObject(hbm);
        DeleteDC(hdcMem);
        ReleaseDC(NULL, hdc);
        // Remove the hook
        UnhookAndReport((PVOID*)&TrueSelectObject, "SelectObject");
    }

    printf("Testing getaddrinfo.\n");
    if (Mhook_SetHook((PVOID*)&Truegetaddrinfo, reinterpret_cast<PVOID>(Hookgetaddrinfo)))
    {
        // error checking omitted for brevity. doesn't matter much
        // in this context anyway.
        WSADATA wd = {};
        WSAStartup(MAKEWORD(2, 2), &wd);
        const char* ip = "localhost";
        struct addrinfo aiHints;
        struct addrinfo* res = NULL;
        memset(&aiHints, 0, sizeof(aiHints));
        aiHints.ai_family = PF_UNSPEC;
        aiHints.ai_socktype = SOCK_STREAM;
        if (getaddrinfo(ip, NULL, &aiHints, &res))
        {
            printf("getaddrinfo failed\n");
        }
        else
        {
            int n = 0;
            while (res)
            {
                res = res->ai_next;
                n++;
            }
            printf("got %d addresses\n", n);
        }
        WSACleanup();
        // Remove the hook
        UnhookAndReport((PVOID*)&Truegetaddrinfo, "getaddrinfo");
    }

    printf("Testing HeapAlloc.\n");
    if (Mhook_SetHook((PVOID*)&TrueHeapAlloc, reinterpret_cast<PVOID>(HookHeapAlloc)))
    {
        free(malloc(10));
        // Remove the hook
        UnhookAndReport((PVOID*)&TrueHeapAlloc, "HeapAlloc");
    }

    printf("Testing NtClose.\n");
    if (Mhook_SetHook((PVOID*)&TrueNtClose, reinterpret_cast<PVOID>(HookNtClose)))
    {
        CloseHandle(NULL);
        // Remove the hook
        UnhookAndReport((PVOID*)&TrueNtClose, "NtClose");
    }

    return 0;
}
