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

#pragma once

#include <windows.h>

#ifdef __cplusplus
extern "C"
{
#endif //__cplusplus

// Error codes reported through GetLastError() when the functions below fail.
// Bit 29 is the range Windows reserves for application-defined codes, so these
// can never collide with a system error.
#define MHOOK_ERROR_NOT_HOOKED      ((DWORD)((1UL << 29) | 1UL))
#define MHOOK_ERROR_TARGET_MODIFIED ((DWORD)((1UL << 29) | 2UL))

BOOL Mhook_SetHook(PVOID *ppSystemFunction, PVOID pHookFunction);

// Restores the bytes Mhook overwrote and returns TRUE, writing the original
// function address back through ppHookedFunction.
//
// Returns FALSE without touching the target, and without touching
// *ppHookedFunction, when the prologue no longer holds the patch Mhook
// installed, which means another writer has patched the same code since. The
// hook then stays registered - Mhook holds the only copy of the original bytes,
// so throwing it away would make the code unrestorable for good - and
// GetLastError() reports MHOOK_ERROR_TARGET_MODIFIED. A caller that sees this
// can leave the hook in place, or retry later: once the other writer restores
// Mhook's patch, a second call succeeds normally. Use Mhook_GetTarget to find
// out which address is contested.
//
// Returns FALSE with MHOOK_ERROR_NOT_HOOKED when ppHookedFunction does not name
// a live hook.
BOOL Mhook_Unhook(PVOID *ppHookedFunction);

// Returns the address Mhook patched for a live hook, given the pointer
// Mhook_SetHook produced. Returns NULL and sets MHOOK_ERROR_NOT_HOOKED if there
// is no such hook.
PVOID Mhook_GetTarget(PVOID pHookedFunction);

#ifdef __cplusplus
}
#endif //__cplusplus
