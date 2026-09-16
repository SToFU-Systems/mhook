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

//================================================================================
// Enum: MHOOK_STATUS
// Description: Identifies the final outcome of the calling thread's most
//              recent Mhook operation. SUCCESS means the operation completed; 
//              other statuses identify the terminal failure classes.
//================================================================================
typedef enum MHOOK_STATUS
{
    MHOOK_STATUS_SUCCESS = 0,
    MHOOK_STATUS_INVALID_ARGUMENT = 1,
    MHOOK_STATUS_DECODE_FAILED = 2,
    MHOOK_STATUS_UNSUPPORTED_PROLOGUE = 3,
    MHOOK_STATUS_TRAMPOLINE_ALLOCATION_FAILED = 4,
    MHOOK_STATUS_MEMORY_PROTECTION_FAILED = 5,
    MHOOK_STATUS_HOOK_NOT_FOUND = 6,
    MHOOK_STATUS_THREAD_SUSPENSION_FAILED = 7,
    MHOOK_STATUS_PATCH_FAILED = 8
} MHOOK_STATUS;

BOOL Mhook_SetHook(PVOID *ppSystemFunction, PVOID pHookFunction);
BOOL Mhook_Unhook(PVOID *ppHookedFunction);

//================================================================================
// Function: Mhook_GetLastStatus
// Description: Returns the status produced by the calling thread's most recent
//              Mhook_SetHook or Mhook_Unhook operation without changing the
//              stored value.
//================================================================================
MHOOK_STATUS Mhook_GetLastStatus(void);

#ifdef __cplusplus
}
#endif //__cplusplus
