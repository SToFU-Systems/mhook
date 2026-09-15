//================================================================================
// Mhook
//
// Copyright (c) 2026, SToFU Systems (https://stofu.io). All rights reserved.
//
// Licensed under the MIT License.
// See LICENSE in the repository root for the full license text.
//================================================================================

#include "mhook-lib/mhook.h"
#include "mhook-lib/mhook.h"

#ifdef _M_IX86_X64
#error mhook.h must not expose the private architecture macro
#endif

// Volatile references keep both API symbols in optimized link checks.
static BOOL (*volatile set_hook)(PVOID*, PVOID) = &Mhook_SetHook;
static BOOL (*volatile remove_hook)(PVOID*) = &Mhook_Unhook;

int main(void)
{
    return (set_hook && remove_hook) ? 0 : 1;
}
