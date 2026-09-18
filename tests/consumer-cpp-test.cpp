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

static BOOL (*volatile setHook)(PVOID*, PVOID) = &Mhook_SetHook;
static BOOL (*volatile removeHook)(PVOID*) = &Mhook_Unhook;
static PVOID (*volatile getTarget)(PVOID) = &Mhook_GetTarget;
static MHOOK_STATUS (*volatile getLastStatus)(void) = &Mhook_GetLastStatus;


/**
 * @brief Verifies the public API from a C++ consumer.
 *
 * @return Zero on success; otherwise nonzero.
 */
int main(void)
{
    return (setHook && removeHook && getTarget && getLastStatus) ? 0 : 1;
}
