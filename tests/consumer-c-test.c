//================================================================================
// Mhook
//
// Copyright (c) 2026, SToFU Systems (https://stofu.io). All rights reserved.
//
// Licensed under the MIT License.
// See LICENSE in the repository root for the full license text.
//================================================================================

#include <stdio.h>

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
 * @brief Reports a consumer integration test failure.
 *
 * @param[in] message Failure description.
 * @return Nonzero test exit code.
 */
static int fail(const char* message)
{
    fprintf(stderr, "%s\n", message);
    return 1;
}


/**
 * @brief Verifies the public API from a C consumer.
 *
 * @return Zero on success; otherwise nonzero.
 */
int main(void)
{
    MHOOK_STATUS status = getLastStatus();
    BOOL result = FALSE;

    // Verify that every public symbol remains available to C consumers.
    if (!setHook || !removeHook || !getTarget || !getLastStatus)
        return fail("one or more public Mhook symbols are unavailable");

    // Verify thread-local status initialization through the public API.
    if (status != MHOOK_STATUS_SUCCESS)
        return fail("initial Mhook status is not success");

    // Exercise the implementation without installing a hook.
    result = setHook(NULL, NULL);
    if (result)
        return fail("Mhook_SetHook accepted invalid arguments");

    status = getLastStatus();
    if (status != MHOOK_STATUS_INVALID_ARGUMENT)
        return fail("Mhook_SetHook did not store the expected status");

    return 0;
}
