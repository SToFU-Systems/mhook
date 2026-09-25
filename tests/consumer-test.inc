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

// Shared body of the consumer integration checks. Compiled once as C and once
// as C++ so the two languages cannot drift apart: the whole point of having
// both is to prove the public header serves both, which only holds if they
// assert the same things.
//
// Included twice on purpose by each wrapper, to prove the header's include
// guard works.

#include <stdio.h>
#include <string.h>

#include "mhook-lib/mhook.h"
#include "mhook-lib/mhook.h"

#ifdef _M_IX86_X64
#error mhook.h must not expose the private architecture macro
#endif

// Volatile function pointers, so the compiler cannot fold the availability
// checks away as trivially true.
static BOOL (*volatile setHook)(PVOID*, PVOID) = &Mhook_SetHook;
static BOOL (*volatile setHookBatch)(MHOOK_HOOK_INFO*, SIZE_T) = &Mhook_SetHookBatch;
static BOOL (*volatile removeHook)(PVOID*) = &Mhook_Unhook;
static BOOL (*volatile removeHookBatch)(MHOOK_HOOK_INFO*, SIZE_T) = &Mhook_UnhookBatch;
static PVOID (*volatile getTarget)(PVOID) = &Mhook_GetTarget;
static MHOOK_STATUS (*volatile getLastStatus)(void) = &Mhook_GetLastStatus;
static const char* (*volatile getVersion)(void) = &Mhook_GetVersion;
static BOOL (*volatile getPoolStatistics)(MHOOK_POOL_STATISTICS*) = &Mhook_GetPoolStatistics;
static BOOL (*volatile reclaimRetired)(void) = &Mhook_ReclaimRetired;

/**
 * @brief Reports a consumer integration test failure.
 *
 * @param[in] message Failure description.
 * @return Nonzero test exit code.
 */
static int mhookConsumerFail(const char* message)
{
    fprintf(stderr, "%s\n", message);
    return 1;
}

/**
 * @brief Verifies the public API from the including language.
 *
 * @return Zero on success; otherwise nonzero.
 */
static int mhookConsumerCheck(void)
{
    MHOOK_STATUS status = getLastStatus();
    BOOL result = FALSE;

    // Every public symbol must be reachable from this language.
    if (!setHook || !setHookBatch || !removeHook || !removeHookBatch || !getTarget || !getLastStatus || !getVersion ||
        !getPoolStatistics || !reclaimRetired)
        return mhookConsumerFail("one or more public Mhook symbols are unavailable");

    // The linked library must report the version its headers declare. They can
    // only disagree if a stale binary is being linked against fresh headers.
    if (strcmp(getVersion(), MHOOK_VERSION_STRING) != 0)
        return mhookConsumerFail("Mhook_GetVersion disagrees with MHOOK_VERSION_STRING");

    // Thread-local status must start out clean.
    if (status != MHOOK_STATUS_SUCCESS)
        return mhookConsumerFail("initial Mhook status is not success");

    // Exercise the implementation without installing a hook.
    result = setHook(NULL, NULL);
    if (result)
        return mhookConsumerFail("Mhook_SetHook accepted invalid arguments");

    status = getLastStatus();
    if (status != MHOOK_STATUS_INVALID_ARGUMENT)
        return mhookConsumerFail("Mhook_SetHook did not store the expected status");

    return 0;
}
