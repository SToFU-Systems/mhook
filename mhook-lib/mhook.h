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

/**
 * @file
 * @brief Public interface of the Mhook function hooking library.
 *
 * A hook overwrites the start of the target's prologue with a jump, and moves
 * the displaced instructions into a trampoline that jumps back to the rest of
 * the function, so the replacement can still call the code it replaced.
 *
 * All entry points serialise on one process wide lock. Installing and removing
 * a hook suspends the other threads of the process for the duration.
 */

#include <windows.h>

#ifdef __cplusplus
extern "C"
{
#endif //__cplusplus

/**
 * @brief Identifies the detailed result of a hook operation.
 *
 * Mhook_SetHook() and Mhook_Unhook() store one of these values for the calling
 * thread. The value describes the first detected internal failure unless a
 * later failure determines that the operation itself cannot complete.
 *
 */
typedef enum MHOOK_STATUS
{
    /** No monitored operation reported a failure. */
    MHOOK_STATUS_SUCCESS = 0,

    /** A required pointer or pointed-to address was NULL. */
    MHOOK_STATUS_INVALID_ARGUMENT = 1,

    /** The target prologue could not be decoded. */
    MHOOK_STATUS_DECODE_FAILED = 2,

    /** The decoded prologue cannot hold a supported patch. */
    MHOOK_STATUS_UNSUPPORTED_PROLOGUE = 3,

    /** No suitable trampoline could be allocated. */
    MHOOK_STATUS_TRAMPOLINE_ALLOCATION_FAILED = 4,

    /** A required memory-protection change failed. */
    MHOOK_STATUS_MEMORY_PROTECTION_FAILED = 5,

    /** The supplied trampoline does not identify an active hook. */
    MHOOK_STATUS_HOOK_NOT_FOUND = 6,

    /** Thread enumeration, inspection, or suspension failed. */
    MHOOK_STATUS_THREAD_SUSPENSION_FAILED = 7,

    /** An instruction-cache flush for modified code failed. */
    MHOOK_STATUS_PATCH_FAILED = 8
} MHOOK_STATUS;


/**
 * @name Error codes reported through GetLastError()
 * The values sit in the range Windows reserves for application defined codes.
 * @{
 */

 /** The pointer does not name a hook that is currently installed. */
#define MHOOK_ERROR_NOT_HOOKED      ((DWORD)((1UL << 29) | 1UL))

/** Another writer has patched the target since. See Mhook_Unhook(). */
#define MHOOK_ERROR_TARGET_MODIFIED ((DWORD)((1UL << 29) | 2UL))

/** @} */

/**
 * @brief Installs a hook, redirecting a function to a replacement.
 *
 * Both addresses are followed through jump thunks first, so hooking an import
 * stub hooks the function behind it.
 *
 * @param[in,out] ppSystemFunction On entry the function to hook. On success,
 *        receives the trampoline: call it to reach the original, and pass it to
 *        Mhook_Unhook() and Mhook_GetTarget(). Unchanged on failure.
 * @param[in]     pHookFunction    Replacement, with the same calling convention
 *        and signature as the target.
 * @return TRUE if the hook was installed.
 *
 * @note Fails if the prologue does not decode into at least five bytes of whole
 *       instructions, and does not report a reason through GetLastError().
 */
BOOL Mhook_SetHook(PVOID *ppSystemFunction, PVOID pHookFunction);


/**
 * @brief Removes a hook and restores the bytes it overwrote.
 *
 * Restores only if the prologue still holds exactly the patch this hook
 * installed. Otherwise another writer has patched the same code since, and
 * nothing is written, so their work is not destroyed.
 *
 * The hook then stays installed, because Mhook holds the only copy of the
 * original bytes. Retry once the other writer puts Mhook's patch back, or leave
 * the hook in place. Mhook_GetTarget() names the contested address.
 *
 * @param[in,out] ppHookedFunction The trampoline from Mhook_SetHook(). On
 *        success receives the original function address; unchanged on any
 *        failure, so a refused call can be retried with the same pointer.
 * @return TRUE if the original bytes were restored.
 * @retval FALSE GetLastError() is MHOOK_ERROR_TARGET_MODIFIED,
 *         MHOOK_ERROR_NOT_HOOKED, or the code from the failed VirtualProtect.
 *
 * @warning The trampoline is not freed, since a thread may still be running in
 *          it, but it must not be called once this returns TRUE.
 */
BOOL Mhook_Unhook(PVOID *ppHookedFunction);


/**
 * @brief Reports which address an installed hook patched.
 *
 * The way to learn which address is contested after Mhook_Unhook() refuses.
 *
 * @param[in] pHookedFunction The trampoline from Mhook_SetHook().
 * @return The patched address, or NULL with MHOOK_ERROR_NOT_HOOKED if the
 *         pointer names no installed hook.
 *
 * @note This is the address after jump thunks were followed, not necessarily
 *       the one handed to Mhook_SetHook().
 */
PVOID Mhook_GetTarget(PVOID pHookedFunction);


/**
 * @brief Returns the detailed status of the calling thread's most recent hook
 *        installation or removal.
 *
 * Each thread owns an independent status initialized to MHOOK_STATUS_SUCCESS.
 * Reading the value does not clear it. The next Mhook_SetHook() or
 * Mhook_Unhook() call on the same thread replaces it, so callers that need a
 * diagnostic should retrieve it immediately after the operation.
 *
 * @return One of the MHOOK_STATUS values describing the latest operation on
 *         the calling thread.
 */
MHOOK_STATUS Mhook_GetLastStatus(void);

#ifdef __cplusplus
}
#endif //__cplusplus
