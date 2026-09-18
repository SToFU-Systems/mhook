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

    /** A required address is NULL, or the resolved target and replacement are identical. */
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
    MHOOK_STATUS_PATCH_FAILED = 8,

    /** Another writer modified the target after the hook was installed. */
    MHOOK_STATUS_TARGET_MODIFIED = 9,

    /** The caller's function-pointer slot is misaligned, unreadable, or unwritable. */
    MHOOK_STATUS_INVALID_DESCRIPTOR = 10,

    /** Executable code or an indirect jump's pointer slot cannot be read. */
    MHOOK_STATUS_INVALID_TARGET = 11,

    /** Following entry-point jumps encountered an address already visited. */
    MHOOK_STATUS_JUMP_CYCLE = 12,

    /** Following entry-point jumps exceeded the supported depth. */
    MHOOK_STATUS_JUMP_DEPTH_EXCEEDED = 13,

    /** A function-resolution chain reached a target with an active hook. */
    MHOOK_STATUS_ALREADY_HOOKED = 14
} MHOOK_STATUS;


/**
 * @brief Carries one hook request and its result through batch operations.
 *
 * Both batch APIs update the caller-owned function slot, so the same descriptor
 * array can install and later remove its hooks without being rebuilt.
 */
typedef struct MHOOK_HOOK_INFO
{
    /** Caller-owned slot that receives the trampoline or restored target. */
    PVOID* ppSystemFunction;

    /** Replacement used for installation and ignored during removal. */
    PVOID pHookFunction;

    /** Result written for this request by the most recent batch operation. */
    MHOOK_STATUS status;
} MHOOK_HOOK_INFO;


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
 * Both addresses are followed through up to 16 jump thunks first, so hooking
 * an import stub hooks the function behind it. Longer or cyclic chains are
 * rejected. Requests are also rejected when both chains resolve to the same
 * address or either chain reaches a target with an active hook.
 *
 * @param[in,out] ppSystemFunction On entry the function to hook. On success,
 *        receives the trampoline: call it to reach the original, and pass it to
 *        Mhook_Unhook() and Mhook_GetTarget(). Unchanged on failure.
 * @param[in]     pHookFunction    Replacement, with the same calling convention
 *        and signature as the target.
 * @return TRUE if the hook was installed. The caller's GetLastError value is
 *         preserved on both success and failure.
 *
 * @note Fails if the prologue does not decode into at least five bytes of whole
 *       instructions. Retrieve failure details with Mhook_GetLastStatus().
 */
BOOL Mhook_SetHook(PVOID *ppSystemFunction, PVOID pHookFunction);


/**
 * @brief Installs hook requests in order and reports every result.
 *
 * This initial batch API reuses the single-hook workflow to preserve its
 * validation and compatibility behavior. Requests are independent, so an
 * earlier success is not reverted when a later request fails.
 *
 * @param[in,out] hooks Requests to install and storage for their results.
 * @param[in]     hookCount Number of descriptors in hooks.
 * @return TRUE when every hook was installed; otherwise FALSE.
 */
BOOL Mhook_SetHookBatch(MHOOK_HOOK_INFO* hooks, SIZE_T hookCount);


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
 * @return TRUE if the original bytes were restored. On success, the caller's
 *         GetLastError value is preserved.
 * @retval FALSE Invalid arguments, descriptors, and inaccessible targets
 *         preserve GetLastError. Otherwise it is MHOOK_ERROR_TARGET_MODIFIED,
 *         MHOOK_ERROR_NOT_HOOKED, or the code from the failed VirtualProtect.
 *
 * @warning The trampoline is not freed, since a thread may still be running in
 *          it, but it must not be called once this returns TRUE.
 */
BOOL Mhook_Unhook(PVOID *ppHookedFunction);


/**
 * @brief Removes hook requests in order and reports every result.
 *
 * This initial batch API reuses the single-unhook workflow to preserve its
 * ownership checks and legacy error behavior. Requests are independent, so an
 * earlier removal is not reverted when a later request fails.
 *
 * @param[in,out] hooks Requests to remove and storage for their results.
 *        pHookFunction is ignored.
 * @param[in]     hookCount Number of descriptors in hooks.
 * @return TRUE when every hook was removed; otherwise FALSE.
 */
BOOL Mhook_UnhookBatch(MHOOK_HOOK_INFO* hooks, SIZE_T hookCount);


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
 * Reading the value does not clear it. The next set or unhook operation on the
 * same thread replaces it, so callers that need a diagnostic should retrieve
 * it immediately after the operation. For a batch operation, this reports the
 * overall result; each descriptor reports its own result through status.
 *
 * @return One of the MHOOK_STATUS values describing the latest operation on
 *         the calling thread.
 */
MHOOK_STATUS Mhook_GetLastStatus(void);

#ifdef __cplusplus
}
#endif //__cplusplus
