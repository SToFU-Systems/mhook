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
// Copyright (C) 2002, Matt Conover (mconover@gmail.com)
//================================================================================

#ifndef MISC_H
#define MISC_H
#ifdef __cplusplus
extern "C"
{
#endif

#include <windows.h>
#include <stdio.h>
#include <stdarg.h>
#include <assert.h>

/** Returns the smaller of two values. */
#define MIN(a, b) ((a) < (b) ? (a) : (b))
/** Returns the larger of two values. */
#define MAX(a, b) ((a) > (b) ? (a) : (b))

/**
 * @brief Tests whether @p x falls within [@p s, @p e).
 *
 * The end is exclusive, i.e. start <= x < end, except when @p s and @p e are
 * themselves equal: then @p x must equal that shared value.
 */
#define IS_IN_RANGE(x, s, e)                                                                                           \
    (((ULONG_PTR)(x) == (ULONG_PTR)(s) && (ULONG_PTR)(x) == (ULONG_PTR)(e)) ||                                         \
     ((ULONG_PTR)(x) >= (ULONG_PTR)(s) && (ULONG_PTR)(x) < (ULONG_PTR)(e)))

#if defined(_WIN64)
/** Highest address IS_VALID_ADDRESS() accepts; Win64 specific. */
#define VALID_ADDRESS_MAX 0x7FFEFFFFFFFFFFFF // Win64 specific
/** Unsigned integer wide enough to hold a pointer, 64-bit build. */
typedef unsigned __int64 ULONG_PTR, *PULONG_PTR;
#else
/** Highest address IS_VALID_ADDRESS() accepts; Win32 specific. */
#define VALID_ADDRESS_MAX 0x7FFEFFFF // Win32 specific
/** Unsigned integer wide enough to hold a pointer, 32-bit build. */
typedef unsigned long ULONG_PTR, *PULONG_PTR;
#endif

#ifndef DECLSPEC_ALIGN
#if (_MSC_VER >= 1300) && !defined(MIDL_PASS)
/** Fallback alignment attribute, for SDK headers that do not already define it. */
#define DECLSPEC_ALIGN(x) __declspec(align(x))
#else
/** Fallback alignment attribute (no-op) for compilers without an equivalent. */
#define DECLSPEC_ALIGN(x)
#endif
#endif

/** Lowest valid address (Win32 specific). */
#define VALID_ADDRESS_MIN 0x10000 // Win32 specific
/** Tests whether @p a lies within the valid user-mode address range for the current pointer size. */
#define IS_VALID_ADDRESS(a) IS_IN_RANGE(a, VALID_ADDRESS_MIN, VALID_ADDRESS_MAX + 1)

/**
 * @brief Tests whether a byte is an ASCII hex digit.
 * @param[in] ch Byte to test.
 * @return TRUE for '0'-'9', 'A'-'F', or 'a'-'f'; FALSE otherwise.
 */
BOOL IsHexChar(BYTE ch);

/**
 * @brief Parses a hex-string byte pattern into a newly allocated byte buffer.
 *
 * Accepts three input forms: space-separated pairs (e.g. "AA BB CC"),
 * C-style escapes (e.g. "\xAA\x00BB"), and a contiguous string of hex
 * digit pairs (e.g. "AABBCC"). A leading/trailing quote and leading
 * whitespace are tolerated.
 *
 * @param[in]  Input        Hex-string to parse; not required to be
 *             null-terminated within InputLength, but must be readable for
 *             the calls this function makes into the C string functions.
 * @param[in]  InputLength  Number of characters in Input to consider.
 * @param[out] OutputLength Set to the number of bytes decoded, or 0 on failure.
 * @return Newly allocated buffer holding the decoded bytes, or NULL if
 *         InputLength or OutputLength is missing, or the input is empty or
 *         malformed. The caller must free() the returned buffer.
 */
BYTE* HexToBinary(char* Input, DWORD InputLength, DWORD* OutputLength);

#ifdef __cplusplus
}
#endif
#endif // MISC_H
