#pragma once

#include <windows.h>
#include <stdint.h>
#include <mhook-lib/mhook.h>

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * @brief Builds staged hook code with simulated addresses and data storage.
 * @param[in] bytes Prologue bytes supplied to the existing engine.
 * @param[in] byteCount Number of supplied prologue bytes.
 * @param[in] sourceAddress Simulated execution address of bytes.
 * @param[in] trampolineAddress Simulated execution address of the relocated prologue.
 * @param[out] output Data storage receiving the relocated prologue and jump back.
 * @param[in] outputCapacity Number of writable bytes in output.
 * @param[out] instructionLength Number of complete prologue bytes relocated.
 * @return Status returned by the existing prologue analysis path.
 */
MHOOK_STATUS stageHookCodeForTest(
    const uint8_t* bytes,
    SIZE_T byteCount,
    ULONG_PTR sourceAddress,
    ULONG_PTR trampolineAddress,
    OUT uint8_t* output,
    SIZE_T outputCapacity,
    OUT DWORD* instructionLength
);

#ifdef __cplusplus
}
#endif
