#include "relocation-test.h"

// Compile the existing engine into this white-box test translation unit.
#include "mhook-lib/src/mhook.c"

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
)
{
    if (!bytes || !byteCount || byteCount > MHOOKS_MAX_CODE_BYTES || !sourceAddress ||
        trampolineAddress < MHOOKS_TRAMPOLINE_OFFSET || !output || outputCapacity < MHOOKS_MAX_CODE_BYTES ||
        !instructionLength)
    {
        return MHOOK_STATUS_INVALID_ARGUMENT;
    }

    // Analyze a padded copy through the existing decoder and relocation collector.
    U8 snapshot[MHOOKS_MAX_CODE_BYTES] = {0};
    memcpy(snapshot, bytes, byteCount);

    MHOOKS_PATCHDATA patchData = {0};
    MHOOK_STATUS status =
        DisassembleAndSkip((PVOID)sourceAddress, MHOOK_JMPSIZE, snapshot, byteCount, &patchData, instructionLength);
    if (status != MHOOK_STATUS_SUCCESS)
        return status;

    // Simulate the reserved slot and replacement address without allocating code memory.
    HookEntry trampoline = {0};
    trampoline.code = (PBYTE)(trampolineAddress - MHOOKS_TRAMPOLINE_OFFSET);
    const ULONG_PTR kHookAddressOffset = 0x100;
    buildHookCode(
        &trampoline,
        (PBYTE)sourceAddress,
        (PBYTE)(sourceAddress + kHookAddressOffset),
        snapshot,
        *instructionLength,
        &patchData
    );

    // Return the staged trampoline region as ordinary data.
    memcpy(output, trampoline.stagedCode + MHOOKS_TRAMPOLINE_OFFSET, MHOOKS_MAX_CODE_BYTES);
    return MHOOK_STATUS_SUCCESS;
}
