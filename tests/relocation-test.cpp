#include <windows.h>
#include <stdio.h>
#include <array>
#include <cstdint>
#include <cstring>
#include "relocation-test.h"

/**
 * @brief Tests relocation of a RIP-relative load.
 * @return Zero when the staged instruction retains its original target.
 */
static int caseRipRelativeLoadRelocation(void)
{
    // MOV RAX, [RIP + 9] references address 0x10000010.
    constexpr ULONG_PTR kSourceAddress = 0x10000000;
    constexpr ULONG_PTR kExpectedTargetAddress = 0x10000010;
    constexpr std::array<uint8_t, 7> bytes = {0x48, 0x8B, 0x05, 0x09, 0x00, 0x00, 0x00};

    // Build the hook image using simulated addresses and ordinary data storage.
    constexpr ULONG_PTR kTrampolineAddress = 0x10001000;
    std::array<uint8_t, 32> output = {};
    DWORD instructionLength = 0;
    const MHOOK_STATUS status = stageHookCodeForTest(
        bytes.data(),
        bytes.size(),
        kSourceAddress,
        kTrampolineAddress,
        output.data(),
        output.size(),
        &instructionLength
    );
    if (status != MHOOK_STATUS_SUCCESS)
    {
        fprintf(stderr, "RIP-relative load relocation returned status=%d\n", static_cast<int>(status));
        return 1;
    }

    // Resolve the target represented by the relocated displacement.
    constexpr size_t kInstructionLength = 7;
    constexpr size_t kDisplacementOffset = 3;
    int32_t relocatedDisplacement = 0;
    std::memcpy(&relocatedDisplacement, output.data() + kDisplacementOffset, sizeof(relocatedDisplacement));

    const int64_t relocatedTargetAddress =
        static_cast<int64_t>(kTrampolineAddress + kInstructionLength) + relocatedDisplacement;
    if (relocatedTargetAddress != kExpectedTargetAddress)
    {
        fprintf(
            stderr,
            "RIP-relative load relocation produced target=%llx\n",
            static_cast<unsigned long long>(relocatedTargetAddress)
        );
        return 1;
    }

    return 0;
}

int main(void)
{
    if (caseRipRelativeLoadRelocation() != 0)
        return 1;

    puts("Relocation checks passed.");
    return 0;
}
