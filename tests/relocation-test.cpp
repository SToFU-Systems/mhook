#include <windows.h>
#include <stdio.h>
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <random>
#include "relocation-test.h"

#ifdef _M_X64
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

/**
 * @brief Tests random RIP-relative displacements.
 * @return Zero when relocation preserves every referenced address.
 */
static int caseRandomRipRelativeDisplacement(void)
{
    // MOV RAX, [RIP + disp32].
    std::array<uint8_t, 7> bytes = {0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00};
    std::array<uint8_t, 32> output = {};

    constexpr uint32_t kSeed = 25;
    std::mt19937 random(kSeed);

    // Keep every displacement valid after moving the instruction.
    constexpr int32_t kMinimumDisplacement = -0x10000000;
    constexpr int32_t kMaximumDisplacement = 0x10000000;
    std::uniform_int_distribution<int32_t> displacementDistribution(kMinimumDisplacement, kMaximumDisplacement);

    constexpr ULONG_PTR kSourceAddress = 0x10000000;
    constexpr ULONG_PTR kTrampolineAddress = 0x10001000;
    constexpr uint32_t kSampleCount = 10000;
    for (uint32_t sample = 0; sample < kSampleCount; ++sample)
    {
        const int32_t displacement = displacementDistribution(random);
        std::memcpy(bytes.data() + 3, &displacement, sizeof(displacement));

        // Relocate the instruction through the existing engine.
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
            fprintf(stderr, "seed %u, sample %u returned status=%d\n", kSeed, sample, static_cast<int>(status));
            return 1;
        }

        // Compare the referenced address before and after relocation.
        int32_t relocatedDisplacement = 0;
        std::memcpy(&relocatedDisplacement, output.data() + 3, sizeof(relocatedDisplacement));

        const int64_t originalTarget = static_cast<int64_t>(kSourceAddress + bytes.size()) + displacement;
        const int64_t relocatedTarget = static_cast<int64_t>(kTrampolineAddress + bytes.size()) + relocatedDisplacement;
        if (relocatedTarget != originalTarget)
        {
            fprintf(stderr, "seed %u, sample %u changed the RIP-relative target\n", kSeed, sample);
            return 1;
        }
    }

    return 0;
}
#endif

/**
 * @brief Tests random bytes through analysis and relocation staging.
 * @return Zero when every accepted input produces a valid resume jump.
 */
static int caseRandomRelocationPipeline(void)
{
    // Generate reproducible prologue samples.
    constexpr uint32_t kSeed = 25;
    std::mt19937 random(kSeed);
    std::array<uint8_t, 32> bytes = {};
    std::array<uint8_t, 32> output = {};

    constexpr ULONG_PTR kSourceAddress = 0x10000000;
    constexpr ULONG_PTR kTrampolineAddress = 0x10001000;
    constexpr uint32_t kSampleCount = 10000;
    uint32_t stagedSampleCount = 0;

    for (uint32_t sample = 0; sample < kSampleCount; ++sample)
    {
        std::generate(bytes.begin(), bytes.end(), [&random] { return static_cast<uint8_t>(random()); });

        // Continue into relocation only when analysis accepts the sample.
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
            continue;

        ++stagedSampleCount;

        // JMP rel32 must return to the first instruction not copied.
        constexpr uint8_t kJumpOpcode = 0xE9;
        constexpr size_t kRelativeJumpSize = 5;
        if (instructionLength + kRelativeJumpSize > output.size() || output[instructionLength] != kJumpOpcode)
        {
            fprintf(stderr, "seed %u, sample %u produced an invalid resume jump\n", kSeed, sample);
            return 1;
        }

        int32_t displacement = 0;
        std::memcpy(&displacement, output.data() + instructionLength + 1, sizeof(displacement));

        const int64_t resumeAddress =
            static_cast<int64_t>(kTrampolineAddress + instructionLength + kRelativeJumpSize) + displacement;
        const int64_t expectedAddress = static_cast<int64_t>(kSourceAddress + instructionLength);
        if (resumeAddress != expectedAddress)
        {
            fprintf(
                stderr,
                "seed %u, sample %u produced resume address=%llx\n",
                kSeed,
                sample,
                static_cast<unsigned long long>(resumeAddress)
            );
            return 1;
        }
    }

    // Ensure the deterministic input exercised relocation staging.
    if (!stagedSampleCount)
    {
        fprintf(stderr, "seed %u produced no accepted prologues\n", kSeed);
        return 1;
    }

    return 0;
}

/**
 * @brief Runs relocation staging checks.
 * @return Zero when every relocation check passes.
 */
int main(void)
{
#ifdef _M_X64
    if (caseRipRelativeLoadRelocation() != 0)
        return 1;
    if (caseRandomRipRelativeDisplacement() != 0)
        return 1;
#endif
    if (caseRandomRelocationPipeline() != 0)
        return 1;

    puts("Relocation checks passed.");
    return 0;
}
