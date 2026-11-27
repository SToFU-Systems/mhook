#include <windows.h>
#include <stdio.h>
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <random>
#include "fuzz-replay.h"
#include "relocation-test.h"

/**
 * @brief Describes the outcome of one relocation-pipeline input.
 */
enum class RelocationCheckResult
{
    Rejected,
    Staged,
    Failed
};

/**
 * @brief Returns the architecture compiled into the relocation test.
 * @return Current replay architecture.
 */
static ReplayArchitecture currentReplayArchitecture(void)
{
#if defined _M_IX86
    return ReplayArchitecture::X86;
#elif defined _M_X64
    return ReplayArchitecture::X64;
#else
#error unsupported platform
#endif
}

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
 * @brief Checks one RIP-relative input after relocation.
 * @param[in] input Saved instruction bytes.
 * @return True when relocation preserves the referenced address.
 */
static bool checkRipRelativeRelocation(const ReplayInput& input)
{
    constexpr ULONG_PTR kSourceAddress = 0x10000000;
    constexpr ULONG_PTR kTrampolineAddress = 0x10001000;

    std::array<uint8_t, 32> output = {};
    DWORD instructionLength = 0;
    const MHOOK_STATUS status = stageHookCodeForTest(
        input.bytes.data(),
        input.byteCount,
        kSourceAddress,
        kTrampolineAddress,
        output.data(),
        output.size(),
        &instructionLength
    );
    if (status != MHOOK_STATUS_SUCCESS)
    {
        fprintf(stderr, "RIP-relative relocation returned status=%d\n", static_cast<int>(status));
        return false;
    }

    // Compare the referenced address before and after relocation.
    int32_t originalDisplacement = 0;
    std::memcpy(&originalDisplacement, input.bytes.data() + 3, sizeof(originalDisplacement));

    int32_t relocatedDisplacement = 0;
    std::memcpy(&relocatedDisplacement, output.data() + 3, sizeof(relocatedDisplacement));

    const int64_t originalTarget = static_cast<int64_t>(kSourceAddress + input.byteCount) + originalDisplacement;
    const int64_t relocatedTarget = static_cast<int64_t>(kTrampolineAddress + input.byteCount) + relocatedDisplacement;
    if (relocatedTarget != originalTarget)
    {
        fprintf(stderr, "RIP-relative relocation changed the referenced address\n");
        return false;
    }

    return true;
}

/**
 * @brief Tests random RIP-relative displacements.
 * @param[in] executablePath Test executable used for replay output.
 * @return Zero when relocation preserves every referenced address.
 */
static int caseRandomRipRelativeDisplacement(const char* executablePath)
{
    // MOV RAX, [RIP + disp32].
    ReplayInput input = {};
    input.target = ReplayTarget::RipRelativeRelocation;
    input.architecture = ReplayArchitecture::X64;
    input.byteCount = 7;
    input.bytes = {0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00};

    constexpr uint32_t kSeed = 25;
    std::mt19937 random(kSeed);

    // Keep every displacement valid after moving the instruction.
    constexpr int32_t kMinimumDisplacement = -0x10000000;
    constexpr int32_t kMaximumDisplacement = 0x10000000;
    std::uniform_int_distribution<int32_t> displacementDistribution(kMinimumDisplacement, kMaximumDisplacement);

    // Keep the exact current sample available if relocation crashes or hangs.
    const std::filesystem::path replayPath = makeSnapshotPath("relocation", "mhook-relocation");
    fprintf(stderr, "relocation replay: & \"%s\" --replay \"%s\"\n", executablePath, replayPath.string().c_str());
    fflush(stderr);

    constexpr uint32_t kSampleCount = 10000;
    {
        FuzzSnapshot snapshot(replayPath, input.target, input.architecture);
        for (uint32_t sample = 0; sample < kSampleCount; ++sample)
        {
            const int32_t displacement = displacementDistribution(random);
            std::memcpy(input.bytes.data() + 3, &displacement, sizeof(displacement));

            const bool saved = snapshot.saveSnapshot(input.bytes, input.byteCount);
            if (!saved)
            {
                fprintf(stderr, "could not save RIP-relative snapshot\n");
                return 1;
            }

            const bool valid = checkRipRelativeRelocation(input);
            if (!valid)
            {
                fprintf(
                    stderr,
                    "seed %u, sample %u; replay with & \"%s\" --replay \"%s\"\n",
                    kSeed,
                    sample,
                    executablePath,
                    replayPath.string().c_str()
                );
                return 1;
            }
        }
    }

    std::error_code removeError = {};
    const bool removed = std::filesystem::remove(replayPath, removeError);
    if (!removed || removeError)
    {
        fprintf(stderr, "could not remove RIP-relative snapshot\n");
        return 1;
    }

    return 0;
}
#endif

/**
 * @brief Checks one input through prologue analysis and relocation staging.
 * @param[in] input Saved prologue bytes.
 * @return Rejected, staged, or failed invariant result.
 */
static RelocationCheckResult checkRelocationPipeline(const ReplayInput& input)
{
    constexpr ULONG_PTR kSourceAddress = 0x10000000;
    constexpr ULONG_PTR kTrampolineAddress = 0x10001000;

    std::array<uint8_t, 32> output = {};
    DWORD instructionLength = 0;
    const MHOOK_STATUS status = stageHookCodeForTest(
        input.bytes.data(),
        input.byteCount,
        kSourceAddress,
        kTrampolineAddress,
        output.data(),
        output.size(),
        &instructionLength
    );
    if (status != MHOOK_STATUS_SUCCESS)
        return RelocationCheckResult::Rejected;

    // JMP rel32 must return to the first instruction not copied.
    constexpr uint8_t kJumpOpcode = 0xE9;
    constexpr size_t kRelativeJumpSize = 5;
    if (instructionLength + kRelativeJumpSize > output.size() || output[instructionLength] != kJumpOpcode)
    {
        fprintf(stderr, "relocation produced an invalid resume jump\n");
        return RelocationCheckResult::Failed;
    }

    int32_t displacement = 0;
    std::memcpy(&displacement, output.data() + instructionLength + 1, sizeof(displacement));

    const int64_t resumeAddress =
        static_cast<int64_t>(kTrampolineAddress + instructionLength + kRelativeJumpSize) + displacement;
    const int64_t expectedAddress = static_cast<int64_t>(kSourceAddress + instructionLength);
    if (resumeAddress != expectedAddress)
    {
        fprintf(stderr, "relocation produced resume address=%llx\n", static_cast<unsigned long long>(resumeAddress));
        return RelocationCheckResult::Failed;
    }

    return RelocationCheckResult::Staged;
}

/**
 * @brief Tests random bytes through analysis and relocation staging.
 * @param[in] executablePath Test executable used for replay output.
 * @return Zero when every accepted input produces a valid resume jump.
 */
static int caseRandomRelocationPipeline(const char* executablePath)
{
    // Generate reproducible prologue samples.
    constexpr uint32_t kSeed = 25;
    std::mt19937 random(kSeed);

    ReplayInput input = {};
    input.target = ReplayTarget::RelocationPipeline;
    input.architecture = currentReplayArchitecture();
    input.byteCount = static_cast<uint8_t>(input.bytes.size());

    // Keep the exact current sample available if relocation crashes or hangs.
    const std::filesystem::path replayPath = makeSnapshotPath("relocation", "mhook-relocation");
    fprintf(stderr, "relocation replay: & \"%s\" --replay \"%s\"\n", executablePath, replayPath.string().c_str());
    fflush(stderr);

    constexpr uint32_t kSampleCount = 10000;
    uint32_t stagedSampleCount = 0;
    {
        FuzzSnapshot snapshot(replayPath, input.target, input.architecture);
        for (uint32_t sample = 0; sample < kSampleCount; ++sample)
        {
            std::generate(input.bytes.begin(), input.bytes.end(), [&random] { return static_cast<uint8_t>(random()); });

            const bool saved = snapshot.saveSnapshot(input.bytes, input.byteCount);
            if (!saved)
            {
                fprintf(stderr, "could not save relocation snapshot\n");
                return 1;
            }

            const RelocationCheckResult result = checkRelocationPipeline(input);
            if (result == RelocationCheckResult::Failed)
            {
                fprintf(
                    stderr,
                    "seed %u, sample %u; replay with & \"%s\" --replay \"%s\"\n",
                    kSeed,
                    sample,
                    executablePath,
                    replayPath.string().c_str()
                );
                return 1;
            }
            if (result == RelocationCheckResult::Staged)
                ++stagedSampleCount;
        }
    }

    // Ensure the deterministic input exercised relocation staging.
    if (!stagedSampleCount)
    {
        std::error_code removeError = {};
        const bool removed = std::filesystem::remove(replayPath, removeError);
        if (!removed || removeError)
            fprintf(stderr, "could not remove relocation snapshot\n");
        fprintf(stderr, "seed %u produced no accepted prologues\n", kSeed);
        return 1;
    }

    std::error_code removeError = {};
    const bool removed = std::filesystem::remove(replayPath, removeError);
    if (!removed || removeError)
    {
        fprintf(stderr, "could not remove relocation snapshot\n");
        return 1;
    }

    return 0;
}

/**
 * @brief Loads and dispatches one saved relocation input.
 * @param[in] path Replay file path.
 * @return Zero when the saved input satisfies its original invariant.
 */
static int replaySavedInput(const std::filesystem::path& path)
{
    const std::optional<ReplayInput> input = loadSnapshot(path);
    if (!input)
    {
        fprintf(stderr, "could not load replay input %s\n", path.string().c_str());
        return 1;
    }
    if (input->architecture != currentReplayArchitecture())
    {
        fprintf(stderr, "relocation replay architecture does not match this build\n");
        return 1;
    }

    switch (input->target)
    {
    case ReplayTarget::RelocationPipeline:
        return checkRelocationPipeline(input.value()) == RelocationCheckResult::Failed ? 1 : 0;
#ifdef _M_X64
    case ReplayTarget::RipRelativeRelocation:
        return checkRipRelativeRelocation(input.value()) ? 0 : 1;
#endif
    default:
        fprintf(stderr, "replay input belongs to the decoder test\n");
        return 1;
    }
}

/**
 * @brief Runs relocation staging checks or replays one saved input.
 * @param[in] argumentCount Number of command-line arguments.
 * @param[in] arguments Command-line argument values.
 * @return Zero when every selected relocation check passes.
 */
int main(int argumentCount, char* arguments[])
{
    if (argumentCount == 3 && std::strcmp(arguments[1], "--replay") == 0)
        return replaySavedInput(arguments[2]);
    if (argumentCount != 1)
    {
        fprintf(stderr, "usage: %s [--replay case-file]\n", arguments[0]);
        return 1;
    }

#ifdef _M_X64
    if (caseRipRelativeLoadRelocation() != 0)
        return 1;
    if (caseRandomRipRelativeDisplacement(arguments[0]) != 0)
        return 1;
#endif
    if (caseRandomRelocationPipeline(arguments[0]) != 0)
        return 1;

    puts("Relocation checks passed.");
    return 0;
}
