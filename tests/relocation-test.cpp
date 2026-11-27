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
 * @brief Stores the staged trampoline bytes returned by the relocation engine.
 */
using RelocationOutput = std::array<uint8_t, 32>;

/**
 * @brief Checks that staged code resumes at the first source byte not relocated.
 * @param[in] output Staged trampoline bytes.
 * @param[in] instructionLength Number of source bytes relocated.
 * @param[in] sourceAddress Simulated source address.
 * @param[in] trampolineAddress Simulated trampoline address.
 * @return True when the staged relative jump reaches the expected source address.
 */
static bool hasExpectedResumeJump(
    const RelocationOutput& output,
    DWORD instructionLength,
    ULONG_PTR sourceAddress,
    ULONG_PTR trampolineAddress
)
{
    constexpr uint8_t kJumpOpcode = 0xE9;
    constexpr size_t kJumpSize = 5;
    if (instructionLength + kJumpSize > output.size() || output[instructionLength] != kJumpOpcode)
        return false;

    // Resolve the staged displacement from its simulated execution address.
    int32_t displacement = 0;
    std::memcpy(&displacement, output.data() + instructionLength + 1, sizeof(displacement));
    const int64_t resumeAddress =
        static_cast<int64_t>(trampolineAddress + instructionLength + kJumpSize) + displacement;
    const int64_t expectedAddress = static_cast<int64_t>(sourceAddress + instructionLength);
    return resumeAddress == expectedAddress;
}

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

#ifdef _M_IX86
/**
 * @brief Tests that x86 relocation copies complete instructions before resuming.
 * @return Zero when both complete instructions and the resume jump are staged correctly.
 */
static int caseX86WholeInstructionRelocation(void)
{
    constexpr ULONG_PTR kSourceAddress = 0x10000000;
    constexpr ULONG_PTR kTrampolineAddress = 0x10001000;
    constexpr DWORD kExpectedInstructionLength = 6;

    // PUSHAD; ADD EAX, 1; POPAD; RET.
    constexpr std::array<uint8_t, 8> bytes = {0x60, 0x05, 0x01, 0x00, 0x00, 0x00, 0x61, 0xC3};
    RelocationOutput output = {};
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
        fprintf(stderr, "x86 whole-instruction relocation returned status=%d\n", static_cast<int>(status));
        return 1;
    }

    // The five-byte patch span must include the complete five-byte ADD instruction.
    if (instructionLength != kExpectedInstructionLength)
    {
        fprintf(
            stderr,
            "x86 relocation copied %lu bytes instead of %lu\n",
            static_cast<unsigned long>(instructionLength),
            static_cast<unsigned long>(kExpectedInstructionLength)
        );
        return 1;
    }
    if (!std::equal(bytes.begin(), bytes.begin() + instructionLength, output.begin()))
    {
        fprintf(stderr, "x86 relocation changed the copied instructions\n");
        return 1;
    }
    if (!hasExpectedResumeJump(output, instructionLength, kSourceAddress, kTrampolineAddress))
    {
        fprintf(stderr, "x86 relocation produced an invalid resume jump\n");
        return 1;
    }

    return 0;
}
#endif

#ifdef _M_X64
constexpr size_t kRipRelativeCaseSize = 9;

/**
 * @brief Describes one supported RIP-relative instruction sequence.
 */
struct RipRelativeCase
{
    const char* name;
    size_t byteCount;
    size_t instructionOffset;
    DWORD instructionLength;
    std::array<uint8_t, kRipRelativeCaseSize> bytes;
};

/**
 * @brief Checks one structured RIP-relative relocation case.
 * @param[in] test Structured instruction bytes and expected copied span.
 * @return Zero when relocation preserves the instruction target and resume address.
 */
static int checkRipRelativeCase(const RipRelativeCase& test)
{
    constexpr ULONG_PTR kSourceAddress = 0x10000000;
    constexpr ULONG_PTR kTrampolineAddress = 0x10001000;
    constexpr size_t kInstructionSize = 7;
    constexpr size_t kDisplacementOffset = 3;
    constexpr size_t kReferencedDataOffset = 16;

    RelocationOutput output = {};
    DWORD instructionLength = 0;
    const MHOOK_STATUS status = stageHookCodeForTest(
        test.bytes.data(),
        test.byteCount,
        kSourceAddress,
        kTrampolineAddress,
        output.data(),
        output.size(),
        &instructionLength
    );
    if (status != MHOOK_STATUS_SUCCESS)
    {
        fprintf(stderr, "%s returned status=%d\n", test.name, static_cast<int>(status));
        return 1;
    }

    // Check the copied span and every opcode byte before the adjusted displacement.
    const size_t displacementOffset = test.instructionOffset + kDisplacementOffset;
    if (instructionLength != test.instructionLength)
    {
        fprintf(stderr, "%s copied an unexpected instruction span\n", test.name);
        return 1;
    }
    if (!std::equal(test.bytes.begin(), test.bytes.begin() + displacementOffset, output.begin()))
    {
        fprintf(stderr, "%s changed bytes outside the RIP-relative displacement\n", test.name);
        return 1;
    }

    // Resolve the adjusted displacement and compare it with the fixture's data address.
    int32_t relocatedDisplacement = 0;
    std::memcpy(&relocatedDisplacement, output.data() + displacementOffset, sizeof(relocatedDisplacement));
    const int64_t relocatedTarget =
        static_cast<int64_t>(kTrampolineAddress + test.instructionOffset + kInstructionSize) + relocatedDisplacement;
    const int64_t expectedTarget = static_cast<int64_t>(kSourceAddress + kReferencedDataOffset);
    if (relocatedTarget != expectedTarget)
    {
        fprintf(stderr, "%s changed the RIP-relative target\n", test.name);
        return 1;
    }
    if (!hasExpectedResumeJump(output, instructionLength, kSourceAddress, kTrampolineAddress))
    {
        fprintf(stderr, "%s produced an invalid resume jump\n", test.name);
        return 1;
    }

    return 0;
}

/**
 * @brief Tests structured RIP-relative loads, stores, and address calculations.
 * @return Zero when every supported instruction shape relocates correctly.
 */
static int caseRipRelativeInstructionRelocation(void)
{
    constexpr RipRelativeCase kCases[] = {
        // MOV RAX, [RIP + 9].
        {"load at entry", 7, 0, 7, {0x48, 0x8B, 0x05, 0x09, 0x00, 0x00, 0x00}},
        // XOR EAX, EAX; MOV RAX, [RIP + 7].
        {"load after xor", 9, 2, 9, {0x33, 0xC0, 0x48, 0x8B, 0x05, 0x07, 0x00, 0x00, 0x00}},
        // MOV [RIP + 9], RAX.
        {"store at entry", 7, 0, 7, {0x48, 0x89, 0x05, 0x09, 0x00, 0x00, 0x00}},
        // LEA RAX, [RIP + 9].
        {"lea at entry", 7, 0, 7, {0x48, 0x8D, 0x05, 0x09, 0x00, 0x00, 0x00}},
    };

    for (const RipRelativeCase& test : kCases)
        if (checkRipRelativeCase(test) != 0)
            return 1;

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

    RelocationOutput output = {};
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
 * @brief Tests rejection of control transfers inside the relocated prologue span.
 * @return Zero when every unsupported instruction shape returns its explicit status.
 */
static int caseUnsupportedControlTransferRelocation(void)
{
    constexpr ULONG_PTR kSourceAddress = 0x10000000;
    constexpr ULONG_PTR kTrampolineAddress = 0x10001000;

    struct PrologueCase
    {
        const char* name;
        std::array<uint8_t, 8> bytes;
    };

    constexpr PrologueCase kCases[] = {
        // NOP; CALL +1; RET; RET.
        {"relative call", {0x90, 0xE8, 0x01, 0x00, 0x00, 0x00, 0xC3, 0xC3}},
        // NOP; JMP +1; NOP; RET.
        {"unconditional jump", {0x90, 0xE9, 0x01, 0x00, 0x00, 0x00, 0x90, 0xC3}},
        // NOP; JNE +4; 4 NOPs; RET.
        {"conditional jump", {0x90, 0x75, 0x04, 0x90, 0x90, 0x90, 0x90, 0xC3}},
    };

    for (const PrologueCase& test : kCases)
    {
        RelocationOutput output = {};
        DWORD instructionLength = 0;
        const MHOOK_STATUS status = stageHookCodeForTest(
            test.bytes.data(),
            test.bytes.size(),
            kSourceAddress,
            kTrampolineAddress,
            output.data(),
            output.size(),
            &instructionLength
        );
        if (status != MHOOK_STATUS_UNSUPPORTED_PROLOGUE)
        {
            fprintf(stderr, "%s returned status=%d\n", test.name, static_cast<int>(status));
            return 1;
        }
    }

    return 0;
}

/**
 * @brief Checks one input through prologue analysis and relocation staging.
 * @param[in] input Saved prologue bytes.
 * @return Rejected, staged, or failed invariant result.
 */
static RelocationCheckResult checkRelocationPipeline(const ReplayInput& input)
{
    constexpr ULONG_PTR kSourceAddress = 0x10000000;
    constexpr ULONG_PTR kTrampolineAddress = 0x10001000;

    RelocationOutput output = {};
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

    // Accepted prologues must resume at the first source byte not copied.
    if (!hasExpectedResumeJump(output, instructionLength, kSourceAddress, kTrampolineAddress))
    {
        fprintf(stderr, "relocation produced an invalid resume jump\n");
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
    if (caseRipRelativeInstructionRelocation() != 0)
        return 1;
    if (caseRandomRipRelativeDisplacement(arguments[0]) != 0)
        return 1;
#elif defined _M_IX86
    if (caseX86WholeInstructionRelocation() != 0)
        return 1;
#endif
    if (caseUnsupportedControlTransferRelocation() != 0)
        return 1;
    if (caseRandomRelocationPipeline(arguments[0]) != 0)
        return 1;

    puts("Relocation checks passed.");
    return 0;
}
