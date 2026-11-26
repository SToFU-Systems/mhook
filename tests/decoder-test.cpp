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

#include <windows.h>
#include <stdio.h>
#include <algorithm>
#include <array>
#include <cstdint>
#include <exception>
#include <memory>
#include <random>
#include "mhook-lib/mhook.h"
#include "disasm-lib/disasm.h"

extern "C" MHOOK_STATUS MhookAnalyzePrologue(const U8* bytes, SIZE_T byteCount, OUT DWORD* instructionLength);

static BOOL (*volatile set_hook)(PVOID*, PVOID) = &Mhook_SetHook;
static BOOL (*volatile remove_hook)(PVOID*) = &Mhook_Unhook;

/**
 * @brief Releases memory reserved by VirtualAlloc.
 * @param[in] memory Allocation base, or null.
 */
static void releaseVirtualAllocation(U8* memory)
{
    if (!memory)
        return;

    const BOOL released = VirtualFree(memory, 0, MEM_RELEASE);
    if (!released)
    {
        fprintf(stderr, "VirtualFree failed with error %lu\n", GetLastError());
        std::terminate();
    }
}

using VirtualAllocation = std::unique_ptr<U8, decltype(&releaseVirtualAllocation)>;

/**
 * @brief Allocates writable bytes directly before an inaccessible page.
 * @param[in] bufferSize Number of writable bytes exposed to the caller.
 * @param[out] buffer Start of the writable bytes.
 * @return Owned page allocation, or an empty allocation on failure.
 */
static VirtualAllocation allocateGuardedBuffer(SIZE_T bufferSize, OUT U8** buffer)
{
    *buffer = NULL;

    SYSTEM_INFO systemInfo = {};
    GetSystemInfo(&systemInfo);

    if (!bufferSize || bufferSize > systemInfo.dwPageSize)
    {
        fprintf(stderr, "invalid guarded buffer size\n");
        return VirtualAllocation(NULL, &releaseVirtualAllocation);
    }

    // Reserve one readable page followed by the inaccessible guard page.
    constexpr SIZE_T kPageCount = 2;
    const SIZE_T allocationSize = systemInfo.dwPageSize * kPageCount;
    U8* allocationBase = static_cast<U8*>(VirtualAlloc(NULL, allocationSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    VirtualAllocation allocation(allocationBase, &releaseVirtualAllocation);
    if (!allocation)
    {
        fprintf(stderr, "VirtualAlloc failed with error %lu\n", GetLastError());
        return allocation;
    }

    // Reject any access immediately beyond the exposed buffer.
    DWORD oldProtection = 0;
    const BOOL protectedPage =
        VirtualProtect(allocation.get() + systemInfo.dwPageSize, systemInfo.dwPageSize, PAGE_NOACCESS, &oldProtection);
    if (!protectedPage)
    {
        fprintf(stderr, "VirtualProtect failed with error %lu\n", GetLastError());
        return VirtualAllocation(NULL, &releaseVirtualAllocation);
    }

    *buffer = allocation.get() + systemInfo.dwPageSize - bufferSize;
    return allocation;
}

static bool CheckInstruction(ARCHITECTURE_TYPE architecture, U8* bytes, U32 length, INSTRUCTION_TYPE type)
{
    DISASSEMBLER decoder;
    if (!InitDisassembler(&decoder, architecture))
    {
        fprintf(stderr, "Decoder initialization failed for architecture %d\n", architecture);
        return false;
    }

    INSTRUCTION* instruction =
        GetInstruction(&decoder, (U64)(ULONG_PTR)bytes, bytes, DISASM_DECODE | DISASM_SUPPRESSERRORS);
    const bool valid =
        instruction && !instruction->ErrorOccurred && instruction->Length == length && instruction->Type == type;
    if (!valid)
    {
        fprintf(
            stderr,
            "Decode failed for architecture %d: expected length %lu, type %d\n",
            architecture,
            (unsigned long)length,
            type
        );
    }
    CloseDisassembler(&decoder);
    return valid;
}

/**
 * @brief Verifies that decoding from copied bytes preserves their represented virtual address.
 * @return True when a RIP-relative target is calculated from the virtual address.
 */
static bool CheckSnapshotVirtualAddress(void)
{
    const U64 kVirtualAddress = 0x10000000;
    const U64 kExpectedTargetAddress = 0x10000010;
    U8 bytes[32] = {0x48, 0x8B, 0x05, 0x09, 0x00, 0x00, 0x00};
    DISASSEMBLER decoder = {};
    if (!InitDisassembler(&decoder, ARCH_X64))
    {
        fprintf(stderr, "Decoder initialization failed for snapshot address test\n");
        return false;
    }

    INSTRUCTION* instruction = GetInstruction(&decoder, kVirtualAddress, bytes, DISASM_DECODE | DISASM_SUPPRESSERRORS);
    const U64 targetAddress =
        instruction ? instruction->Operands[1].TargetAddress + instruction->VirtualAddressDelta : 0;
    const bool valid = instruction && !instruction->ErrorOccurred && instruction->Length == 7 &&
                       instruction->Type == ITYPE_MOV && targetAddress == kExpectedTargetAddress;
    if (!valid)
        fprintf(stderr, "Snapshot decoding did not preserve the original virtual address\n");

    CloseDisassembler(&decoder);
    return valid;
}

/**
 * @brief Verifies that a general register encoded in ModRM.rm is decoded as that register.
 * @return True when "mov ebx, cr0" names EBX as its destination.
 */
static bool CheckModRmRegisterOperand(void)
{
    U8 bytes[32] = {0x0F, 0x20, 0xC3}; // mov ebx, cr0
    DISASSEMBLER decoder = {};
    if (!InitDisassembler(&decoder, ARCH_X86))
    {
        fprintf(stderr, "Decoder initialization failed for register operand test\n");
        return false;
    }

    INSTRUCTION* instruction =
        GetInstruction(&decoder, (U64)(ULONG_PTR)bytes, bytes, DISASM_DECODE | DISASM_SUPPRESSERRORS);
    const bool valid = instruction && !instruction->ErrorOccurred && instruction->Length == 3 &&
                       (instruction->Operands[0].Flags & OP_REG) && instruction->Operands[0].Register == X86_REG_EBX;
    if (!valid)
        fprintf(stderr, "ModRM.rm register operand was not decoded as EBX\n");

    CloseDisassembler(&decoder);
    return valid;
}

/**
 * @brief Verifies acceptance at the maximum instruction-length boundary.
 * @param[in] mode Decoder architecture to exercise.
 * @return True when the 15-byte prefix sequence decodes successfully.
 */
static bool checkMaximumPrefixSequenceLength(ARCHITECTURE_TYPE mode)
{
    constexpr size_t kMaximumInstructionLength = 15;
    constexpr U32 kDecodeFlags = DISASM_DECODE | DISASM_SUPPRESSERRORS;

    // NOP + 14 operand-size prefixes.
    constexpr U8 kOperandSizePrefix = 0x66;
    constexpr U8 kNop = 0x90;
    std::array<U8, kMaximumInstructionLength> bytes = {};
    std::fill_n(bytes.begin(), bytes.size() - 1, kOperandSizePrefix);
    bytes[kMaximumInstructionLength - 1] = kNop;

    DISASSEMBLER decoder = {};
    if (!InitDisassembler(&decoder, mode))
    {
        fprintf(stderr, "could not initialize decoder mode %d\n", static_cast<int>(mode));
        return false;
    }

    const U64 address = static_cast<U64>(reinterpret_cast<ULONG_PTR>(bytes.data()));
    const INSTRUCTION* instruction = GetInstruction(&decoder, address, bytes.data(), kDecodeFlags);
    const bool hasInstruction = instruction != nullptr;
    const bool hasNoError = hasInstruction && !instruction->ErrorOccurred;
    const bool hasExpectedLength = hasInstruction && instruction->Length == kMaximumInstructionLength;
    if (!hasInstruction || !hasNoError || !hasExpectedLength)
    {
        CloseDisassembler(&decoder);
        fprintf(
            stderr,
            "decoder mode %d failed the 15-byte prefix sequence: instruction=%d, error-free=%d, expected-length=%d\n",
            static_cast<int>(mode),
            hasInstruction,
            hasNoError,
            hasExpectedLength
        );
        return false;
    }

    CloseDisassembler(&decoder);
    return true;
}

/**
 * @brief Verifies that the decoder rejects an overlong instruction.
 */
static bool checkOverlongInstruction(ARCHITECTURE_TYPE mode)
{
    constexpr size_t kBufferSize = 32;
    constexpr size_t kMaxInstructionLength = 15;
    constexpr U8 kOperandSizePrefix = 0x66;
    constexpr U8 kNop = 0x90;

    std::array<U8, kBufferSize> bytes = {};
    std::fill_n(bytes.begin(), kMaxInstructionLength, kOperandSizePrefix);
    bytes[kMaxInstructionLength] = kNop;

    DISASSEMBLER decoder = {};
    if (!InitDisassembler(&decoder, mode))
    {
        fprintf(stderr, "could not initialize decoder mode %d\n", static_cast<int>(mode));
        return false;
    }

    const U64 address = static_cast<U64>(reinterpret_cast<ULONG_PTR>(bytes.data()));
    const bool rejected =
        GetInstruction(&decoder, address, bytes.data(), DISASM_DECODE | DISASM_SUPPRESSERRORS) == nullptr;
    if (!rejected)
        fprintf(stderr, "decoder mode %d accepted an overlong instruction\n", static_cast<int>(mode));

    CloseDisassembler(&decoder);
    return rejected;
}

/**
 * @brief Verifies decoder read and instruction-length bounds on random input.
 * @return Zero when both decoder modes stay within the 15-byte limit.
 */
static int caseRandomDecoderBounds(void)
{
    // Expose exactly one maximum-length instruction window.
    constexpr SIZE_T kMaximumInstructionLength = 15;
    U8* bytes = NULL;
    VirtualAllocation allocation = allocateGuardedBuffer(kMaximumInstructionLength, &bytes);
    if (!allocation)
        return 1;

    const U64 address = static_cast<U64>(reinterpret_cast<ULONG_PTR>(bytes));

    // Exercise identical random input sequences in both decoder modes.
    constexpr ARCHITECTURE_TYPE kModes[] = {ARCH_X86, ARCH_X64};
    for (const ARCHITECTURE_TYPE mode : kModes)
    {
        constexpr uint32_t kSeed = 25;
        std::mt19937 random(kSeed);

        DISASSEMBLER decoder = {};
        if (!InitDisassembler(&decoder, mode))
        {
            fprintf(stderr, "random decoder setup failed for mode %d\n", static_cast<int>(mode));
            return 1;
        }

        constexpr uint32_t kSampleCount = 10000;
        constexpr U32 kDecodeFlags = DISASM_DECODE | DISASM_SUPPRESSERRORS;
        for (uint32_t sample = 0; sample < kSampleCount; ++sample)
        {
            std::generate_n(bytes, kMaximumInstructionLength, [&random] { return static_cast<U8>(random()); });

            const INSTRUCTION* instruction = GetInstruction(&decoder, address, bytes, kDecodeFlags);
            if (!instruction || instruction->ErrorOccurred)
                continue;

            const bool hasNonzeroLength = instruction->Length != 0;
            const bool hasBoundedLength = instruction->Length <= kMaximumInstructionLength;
            if (!hasNonzeroLength || !hasBoundedLength)
            {
                CloseDisassembler(&decoder);
                fprintf(
                    stderr,
                    "mode %d, seed %u, sample %u: nonzero-length=%d, bounded-length=%d, length=%u\n",
                    static_cast<int>(mode),
                    kSeed,
                    sample,
                    hasNonzeroLength,
                    hasBoundedLength,
                    static_cast<unsigned>(instruction->Length)
                );
                return 1;
            }
        }

        CloseDisassembler(&decoder);
    }

    return 0;
}

/**
 * @brief Tests random prologue byte sequences.
 * @return Zero when every analysis returns a documented status and valid length.
 */
static int caseRandomPrologueAnalysis(void)
{
    // End every sample at the guard page so reading beyond byteCount fails.
    constexpr SIZE_T kMaximumPrologueSize = 32;
    U8* guardedBytes = NULL;
    VirtualAllocation allocation = allocateGuardedBuffer(kMaximumPrologueSize, &guardedBytes);
    if (!allocation)
        return 1;

    // Generate reproducible sample lengths and byte sequences.
    constexpr uint32_t kSeed = 25;
    std::mt19937 random(kSeed);
    std::uniform_int_distribution<SIZE_T> byteCountDistribution(1, kMaximumPrologueSize);

    constexpr uint32_t kSampleCount = 10000;
    for (uint32_t sample = 0; sample < kSampleCount; ++sample)
    {
        const SIZE_T byteCount = byteCountDistribution(random);
        U8* bytes = guardedBytes + kMaximumPrologueSize - byteCount;
        std::generate_n(bytes, byteCount, [&random] { return static_cast<U8>(random()); });

        // Accept only outcomes defined by prologue analysis.
        DWORD instructionLength = 0;
        const MHOOK_STATUS status = MhookAnalyzePrologue(bytes, byteCount, &instructionLength);
        if (status != MHOOK_STATUS_SUCCESS && status != MHOOK_STATUS_DECODE_FAILED &&
            status != MHOOK_STATUS_INVALID_TARGET && status != MHOOK_STATUS_UNSUPPORTED_PROLOGUE)
        {
            fprintf(
                stderr,
                "seed %u, sample %u returned undocumented status %d\n",
                kSeed,
                sample,
                static_cast<int>(status)
            );
            return 1;
        }

        // Reject reports that consume bytes outside the supplied sample.
        if (instructionLength > byteCount)
        {
            fprintf(
                stderr,
                "seed %u, sample %u consumed %lu of %llu supplied bytes\n",
                kSeed,
                sample,
                static_cast<unsigned long>(instructionLength),
                static_cast<unsigned long long>(byteCount)
            );
            return 1;
        }
    }

    return 0;
}

/**
 * @brief Verifies acceptance of exactly one five-byte patch span.
 * @return Zero when analysis succeeds and consumes the complete span.
 */
static int caseExactPrologueSpan(void)
{
    // 5 NOPs fill the jump patch.
    constexpr U8 kNop = 0x90;
    std::array<U8, 5> bytes = {};
    bytes.fill(kNop);

    DWORD instructionLength = 0;
    const MHOOK_STATUS status = MhookAnalyzePrologue(bytes.data(), bytes.size(), &instructionLength);

    if (status != MHOOK_STATUS_SUCCESS || instructionLength != static_cast<DWORD>(bytes.size()))
    {
        fprintf(
            stderr,
            "exact prologue span failed: status=%d, length=%lu\n",
            static_cast<int>(status),
            static_cast<unsigned long>(instructionLength)
        );
        return 1;
    }

    return 0;
}

/**
 * @brief Verifies rejection of a prologue shorter than the jump patch.
 * @return Zero when analysis reports an invalid target.
 */
static int caseShortPrologueSpan(void)
{
    // 4 NOPs are one byte short of the jump patch.
    constexpr U8 kNop = 0x90;
    std::array<U8, 4> bytes = {};
    bytes.fill(kNop);

    DWORD instructionLength = 0;
    const MHOOK_STATUS status = MhookAnalyzePrologue(bytes.data(), bytes.size(), &instructionLength);

    if (status != MHOOK_STATUS_INVALID_TARGET)
    {
        fprintf(
            stderr,
            "short prologue span returned status=%d, length=%lu\n",
            static_cast<int>(status),
            static_cast<unsigned long>(instructionLength)
        );
        return 1;
    }

    return 0;
}

/**
 * @brief Verifies rejection of input larger than the analysis snapshot.
 * @return Zero when analysis reports an invalid argument.
 */
static int caseOversizedPrologueInput(void)
{
    // 33 NOPs exceed the 32-byte snapshot capacity.
    constexpr U8 kNop = 0x90;
    std::array<U8, 33> bytes = {};
    bytes.fill(kNop);

    DWORD instructionLength = 0;
    const MHOOK_STATUS status = MhookAnalyzePrologue(bytes.data(), bytes.size(), &instructionLength);

    if (status != MHOOK_STATUS_INVALID_ARGUMENT)
    {
        fprintf(stderr, "oversized prologue input returned status=%d\n", static_cast<int>(status));
        return 1;
    }

    return 0;
}

/**
 * @brief Verifies acceptance of the largest possible five-byte patch span.
 * @return Zero when analysis consumes all nineteen bytes.
 */
static int caseMaximumPrologueSpan(void)
{
    // 4 NOPs + 14 operand-size prefixes + NOP.
    constexpr size_t kLeadingNopCount = 4;
    constexpr size_t kPrefixCount = 14;
    constexpr U8 kOperandSizePrefix = 0x66;
    constexpr U8 kNop = 0x90;
    std::array<U8, 19> bytes = {};
    std::fill_n(bytes.begin(), kLeadingNopCount, kNop);
    std::fill_n(bytes.begin() + kLeadingNopCount, kPrefixCount, kOperandSizePrefix);
    bytes[kLeadingNopCount + kPrefixCount] = kNop;

    DWORD instructionLength = 0;
    const MHOOK_STATUS status = MhookAnalyzePrologue(bytes.data(), bytes.size(), &instructionLength);

    if (status != MHOOK_STATUS_SUCCESS || instructionLength != static_cast<DWORD>(bytes.size()))
    {
        fprintf(
            stderr,
            "maximum prologue span failed: status=%d, length=%lu\n",
            static_cast<int>(status),
            static_cast<unsigned long>(instructionLength)
        );
        return 1;
    }

    return 0;
}

/**
 * @brief Tests a prologue containing only instruction prefixes.
 * @return Zero when analysis reports an invalid target.
 */
static int casePrefixOnlyPrologue(void)
{
    // 5 operand-size prefixes without an opcode.
    constexpr U8 kOperandSizePrefix = 0x66;
    std::array<U8, 5> bytes = {};
    bytes.fill(kOperandSizePrefix);

    DWORD instructionLength = 0;
    const MHOOK_STATUS status = MhookAnalyzePrologue(bytes.data(), bytes.size(), &instructionLength);
    if (status != MHOOK_STATUS_INVALID_TARGET)
    {
        fprintf(stderr, "prefix-only prologue returned status=%d\n", static_cast<int>(status));
        return 1;
    }

    return 0;
}

/**
 * @brief Verifies rejection of a truncated opcode.
 * @return Zero when analysis reports an invalid target.
 */
static int caseTruncatedOpcode(void)
{
    // 4 NOPs + truncated 0F opcode escape.
    constexpr U8 kNop = 0x90;
    constexpr U8 kOpcodeEscape = 0x0F;
    std::array<U8, 5> bytes = {};
    std::fill_n(bytes.begin(), bytes.size() - 1, kNop);
    bytes[bytes.size() - 1] = kOpcodeEscape;

    DWORD instructionLength = 0;
    const MHOOK_STATUS status = MhookAnalyzePrologue(bytes.data(), bytes.size(), &instructionLength);

    if (status != MHOOK_STATUS_INVALID_TARGET)
    {
        fprintf(stderr, "truncated opcode returned status=%d\n", static_cast<int>(status));
        return 1;
    }

    return 0;
}

/**
 * @brief Verifies rejection of a truncated ModRM instruction.
 * @return Zero when analysis reports an invalid target.
 */
static int caseTruncatedModRm(void)
{
    // 4 NOPs + truncated MOV r/m32, r32 without ModRM.
    constexpr U8 kNop = 0x90;
    constexpr U8 kMoveOpcode = 0x89;
    std::array<U8, 5> bytes = {};
    std::fill_n(bytes.begin(), bytes.size() - 1, kNop);
    bytes[bytes.size() - 1] = kMoveOpcode;

    DWORD instructionLength = 0;
    const MHOOK_STATUS status = MhookAnalyzePrologue(bytes.data(), bytes.size(), &instructionLength);

    if (status != MHOOK_STATUS_INVALID_TARGET)
    {
        fprintf(stderr, "truncated ModRM returned status=%d\n", static_cast<int>(status));
        return 1;
    }

    return 0;
}

/**
 * @brief Verifies rejection of a truncated displacement.
 * @return Zero when analysis reports an invalid target.
 */
static int caseTruncatedDisplacement(void)
{
    // 4 NOPs + truncated MOV EAX, [disp32/RIP+disp32].
    constexpr size_t kMoveInstructionSize = 2;
    constexpr U8 kNop = 0x90;
    constexpr U8 kMoveOpcode = 0x8B;
    constexpr U8 kDisplacementOperand = 0x05;
    std::array<U8, 6> bytes = {};
    std::fill_n(bytes.begin(), bytes.size() - kMoveInstructionSize, kNop);
    bytes[bytes.size() - kMoveInstructionSize] = kMoveOpcode;
    bytes[bytes.size() - 1] = kDisplacementOperand;

    DWORD instructionLength = 0;
    const MHOOK_STATUS status = MhookAnalyzePrologue(bytes.data(), bytes.size(), &instructionLength);

    if (status != MHOOK_STATUS_INVALID_TARGET)
    {
        fprintf(stderr, "truncated displacement returned status=%d\n", static_cast<int>(status));
        return 1;
    }

    return 0;
}

/**
 * @brief Verifies rejection of a truncated immediate.
 * @return Zero when analysis reports an invalid target.
 */
static int caseTruncatedImmediate(void)
{
    // 4 NOPs + truncated MOV EAX, imm32.
    constexpr U8 kNop = 0x90;
    constexpr U8 kMoveImmediateOpcode = 0xB8;
    std::array<U8, 5> bytes = {};
    std::fill_n(bytes.begin(), bytes.size() - 1, kNop);
    bytes[bytes.size() - 1] = kMoveImmediateOpcode;

    DWORD instructionLength = 0;
    const MHOOK_STATUS status = MhookAnalyzePrologue(bytes.data(), bytes.size(), &instructionLength);

    if (status != MHOOK_STATUS_INVALID_TARGET)
    {
        fprintf(stderr, "truncated immediate returned status=%d\n", static_cast<int>(status));
        return 1;
    }

    return 0;
}

/**
 * @brief Verifies rejection of a relative call in the patch span.
 * @return Zero when analysis reports an unsupported prologue.
 */
static int caseRelativeCallPrologue(void)
{
    // CALL rel32(0) targets the next instruction.
    constexpr U8 kCallOpcode = 0xE8;
    std::array<U8, 5> bytes = {};
    bytes[0] = kCallOpcode;

    DWORD instructionLength = 0;
    const MHOOK_STATUS status = MhookAnalyzePrologue(bytes.data(), bytes.size(), &instructionLength);

    if (status != MHOOK_STATUS_UNSUPPORTED_PROLOGUE)
    {
        fprintf(stderr, "relative call returned status=%d\n", static_cast<int>(status));
        return 1;
    }

    return 0;
}

/**
 * @brief Verifies rejection of an unconditional relative jump.
 * @return Zero when analysis reports an unsupported prologue.
 */
static int caseUnconditionalJumpPrologue(void)
{
    // JMP rel32(0) targets the next instruction.
    constexpr U8 kJumpOpcode = 0xE9;
    std::array<U8, 5> bytes = {};
    bytes[0] = kJumpOpcode;

    DWORD instructionLength = 0;
    const MHOOK_STATUS status = MhookAnalyzePrologue(bytes.data(), bytes.size(), &instructionLength);

    if (status != MHOOK_STATUS_UNSUPPORTED_PROLOGUE)
    {
        fprintf(stderr, "unconditional jump returned status=%d\n", static_cast<int>(status));
        return 1;
    }

    return 0;
}

/**
 * @brief Verifies rejection of a conditional relative jump.
 * @return Zero when analysis reports an unsupported prologue.
 */
static int caseConditionalJumpPrologue(void)
{
    // JE rel32(0) targets the next instruction.
    constexpr U8 kOpcodeEscape = 0x0F;
    constexpr U8 kJumpEqualOpcode = 0x84;
    std::array<U8, 6> bytes = {};
    bytes[0] = kOpcodeEscape;
    bytes[1] = kJumpEqualOpcode;

    DWORD instructionLength = 0;
    const MHOOK_STATUS status = MhookAnalyzePrologue(bytes.data(), bytes.size(), &instructionLength);

    if (status != MHOOK_STATUS_UNSUPPORTED_PROLOGUE)
    {
        fprintf(stderr, "conditional jump returned status=%d\n", static_cast<int>(status));
        return 1;
    }

    return 0;
}

int main()
{
    if (!set_hook || !remove_hook)
    {
        fprintf(stderr, "Public hook API linkage failed\n");
        return 1;
    }

    // Padded buffers accommodate the legacy decoder's lookahead.
    U8 move_immediate[32] = {0xb8, 0x2a, 0x00, 0x00, 0x00}; // mov eax, 42
    U8 return_instruction[32] = {0xc3};                     // ret
    const ARCHITECTURE_TYPE modes[] = {ARCH_X86, ARCH_X64};
    for (unsigned i = 0; i < sizeof(modes) / sizeof(modes[0]); ++i)
    {
        if (!CheckInstruction(modes[i], move_immediate, 5, ITYPE_MOV) ||
            !CheckInstruction(modes[i], return_instruction, 1, ITYPE_RET) ||
            !checkMaximumPrefixSequenceLength(modes[i]) || !checkOverlongInstruction(modes[i]))
        {
            return 1;
        }
    }
    if (!CheckSnapshotVirtualAddress() || !CheckModRmRegisterOperand())
        return 1;
    if (caseRandomDecoderBounds() != 0)
        return 1;
    if (caseRandomPrologueAnalysis() != 0)
        return 1;
    if (caseExactPrologueSpan() != 0)
        return 1;
    if (caseShortPrologueSpan() != 0)
        return 1;
    if (caseOversizedPrologueInput() != 0)
        return 1;
    if (caseMaximumPrologueSpan() != 0)
        return 1;
    if (casePrefixOnlyPrologue() != 0)
        return 1;
    if (caseTruncatedOpcode() != 0)
        return 1;
    if (caseTruncatedModRm() != 0)
        return 1;
    if (caseTruncatedDisplacement() != 0)
        return 1;
    if (caseTruncatedImmediate() != 0)
        return 1;
    if (caseRelativeCallPrologue() != 0)
        return 1;
    if (caseUnconditionalJumpPrologue() != 0)
        return 1;
    if (caseConditionalJumpPrologue() != 0)
        return 1;
    puts("Archive linkage and x86/x64 decoder checks passed.");
    return 0;
}
