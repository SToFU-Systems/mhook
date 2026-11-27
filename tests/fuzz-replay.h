#pragma once

#include <windows.h>
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>

/**
 * @brief Identifies the engine check used to replay saved bytes.
 */
enum class ReplayTarget : uint8_t
{
    DecoderBounds = 0,
    PrologueAnalysis = 1,
    RelocationPipeline = 2,
    RipRelativeRelocation = 3,
    Count = 4
};

/**
 * @brief Identifies the architecture used to process saved bytes.
 */
enum class ReplayArchitecture : uint8_t
{
    X86 = 0,
    X64 = 1,
    Count = 2
};

/**
 * @brief Stores input loaded for replay.
 */
struct ReplayInput
{
    ReplayTarget target = ReplayTarget::DecoderBounds;
    ReplayArchitecture architecture = ReplayArchitecture::X86;
    uint8_t byteCount = 0;
    std::array<uint8_t, 32> bytes = {};
};

/**
 * @brief Saves the current fuzz input before it enters the engine.
 */
class FuzzSnapshot
{
public:
    /**
     * @brief Opens a snapshot for one engine and architecture.
     * @param[in] path Snapshot file path.
     * @param[in] target Engine check used for replay.
     * @param[in] architecture Architecture used by the engine.
     */
    FuzzSnapshot(const std::filesystem::path& path, ReplayTarget target, ReplayArchitecture architecture) :
        m_path(path), m_target(target), m_architecture(architecture)
    {
        std::error_code createError = {};
        std::filesystem::create_directories(m_path.parent_path(), createError);
        if (createError)
            return;

        m_file.open(m_path, std::ios::binary | std::ios::trunc);
    }

    /**
     * @brief Overwrites and flushes the current fuzz input.
     * @param[in] bytes Input buffer passed to the engine.
     * @param[in] byteCount Number of input bytes.
     * @return True when the complete snapshot was flushed.
     */
    bool saveSnapshot(const std::array<uint8_t, 32>& bytes, size_t byteCount)
    {
        constexpr size_t kTargetOffset = 0;
        constexpr size_t kArchitectureOffset = 1;
        constexpr size_t kByteCountOffset = 2;
        constexpr size_t kBytesOffset = 3;
        constexpr size_t kRecordSize = 35;

        if (!m_file.is_open() || !byteCount || byteCount > bytes.size())
            return false;

        // Encode a fixed-size record so each input replaces the previous one.
        std::array<uint8_t, kRecordSize> record = {};
        record[kTargetOffset] = static_cast<uint8_t>(m_target);
        record[kArchitectureOffset] = static_cast<uint8_t>(m_architecture);
        record[kByteCountOffset] = static_cast<uint8_t>(byteCount);
        std::copy_n(bytes.begin(), byteCount, record.begin() + kBytesOffset);

        // Flush before the engine call so crashes and timeouts retain the input.
        m_file.clear();
        m_file.seekp(0, std::ios::beg);
        if (!m_file)
            return false;

        m_file.write(reinterpret_cast<const char*>(record.data()), static_cast<std::streamsize>(record.size()));
        if (!m_file)
            return false;

        m_file.flush();
        return m_file.good();
    }

private:
    std::filesystem::path m_path;
    ReplayTarget m_target;
    ReplayArchitecture m_architecture;
    std::ofstream m_file;
};

/**
 * @brief Creates a process-specific snapshot path.
 * @param[in] testName Test-specific replay directory name.
 * @param[in] snapshotName Snapshot file name prefix.
 * @return Absolute snapshot path.
 */
inline std::filesystem::path makeSnapshotPath(const char* testName, const char* snapshotName)
{
    const std::string fileName = std::string(snapshotName) + "-" + std::to_string(GetCurrentProcessId()) + ".case";
    return std::filesystem::current_path() / "replay" / testName / fileName;
}

/**
 * @brief Loads one saved fuzz input.
 * @param[in] path Snapshot file path.
 * @return Loaded input, or no value when the file is invalid.
 */
inline std::optional<ReplayInput> loadSnapshot(const std::filesystem::path& path)
{
    constexpr size_t kTargetOffset = 0;
    constexpr size_t kArchitectureOffset = 1;
    constexpr size_t kByteCountOffset = 2;
    constexpr size_t kBytesOffset = 3;
    constexpr size_t kRecordSize = 35;

    // Read exactly one fixed-size snapshot.
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open())
        return std::nullopt;

    std::array<uint8_t, kRecordSize> record = {};
    file.read(reinterpret_cast<char*>(record.data()), static_cast<std::streamsize>(record.size()));
    if (!file || file.peek() != std::char_traits<char>::eof())
        return std::nullopt;

    // Reject values outside the serialized target and architecture ranges.
    if (record[kTargetOffset] >= static_cast<uint8_t>(ReplayTarget::Count))
        return std::nullopt;
    if (record[kArchitectureOffset] >= static_cast<uint8_t>(ReplayArchitecture::Count))
        return std::nullopt;

    if (!record[kByteCountOffset] || record[kByteCountOffset] > ReplayInput().bytes.size())
        return std::nullopt;

    ReplayInput input = {};
    input.target = static_cast<ReplayTarget>(record[kTargetOffset]);
    input.architecture = static_cast<ReplayArchitecture>(record[kArchitectureOffset]);
    input.byteCount = record[kByteCountOffset];
    std::copy_n(record.begin() + kBytesOffset, input.bytes.size(), input.bytes.begin());
    return input;
}
