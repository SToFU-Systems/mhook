# mhook

A Windows API hooking library.

## Table of Contents

- [Overview](#overview)
- [License](#license)
- [Usage](#usage)
- [Build](#build)
- [Version History](#version-history)

## Overview

The [Mhook](https://github.com/martona/mhook) library was created by [Marton Anka](https://github.com/martona) for inline function hooking in Windows x86 and x64 applications. It redirects calls to a replacement function while preserving access to the original function. Hooks can be installed and removed at runtime. Mhook additionally includes Matt Conover's disassembler. The latest original release version is [v2.4](https://github.com/martona/mhook/tree/v2.4). The [last commit](https://github.com/martona/mhook/commit/e58a58ca31dbe14f202b9b26315bff9f7a32598c) was made on March 6, 2014.

**SToFU Systems** now maintains and develops this fork.

Our site: [https://stofu.io](https://stofu.io)

## License

Licensed under the [MIT License](LICENSE).

## Usage

`Mhook_SetHook` and `Mhook_Unhook` retain their Boolean results. Call `Mhook_GetLastStatus` immediately after either operation when a detailed result is needed. The status belongs to the calling thread and is replaced by its next hook or unhook operation.

`Mhook_SetHook` follows at most 16 entry-point jumps for both the target and replacement. It rejects longer chains, cycles, and addresses that cannot be read as executable code before changing hook state.

| Status | Meaning | Handling |
| --- | --- | --- |
| `MHOOK_STATUS_SUCCESS` | No reported failure. | Continue normally. |
| `MHOOK_STATUS_INVALID_ARGUMENT` | A required argument or pointed-to address is null. | Correct the call before retrying. |
| `MHOOK_STATUS_DECODE_FAILED` | The target prologue could not be decoded. | Skip the target or use another hooking method. |
| `MHOOK_STATUS_UNSUPPORTED_PROLOGUE` | The decoded prologue cannot hold a supported patch. | Skip the target or use another hooking method. |
| `MHOOK_STATUS_TRAMPOLINE_ALLOCATION_FAILED` | No suitable trampoline could be allocated. | Retry only if memory availability may have changed. |
| `MHOOK_STATUS_MEMORY_PROTECTION_FAILED` | A required memory-protection change failed. | Stop the operation and retry only if process conditions may have changed. |
| `MHOOK_STATUS_HOOK_NOT_FOUND` | The supplied pointer does not identify an active hook. | Correct the hook lifecycle or pointer before retrying. |
| `MHOOK_STATUS_THREAD_SUSPENSION_FAILED` | Required thread coordination failed. | Stop changing hooks and retry only if thread conditions may have changed. |
| `MHOOK_STATUS_PATCH_FAILED` | Publishing modified code failed. | Treat the hook state as uncertain and stop further hook changes. |
| `MHOOK_STATUS_TARGET_MODIFIED` | Another writer modified the target after the hook was installed. | Leave the hook installed and retry only after Mhook's patch has been restored. |
| `MHOOK_STATUS_INVALID_DESCRIPTOR` | The supplied function-pointer slot is misaligned, unreadable, or unwritable. | Pass an aligned pointer to readable and writable `PVOID` storage. |
| `MHOOK_STATUS_INVALID_TARGET` | A target or replacement cannot be read as executable code, or an indirect jump slot is unreadable. | Correct the address or its memory protection before retrying. |
| `MHOOK_STATUS_JUMP_CYCLE` | Entry-point jump resolution encountered an address it had already visited. | Correct the cyclic thunk chain before retrying. |
| `MHOOK_STATUS_JUMP_DEPTH_EXCEEDED` | Entry-point jump resolution would follow more than 16 jumps. | Shorten the thunk chain before retrying. |

## Build

### Requirements

- Windows, targeting x86 or x64.
- CMake 3.24 or newer, available on `PATH`.
- For MSVC builds: Visual Studio 2022 or Build Tools 2022 with C++ tools and a Windows SDK.

### Configure and build

Run these commands from the repository root:

```powershell
cmake --preset msvc-[x86/x64]
cmake --build --preset msvc-[x86/x64]-[debug/release]
```

### Run tests

```powershell
ctest --preset msvc-[x86/x64]-[debug/release]
```

### MinGW (WIP)

```powershell
cmake --preset mingw-[x86/x64]-[debug/release]
cmake --build --preset mingw-[x86/x64]-[debug/release]
ctest --preset mingw-[x86/x64]-[debug/release]
```

## Version History

| Version | Date | Highlights |
| --- | --- | --- |
| |  |  |
| [Original 2.4](https://github.com/martona/mhook/tree/v2.4) | 2014-03-05 | Last original release. |

See [CHANGELOG.md](CHANGELOG.md) for detailed changes.
