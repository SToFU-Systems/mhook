# mhook

A Windows API hooking library.

## Table of Contents

- [Overview](#overview)
- [License](#license)
- [Usage](#usage)
- [Documentation](#documentation)
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

Successful hook operations preserve the caller's `GetLastError` value. `Mhook_SetHook` also preserves it on failure because detailed errors are reported through `Mhook_GetLastStatus`. `Mhook_Unhook` preserves it for validation failures, while failures involving an installed hook continue to report their documented legacy error through `GetLastError`. Calling through a trampoline adds no error-state changes beyond those made by the original function.

`Mhook_SetHook` follows at most 16 entry-point jumps for both the target and replacement. It rejects longer chains, cycles, and addresses that cannot be read as executable code before changing hook state.

| Status | Meaning | Handling |
| --- | --- | --- |
| `MHOOK_STATUS_SUCCESS` | No reported failure. | Continue normally. |
| `MHOOK_STATUS_INVALID_ARGUMENT` | A required address is null, or the target and replacement resolve to the same address. | Correct the call before retrying. |
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
| `MHOOK_STATUS_ALREADY_HOOKED` | Either the requested target or replacement resolution chain reached a target with an active hook. | Reuse or remove the existing hook before retrying. |

## Documentation

The API reference documents the public interface, rendered from the Doxygen
comments in `mhook-lib/mhook.h` through Breathe and Sphinx.

Build it with:

```powershell
setup.bat --docs
```

The result lands in `_docs/html/index.html`.

Doxygen must be on `PATH`. The Python packages are provisioned automatically
and are never installed system wide: `setup.bat` provides the virtual
environment, and `--docs` installs the versions pinned in
`docs/requirements.txt` into it. It is the only command that needs a
third-party package; the library build itself needs none.

CI builds the documentation on every pull request and uploads the rendered HTML
as a build artifact, so it can be read without building anything locally.

## Build

### Requirements

- Windows, targeting x86 or x64.
- CMake 3.24 or newer, available on `PATH`.
- Python 3.9 or newer, for `setup.bat`.
- For MSVC builds: Visual Studio 2022 or Build Tools 2022 with C++ tools and a Windows SDK.
- For MinGW builds: a MinGW-w64 GCC toolchain, with its root in `MHOOK_MINGW_X86_ROOT` or `MHOOK_MINGW_X64_ROOT`.
- clang-format 20.1.8, for `setup.bat --format` and the pre-commit hook.

### setup.bat

`setup.bat` is the single entry point for every build task. It checks that
Python is on `PATH`, creates `.venv` on first use and runs everything inside
it, so no command this project offers installs a package into your global
site-packages. The Git hooks, the VS Code tasks and CI all route through it for
the same reason.

| Command | Effect |
| --- | --- |
| `setup.bat --build TYPE` | Configure, build and install |
| `setup.bat --run-tests TYPE` | Build, then run the tests with JUnit and HTML reports |
| `setup.bat --package TYPE` | The full pipeline, then package with CPack |
| `setup.bat --docs` | Generate the API documentation into `_docs/html/` |
| `setup.bat --format` | Format the sources with clang-format |
| `setup.bat --format-check` | Check formatting without modifying files |
| `setup.bat --clean` | Remove `_build`, `_install`, `_package` and `_docs` |

`TYPE` is `<arch>-<config>`:

| Architecture | Configuration |
| --- | --- |
| `x86`, `x64`, `mingw-x86`, `mingw-x64` | `debug`, `release`, `relwithdebinfo` |

For example:

```powershell
setup.bat --build x64-debug
setup.bat --run-tests x86-release
setup.bat --package x64-relwithdebinfo
```

### CMake presets directly

```powershell
cmake --preset x64-debug-configuration
cmake --build --preset x64-debug-build
ctest --preset x64-debug-test
```

MinGW presets follow the same pattern with a `mingw-` prefix on the
architecture, and activate only when the matching environment variable is set.

### Install

`setup.bat --build TYPE` installs into `_install/<arch>/<config>`. Each
architecture and configuration has its own install directory.

An installed package can be used from another CMake project:

```cmake
find_package(mhook 3.0 CONFIG REQUIRED)
target_link_libraries(your_target PRIVATE mhook::mhook)
```

Configure that project with `CMAKE_PREFIX_PATH` pointing to the chosen install
directory. The public header is available as `<mhook-lib/mhook.h>`.

### Use as a subproject

Mhook can also be consumed directly from source, with `FetchContent` or a
plain `add_subdirectory`:

```cmake
include(FetchContent)
FetchContent_Declare(mhook
    GIT_REPOSITORY https://github.com/SToFU-Systems/mhook.git
    GIT_TAG        v3.0.0)
FetchContent_MakeAvailable(mhook)

target_link_libraries(your_target PRIVATE mhook::mhook)
```

Consumed this way, mhook builds neither its tests nor its examples, and it does
not touch your project's packaging. Its tests are gated on
`MHOOK_BUILD_TESTING` rather than the usual `BUILD_TESTING`, so enabling CTest
in your own project does not drag them into your build; pass
`-DMHOOK_BUILD_TESTING=ON` if you do want them.

## Version History

| Version | Date | Highlights |
| --- | --- | --- |
| 3.0.0 | 2026-09-22 | Template layout, C99, versioned package, generated docs. |
| [Original 2.4](https://github.com/martona/mhook/tree/v2.4) | 2014-03-05 | Last original release. |

See [CHANGELOG.md](CHANGELOG.md) for detailed changes.
