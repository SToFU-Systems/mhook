# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.0.0] - 2026-09-22

The first SToFU Systems release. It covers everything changed since the fork
point, Marton Anka's mhook 2.4: a rewrite of the implementation in C, a
diagnostic status API, batch operations, a test suite, a CMake build with a
consumable package, continuous integration and generated documentation.

### Added

- **Failure diagnostics.** `Mhook_GetLastStatus()` and the `MHOOK_STATUS` enum
  report why an operation failed, where previously only a boolean was
  available. The status is per thread and is replaced by that thread's next
  hook or unhook operation.
- **Batch operations.** `Mhook_SetHookBatch()` and `Mhook_UnhookBatch()` install
  or remove a set of hooks all-or-nothing: if any member of the batch cannot be
  prepared or published, none of them are.
- **Version information.** `Mhook_GetVersion()` returns the version compiled
  into the library, and `<mhook-lib/version.h>` provides `MHOOK_VERSION_MAJOR`,
  `MHOOK_VERSION_MINOR`, `MHOOK_VERSION_PATCH` and `MHOOK_VERSION_STRING` for
  compile-time checks. The public header includes it, so including
  `<mhook-lib/mhook.h>` is enough.
- **Documentation.** The public interface is documented with Doxygen comments,
  and `setup.bat --docs` renders an HTML API reference through Breathe and
  Sphinx.
- **Tests.** A CTest suite covering the hook engine, the instruction decoder,
  every status value, and the public header's consumability from C99, C11, C17,
  C++17 and C++20. The C and C++ consumer checks share one body so they cannot
  drift apart.
- **CMake package.** `find_package(mhook 3.0 CONFIG REQUIRED)` provides
  `mhook::mhook` and `mhook::headers`, with a version file that accepts any
  3.x. CPack produces a ZIP of the library, its headers and that package.
- **Subproject support.** Mhook can be consumed straight from source with
  `FetchContent` or `add_subdirectory`, building neither its tests nor its
  examples and leaving the parent project's packaging alone.
- **Continuous integration.** GitHub Actions builds and tests MSVC x86 and x64
  in Debug and Release, builds under MinGW GCC, checks formatting, and builds
  the documentation.
- **Build orchestration.** `setup.bat` with `scripts/setup.py` drives
  configuring, building, testing, packaging, documentation and formatting.
- **Project conventions.** `.clang-format`, `.editorconfig`, `.gitattributes`,
  VS Code tasks and launch configurations, and Git hooks that reject
  unformatted sources and malformed commit messages.

### Changed

- **The implementation is now C, not C++.** The engine was converted; the
  public interface was already C-compatible and did not change.
- **The build moved from Visual Studio project files to CMake**, with presets
  for x86, x64 and MinGW across Debug, Release and RelWithDebInfo.
- **The repository was restructured** onto `src/<component>/{include,src}`,
  with tests and examples at the top level. The public include path did not
  change.
- **The library targets C99** with compiler extensions enabled. A C11
  `_Alignof` was replaced with a compiler-intrinsic macro; behaviour is
  identical.
- **Licence headers were reworked** so each file names its own original author:
  Marton Anka for the hook engine, Matt Conover for the vendored disassembler,
  and neither for files written for this fork.
- **The option that builds the tests is `MHOOK_BUILD_TESTING`**, not the global
  `BUILD_TESTING`. A parent project enabling CTest used to drag mhook's tests
  into its own build.
- Version numbering restarts at 3.0.0; upstream's last release was 2.4.

### Fixed

- `Mhook_Unhook()` could fail to find the hook it was asked to remove.
- Unhooking a target that another writer had patched since is now refused
  instead of corrupting that writer's patch; `Mhook_GetTarget()` names the
  contested address.
- The caller's `GetLastError()` value is preserved across successful hook
  operations, and across `Mhook_SetHook()` failures, which report through the
  status API instead.
- Conflicting hook requests are detected and rejected before any hook state
  changes.
- Prologue decoding works from a validated snapshot of the target, so a target
  changing underneath the decoder cannot mislead it.
- Entry-point jump resolution is bounded: at most 16 jumps, with cycles and
  unreadable addresses rejected before hook state changes.
- Duplicate trampoline allocation for the same target was eliminated.
- Targets are validated as live and executable before unhooking.
- A failure to suspend a thread now aborts the operation rather than letting it
  proceed with threads possibly executing the code being patched.
- Function-pointer slots are validated for alignment, readability and
  writability before use.
- Missing includes and SDK structure packing issues were resolved.

### Removed

- The Visual Studio solution and project files, and the `stdafx` precompiled
  header pair. CMake replaces them.

### Compatibility

Source compatible with 2.x. The public header is still included as
`<mhook-lib/mhook.h>`, no public symbol was renamed, and no existing signature
changed. Code written against 2.4 compiles unchanged; the additions above are
additions only.
