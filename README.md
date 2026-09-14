# Mhook

A Windows inline-hooking library for x86 and x64.

## Build

Use CMake 3.24 or newer and Visual Studio 2022 with C++ tools and a Windows SDK:

```powershell
cmake --preset msvc-[x64/x86]
cmake --build --preset msvc-[x64/x86]-[debug/release]
ctest --preset msvc-[x64/x86]-[debug/release]
```

Alternatively use build script:

```powershell
python build.py
```

Choose a preset or **All presets**, then **Build**, **Rebuild**, or **Clean**.

## License

See [COPYING](COPYING). Existing source notices remain applicable.
