# Packaging

This directory holds the package definitions maintained with the library. `mhook-fork-dev` and `0.0.0-dev` are temporary package IDs and versions. Nothing in this directory has been submitted to a public package registry.

## vcpkg

`vcpkg/ports/mhook-fork-dev/vcpkg.json` contains the port name, version, license, supported platforms, and build-tool dependencies. `portfile.cmake` tells vcpkg which source archive to download and how to build it with the existing CMake install rules.

When the final name and release are ready:

1. Rename `vcpkg/ports/mhook-fork-dev` and set the same name in `vcpkg.json`.
2. Replace `0.0.0-dev` in `vcpkg.json` with the release version.
3. Replace `<release-tag>` in `portfile.cmake` with the published Git tag and `SHA512 0` with that archive's SHA512.
4. Set `HEAD_REF` to the default branch. If it is still `master`, leave `HEAD_REF master` as it is. This field is used for optional head builds; normal versioned builds use `REF`.

For the official vcpkg registry, copy the finished port directory to `ports/<final-name>` in a fork of [microsoft/vcpkg](https://github.com/microsoft/vcpkg). That repository also requires a version-database update under `versions/` and a pull request; copying the files alone does not publish the port. See the [official contribution tutorial](https://learn.microsoft.com/en-us/vcpkg/get_started/get-started-adding-to-registry). The README in this repository is not part of the port submission.

## Conan 2

`conan/` follows the [ConanCenterIndex recipe layout](https://github.com/conan-io/conan-center-index/blob/master/docs/adding_packages/folders_and_files.md): `config.yml` maps a version to the `all/` recipe, `all/conandata.yml` identifies the source archive and checksum, `all/conanfile.py` builds and packages the library, and `all/test_package/` checks the public header and link target.

When the final name and release are ready:

1. Replace `mhook-fork-dev` in `all/conanfile.py` with the final Conan package name. Rename the `conan/` directory to that name when copying it to ConanCenterIndex.
2. Replace `0.0.0-dev` with the same release version in both `config.yml` and `all/conandata.yml`.
3. Replace `<release-tag>` and `<sha256>` in `all/conandata.yml` with the published Git tag and the SHA256 of its source archive.
4. Check that `license`, `homepage`, and `description` in `all/conanfile.py` still describe the released project.

For the official ConanCenter, copy the finished `conan/` directory to `recipes/<final-name>/` in a fork of [conan-io/conan-center-index](https://github.com/conan-io/conan-center-index), then open a pull request. ConanCenter builds the binaries and publishes the package after the pull request is merged. There is no direct package upload to ConanCenter. The placeholder tag and checksum prevent a real build until they are replaced. Follow the [official submission guide](https://github.com/conan-io/conan-center-index/blob/master/docs/adding_packages/README.md); the submitted recipe must pass its review and CI.

## NuGet

`nuget/mhook-fork-dev.nuspec` describes the package and lists its files. `nuget/mhook-fork-dev.targets` adds the header path and selects the MSVC library for Win32/x64 and Debug/Release. `nuget/pack.py` builds those four binaries with the existing CMake presets and creates the `.nupkg`.

After choosing the final package ID, update the `.nuspec` `id`, rename the `.targets` file to `<final-id>.targets`, and update its `src` entry in the `.nuspec`. Rename the `.nuspec` file for clarity; `pack.py` finds the single `.nuspec` in its directory. Replace the `.nuspec` version with the release version.

NuGet needs a generated binary archive. From the checkout of the released Git tag, run on Windows with Python, CMake, Visual Studio 2022 C++ tools, and `nuget.exe` available:

```powershell
py .\packaging\nuget\pack.py
```

If `nuget.exe` is not on `PATH`, pass `--nuget "C:\path\to\nuget.exe"`. The resulting `<final-id>.<version>.nupkg` is written to `build/nuget/dist`. The NuGet files do not contain a Git tag field; the binaries come from the checkout on which the script runs.

To publish on [nuget.org](https://www.nuget.org/), sign in, choose **Upload**, select that `.nupkg`, review the displayed metadata, and submit it. The package ID must be available to your account, and the same ID/version cannot be published twice. See the [official publishing guide](https://learn.microsoft.com/en-us/nuget/nuget-org/publish-a-package). Do not store a nuget.org API key in this repository.

## Shared naming

Use the same release version for all three packages. The package-manager ID may differ from the installed CMake package name `mhook` and targets `mhook::mhook` and `mhook::headers`; changing the package ID does not require renaming those CMake targets.
