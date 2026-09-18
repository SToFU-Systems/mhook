import argparse
from pathlib import Path
import shutil
import subprocess
import sys


ARCHITECTURES = ("x86", "x64")
CONFIGURATIONS = ("Debug", "Release")


def main():
    parser = argparse.ArgumentParser(description="Build and pack the native Mhook NuGet package")
    parser.add_argument("--nuget", help="Path to nuget.exe (defaults to nuget on PATH)")
    args = parser.parse_args()

    if sys.platform != "win32":
        parser.error("NuGet binaries are built with MSVC on Windows")

    cmake = shutil.which("cmake")
    nuget = args.nuget or shutil.which("nuget")
    if not cmake:
        parser.error("CMake is required on PATH")
    if not nuget or not Path(nuget).is_file():
        parser.error("nuget.exe is required; put it on PATH or pass --nuget")

    repo_root = Path(__file__).resolve().parents[2]
    build_root = repo_root / "build"
    manifests = list(Path(__file__).parent.glob("*.nuspec"))
    if len(manifests) != 1:
        parser.error("packaging/nuget must contain exactly one .nuspec file")

    try:
        for arch in ARCHITECTURES:
            configure_preset = f"msvc-{arch}"
            binary_dir = build_root / configure_preset
            subprocess.run([cmake, "--preset", configure_preset], cwd=repo_root, check=True)

            for config in CONFIGURATIONS:
                build_preset = f"{configure_preset}-{config.lower()}"
                install_dir = build_root / "install" / build_preset
                subprocess.run([
                    cmake, "--build", "--preset", build_preset,
                    "--target", "mhook", "--parallel",
                ], cwd=repo_root, check=True)
                subprocess.run([
                    cmake, "--install", str(binary_dir), "--config", config,
                    "--prefix", str(install_dir),
                ], check=True)
                library = install_dir / "lib" / "mhook.lib"
                if not library.is_file():
                    raise FileNotFoundError(f"CMake install did not produce {library}")

        header = build_root / "install" / "msvc-x64-release" / "include" / "mhook-lib" / "mhook.h"
        if not header.is_file():
            raise FileNotFoundError(f"CMake install did not produce {header}")

        package_dir = build_root / "nuget" / "dist"
        package_dir.mkdir(parents=True, exist_ok=True)
        subprocess.run([
            nuget, "pack", str(manifests[0]),
            "-BasePath", str(repo_root), "-OutputDirectory", str(package_dir),
            "-NonInteractive",
        ], check=True)
    except (OSError, subprocess.CalledProcessError) as error:
        print(f"NuGet packaging failed: {error}", file=sys.stderr)
        return 1

    print(f"Package created in {package_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
