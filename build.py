import json
from pathlib import Path
import shutil
import subprocess
import sys


ACTIONS = {
    1: {"label": "Build", "clean": False, "build": True},
    2: {"label": "Rebuild", "clean": True, "build": True},
    3: {"label": "Clean", "clean": True, "build": False},
}


def select_option(title, options, prompt):
    print(title)
    for number, option in options.items():
        print(str(number) + ". " + option["label"])
    print("0. Cancel")

    while True:
        try:
            number = int(input(prompt).strip())
        except ValueError:
            number = -1
        except (EOFError, KeyboardInterrupt):
            print()
            return None
        if number == 0:
            return None
        if number in options:
            return options[number]
        print("Enter a number from 0 to " + str(max(options)) + ".")


def select_presets(presets):
    options = {
        number: {"label": name, "presets": [preset]}
        for number, (name, preset) in enumerate(presets.items(), start=1)
    }
    options[len(options) + 1] = {"label": "All presets", "presets": list(presets.values())}
    selected = select_option("Select presets:", options, "Preset number: ")
    return selected["presets"] if selected is not None else None


def main(argv=None):
    if argv:
        print("Run python build.py without arguments and select a preset.", file=sys.stderr)
        return 2
    repo_root = Path(__file__).resolve().parent

    try:
        with (repo_root / "CMakePresets.json").open(encoding="utf-8-sig") as source:
            settings = json.load(source)
        test_presets = {preset["name"] for preset in settings.get("testPresets", [])}
        presets = {
            preset["name"]: preset for preset in settings.get("buildPresets", [])
            if preset.get("configurePreset") in ("msvc-x86", "msvc-x64")
            and preset["name"] in test_presets and not preset.get("hidden", False)
        }
        if not presets:
            raise ValueError("No MSVC build presets with matching test presets were found.")
        selected = select_presets(presets)
        if selected is None:
            print("Cancelled.")
            return 0

        build_dirs = {
            preset["configurePreset"]: repo_root / "build" / preset["configurePreset"]
            for preset in selected
        }
        print("\nSelected: " + ", ".join(preset["name"] for preset in selected))
        print("Clean/Rebuild will remove all configurations in:")
        for build_dir in build_dirs.values():
            print("  " + str(build_dir))
        action = select_option("\nSelect an action:", ACTIONS, "Action number: ")
        if action is None:
            print("Cancelled.")
            return 0

        if action["build"]:
            cmake = shutil.which("cmake")
            ctest = shutil.which("ctest")
            if not cmake or not ctest:
                raise OSError("CMake and CTest must be available on PATH.")
        processed = set()
        for preset in selected:
            configure_preset = preset["configurePreset"]
            build_preset = preset["name"]
            commands = []
            if configure_preset not in processed:
                if action["clean"]:
                    build_dir = build_dirs[configure_preset]
                    if build_dir.resolve() != build_dir:
                        raise OSError("Refusing to clean a build directory redirected by a link.")
                    if build_dir.exists():
                        print("Removing " + str(build_dir), flush=True)
                        shutil.rmtree(build_dir)
                    else:
                        print("Already clean: " + str(build_dir), flush=True)
                if action["build"]:
                    commands.append([cmake, "--preset", configure_preset])

            if action["build"]:
                print("Building preset: " + build_preset, flush=True)
                commands.extend((
                    [cmake, "--build", "--preset", build_preset, "--parallel"],
                    [ctest, "--preset", build_preset],
                ))
            for command in commands:
                print("> " + subprocess.list2cmdline(command), flush=True)
                subprocess.run(command, cwd=repo_root, check=True)
            processed.add(configure_preset)
    except subprocess.CalledProcessError as error:
        return error.returncode
    except (OSError, ValueError) as error:
        print("Operation failed: " + str(error), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nOperation interrupted.", file=sys.stderr)
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
