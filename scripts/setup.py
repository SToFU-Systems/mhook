#!/usr/bin/env python3
"""Build orchestration for mhook.

Wraps CMake configure/build/install, CTest execution with report
generation, code formatting, cleaning, and packaging. Intended to be
launched through setup.bat.
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
from shutil import which

# The Windows console defaults to cp1252, and some messages below contain
# emoji. Without this the script dies with UnicodeEncodeError instead of
# printing its error. "replace" keeps a legacy console readable-ish rather
# than crashing.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):
        pass

# Repository root is the parent of this scripts/ directory.
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

ARCHES = ("x86", "x64", "mingw-x86", "mingw-x64")
CONFIGS = ("debug", "release", "relwithdebinfo")

# Every supported build type, "<arch>-<config>".
BUILD_TYPES = tuple(f"{arch}-{config}" for arch in ARCHES for config in CONFIGS)

# config token -> CMake/CPack configuration name.
_CMAKE_CONFIG = {
    "debug": "Debug",
    "release": "Release",
    "relwithdebinfo": "RelWithDebInfo",
}

GITHOOKS_DIR = os.path.join(REPO_ROOT, ".githooks")
OUTPUT_DIRS = ("_build", "_install", "_package", "_docs")
SOURCE_EXTENSIONS = (".cpp", ".hpp", ".h", ".c", ".cc", ".cxx", ".inc")

DOCS_DIR = os.path.join(REPO_ROOT, "docs")
DOCS_OUTPUT_DIR = os.path.join(REPO_ROOT, "_docs")


def log(message):
    print(f"[setup] {message}")


def fail(message):
    print(f"[setup][error] {message}", file=sys.stderr)
    sys.exit(1)


def run(command, check=True):
    log("run: " + " ".join(command))
    result = subprocess.run(command, cwd=REPO_ROOT)
    if result.returncode != 0 and check:
        fail(f"command failed ({result.returncode}): {' '.join(command)}")
    return result.returncode


def split_build_type(build_type):
    """Splits '<arch>-<config>' into its parts.

    Splitting from the right is what makes 'mingw-x64-debug' work: the
    architecture may contain a hyphen, the configuration never does.
    """
    arch, _, config = build_type.rpartition("-")
    return arch, config


def preset_names(build_type):
    """Returns the configure, build and test preset names for a build type."""
    return (
        f"{build_type}-configuration",
        f"{build_type}-build",
        f"{build_type}-test",
    )


def validate_build_type(build_type):
    if build_type not in BUILD_TYPES:
        fail(f"unknown build type '{build_type}'. Valid: {', '.join(BUILD_TYPES)}")


def cpu_count():
    return str(os.cpu_count() or 4)


def configure_git_hooks():
    if not os.path.isdir(GITHOOKS_DIR):
        return
    if not os.path.isdir(os.path.join(REPO_ROOT, ".git")):
        return
    desired = ".githooks"
    current = subprocess.run(
        ["git", "config", "--get", "core.hooksPath"],
        cwd=REPO_ROOT, capture_output=True, text=True,
    ).stdout.strip()
    if current == desired:
        return
    if run(["git", "config", "core.hooksPath", desired], check=False) == 0:
        log(f"configured core.hooksPath -> {desired}")


COMMIT_TYPES = {
    "\U0001F525": "new feature",              # fire
    "\U0001F41B": "bug fix",                  # bug
    "\U0001F4C4": "documentation",            # doc
    "\U0001F3D7": "infrastructure",           # build
    "\U000026A1": "optimization",             # volt
    "\U0000267B": "refactoring",              # recycle
    "\U00002705": "tests",                    # check
    "\U0001F4E6": "dependencies",             # box
    "\U0001F477": "CI configuration",         # worker
    "\U0001F5D1": "removing code or files",   # waste
}

# Git composes these itself; their format is not ours to enforce.
SKIP_PREFIXES = ("Merge ", "Revert ", "fixup!", "squash!", "amend!")

SUBJECT_RE = re.compile(r"^(.)\s\[([A-Za-z0-9._-]+)\]\s(\S.*)$")


def check_commit_msg(path):
    """Validates a commit message and exits with an error on any violation."""
    with open(path, encoding="utf-8") as handle:
        raw = handle.read()

    # Git comments and leading blank lines are not part of the message.
    lines = [line for line in raw.splitlines() if not line.startswith("#")]
    while lines and not lines[0].strip():
        lines.pop(0)
    if not lines:
        fail("commit message is empty")

    # The U+FE0F variation selector is optional: the two spellings of a
    # recycle or wastebasket mark look identical, so neither may be rejected.
    subject = lines[0].replace("\uFE0F", "").rstrip()

    if subject.startswith(SKIP_PREFIXES):
        return

    match = SUBJECT_RE.match(subject)
    if not match:
        fail(
            "commit subject must look like '<emoji> [scope] Subject'\n"
            f"  got:     {lines[0]}\n"
            "  example: \U0001F525 [mhook-lib] Implement batch hook removal"
        )

    emoji = match.group(1)
    if emoji not in COMMIT_TYPES:
        known = " ".join(COMMIT_TYPES)
        fail(f"unknown commit type '{emoji}'\n  allowed: {known}")

    if len(lines) > 1 and lines[1].strip():
        fail("the second line must be blank: subject, blank line, body")


def _binary_dir_parts(build_type):
    """Returns the path components of a build type's binary directory.

    MSVC is a multi-config generator, so one directory per architecture holds
    every configuration. MinGW builds with Ninja, which is single-config and
    needs one directory per configuration.
    """
    arch, config = split_build_type(build_type)
    if arch.startswith("mingw-"):
        return (arch, config)
    return (arch,)


def build(build_type):
    validate_build_type(build_type)
    configure, build_preset, _ = preset_names(build_type)
    arch, config = split_build_type(build_type)
    jobs = cpu_count()
    prefix = os.path.join(REPO_ROOT, "_install", arch, config)
    run(["cmake", "-S", ".", "--preset", configure])
    run(["cmake", "--build", "--preset", build_preset, "-j", jobs])
    # The MSVC configurations of one architecture share a binary directory, so
    # CMAKE_INSTALL_PREFIX in the cache belongs to whichever configure ran
    # last. Passing --prefix here makes the destination depend on the build
    # type being installed rather than on command ordering.
    run([
        "cmake", "--install", os.path.join("_build", *_binary_dir_parts(build_type)),
        "--config", _CMAKE_CONFIG[config],
        "--prefix", prefix,
    ])


def run_tests(build_type):
    validate_build_type(build_type)
    _, _, test_preset = preset_names(build_type)
    results_dir = os.path.join(REPO_ROOT, "_build", *_binary_dir_parts(build_type), "TestResults")
    os.makedirs(results_dir, exist_ok=True)
    junit_path = os.path.join(results_dir, "junit.xml")
    returncode = run(["ctest", "--preset", test_preset, "--output-junit", junit_path], check=False)
    html_path = os.path.join(results_dir, "index.html")
    write_html_report(junit_path, html_path)
    log(f"JUnit report: {junit_path}")
    log(f"HTML report:  {html_path}")
    if returncode != 0:
        fail(f"tests failed ({returncode}); see {html_path}")


def write_html_report(junit_path, html_path):
    import xml.etree.ElementTree as ET
    from html import escape

    if not os.path.isfile(junit_path):
        log("no JUnit XML produced, skipping HTML report")
        return
    try:
        root = ET.parse(junit_path).getroot()
    except ET.ParseError as error:
        log(f"could not parse JUnit XML: {error}")
        return

    suites = [root] if root.tag == "testsuite" else root.findall(".//testsuite")

    def total(attr):
        return sum(int(suite.attrib.get(attr, 0)) for suite in suites)

    tests = total("tests")
    failures = total("failures")
    errors = total("errors")
    skipped = total("skipped")
    passed = tests - failures - errors - skipped

    rows = []
    for suite in suites:
        for case in suite.findall("testcase"):
            name = escape(case.attrib.get("name", ""))
            classname = escape(case.attrib.get("classname", ""))
            # CTest's JUnit output repeats the full test name in both
            # classname and name, so only prefix classname when it adds
            # information the name does not already carry.
            if classname and classname != name and not name.startswith(f"{classname}."):
                full = f"{classname}.{name}"
            else:
                full = name
            seconds = escape(case.attrib.get("time", "0"))
            if case.find("failure") is not None:
                status, css = "FAILED", "fail"
            elif case.find("error") is not None:
                status, css = "ERROR", "fail"
            elif case.find("skipped") is not None:
                status, css = "SKIPPED", "skip"
            else:
                status, css = "PASSED", "pass"
            rows.append(
                f"<tr><td>{full}</td><td class='{css}'>{status}</td>"
                f"<td>{seconds}s</td></tr>"
            )

    document = f"""<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Test Results</title>
<style>
body {{ font-family: system-ui, sans-serif; margin: 2rem; }}
table {{ border-collapse: collapse; width: 100%; margin-top: 1rem; }}
th, td {{ text-align: left; padding: .4rem .6rem; border: 1px solid #ccc; }}
.pass {{ color: #157f3b; }} .fail {{ color: #c0392b; }} .skip {{ color: #b8860b; }}
</style></head>
<body>
<h1>Test Results</h1>
<p>Total: {tests} - Passed: {passed} - Failed: {failures} - Errors: {errors} - Skipped: {skipped}</p>
<table><tr><th>Test</th><th>Status</th><th>Time</th></tr>
{''.join(rows)}
</table>
</body></html>
"""
    with open(html_path, "w", encoding="utf-8") as handle:
        handle.write(document)


def package(build_type):
    validate_build_type(build_type)
    build(build_type)
    run_tests(build_type)
    _, config = split_build_type(build_type)
    cpack_config = os.path.join("_build", *_binary_dir_parts(build_type), "CPackConfig.cmake")
    if not os.path.isfile(os.path.join(REPO_ROOT, cpack_config)):
        fail(f"CPack configuration not found: {cpack_config}")
    # The generator is chosen in CMakeLists.txt (ZIP for now).
    run(["cpack", "-C", _CMAKE_CONFIG[config], "--config", cpack_config])
    log("packages written to _package/")


def collect_sources():
    sources = []
    for directory in ("src", "tests", "examples"):
        for current, _, files in os.walk(os.path.join(REPO_ROOT, directory)):
            for name in files:
                if name.endswith(SOURCE_EXTENSIONS):
                    sources.append(os.path.join(current, name))
    return sources


def format_code(check_only):
    if which("clang-format") is None:
        fail("clang-format not found on PATH (install LLVM).")
    sources = collect_sources()
    if not sources:
        log("no C/C++ sources found under src/, tests/ or examples/")
        return
    if check_only:
        failed = [
            path for path in sources
            if subprocess.run(
                ["clang-format", "--dry-run", "--Werror", path], cwd=REPO_ROOT
            ).returncode != 0
        ]
        if failed:
            fail(f"{len(failed)} file(s) need formatting; run setup.bat --format")
        log(f"all {len(sources)} file(s) correctly formatted")
    else:
        run(["clang-format", "-i", *sources])
        log(f"formatted {len(sources)} file(s)")


def clean():
    for name in OUTPUT_DIRS:
        path = os.path.join(REPO_ROOT, name)
        if os.path.isdir(path):
            shutil.rmtree(path, ignore_errors=True)
            log(f"removed {name}/")


def _docs_python():
    """Returns this interpreter, with the documentation packages installed.

    setup.bat provisions and activates the virtual environment before handing
    control here, so this is already that environment's interpreter and nothing
    lands in a developer's global site-packages. Only --docs needs third-party
    packages, so only --docs installs them.
    """
    # Installed on every run rather than probed for importability. pip is
    # idempotent once the pins are satisfied, and a probe would silently miss
    # an edit to docs/requirements.txt.
    run([sys.executable, "-m", "pip", "install", "--disable-pip-version-check",
         "-q", "-r", os.path.join("docs", "requirements.txt")])
    return sys.executable


def build_docs():
    """Generates the API documentation into _docs/html."""
    # Both preconditions are checked before any work starts, so a missing tool
    # is reported immediately rather than after a Doxygen run that is about to
    # be wasted.
    if which("doxygen") is None:
        fail("doxygen not found on PATH. Install it from https://www.doxygen.nl/")
    if sys.prefix == sys.base_prefix:
        fail("run this through setup.bat. It provisions the virtual "
             "environment the documentation packages install into, and "
             "installing them globally is what that arrangement avoids")

    # Doxygen 1.10 only creates the last path component of XML_OUTPUT itself,
    # so the intermediate "doxygen" directory has to exist beforehand.
    os.makedirs(os.path.join(DOCS_OUTPUT_DIR, "doxygen", "xml"), exist_ok=True)

    log("running doxygen")
    result = subprocess.run(["doxygen", "Doxyfile"], cwd=DOCS_DIR)
    if result.returncode != 0:
        fail(f"doxygen failed ({result.returncode})")

    python = _docs_python()
    html_dir = os.path.join(DOCS_OUTPUT_DIR, "html")
    log("running sphinx")
    # -W turns warnings into errors: a warning here is a broken cross-reference
    # or an undocumented public symbol, which should fail as loudly as a
    # formatting violation.
    result = subprocess.run(
        [python, "-m", "sphinx", "-b", "html", "-W", "--keep-going",
         DOCS_DIR, html_dir],
        cwd=REPO_ROOT,
    )
    if result.returncode != 0:
        fail(f"sphinx failed ({result.returncode})")

    log(f"documentation written to {os.path.join(html_dir, 'index.html')}")


def build_parser():
    parser = argparse.ArgumentParser(
        prog="setup.py",
        description="Build orchestration for mhook.",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    types_help = "types: " + ", ".join(BUILD_TYPES)
    parser.add_argument("--build", metavar="TYPE", help=f"configure, build and install\n{types_help}")
    parser.add_argument("--run-tests", metavar="TYPE",
        help="build then run tests with JUnit + HTML reports")
    parser.add_argument("--package", metavar="TYPE",
        help="build pipeline then package with CPack")
    parser.add_argument("--format", action="store_true",
        help="format C/C++ sources under src/, tests/ and examples/ with clang-format")
    parser.add_argument("--format-check", action="store_true",
        help="check formatting without modifying files")
    parser.add_argument("--clean", action="store_true",
        help="remove _build/_install/_package/_docs")
    parser.add_argument("--docs", action="store_true",
        help="generate the API documentation into _docs/html")
    parser.add_argument("--check-commit-msg", metavar="FILE",
        help="validate a commit message file (used by the commit-msg hook)")
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if not any(vars(args).values()):
        parser.print_help()
        sys.exit(1)

    # Before configure_git_hooks: this runs on every commit, and reconfiguring
    # hooks each time would be pointless work.
    if args.check_commit_msg:
        check_commit_msg(args.check_commit_msg)
        return

    configure_git_hooks()

    if args.clean:
        clean()
    if args.format:
        format_code(check_only=False)
    if args.format_check:
        format_code(check_only=True)
    if args.build:
        build(args.build)
    if args.run_tests:
        build(args.run_tests)
        run_tests(args.run_tests)
    if args.package:
        package(args.package)
    if args.docs:
        build_docs()


if __name__ == "__main__":
    main()
