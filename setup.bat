@echo off
setlocal

rem Single entry point for every build task. It performs the environment checks
rem once, here, so that nothing downstream has to repeat them: the Git hooks,
rem the VS Code tasks and CI all route through this file.

set "VENV_DIR=%~dp0.venv"
set "SCRIPT=%~dp0scripts\setup.py"

where python >nul 2>nul
if errorlevel 1 (
    echo [setup][error] Python not found on PATH. Install it from https://www.python.org/downloads/
    exit /b 1
)

rem Everything runs inside the virtual environment, so no command ever installs
rem a package into the developer's global site-packages.
if not exist "%VENV_DIR%\Scripts\activate.bat" (
    echo [setup] creating virtual environment in %VENV_DIR%
    python -m venv "%VENV_DIR%"
    if errorlevel 1 (
        echo [setup][error] failed to create the virtual environment
        exit /b 1
    )
)

call "%VENV_DIR%\Scripts\activate.bat"
if errorlevel 1 (
    echo [setup][error] failed to activate the virtual environment
    exit /b 1
)

python "%SCRIPT%" %*
set "EXITCODE=%ERRORLEVEL%"

call deactivate

exit /b %EXITCODE%
