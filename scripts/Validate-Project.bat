@echo off
@echo off
setlocal EnableExtensions

for %%I in ("%~dp0..") do set "PROJECT_ROOT=%%~fI"
pushd "%PROJECT_ROOT%"
if errorlevel 1 goto push_failed

where py >nul 2>nul
if not errorlevel 1 (
    set "PY=py -3"
) else (
    set "PY=python"
)

echo.
echo ==========================================
echo       TCTC Guardian Z797 Validation
echo ==========================================
echo Python command: %PY%
echo.

echo [1/3] Compiling Python sources...
call %PY% -m compileall -q src tests
if errorlevel 1 goto failed
echo [PASS] Compilation completed.

echo.
echo [2/3] Running application self-check...
call %PY% src\main.py --self-check
if errorlevel 1 goto failed
echo [PASS] Application self-check completed.

echo.
echo [3/3] Running unit tests...
call %PY% -m unittest discover -s tests -t . -v
if errorlevel 1 goto failed
echo.
echo [PASS] Unit tests completed.

echo.
echo ==========================================
echo       ALL VALIDATION CHECKS PASSED
echo ==========================================
echo.
echo Note: Windows native APIs and the PySide6 GUI
echo still require functional Windows testing.
echo.
pause
exit /b 0

:failed
set "VALIDATION_EXIT=%ERRORLEVEL%"
if "%VALIDATION_EXIT%"=="0" set "VALIDATION_EXIT=1"
echo.
echo ==========================================
echo          VALIDATION FAILED
echo ==========================================
echo Exit code: %VALIDATION_EXIT%
echo Review the error output above.
echo.
pause
exit /b %VALIDATION_EXIT%