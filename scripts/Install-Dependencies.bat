@echo off
setlocal
for %%I in ("%~dp0..") do set "PROJECT_ROOT=%%~fI"
pushd "%PROJECT_ROOT%"
where py >nul 2>nul
if %errorlevel%==0 (set "PY=py -3") else (set "PY=python")
%PY% -m pip install --upgrade pip
if errorlevel 1 goto failed
%PY% -m pip install -r "%PROJECT_ROOT%\requirements.txt"
if errorlevel 1 goto failed
%PY% -c "import PySide6; print('PySide6 GUI runtime is available:', PySide6.__version__)"
if errorlevel 1 goto failed
echo.
echo Dependencies installed. Launch scripts\Run-TCTC-Guardian.bat.
popd
pause
exit /b 0
:failed
echo Dependency installation failed. Check Python 3.11+ and network connectivity.
popd
pause
exit /b 1
