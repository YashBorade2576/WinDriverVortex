@echo off
echo DriverVulnHunter-IDAPRO Verification
echo ===================================
echo.

echo Checking Python installation...
python --version
if errorlevel 1 (
    echo FAIL: Python not found
    goto failure
)
echo PASS: Python installed

echo.
echo Checking Python dependencies...
python -c "import pefile" >nul 2>&1
if errorlevel 1 (
    echo FAIL: pefile library missing
    goto failure
)
echo PASS: pefile library found

python -c "import capstone" >nul 2>&1
if errorlevel 1 (
    echo FAIL: capstone library missing
    goto failure
)
echo PASS: capstone library found

echo.
echo Checking .NET installation...
dotnet --version >nul 2>&1
if errorlevel 1 (
    echo FAIL: .NET SDK not found
    goto failure
)
echo PASS: .NET SDK installed

echo.
echo Checking project structure...
if not exist "python_engine\driver_analyzer.py" (
    echo FAIL: Python engine files missing
    goto failure
)
echo PASS: Python engine files present

if not exist "gui_application\src\MainForm.cs" (
    echo FAIL: GUI source files missing
    goto failure
)
echo PASS: GUI source files present

if not exist "ida_plugin\src\driver_analyzer_plugin.cpp" (
    echo WARNING: IDA plugin source files missing
) else (
    echo PASS: IDA plugin source files present
)

echo.
echo Checking GUI application build...
cd gui_application
dotnet build --nologo --verbosity minimal >nul 2>&1
if errorlevel 1 (
    echo FAIL: GUI application build failed
    cd ..
    goto failure
)
cd ..

if exist "gui_application\bin\Debug\net5.0-windows\DriverAnalyzerGUI.exe" (
    echo PASS: GUI application built successfully
) else (
    echo FAIL: GUI application executable not found
    goto failure
)

echo.
echo ===================================
echo VERIFICATION PASSED
echo ===================================
echo All components are properly installed
echo.
pause
exit /b 0

:failure
echo.
echo ===================================
echo VERIFICATION FAILED
echo ===================================
echo Please check the errors above
echo Refer to INSTALLATION.md for setup instructions
echo.
pause
exit /b 1
