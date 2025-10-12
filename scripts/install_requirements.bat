@echo off
title DriverVulnHunter - Installation Script
echo ========================================
echo    DRIVER VULNERABILITY ANALYZER
echo    Installation Script
echo ========================================
echo.

echo Checking Python installation...
python --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.7 or later from python.org
    pause
    exit /b 1
)

echo Python found, installing dependencies...
echo.

echo Installing PE file analysis library...
pip install pefile
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Failed to install pefile
    pause
    exit /b 1
)

echo Installing disassembly engine...
pip install capstone
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Failed to install capstone  
    pause
    exit /b 1
)

echo Installing JSON utilities...
pip install simplejson
if %ERRORLEVEL% NEQ 0 (
    echo WARNING: Failed to install simplejson, using built-in JSON
)

echo.
echo Python dependencies installed successfully!
echo.

echo Building C# GUI application...
cd ..\gui_application
dotnet build --configuration Release
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Failed to build C# application
    echo Please ensure .NET 5.0 or later is installed
    pause
    exit /b 1
)

cd ..\scripts
echo.
echo C# GUI application built successfully!
echo.

echo ========================================
echo INSTALLATION COMPLETED SUCCESSFULLY!
echo ========================================
echo.
echo Next steps:
echo 1. IDA Plugin: Build and copy to IDA plugins directory
echo 2. GUI: Run gui_application\bin\Release\net5.0-windows\DriverAnalyzerGUI.exe
echo 3. Python: Use python_engine\driver_analyzer.py for command-line analysis
echo.
echo For support, see the documentation in the docs folder.
echo.
pause
