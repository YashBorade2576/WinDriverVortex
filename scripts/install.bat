@echo off
echo DriverVulnHunter-IDAPRO Installation
echo ====================================
echo.

echo   Checking Python installation...
python --version >nul 2>&1
if errorlevel 1 (
    echo Error: Python not found in PATH
    echo Please install Python 3.7 or newer from python.org
    echo Make sure to check "Add Python to PATH" during installation
    pause
    exit /b 1
)

echo Python found, installing dependencies...
echo.

echo Installing pefile for PE parsing...
pip install pefile
if errorlevel 1 (
    echo Error: Failed to install pefile
    echo Please check your Python installation
    pause
    exit /b 1
)

echo Installing capstone for disassembly...
pip install capstone
if errorlevel 1 (
    echo Error: Failed to install capstone
    echo Please check your Python installation
    pause
    exit /b 1
)

echo Installing simplejson for data handling...
pip install simplejson
if errorlevel 1 (
    echo Warning: simplejson installation failed, using built-in JSON
)

echo.
echo Python dependencies installed successfully
echo.

echo   Checking .NET installation...
dotnet --version >nul 2>&1
if errorlevel 1 (
    echo Error: .NET SDK not found
    echo Please install .NET 5.0 or newer from Microsoft
    pause
    exit /b 1
)

echo Building GUI application...
cd gui_application
dotnet build --configuration Release --nologo
if errorlevel 1 (
    echo Error: Failed to build GUI application
    echo Please check .NET SDK installation
    pause
    exit /b 1
)

cd ..
echo.
echo GUI application built successfully
echo.

echo   Verification...
if exist "python_engine\driver_analyzer.py" (
    echo Python engine files verified
) else (
    echo Error: Python engine files missing
    pause
    exit /b 1
)

if exist "gui_application\bin\Release\net5.0-windows\DriverAnalyzerGUI.exe" (
    echo GUI application verified
) else (
    echo Error: GUI application not found
    pause
    exit /b 1
)

echo.
echo ====================================
echo Installation completed successfully
echo ====================================
echo.
echo Next steps:
echo 1. For GUI usage: Run gui_application\bin\Release\net5.0-windows\DriverAnalyzerGUI.exe
echo 2. For command line: Use python_engine\driver_analyzer.py
echo 3. For IDA Pro: Build and install the plugin from ida_plugin folder
echo.
echo Refer to INSTALLATION.md for detailed usage instructions
echo.
pause
