@echo off
echo Building IDA Pro Plugin for DriverVulnHunter
echo.

set IDA_SDK_DIR=C:\Program Files\IDA Pro SDK
set IDA_INSTALL_DIR=C:\Program Files\IDA Pro

if not exist "%IDA_SDK_DIR%" (
    echo ERROR: IDA Pro SDK not found at %IDA_SDK_DIR%
    echo Please update the IDA_SDK_DIR path in this script
    pause
    exit /b 1
)

if not exist "%IDA_INSTALL_DIR%" (
    echo ERROR: IDA Pro installation not found at %IDA_INSTALL_DIR%
    echo Please update the IDA_INSTALL_DIR path in this script  
    pause
    exit /b 1
)

echo Compiling plugin source files...
cl /nologo /c /D__IDP__ /D__PLUGIN__ /MT /W0 /D_CRT_SECURE_NO_WARNINGS ^
    /I"%IDA_SDK_DIR%\include" ^
    src\vulnerability_detector.cpp src\driver_analyzer_plugin.cpp

if errorlevel 1 (
    echo Compilation failed!
    pause
    exit /b 1
)

echo Linking plugin...
link /nologo /DLL /OUT:driver_analyzer_plugin.plw /SUBSYSTEM:CONSOLE ^
    vulnerability_detector.obj driver_analyzer_plugin.obj ^
    "%IDA_SDK_DIR%\lib\x86_win_vc_32\ida.lib"

if errorlevel 1 (
    echo Linking failed!
    pause
    exit /b 1
)

echo Copying plugin to IDA Pro plugins directory...
copy driver_analyzer_plugin.plw "%IDA_INSTALL_DIR%\plugins\"

if errorlevel 1 (
    echo Failed to copy plugin!
    pause
    exit /b 1
)

echo.
echo Build successful!
echo Plugin installed to: %IDA_INSTALL_DIR%\plugins\driver_analyzer_plugin.plw
echo.
echo Usage: Restart IDA Pro and use Ctrl-Alt-D to run the analyzer
pause
