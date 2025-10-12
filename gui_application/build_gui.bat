@echo off
echo Building Driver Analyzer GUI Application...
echo.

dotnet build --configuration Release

if %ERRORLEVEL% EQU 0 (
    echo.
    echo Build successful!
    echo Output: bin\Release\net5.0-windows\
) else (
    echo.
    echo Build failed!
)

pause
