# DriverVulnHunter-IDAPRO 

## System Requirements

### Required Software
- Windows 10 or Windows 11 (64-bit)
- Python 3.7 or newer
- .NET 5.0 SDK or newer
- 8GB RAM minimum, 16GB recommended
- 2GB free disk space

### Optional Components
- IDA Pro 7.0 or newer for plugin functionality
- Visual Studio 2019+ for plugin compilation

## Installation Steps

###   Install Python

Download and install Python from python.org:

1. Visit https://www.python.org/downloads/
2. Download Python 3.9 or newer
3. Run the installer
4. Check "Add Python to PATH" during installation
5. Complete the installation

Verify Python installation:
```cmd
python --version
pip --version
```

###   Install Python Dependencies

Open Command Prompt and install required packages:

```cmd
pip install pefile
pip install capstone
pip install simplejson
```

Verify the installations work correctly:
```cmd
python -c "import pefile, capstone; print('Libraries imported successfully')"
```

###   Install .NET SDK

Download and install .NET SDK:

1. Visit https://dotnet.microsoft.com/download
2. Download .NET 5.0 SDK or newer
3. Run the installer
4. Follow the setup wizard

Verify .NET installation:
```cmd
dotnet --version
```

###   Build the GUI Application

Build the C# Windows Forms application:

```cmd
cd gui_application
dotnet restore
dotnet build --configuration Release
```

  the application:
```cmd
cd bin\Release\net5.0-windows\
DriverAnalyzerGUI.exe
```

###   IDA Pro Plugin Setup (Optional)

#### Prerequisites
- IDA Pro 7.0 or newer installed
- IDA Pro SDK downloaded from Hex-Rays
- Visual Studio with C++ development tools

#### Build the Plugin

1. Download IDA Pro SDK from the Hex-Rays website
2. Extract the SDK to a known location
3. Edit the build script with correct paths:
   - Open `ida_plugin/build_plugin.bat`
   - Update the IDA_SDK_DIR and IDA_INSTALL_DIR variables

4. Build the plugin:
```cmd
cd ida_plugin
build_plugin.bat
```

5. The plugin file will be copied to your IDA Pro plugins directory

#### Manual Compilation

If the build script fails, compile manually:

1. Open "Developer Command Prompt" for Visual Studio
2. Navigate to the ida_plugin directory
3. Compile the source files:
```cmd
cl /c /D__IDP__ /D__PLUGIN__ /MT /W0 /D_CRT_SECURE_NO_WARNINGS /I"C:\Program Files\IDA Pro SDK\include" src\vulnerability_detector.cpp src\driver_analyzer_plugin.cpp
```

4. Link the plugin:
```cmd
link /DLL /OUT:driver_analyzer_plugin.plw /SUBSYSTEM:CONSOLE vulnerability_detector.obj driver_analyzer_plugin.obj "C:\Program Files\IDA Pro SDK\lib\x86_win_vc_32\ida.lib"
```

5. Copy the plugin to IDA Pro plugins folder

## Verification

###   Python Engine

Verify the Python analysis engine works:

```cmd
cd python_engine
python driver_analyzer.py --help
```

###   GUI Application

1. Launch the GUI application from `gui_application/bin/Release/net5.0-windows/DriverAnalyzerGUI.exe`
2. Click the Browse button and select a Windows driver file (.sys extension)
3. Click Analyze to   the functionality
4. The application should display analysis results without errors

###   IDA Plugin

1. Start IDA Pro and load a Windows driver
2. Use the hotkey Ctrl+Alt+D or navigate to Edit > Plugins > DriverVulnHunter
3. Check the IDA output window for analysis results



### Command Line Analysis
Analyze a driver file using the Python engine:

```cmd
cd python_engine
python driver_analyzer.py C:\Windows\System32\drivers\example.sys
```

### GUI Analysis

1. Start DriverAnalyzerGUI.exe
2. Click Browse and select a driver file
3. Click Analyze to begin scanning
4. Review the results in the table and report panel
5. Use Export Report to save findings

### IDA Pro Integration

1. Load a driver binary in IDA Pro
2. Run the DriverVulnHunter plugin
3. View detected vulnerabilities in the output window
4. Addresses are linked to corresponding code locations

## Troubleshooting

### Common Issues

**Python not found in PATH**
- Reinstall Python and check "Add to PATH"
- Or manually add Python installation directory to system PATH

**Module import errors**
- Ensure all dependencies are installed: pip install pefile capstone
- Check Python version compatibility

**.NET build failures**
- Verify .NET SDK is installed correctly
- Run dotnet restore before building
- Check for missing NuGet packages

**IDA plugin compilation errors**
- Confirm IDA SDK paths are correct
- Ensure Visual Studio C++ tools are installed
- Check IDA Pro version compatibility

**GUI application crashes**
- Run the application as Administrator
- Verify file permissions for target drivers
- Check Python integration paths

### Getting Help

If you encounter issues:

1. Check the documentation in the docs folder
2. Verify all prerequisites are installed
3. Ensure paths and environment variables are set correctly
4.   with a known good driver file


## Support
For technical support or to report issues, please check the project documentation or create an issue in the project repository.
