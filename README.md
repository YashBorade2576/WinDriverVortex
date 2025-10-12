# Quick Start Guide - WinDriverVortex

### 1. Install Dependencies

Open Command Prompt as Administrator and run:

```cmd
scripts\install.bat
```

This will automatically:
- Check for Python and .NET
- Install required Python packages
- Build the GUI application

### 2. Verify Installation

Run the verification script:

```cmd
scripts\verify.bat
```

If all checks pass, you're ready to use WinDriverVortex.

## Quick Analysis

### Method 1: GUI Analysis (Recommended for Beginners)

1. **Launch the application**:
   ```cmd
   gui_application\bin\Release\net5.0-windows\DriverAnalyzerGUI.exe
   ```

2. **Select a driver file**:
   - Click the "Browse" button
   - Navigate to a Windows driver file (.sys extension)
   - Common locations: C:\Windows\System32\drivers\

3. **Run analysis**:
   - Click the "Analyze" button
   - Wait for the analysis to complete
   - Review results in the main table

4. **Export results**:
   - Use "Export Report" to save findings
   - Choose JSON or text format

### Method 2: Command Line Analysis

For quick analysis without the GUI:

```cmd
cd python_engine
python driver_analyzer.py C:\Windows\System32\drivers\your_driver.sys
```

The output will be in JSON format, suitable for automated processing.

### Method 3: IDA Pro Integration (Advanced Users)

1. Build the IDA plugin (see INSTALLATION.md)
2. Copy the plugin to your IDA Pro plugins directory
3. Load a driver in IDA Pro
4. Press Ctrl+Alt+D or use Edit > Plugins > WinDriverVortex
5. View results in IDA output window

## Proof Of Analysis

Test the system with a known Windows driver:

```cmd
cd python_engine
python driver_analyzer.py C:\Windows\System32\drivers\ntoskrnl.exe
```


### Severity Levels
- **Critical (5)**: Memory corruption, privilege escalation
- **High (4)**: Buffer overflows, unsafe functions
- **Medium (3)**: Potential issues, code patterns
- **Low (2)**: Informational findings
- **Info (1)**: General observations

### Common Vulnerability Types
- **Buffer Overflow**: Unsafe memory operations
- **Use After Free**: Memory management issues
- **Integer Overflow**: Arithmetic operation risks
- **Unsafe Functions**: Dangerous API usage
- **IOCTL Issues**: Driver communication vulnerabilities


### Prerequisites Development
- Python 3.7+ with development headers
- .NET 5.0+ SDK
- Visual Studio 2019+ (for C++ development)
- IDA Pro SDK (for plugin development)

### Installation For Environment Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/odaysec/WinDriverVortex.git
   cd WinDriverVortex
   ```

2. **Set up Python virtual environment** (recommended):
   ```bash
   python -m venv venv
   venv\Scripts\activate
   pip install -r python_engine\requirements.txt
   ```

3. **Restore .NET dependencies**:
   ```bash
   cd gui_application
   dotnet restore
   cd ..
   ```

### Component Project Analysis

**Python Analysis Engine** (`python_engine/`)
- Core vulnerability detection logic
- PE file parsing and analysis
- Pattern matching algorithms
- JSON report generation

**GUI Application** (`gui_application/`)
- Windows Forms user interface
- File selection and management
- Results visualization
- Report export functionality

**IDA Pro Plugin** (`ida_plugin/`)
- Native IDA Pro integration
- Binary pattern matching
- Real-time analysis during disassembly
- IDA SDK integration


### Adding New Vulnerability Patterns

#### Python Engine
Edit `python_engine/pattern_matcher.py`:

```python
# Add new pattern to vulnerability_patterns
self.vulnerability_patterns['new_vulnerability'] = [
    {
        'pattern': b'\x90\x90\x90',  # Byte pattern to match
        'description': 'Description of the vulnerability',
        'severity': 3  # 1-5 scale
    }
]
```

#### IDA Plugin
Edit `ida_plugin/src/vulnerability_detector.cpp`:

```cpp
bool VulnerabilityDetector::AnalyzeNewVulnerability(ea_t address)
{
    const char* pattern = "\x90\x90\x90";
    const char* mask = "xxx";
    
    if (CheckPattern(address, pattern, mask))
    {
        AddFinding("FunctionName", "New Vulnerability", address, 3,
                  "Description of detection");
        return true;
    }
    return false;
}
```

### Modifying Analysis Behavior

#### Changing Severity Levels
Edit the severity assignments in detection methods:

```python
# In Python pattern_matcher.py
'severity': 4  # Change from 1-5 as needed
```

```cpp
// In C++ vulnerability_detector.cpp
AddFinding(..., 4, ...);  // Change severity level
```

#### Adding New File Types
Modify the file type detection in `driver_analyzer.py`:

```python
def is_supported_file(file_path):
    # Add new file extensions here
    return file_path.lower().endswith(('.sys', '.drv', '.exe', '.dll'))
```

## Building and Analysis

### Build Commands

**Python Engine** (no build required):
```bash
cd python_engine
python driver_analyzer.py --test
```

**GUI Application**:
```bash
cd gui_application
dotnet clean
dotnet build --configuration Release
```

**IDA Plugin**:
```bash
cd ida_plugin
build_plugin.bat
```

### Testing Changes

1. **Test Python engine**:
   ```bash
   cd python_engine
   python -m pytest tests/ -v
   ```

2. **Test GUI functionality**:
   - Build and run the application
   - Test file browsing and analysis
   - Verify report generation

3. **Test IDA plugin**:
   - Build and install the plugin
   - Load a test driver in IDA Pro
   - Run analysis and verify results

## Code Standards

### Python Code
- Follow PEP 8 style guide
- Use type hints where appropriate
- Include docstrings for functions
- Write unit tests for new features

### C# Code
- Follow Microsoft C# coding conventions
- Use meaningful variable names
- Implement proper error handling
- Use async/await for long operations

### C++ Code
- Follow IDA Pro plugin conventions
- Use IDA SDK types and functions
- Include proper error checking
- Maintain compatibility with IDA versions

## Debugging

### Python Debugging
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

### C# Debugging
- Use Visual Studio debugger
- Or add Debug.WriteLine statements
- Check Windows Event Viewer for crashes

### IDA Plugin Debugging
- Use IDA's built-in debugger
- Check IDA output window for messages
- Use msg() function for logging

