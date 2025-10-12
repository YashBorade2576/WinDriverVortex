using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using Newtonsoft.Json;

namespace DriverAnalyzerGUI
{
    public class PythonIntegration
    {
        private string pythonExecutablePath;
        private string analysisScriptPath;

        public PythonIntegration()
        {
            FindPythonInstallation();
            LocateAnalysisScript();
        }

        private void FindPythonInstallation()
        {
            string[] possiblePythonPaths = {
                "python.exe",
                "python3.exe", 
                "py.exe",
                @"C:\Python39\python.exe",
                @"C:\Python310\python.exe",
                @"C:\Python311\python.exe",
                @"C:\Program Files\Python39\python.exe",
                @"C:\Program Files\Python310\python.exe",
                @"C:\Program Files\Python311\python.exe"
            };

            foreach (string pythonPath in possiblePythonPaths)
            {
                if (File.Exists(pythonPath))
                {
                    pythonExecutablePath = pythonPath;
                    return;
                }

                string pathPython = FindPythonInPath(pythonPath);
                if (pathPython != null)
                {
                    pythonExecutablePath = pathPython;
                    return;
                }
            }

            throw new InvalidOperationException("Python installation not found. Please install Python 3.7 or later.");
        }

        private string FindPythonInPath(string pythonName)
        {
            string pathVariable = Environment.GetEnvironmentVariable("PATH");
            if (string.IsNullOrEmpty(pathVariable))
                return null;

            string[] pathDirectories = pathVariable.Split(Path.PathSeparator);
            foreach (string directory in pathDirectories)
            {
                try
                {
                    string fullPath = Path.Combine(directory, pythonName);
                    if (File.Exists(fullPath))
                        return fullPath;
                }
                catch
                {
                    continue;
                }
            }

            return null;
        }

        private void LocateAnalysisScript()
        {
            string currentDirectory = Directory.GetCurrentDirectory();
            string[] possibleScriptPaths = {
                Path.Combine(currentDirectory, "python_engine", "driver_analyzer.py"),
                Path.Combine(currentDirectory, "..", "python_engine", "driver_analyzer.py"),
                Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "python_engine", "driver_analyzer.py")
            };

            foreach (string scriptPath in possibleScriptPaths)
            {
                if (File.Exists(scriptPath))
                {
                    analysisScriptPath = scriptPath;
                    return;
                }
            }

            throw new FileNotFoundException("Python analysis script 'driver_analyzer.py' not found.");
        }

        public List<VulnerabilityFinding> AnalyzeDriver(string driverFilePath)
        {
            if (!File.Exists(driverFilePath))
            {
                throw new FileNotFoundException($"Driver file not found: {driverFilePath}");
            }

            if (!File.Exists(analysisScriptPath))
            {
                throw new FileNotFoundException($"Analysis script not found: {analysisScriptPath}");
            }

            ProcessStartInfo processConfiguration = new ProcessStartInfo
            {
                FileName = pythonExecutablePath,
                Arguments = $"\"{analysisScriptPath}\" \"{driverFilePath}\"",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8,
                WorkingDirectory = Path.GetDirectoryName(analysisScriptPath)
            };

            StringBuilder outputBuilder = new StringBuilder();
            StringBuilder errorBuilder = new StringBuilder();

            using (Process analysisProcess = new Process())
            {
                analysisProcess.StartInfo = processConfiguration;
                
                analysisProcess.OutputDataReceived += (sender, e) =>
                {
                    if (!string.IsNullOrEmpty(e.Data))
                    {
                        outputBuilder.AppendLine(e.Data);
                    }
                };

                analysisProcess.ErrorDataReceived += (sender, e) =>
                {
                    if (!string.IsNullOrEmpty(e.Data))
                    {
                        errorBuilder.AppendLine(e.Data);
                    }
                };

                analysisProcess.Start();
                analysisProcess.BeginOutputReadLine();
                analysisProcess.BeginErrorReadLine();

                bool processCompleted = analysisProcess.WaitForExit(45000);

                if (!processCompleted)
                {
                    analysisProcess.Kill();
                    throw new TimeoutException("Python analysis process timed out after 45 seconds.");
                }

                if (analysisProcess.ExitCode != 0)
                {
                    string errorDetails = errorBuilder.ToString();
                    throw new ApplicationException($"Python analysis failed with exit code {analysisProcess.ExitCode}: {errorDetails}");
                }
            }

            string analysisOutput = outputBuilder.ToString();
            return ParseAnalysisResults(analysisOutput);
        }

        private List<VulnerabilityFinding> ParseAnalysisResults(string analysisOutput)
        {
            var findingsList = new List<VulnerabilityFinding>();

            if (string.IsNullOrEmpty(analysisOutput))
            {
                return findingsList;
            }

            try
            {
                PythonAnalysisResult analysisResult = JsonConvert.DeserializeObject<PythonAnalysisResult>(analysisOutput);
                
                if (analysisResult?.findings != null)
                {
                    foreach (var pythonFinding in analysisResult.findings)
                    {
                        findingsList.Add(new VulnerabilityFinding
                        {
                            FunctionName = pythonFinding.function_name ?? "Unknown Function",
                            VulnerabilityType = pythonFinding.vulnerability_type ?? "Unknown Type",
                            Address = pythonFinding.address,
                            Severity = pythonFinding.severity,
                            Description = pythonFinding.description ?? "No description provided",
                            Evidence = pythonFinding.evidence ?? "No evidence available"
                        });
                    }
                }
            }
            catch (JsonException jsonException)
            {
                findingsList = ParseTextOutput(analysisOutput);
            }
            catch (Exception generalException)
            {
                throw new ApplicationException($"Failed to parse analysis results: {generalException.Message}", generalException);
            }

            return findingsList;
        }

        private List<VulnerabilityFinding> ParseTextOutput(string textOutput)
        {
            var textFindings = new List<VulnerabilityFinding>();
            string[] outputLines = textOutput.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);

            foreach (string line in outputLines)
            {
                if (line.Contains("Vulnerability:") || line.Contains("Severity:"))
                {
                    try
                    {
                        var finding = ExtractFindingFromTextLine(line);
                        if (finding != null)
                        {
                            textFindings.Add(finding);
                        }
                    }
                    catch
                    {
                        continue;
                    }
                }
            }

            return textFindings;
        }

        private VulnerabilityFinding ExtractFindingFromTextLine(string textLine)
        {
            if (textLine.Contains("Severity:") && textLine.Contains("Address:"))
            {
                return new VulnerabilityFinding
                {
                    FunctionName = "Text Analysis",
                    VulnerabilityType = "Pattern Detected",
                    Address = ExtractAddressFromText(textLine),
                    Severity = ExtractSeverityFromText(textLine),
                    Description = "Vulnerability pattern identified in text output",
                    Evidence = textLine.Trim()
                };
            }

            return null;
        }

        private uint ExtractAddressFromText(string textLine)
        {
            int addressIndex = textLine.IndexOf("0x");
            if (addressIndex >= 0)
            {
                string addressString = textLine.Substring(addressIndex, 10);
                if (uint.TryParse(addressString.Replace("0x", ""), System.Globalization.NumberStyles.HexNumber, null, out uint address))
                {
                    return address;
                }
            }
            return 0;
        }

        private int ExtractSeverityFromText(string textLine)
        {
            if (textLine.Contains("Severity: 5") || textLine.Contains("Critical")) return 5;
            if (textLine.Contains("Severity: 4") || textLine.Contains("High")) return 4;
            if (textLine.Contains("Severity: 3") || textLine.Contains("Medium")) return 3;
            if (textLine.Contains("Severity: 2") || textLine.Contains("Low")) return 2;
            return 1;
        }

        public bool TestPythonConnection()
        {
            try
            {
                ProcessStartInfo testProcessInfo = new ProcessStartInfo
                {
                    FileName = pythonExecutablePath,
                    Arguments = "--version",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true
                };

                using (Process testProcess = Process.Start(testProcessInfo))
                {
                    testProcess.WaitForExit(5000);
                    return testProcess.ExitCode == 0;
                }
            }
            catch
            {
                return false;
            }
        }
    }

    public class PythonAnalysisResult
    {
        public List<PythonFinding> findings { get; set; }
        public AnalysisSummary summary_stats { get; set; }
    }

    public class PythonFinding
    {
        public string function_name { get; set; }
        public string vulnerability_type { get; set; }
        public uint address { get; set; }
        public int severity { get; set; }
        public string description { get; set; }
        public string evidence { get; set; }
    }

    public class AnalysisSummary
    {
        public int total_findings { get; set; }
        public int critical_count { get; set; }
        public int high_count { get; set; }
        public int medium_count { get; set; }
        public int low_count { get; set; }
    }
}
