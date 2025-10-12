using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Windows.Forms;
using System.Text;

namespace DriverAnalyzerGUI
{
    public partial class MainForm : Form
    {
        private List<VulnerabilityFinding> currentFindings;
        private PythonIntegration pythonIntegration;

        public MainForm()
        {
            InitializeComponent();
            pythonIntegration = new PythonIntegration();
            currentFindings = new List<VulnerabilityFinding>();
            SetupDataGridView();
        }

        private void SetupDataGridView()
        {
            findingsGrid.AutoGenerateColumns = false;
            findingsGrid.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
            findingsGrid.ReadOnly = true;
            
            findingsGrid.Columns.Add(new DataGridViewTextBoxColumn()
            {
                Name = "SeverityColumn",
                HeaderText = "Severity",
                DataPropertyName = "SeverityText",
                Width = 80
            });
            
            findingsGrid.Columns.Add(new DataGridViewTextBoxColumn()
            {
                Name = "FunctionColumn",
                HeaderText = "Function",
                DataPropertyName = "FunctionName",
                Width = 150
            });
            
            findingsGrid.Columns.Add(new DataGridViewTextBoxColumn()
            {
                Name = "TypeColumn",
                HeaderText = "Vulnerability Type",
                DataPropertyName = "VulnerabilityType",
                Width = 180
            });
            
            findingsGrid.Columns.Add(new DataGridViewTextBoxColumn()
            {
                Name = "AddressColumn",
                HeaderText = "Address",
                DataPropertyName = "Address",
                Width = 100
            });
            
            findingsGrid.Columns.Add(new DataGridViewTextBoxColumn()
            {
                Name = "DescriptionColumn",
                HeaderText = "Description",
                DataPropertyName = "Description",
                Width = 250
            });
        }

        private void browseButton_Click(object sender, EventArgs e)
        {
            using (OpenFileDialog fileDialog = new OpenFileDialog())
            {
                fileDialog.Filter = "Driver Files|*.sys;*.drv;*.exe|All Files|*.*";
                fileDialog.Title = "Select Driver File";
                
                if (fileDialog.ShowDialog() == DialogResult.OK)
                {
                    filePathBox.Text = fileDialog.FileName;
                    statusLabel.Text = "File selected. Ready to analyze.";
                }
            }
        }

        private void analyzeButton_Click(object sender, EventArgs e)
        {
            if (string.IsNullOrEmpty(filePathBox.Text) || !File.Exists(filePathBox.Text))
            {
                MessageBox.Show("Please select a valid driver file.", "Invalid File", 
                              MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            try
            {
                Cursor = Cursors.WaitCursor;
                analyzeButton.Enabled = false;
                statusLabel.Text = "Analyzing driver file...";

                currentFindings = pythonIntegration.AnalyzeDriver(filePathBox.Text);
                DisplayFindings();
                GenerateReport();
                
                statusLabel.Text = $"Analysis complete. Found {currentFindings.Count} issues.";
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Analysis failed: {ex.Message}", "Error", 
                              MessageBoxButtons.OK, MessageBoxIcon.Error);
                statusLabel.Text = "Analysis failed.";
            }
            finally
            {
                Cursor = Cursors.Default;
                analyzeButton.Enabled = true;
            }
        }

        private void DisplayFindings()
        {
            findingsGrid.Rows.Clear();
            
            foreach (var finding in currentFindings)
            {
                int rowIndex = findingsGrid.Rows.Add();
                DataGridViewRow row = findingsGrid.Rows[rowIndex];
                
                row.Cells["SeverityColumn"].Value = finding.SeverityText;
                row.Cells["FunctionColumn"].Value = finding.FunctionName;
                row.Cells["TypeColumn"].Value = finding.VulnerabilityType;
                row.Cells["AddressColumn"].Value = $"0x{finding.Address:X8}";
                row.Cells["DescriptionColumn"].Value = finding.Description;
                
                Color rowColor = finding.Severity switch
                {
                    5 => Color.LightCoral,
                    4 => Color.LightSalmon,
                    3 => Color.LightYellow,
                    2 => Color.LightGreen,
                    1 => Color.LightBlue,
                    _ => Color.White
                };
                
                row.DefaultCellStyle.BackColor = rowColor;
            }
        }

        private void GenerateReport()
        {
            StringBuilder reportBuilder = new StringBuilder();
            reportBuilder.AppendLine("DRIVER VULNERABILITY ANALYSIS REPORT");
            reportBuilder.AppendLine("====================================");
            reportBuilder.AppendLine($"Analysis Date: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            reportBuilder.AppendLine($"Target File: {filePathBox.Text}");
            reportBuilder.AppendLine($"Total Findings: {currentFindings.Count}");
            reportBuilder.AppendLine();
            
            var groupedFindings = new Dictionary<int, List<VulnerabilityFinding>>();
            foreach (var finding in currentFindings)
            {
                if (!groupedFindings.ContainsKey(finding.Severity))
                    groupedFindings[finding.Severity] = new List<VulnerabilityFinding>();
                groupedFindings[finding.Severity].Add(finding);
            }
            
            foreach (var severity in groupedFindings.Keys)
            {
                reportBuilder.AppendLine($"SEVERITY {severity} FINDINGS:");
                reportBuilder.AppendLine(new string('-', 50));
                
                foreach (var finding in groupedFindings[severity])
                {
                    reportBuilder.AppendLine($"Type: {finding.VulnerabilityType}");
                    reportBuilder.AppendLine($"Function: {finding.FunctionName}");
                    reportBuilder.AppendLine($"Address: 0x{finding.Address:X8}");
                    reportBuilder.AppendLine($"Description: {finding.Description}");
                    reportBuilder.AppendLine($"Evidence: {finding.Evidence}");
                    reportBuilder.AppendLine();
                }
            }
            
            reportTextBox.Text = reportBuilder.ToString();
        }

        private void exportButton_Click(object sender, EventArgs e)
        {
            if (currentFindings.Count == 0)
            {
                MessageBox.Show("No analysis results to export.", "No Data", 
                              MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            using (SaveFileDialog saveDialog = new SaveFileDialog())
            {
                saveDialog.Filter = "JSON Files|*.json|Text Files|*.txt|All Files|*.*";
                saveDialog.Title = "Export Analysis Report";
                
                if (saveDialog.ShowDialog() == DialogResult.OK)
                {
                    try
                    {
                        string jsonData = Newtonsoft.Json.JsonConvert.SerializeObject(currentFindings, Newtonsoft.Json.Formatting.Indented);
                        File.WriteAllText(saveDialog.FileName, jsonData);
                        
                        MessageBox.Show("Report exported successfully!", "Export Complete", 
                                      MessageBoxButtons.OK, MessageBoxIcon.Information);
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show($"Export failed: {ex.Message}", "Export Error", 
                                      MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }
                }
            }
        }
    }
}
