namespace DriverAnalyzerGUI
{
    partial class MainForm
    {
        private System.ComponentModel.IContainer components = null;
        private TextBox filePathBox;
        private Button browseButton;
        private Button analyzeButton;
        private DataGridView findingsGrid;
        private TextBox reportTextBox;
        private Label statusLabel;
        private Button exportButton;
        private Label titleLabel;

        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        private void InitializeComponent()
        {
            this.SuspendLayout();
            
            this.Size = new System.Drawing.Size(1200, 800);
            this.Text = "Driver Vulnerability Analyzer";
            this.StartPosition = FormStartPosition.CenterScreen;
            this.Font = new System.Drawing.Font("Segoe UI", 9F);
            
            CreateTitleSection();
            CreateFileSelectionSection();
            CreateResultsGrid();
            CreateReportSection();
            CreateStatusSection();
            
            this.ResumeLayout(false);
        }

        private void CreateTitleSection()
        {
            titleLabel = new Label();
            titleLabel.Text = "Driver Vulnerability Analyzer";
            titleLabel.Font = new System.Drawing.Font("Segoe UI", 14F, System.Drawing.FontStyle.Bold);
            titleLabel.Location = new System.Drawing.Point(20, 15);
            titleLabel.Size = new System.Drawing.Size(300, 30);
            this.Controls.Add(titleLabel);
        }

        private void CreateFileSelectionSection()
        {
            var fileLabel = new Label();
            fileLabel.Text = "Driver File:";
            fileLabel.Location = new System.Drawing.Point(20, 60);
            fileLabel.Size = new System.Drawing.Size(70, 20);
            this.Controls.Add(fileLabel);
            
            filePathBox = new TextBox();
            filePathBox.Location = new System.Drawing.Point(95, 57);
            filePathBox.Size = new System.Drawing.Size(600, 20);
            filePathBox.ReadOnly = true;
            this.Controls.Add(filePathBox);
            
            browseButton = new Button();
            browseButton.Text = "Browse";
            browseButton.Location = new System.Drawing.Point(705, 55);
            browseButton.Size = new System.Drawing.Size(75, 25);
            browseButton.Click += new EventHandler(browseButton_Click);
            this.Controls.Add(browseButton);
            
            analyzeButton = new Button();
            analyzeButton.Text = "Analyze";
            analyzeButton.Location = new System.Drawing.Point(790, 55);
            analyzeButton.Size = new System.Drawing.Size(75, 25);
            analyzeButton.BackColor = System.Drawing.Color.SteelBlue;
            analyzeButton.ForeColor = System.Drawing.Color.White;
            analyzeButton.Click += new EventHandler(analyzeButton_Click);
            this.Controls.Add(analyzeButton);
        }

        private void CreateResultsGrid()
        {
            var resultsLabel = new Label();
            resultsLabel.Text = "Vulnerability Findings:";
            resultsLabel.Location = new System.Drawing.Point(20, 95);
            resultsLabel.Size = new System.Drawing.Size(150, 20);
            resultsLabel.Font = new System.Drawing.Font("Segoe UI", 9F, System.Drawing.FontStyle.Bold);
            this.Controls.Add(resultsLabel);
            
            findingsGrid = new DataGridView();
            findingsGrid.Location = new System.Drawing.Point(20, 120);
            findingsGrid.Size = new System.Drawing.Size(1150, 250);
            findingsGrid.ScrollBars = ScrollBars.Vertical;
            findingsGrid.RowHeadersVisible = false;
            findingsGrid.AllowUserToAddRows = false;
            findingsGrid.AllowUserToDeleteRows = false;
            findingsGrid.AllowUserToResizeRows = false;
            this.Controls.Add(findingsGrid);
        }

        private void CreateReportSection()
        {
            var reportLabel = new Label();
            reportLabel.Text = "Analysis Report:";
            reportLabel.Location = new System.Drawing.Point(20, 385);
            reportLabel.Size = new System.Drawing.Size(150, 20);
            reportLabel.Font = new System.Drawing.Font("Segoe UI", 9F, System.Drawing.FontStyle.Bold);
            this.Controls.Add(reportLabel);
            
            exportButton = new Button();
            exportButton.Text = "Export Report";
            exportButton.Location = new System.Drawing.Point(1050, 382);
            exportButton.Size = new System.Drawing.Size(120, 25);
            exportButton.Click += new EventHandler(exportButton_Click);
            this.Controls.Add(exportButton);
            
            reportTextBox = new TextBox();
            reportTextBox.Location = new System.Drawing.Point(20, 410);
            reportTextBox.Size = new System.Drawing.Size(1150, 300);
            reportTextBox.Multiline = true;
            reportTextBox.ScrollBars = ScrollBars.Both;
            reportTextBox.ReadOnly = true;
            reportTextBox.Font = new System.Drawing.Font("Consolas", 9F);
            this.Controls.Add(reportTextBox);
        }

        private void CreateStatusSection()
        {
            statusLabel = new Label();
            statusLabel.Text = "Ready to analyze driver files";
            statusLabel.Location = new System.Drawing.Point(20, 720);
            statusLabel.Size = new System.Drawing.Size(500, 20);
            statusLabel.ForeColor = System.Drawing.Color.DarkBlue;
            this.Controls.Add(statusLabel);
        }
    }
}
