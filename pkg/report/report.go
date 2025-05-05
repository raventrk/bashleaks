package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/template"
	"time"

	"github.com/fatih/color"
	"github.com/raventrk/bashleaks/pkg/rules"
	"gopkg.in/yaml.v3"
)

// Format, report format
type Format string

const (
	FormatText     Format = "text"
	FormatJSON     Format = "json"
	FormatYAML     Format = "yaml"
	FormatHTML     Format = "html"
	FormatMarkdown Format = "markdown"
)

// Report, contains scan results
type Report struct {
	Findings    []rules.Finding
	ScanTime    time.Time
	SummaryInfo struct {
		TotalFiles        int
		FilesWithFindings int
		CriticalCount     int
		MediumCount       int
		LowCount          int
	}
}

// NewReport, creates a new report
func NewReport(findings []rules.Finding, totalFiles int) *Report {
	r := &Report{
		Findings: findings,
		ScanTime: time.Now(),
	}
	r.SummaryInfo.TotalFiles = totalFiles

	// Calculate summary information
	filesWithFindings := make(map[string]struct{})

	for _, finding := range findings {
		switch finding.Rule.Level() {
		case rules.RiskLevelCritical:
			r.SummaryInfo.CriticalCount++
		case rules.RiskLevelMedium:
			r.SummaryInfo.MediumCount++
		case rules.RiskLevelLow:
			r.SummaryInfo.LowCount++
		}

		filesWithFindings[finding.FilePath] = struct{}{}
	}

	r.SummaryInfo.FilesWithFindings = len(filesWithFindings)

	return r
}

// Print, prints the report in the specified format
func (r *Report) Print(format Format, output io.Writer) error {
	switch format {
	case FormatText:
		return r.printText(output)
	case FormatJSON:
		return r.printJSON(output)
	case FormatYAML:
		return r.printYAML(output)
	case FormatHTML:
		return r.printHTML(output)
	case FormatMarkdown:
		return r.printMarkdown(output)
	default:
		return fmt.Errorf("unsupported report format: %s", format)
	}
}

// printText, prints the report as colored text
func (r *Report) printText(w io.Writer) error {
	// ANSI color codes
	critical := color.New(color.FgHiRed, color.Bold)
	medium := color.New(color.FgYellow, color.Bold)
	low := color.New(color.FgHiGreen, color.Bold)
	title := color.New(color.FgHiWhite, color.Bold, color.BgBlue)
	subtitle := color.New(color.FgHiWhite, color.Bold)
	header := color.New(color.FgHiCyan, color.Bold)
	info := color.New(color.FgCyan)
	highlight := color.New(color.FgHiYellow)

	// Modern title
	title.Fprintf(w, "  BashLeaks Security Scan Report  ")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "%s %s\n\n", subtitle.Sprint("🕒"), info.Sprintf("Scan Time: %s", r.ScanTime.Format("2006-01-02 15:04:05")))

	// Summary - Block format
	header.Fprintln(w, "📊 SCAN SUMMARY")
	fmt.Fprintln(w, "┌─────────────────────────────┬─────────┐")
	fmt.Fprintf(w, "│ %-27s │ %-7d │\n", "Total Files Scanned", r.SummaryInfo.TotalFiles)
	fmt.Fprintf(w, "│ %-27s │ %-7d │\n", "Files With Vulnerabilities", r.SummaryInfo.FilesWithFindings)

	// Risk counts with color display
	if r.SummaryInfo.CriticalCount > 0 {
		fmt.Fprintf(w, "│ %-27s │ %-7s │\n", "Critical Risk", critical.Sprintf("⚠️  %d", r.SummaryInfo.CriticalCount))
	} else {
		fmt.Fprintf(w, "│ %-27s │ %-7s │\n", "Critical Risk", "0")
	}

	if r.SummaryInfo.MediumCount > 0 {
		fmt.Fprintf(w, "│ %-27s │ %-7s │\n", "Medium Risk", medium.Sprintf("⚠️  %d", r.SummaryInfo.MediumCount))
	} else {
		fmt.Fprintf(w, "│ %-27s │ %-7s │\n", "Medium Risk", "0")
	}

	if r.SummaryInfo.LowCount > 0 {
		fmt.Fprintf(w, "│ %-27s │ %-7s │\n", "Low Risk", low.Sprintf("ℹ️  %d", r.SummaryInfo.LowCount))
	} else {
		fmt.Fprintf(w, "│ %-27s │ %-7s │\n", "Low Risk", "0")
	}

	fmt.Fprintln(w, "└─────────────────────────────┴─────────┘")
	fmt.Fprintln(w)

	// Findings - Sort by risk
	sortedFindings := make([]rules.Finding, len(r.Findings))
	copy(sortedFindings, r.Findings)
	sort.Slice(sortedFindings, func(i, j int) bool {
		// First sort by risk level
		riskPriority := map[rules.RiskLevel]int{
			rules.RiskLevelCritical: 0,
			rules.RiskLevelMedium:   1,
			rules.RiskLevelLow:      2,
		}

		if riskPriority[sortedFindings[i].Rule.Level()] != riskPriority[sortedFindings[j].Rule.Level()] {
			return riskPriority[sortedFindings[i].Rule.Level()] < riskPriority[sortedFindings[j].Rule.Level()]
		}

		// If same risk level, sort by filename
		if sortedFindings[i].FilePath != sortedFindings[j].FilePath {
			return sortedFindings[i].FilePath < sortedFindings[j].FilePath
		}

		// If same file, sort by line number
		return sortedFindings[i].LineNumber < sortedFindings[j].LineNumber
	})

	if len(sortedFindings) == 0 {
		fmt.Fprintln(w, low.Sprint("✅ No security vulnerabilities found!"))
		return nil
	}

	header.Fprintln(w, "🔍 DETECTED VULNERABILITIES")
	fmt.Fprintln(w)

	// Print each finding
	lastRiskLevel := ""

	for i, finding := range sortedFindings {
		var riskHeader *color.Color
		var riskIcon string

		// Set style based on risk level
		switch finding.Rule.Level() {
		case rules.RiskLevelCritical:
			riskHeader = critical
			riskIcon = "⚠️ "
		case rules.RiskLevelMedium:
			riskHeader = medium
			riskIcon = "⚠️ "
		case rules.RiskLevelLow:
			riskHeader = low
			riskIcon = "ℹ️ "
		default:
			riskHeader = info
			riskIcon = "• "
		}

		// Add header when we reach a new risk level
		if string(finding.Rule.Level()) != lastRiskLevel {
			if i > 0 {
				fmt.Fprintln(w)
			}
			riskHeader.Fprintf(w, "[ %s %s ]\n", riskIcon, finding.Rule.Level())
			fmt.Fprintln(w, "───────────────────────────────────────────────────")
			lastRiskLevel = string(finding.Rule.Level())
		}

		// Finding details
		fmt.Fprintf(w, "▶ %s\n", highlight.Sprint(finding.Rule.ID()))
		fmt.Fprintf(w, "  📝 %s\n", finding.Rule.Description())
		fmt.Fprintf(w, "  📄 %s:%d\n", finding.FilePath, finding.LineNumber)
		fmt.Fprintf(w, "  💻 %s\n\n", finding.LineContent)
	}

	return nil
}

// printJSON, prints the report in JSON format
func (r *Report) printJSON(w io.Writer) error {
	type jsonReport struct {
		ScanTime string `json:"scan_time"`
		Summary  struct {
			TotalFiles        int `json:"total_files"`
			FilesWithFindings int `json:"files_with_findings"`
			CriticalCount     int `json:"critical_count"`
			MediumCount       int `json:"medium_count"`
			LowCount          int `json:"low_count"`
		} `json:"summary"`
		Findings []struct {
			RuleID      string `json:"rule_id"`
			Description string `json:"description"`
			Level       string `json:"level"`
			FilePath    string `json:"file_path"`
			LineNumber  int    `json:"line_number"`
			LineContent string `json:"line_content"`
		} `json:"findings"`
	}

	jr := jsonReport{
		ScanTime: r.ScanTime.Format("2006-01-02T15:04:05Z07:00"),
	}

	jr.Summary.TotalFiles = r.SummaryInfo.TotalFiles
	jr.Summary.FilesWithFindings = r.SummaryInfo.FilesWithFindings
	jr.Summary.CriticalCount = r.SummaryInfo.CriticalCount
	jr.Summary.MediumCount = r.SummaryInfo.MediumCount
	jr.Summary.LowCount = r.SummaryInfo.LowCount

	jr.Findings = make([]struct {
		RuleID      string `json:"rule_id"`
		Description string `json:"description"`
		Level       string `json:"level"`
		FilePath    string `json:"file_path"`
		LineNumber  int    `json:"line_number"`
		LineContent string `json:"line_content"`
	}, len(r.Findings))

	for i, finding := range r.Findings {
		jr.Findings[i].RuleID = finding.Rule.ID()
		jr.Findings[i].Description = finding.Rule.Description()
		jr.Findings[i].Level = string(finding.Rule.Level())
		jr.Findings[i].FilePath = finding.FilePath
		jr.Findings[i].LineNumber = finding.LineNumber
		jr.Findings[i].LineContent = strings.TrimSpace(finding.LineContent)
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(jr)
}

// printYAML, prints the report in YAML format
func (r *Report) printYAML(w io.Writer) error {
	type yamlReport struct {
		ScanTime string `yaml:"scan_time"`
		Summary  struct {
			TotalFiles        int `yaml:"total_files"`
			FilesWithFindings int `yaml:"files_with_findings"`
			CriticalCount     int `yaml:"critical_count"`
			MediumCount       int `yaml:"medium_count"`
			LowCount          int `yaml:"low_count"`
		} `yaml:"summary"`
		Findings []struct {
			RuleID      string `yaml:"rule_id"`
			Description string `yaml:"description"`
			Level       string `yaml:"level"`
			FilePath    string `yaml:"file_path"`
			LineNumber  int    `yaml:"line_number"`
			LineContent string `yaml:"line_content"`
		} `yaml:"findings"`
	}

	yr := yamlReport{
		ScanTime: r.ScanTime.Format("2006-01-02T15:04:05Z07:00"),
	}

	yr.Summary.TotalFiles = r.SummaryInfo.TotalFiles
	yr.Summary.FilesWithFindings = r.SummaryInfo.FilesWithFindings
	yr.Summary.CriticalCount = r.SummaryInfo.CriticalCount
	yr.Summary.MediumCount = r.SummaryInfo.MediumCount
	yr.Summary.LowCount = r.SummaryInfo.LowCount

	yr.Findings = make([]struct {
		RuleID      string `yaml:"rule_id"`
		Description string `yaml:"description"`
		Level       string `yaml:"level"`
		FilePath    string `yaml:"file_path"`
		LineNumber  int    `yaml:"line_number"`
		LineContent string `yaml:"line_content"`
	}, len(r.Findings))

	for i, finding := range r.Findings {
		yr.Findings[i].RuleID = finding.Rule.ID()
		yr.Findings[i].Description = finding.Rule.Description()
		yr.Findings[i].Level = string(finding.Rule.Level())
		yr.Findings[i].FilePath = finding.FilePath
		yr.Findings[i].LineNumber = finding.LineNumber
		yr.Findings[i].LineContent = strings.TrimSpace(finding.LineContent)
	}

	encoder := yaml.NewEncoder(w)
	defer encoder.Close()
	return encoder.Encode(yr)
}

// printHTML, prints the report in HTML format
func (r *Report) printHTML(w io.Writer) error {
	// HTML template with Bootstrap 5
	htmlTemplate := `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>BashLeaks Security Report</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.7.2/font/bootstrap-icons.css">
  <style>
    :root {
      --critical: #dc3545;
      --medium: #ffc107;
      --low: #198754;
    }
    body {
      padding-top: 2rem;
      padding-bottom: 4rem;
      background-color: #f8f9fa;
    }
    .card {
      margin-bottom: 1.5rem;
      box-shadow: 0 0.125rem 0.25rem rgba(0, 0, 0, 0.075);
      border: none;
    }
    .card-header {
      font-weight: bold;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .card-header-critical {
      background-color: rgba(220, 53, 69, 0.2);
      color: var(--critical);
    }
    .card-header-medium {
      background-color: rgba(255, 193, 7, 0.2);
      color: #856404;
    }
    .card-header-low {
      background-color: rgba(25, 135, 84, 0.2);
      color: var(--low);
    }
    .finding-card {
      margin-bottom: 1rem;
      border-left: 4px solid transparent;
    }
    .finding-critical {
      border-left-color: var(--critical);
    }
    .finding-medium {
      border-left-color: var(--medium);
    }
    .finding-low {
      border-left-color: var(--low);
    }
    .file-path {
      font-family: monospace;
      font-size: 0.9rem;
      color: #6c757d;
    }
    .code-content {
      font-family: monospace;
      background-color: #f5f5f5;
      padding: 0.5rem;
      border-radius: 0.25rem;
      white-space: pre-wrap;
      overflow-x: auto;
      font-size: 0.9rem;
    }
    .risk-badge {
      font-size: 0.8rem;
      padding: 0.35em 0.65em;
    }
    .no-findings {
      padding: 3rem 0;
      text-align: center;
    }
    .summary-box {
      border-radius: 0.25rem;
      padding: 1.25rem;
      margin-bottom: 1.5rem;
      color: white;
      text-align: center;
    }
    .summary-box h2 {
      font-size: 2.5rem;
      margin: 0;
      padding: 0;
    }
    .summary-box p {
      margin: 0;
      opacity: 0.8;
    }
    .summary-critical {
      background-color: var(--critical);
    }
    .summary-medium {
      background-color: var(--medium);
    }
    .summary-low {
      background-color: var(--low);
    }
    .summary-files {
      background-color: #6610f2;
    }
    .chart-container {
      height: 300px;
      margin-bottom: 2rem;
    }
    .footer {
      margin-top: 3rem;
      padding-top: 1rem;
      border-top: 1px solid #dee2e6;
      color: #6c757d;
      font-size: 0.9rem;
    }
    @media print {
      .container {
        max-width: 100%;
      }
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="d-flex justify-content-between align-items-center mb-4">
      <h1 class="mb-0">
        <i class="bi bi-shield-lock-fill text-primary me-2"></i>
        BashLeaks Security Report
      </h1>
      <div class="text-muted">
        <i class="bi bi-calendar3"></i>
        {{ .ScanTime }}
      </div>
    </div>

    <div class="row">
      <div class="col-md-6">
        <div class="summary-box summary-files">
          <h2>{{ .SummaryInfo.TotalFiles }}</h2>
          <p>Files Scanned</p>
        </div>
      </div>
      <div class="col-md-6">
        <div class="summary-box summary-files" style="background-color: #3f51b5;">
          <h2>{{ .SummaryInfo.FilesWithFindings }}</h2>
          <p>Files With Vulnerabilities</p>
        </div>
      </div>
      <div class="col-md-4">
        <div class="summary-box summary-critical">
          <h2>{{ .SummaryInfo.CriticalCount }}</h2>
          <p>Critical Risks</p>
        </div>
      </div>
      <div class="col-md-4">
        <div class="summary-box summary-medium">
          <h2>{{ .SummaryInfo.MediumCount }}</h2>
          <p>Medium Risks</p>
        </div>
      </div>
      <div class="col-md-4">
        <div class="summary-box summary-low">
          <h2>{{ .SummaryInfo.LowCount }}</h2>
          <p>Low Risks</p>
        </div>
      </div>
    </div>

    <!-- Chart for visualization of findings -->
    {{ if gt (add .SummaryInfo.CriticalCount .SummaryInfo.MediumCount .SummaryInfo.LowCount) 0 }}
    <div class="card mt-4">
      <div class="card-header bg-white">
        <h5 class="card-title mb-0">Vulnerability Distribution</h5>
      </div>
      <div class="card-body">
        <div class="chart-container">
          <canvas id="risksChart"></canvas>
        </div>
      </div>
    </div>
    {{ end }}

    <!-- Findings -->
    <h2 class="mt-4 mb-3">Security Findings</h2>

    {{ if eq (len .Findings) 0 }}
    <div class="no-findings">
      <i class="bi bi-check-circle-fill text-success" style="font-size: 4rem;"></i>
      <h3 class="mt-3">No vulnerabilities found!</h3>
      <p class="text-muted">Your scripts are secure based on the current rule set.</p>
    </div>
    {{ else }}
    
    <!-- Critical findings -->
    {{ if gt .SummaryInfo.CriticalCount 0 }}
    <div class="card">
      <div class="card-header card-header-critical">
        <div>
          <i class="bi bi-exclamation-triangle-fill me-1"></i>
          Critical Risk Findings
        </div>
        <span class="badge bg-danger risk-badge">{{ .SummaryInfo.CriticalCount }}</span>
      </div>
      <div class="card-body">
        {{ range .Findings }}
          {{ if eq (string .Rule.Level) "Critical" }}
            <div class="card finding-card finding-critical">
              <div class="card-body">
                <h5 class="card-title">{{ .Rule.ID }}</h5>
                <p class="mb-2">{{ .Rule.Description }}</p>
                <div class="file-path mb-2">
                  <i class="bi bi-file-earmark-code"></i>
                  {{ .FilePath }}:{{ .LineNumber }}
                </div>
                <div class="code-content">{{ .LineContent }}</div>
              </div>
            </div>
          {{ end }}
        {{ end }}
      </div>
    </div>
    {{ end }}

    <!-- Medium findings -->
    {{ if gt .SummaryInfo.MediumCount 0 }}
    <div class="card">
      <div class="card-header card-header-medium">
        <div>
          <i class="bi bi-exclamation-triangle-fill me-1"></i>
          Medium Risk Findings
        </div>
        <span class="badge bg-warning text-dark risk-badge">{{ .SummaryInfo.MediumCount }}</span>
      </div>
      <div class="card-body">
        {{ range .Findings }}
          {{ if eq (string .Rule.Level) "Medium" }}
            <div class="card finding-card finding-medium">
              <div class="card-body">
                <h5 class="card-title">{{ .Rule.ID }}</h5>
                <p class="mb-2">{{ .Rule.Description }}</p>
                <div class="file-path mb-2">
                  <i class="bi bi-file-earmark-code"></i>
                  {{ .FilePath }}:{{ .LineNumber }}
                </div>
                <div class="code-content">{{ .LineContent }}</div>
              </div>
            </div>
          {{ end }}
        {{ end }}
      </div>
    </div>
    {{ end }}

    <!-- Low findings -->
    {{ if gt .SummaryInfo.LowCount 0 }}
    <div class="card">
      <div class="card-header card-header-low">
        <div>
          <i class="bi bi-info-circle-fill me-1"></i>
          Low Risk Findings
        </div>
        <span class="badge bg-success risk-badge">{{ .SummaryInfo.LowCount }}</span>
      </div>
      <div class="card-body">
        {{ range .Findings }}
          {{ if eq (string .Rule.Level) "Low" }}
            <div class="card finding-card finding-low">
              <div class="card-body">
                <h5 class="card-title">{{ .Rule.ID }}</h5>
                <p class="mb-2">{{ .Rule.Description }}</p>
                <div class="file-path mb-2">
                  <i class="bi bi-file-earmark-code"></i>
                  {{ .FilePath }}:{{ .LineNumber }}
                </div>
                <div class="code-content">{{ .LineContent }}</div>
              </div>
            </div>
          {{ end }}
        {{ end }}
      </div>
    </div>
    {{ end }}
    {{ end }}

    <div class="footer text-center">
      <p>Report generated by BashLeaks security scanner &copy; {{ Year }}</p>
    </div>
  </div>

  <!-- JavaScript for charts and functionality -->
  <script src="https://cdn.jsdelivr.net/npm/chart.js@3.7.0/dist/chart.min.js"></script>
  <script>
    // Add helper function for template
    function add(a, b, c) {
      return a + b + c;
    }

    // Charts
    document.addEventListener('DOMContentLoaded', function() {
      {{ if gt (add .SummaryInfo.CriticalCount .SummaryInfo.MediumCount .SummaryInfo.LowCount) 0 }}
      // Risk distribution chart
      const ctx = document.getElementById('risksChart').getContext('2d');
      const risksChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
          labels: ['Critical', 'Medium', 'Low'],
          datasets: [{
            data: [{{ .SummaryInfo.CriticalCount }}, {{ .SummaryInfo.MediumCount }}, {{ .SummaryInfo.LowCount }}],
            backgroundColor: ['#dc3545', '#ffc107', '#198754'],
            borderWidth: 0
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: {
              position: 'right',
            }
          },
          cutout: '50%'
        }
      });
      {{ end }}
    });
  </script>
</body>
</html>
`

	tmpl, err := template.New("html").Funcs(template.FuncMap{
		"toLower": strings.ToLower,
		"string":  func(v interface{}) string { return fmt.Sprintf("%v", v) },
		"Year":    func() int { return time.Now().Year() },
		"add":     func(a, b, c int) int { return a + b + c },
	}).Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse HTML template: %w", err)
	}

	data := struct {
		ScanTime    string
		SummaryInfo struct {
			TotalFiles        int
			FilesWithFindings int
			CriticalCount     int
			MediumCount       int
			LowCount          int
		}
		Findings []rules.Finding
		Year     int
	}{
		ScanTime:    r.ScanTime.Format("2006-01-02 15:04:05"),
		SummaryInfo: r.SummaryInfo,
		Findings:    r.Findings,
		Year:        time.Now().Year(),
	}

	return tmpl.Execute(w, data)
}

// printMarkdown, prints the report in Markdown format
func (r *Report) printMarkdown(w io.Writer) error {
	fmt.Fprintf(w, "# BashLeaks Scan Report\n\n")
	fmt.Fprintf(w, "Scan Time: %s\n\n", r.ScanTime.Format("2006-01-02 15:04:05"))

	fmt.Fprintf(w, "## Summary\n\n")
	fmt.Fprintf(w, "- Total Files Scanned: %d\n", r.SummaryInfo.TotalFiles)
	fmt.Fprintf(w, "- Files With Vulnerabilities: %d\n", r.SummaryInfo.FilesWithFindings)
	fmt.Fprintf(w, "- Critical Risk: %d\n", r.SummaryInfo.CriticalCount)
	fmt.Fprintf(w, "- Medium Risk: %d\n", r.SummaryInfo.MediumCount)
	fmt.Fprintf(w, "- Low Risk: %d\n\n", r.SummaryInfo.LowCount)

	if len(r.Findings) == 0 {
		fmt.Fprintf(w, "## No security vulnerabilities found!\n")
		return nil
	}

	fmt.Fprintf(w, "## Security Vulnerabilities\n\n")

	fmt.Fprintf(w, "| Risk | Rule ID | Description | File | Line | Content |\n")
	fmt.Fprintf(w, "|------|----------|----------|-------|-------|--------|\n")

	for _, finding := range r.Findings {
		fmt.Fprintf(w, "| %s | %s | %s | %s | %d | `%s` |\n",
			finding.Rule.Level(),
			finding.Rule.ID(),
			finding.Rule.Description(),
			finding.FilePath,
			finding.LineNumber,
			strings.TrimSpace(finding.LineContent),
		)
	}

	return nil
}

// SaveToFile, saves the report to a file
func (r *Report) SaveToFile(format Format, filePath string) error {
	// Check and create directory if needed
	dir := filepath.Dir(filePath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory: %w", err)
		}
	}

	// Create or open file
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	// Print report
	if err := r.Print(format, file); err != nil {
		return fmt.Errorf("report writing error: %w", err)
	}

	return nil
}
