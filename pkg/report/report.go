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

// Format, rapor formatı
type Format string

const (
	FormatText     Format = "text"
	FormatJSON     Format = "json"
	FormatYAML     Format = "yaml"
	FormatHTML     Format = "html"
	FormatMarkdown Format = "markdown"
)

// Report, tarama sonuçlarını içerir
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

// NewReport, yeni bir rapor oluşturur
func NewReport(findings []rules.Finding, totalFiles int) *Report {
	r := &Report{
		Findings: findings,
		ScanTime: time.Now(),
	}
	r.SummaryInfo.TotalFiles = totalFiles

	// Özet bilgileri hesaplayalım
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

// Print, raporu belirtilen formatta yazdırır
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
		return fmt.Errorf("desteklenmeyen rapor formatı: %s", format)
	}
}

// printText, raporu renkli metin olarak yazdırır
func (r *Report) printText(w io.Writer) error {
	// Ansi renk kodları
	critical := color.New(color.FgHiRed, color.Bold)
	medium := color.New(color.FgYellow, color.Bold)
	low := color.New(color.FgHiGreen, color.Bold)
	title := color.New(color.FgHiWhite, color.Bold, color.BgBlue)
	subtitle := color.New(color.FgHiWhite, color.Bold)
	header := color.New(color.FgHiCyan, color.Bold)
	info := color.New(color.FgCyan)
	highlight := color.New(color.FgHiYellow)

	// Modern başlık
	title.Fprintf(w, "  BashLeaks Güvenlik Tarama Raporu  ")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "%s %s\n\n", subtitle.Sprint("🕒"), info.Sprintf("Tarama Zamanı: %s", r.ScanTime.Format("2006-01-02 15:04:05")))

	// Özet - Blok formatında
	header.Fprintln(w, "📊 TARAMA ÖZETİ")
	fmt.Fprintln(w, "┌─────────────────────────────┬─────────┐")
	fmt.Fprintf(w, "│ %-27s │ %-7d │\n", "Taranan Dosya Sayısı", r.SummaryInfo.TotalFiles)
	fmt.Fprintf(w, "│ %-27s │ %-7d │\n", "Açık Bulunan Dosya Sayısı", r.SummaryInfo.FilesWithFindings)

	// Risk sayıları renkli gösterim
	if r.SummaryInfo.CriticalCount > 0 {
		fmt.Fprintf(w, "│ %-27s │ %-7s │\n", "Kritik Risk", critical.Sprintf("⚠️  %d", r.SummaryInfo.CriticalCount))
	} else {
		fmt.Fprintf(w, "│ %-27s │ %-7s │\n", "Kritik Risk", "0")
	}

	if r.SummaryInfo.MediumCount > 0 {
		fmt.Fprintf(w, "│ %-27s │ %-7s │\n", "Orta Risk", medium.Sprintf("⚠️  %d", r.SummaryInfo.MediumCount))
	} else {
		fmt.Fprintf(w, "│ %-27s │ %-7s │\n", "Orta Risk", "0")
	}

	if r.SummaryInfo.LowCount > 0 {
		fmt.Fprintf(w, "│ %-27s │ %-7s │\n", "Düşük Risk", low.Sprintf("ℹ️  %d", r.SummaryInfo.LowCount))
	} else {
		fmt.Fprintf(w, "│ %-27s │ %-7s │\n", "Düşük Risk", "0")
	}

	fmt.Fprintln(w, "└─────────────────────────────┴─────────┘")
	fmt.Fprintln(w)

	// Bulgular - Riske göre sırala
	sortedFindings := make([]rules.Finding, len(r.Findings))
	copy(sortedFindings, r.Findings)
	sort.Slice(sortedFindings, func(i, j int) bool {
		// Önce risk seviyesine göre sırala
		riskPriority := map[rules.RiskLevel]int{
			rules.RiskLevelCritical: 0,
			rules.RiskLevelMedium:   1,
			rules.RiskLevelLow:      2,
		}

		if riskPriority[sortedFindings[i].Rule.Level()] != riskPriority[sortedFindings[j].Rule.Level()] {
			return riskPriority[sortedFindings[i].Rule.Level()] < riskPriority[sortedFindings[j].Rule.Level()]
		}

		// Aynı risk seviyesi ise dosya adına göre sırala
		if sortedFindings[i].FilePath != sortedFindings[j].FilePath {
			return sortedFindings[i].FilePath < sortedFindings[j].FilePath
		}

		// Aynı dosya ise satır numarasına göre sırala
		return sortedFindings[i].LineNumber < sortedFindings[j].LineNumber
	})

	if len(sortedFindings) == 0 {
		fmt.Fprintln(w, low.Sprint("✅ Güvenlik açığı bulunamadı!"))
		return nil
	}

	header.Fprintln(w, "🔍 TESPİT EDİLEN AÇIKLAR")
	fmt.Fprintln(w)

	// Her bulguyu yazdır
	lastRiskLevel := ""

	for i, finding := range sortedFindings {
		var riskHeader *color.Color
		var riskIcon string

		// Risk seviyesine göre stil belirle
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

		// Yeni bir risk seviyesine geldiğimizde başlık ekle
		if string(finding.Rule.Level()) != lastRiskLevel {
			if i > 0 {
				fmt.Fprintln(w)
			}
			riskHeader.Fprintf(w, "[ %s %s ]\n", riskIcon, finding.Rule.Level())
			fmt.Fprintln(w, "───────────────────────────────────────────────────")
			lastRiskLevel = string(finding.Rule.Level())
		}

		// Bulgu detayları
		fmt.Fprintf(w, "%s %s\n", highlight.Sprint("▶"), riskHeader.Sprint(finding.Rule.ID()))
		fmt.Fprintf(w, "  📝 %s\n", finding.Rule.Description())
		fmt.Fprintf(w, "  📄 %s:%d\n", finding.FilePath, finding.LineNumber)
		fmt.Fprintf(w, "  💻 %s\n\n", strings.TrimSpace(finding.LineContent))
	}

	return nil
}

// printJSON, raporu JSON formatında yazdırır
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

	report := jsonReport{
		ScanTime: r.ScanTime.Format(time.RFC3339),
		Summary: struct {
			TotalFiles        int `json:"total_files"`
			FilesWithFindings int `json:"files_with_findings"`
			CriticalCount     int `json:"critical_count"`
			MediumCount       int `json:"medium_count"`
			LowCount          int `json:"low_count"`
		}{
			TotalFiles:        r.SummaryInfo.TotalFiles,
			FilesWithFindings: r.SummaryInfo.FilesWithFindings,
			CriticalCount:     r.SummaryInfo.CriticalCount,
			MediumCount:       r.SummaryInfo.MediumCount,
			LowCount:          r.SummaryInfo.LowCount,
		},
		Findings: make([]struct {
			RuleID      string `json:"rule_id"`
			Description string `json:"description"`
			Level       string `json:"level"`
			FilePath    string `json:"file_path"`
			LineNumber  int    `json:"line_number"`
			LineContent string `json:"line_content"`
		}, len(r.Findings)),
	}

	for i, finding := range r.Findings {
		report.Findings[i] = struct {
			RuleID      string `json:"rule_id"`
			Description string `json:"description"`
			Level       string `json:"level"`
			FilePath    string `json:"file_path"`
			LineNumber  int    `json:"line_number"`
			LineContent string `json:"line_content"`
		}{
			RuleID:      finding.Rule.ID(),
			Description: finding.Rule.Description(),
			Level:       string(finding.Rule.Level()),
			FilePath:    finding.FilePath,
			LineNumber:  finding.LineNumber,
			LineContent: strings.TrimSpace(finding.LineContent),
		}
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

// printYAML, raporu YAML formatında yazdırır
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

	report := yamlReport{
		ScanTime: r.ScanTime.Format(time.RFC3339),
		Summary: struct {
			TotalFiles        int `yaml:"total_files"`
			FilesWithFindings int `yaml:"files_with_findings"`
			CriticalCount     int `yaml:"critical_count"`
			MediumCount       int `yaml:"medium_count"`
			LowCount          int `yaml:"low_count"`
		}{
			TotalFiles:        r.SummaryInfo.TotalFiles,
			FilesWithFindings: r.SummaryInfo.FilesWithFindings,
			CriticalCount:     r.SummaryInfo.CriticalCount,
			MediumCount:       r.SummaryInfo.MediumCount,
			LowCount:          r.SummaryInfo.LowCount,
		},
		Findings: make([]struct {
			RuleID      string `yaml:"rule_id"`
			Description string `yaml:"description"`
			Level       string `yaml:"level"`
			FilePath    string `yaml:"file_path"`
			LineNumber  int    `yaml:"line_number"`
			LineContent string `yaml:"line_content"`
		}, len(r.Findings)),
	}

	for i, finding := range r.Findings {
		report.Findings[i] = struct {
			RuleID      string `yaml:"rule_id"`
			Description string `yaml:"description"`
			Level       string `yaml:"level"`
			FilePath    string `yaml:"file_path"`
			LineNumber  int    `yaml:"line_number"`
			LineContent string `yaml:"line_content"`
		}{
			RuleID:      finding.Rule.ID(),
			Description: finding.Rule.Description(),
			Level:       string(finding.Rule.Level()),
			FilePath:    finding.FilePath,
			LineNumber:  finding.LineNumber,
			LineContent: strings.TrimSpace(finding.LineContent),
		}
	}

	encoder := yaml.NewEncoder(w)
	defer encoder.Close()
	return encoder.Encode(report)
}

// printHTML, raporu HTML formatında yazdırır
func (r *Report) printHTML(w io.Writer) error {
	// Modern bir HTML şablonu
	const htmlTemplate = `<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BashLeaks Güvenlik Raporu</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css">
    <style>
        :root {
            --critical: #dc3545;
            --medium: #ffc107;
            --low: #198754;
            --bg-dark: #212529;
            --text-light: #f8f9fa;
        }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            background-color: #f8f9fa;
            color: #333;
            margin: 0;
            padding: 0;
        }
        .header {
            background-color: var(--bg-dark);
            color: var(--text-light);
            padding: 2rem 0;
            margin-bottom: 2rem;
            border-bottom: 4px solid #0d6efd;
        }
        .card {
            border-radius: 8px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            margin-bottom: 1.5rem;
            border: none;
        }
        .card-header {
            font-weight: 600;
            border-radius: 8px 8px 0 0 !important;
        }
        .summary-item {
            display: flex;
            justify-content: space-between;
            padding: 0.5rem 0;
            border-bottom: 1px solid #eee;
        }
        .summary-item:last-child {
            border-bottom: none;
        }
        .risk-badge {
            padding: 0.3rem 0.6rem;
            border-radius: 4px;
            font-weight: 500;
            font-size: 0.8rem;
            text-transform: uppercase;
        }
        .risk-critical {
            background-color: var(--critical);
            color: white;
        }
        .risk-medium {
            background-color: var(--medium);
            color: #333;
        }
        .risk-low {
            background-color: var(--low);
            color: white;
        }
        .findings-table th {
            background-color: #f8f9fa;
            position: sticky;
            top: 0;
            z-index: 10;
        }
        .finding-row-critical {
            border-left: 4px solid var(--critical);
        }
        .finding-row-medium {
            border-left: 4px solid var(--medium);
        }
        .finding-row-low {
            border-left: 4px solid var(--low);
        }
        .finding-code {
            background-color: #f8f9fa;
            padding: 0.5rem;
            border-radius: 4px;
            font-family: SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
            font-size: 0.85rem;
            white-space: pre-wrap;
            max-width: 300px;
            overflow: auto;
        }
        .dashboard {
            display: flex;
            flex-wrap: wrap;
            gap: 1rem;
            margin-bottom: 2rem;
        }
        .dashboard-item {
            flex: 1;
            min-width: 200px;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            padding: 1.5rem;
            background: white;
            border-radius: 8px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }
        .dashboard-value {
            font-size: 2.5rem;
            font-weight: 700;
            margin: 0.5rem 0;
        }
        .dashboard-label {
            font-size: 0.9rem;
            color: #6c757d;
            text-transform: uppercase;
        }
        .critical-value { color: var(--critical); }
        .medium-value { color: var(--medium); }
        .low-value { color: var(--low); }
        .no-findings {
            text-align: center;
            padding: 3rem;
            background-color: #e9f7ef;
            border-radius: 8px;
            margin-top: 2rem;
        }
        .footer {
            text-align: center;
            padding: 2rem 0;
            margin-top: 2rem;
            background-color: var(--bg-dark);
            color: var(--text-light);
        }
    </style>
</head>
<body>
    <header class="header">
        <div class="container">
            <div class="row align-items-center">
                <div class="col">
                    <h1><i class="bi bi-shield-lock"></i> BashLeaks Güvenlik Tarama Raporu</h1>
                    <p class="mb-0">Tarama Zamanı: {{.ScanTime}}</p>
                </div>
            </div>
        </div>
    </header>

    <main class="container">
        <!-- Metrik Dashboard -->
        <div class="dashboard">
            <div class="dashboard-item">
                <div class="dashboard-label">Taranan Dosyalar</div>
                <div class="dashboard-value">{{.SummaryInfo.TotalFiles}}</div>
                <i class="bi bi-file-earmark-text fs-2"></i>
            </div>
            
            <div class="dashboard-item">
                <div class="dashboard-label">Etkilenen Dosyalar</div>
                <div class="dashboard-value">{{.SummaryInfo.FilesWithFindings}}</div>
                <i class="bi bi-file-earmark-x fs-2"></i>
            </div>
            
            <div class="dashboard-item">
                <div class="dashboard-label">Kritik Riskler</div>
                <div class="dashboard-value critical-value">{{.SummaryInfo.CriticalCount}}</div>
                <i class="bi bi-exclamation-triangle-fill fs-2 text-danger"></i>
            </div>
            
            <div class="dashboard-item">
                <div class="dashboard-label">Orta Riskler</div>
                <div class="dashboard-value medium-value">{{.SummaryInfo.MediumCount}}</div>
                <i class="bi bi-exclamation-triangle fs-2 text-warning"></i>
            </div>
            
            <div class="dashboard-item">
                <div class="dashboard-label">Düşük Riskler</div>
                <div class="dashboard-value low-value">{{.SummaryInfo.LowCount}}</div>
                <i class="bi bi-info-circle fs-2 text-success"></i>
            </div>
        </div>

        {{if .Findings}}
        <!-- Bulgular Tablosu -->
        <div class="card">
            <div class="card-header bg-dark text-white">
                <i class="bi bi-list-ul"></i> Bulunan Güvenlik Açıkları
            </div>
            <div class="card-body p-0">
                <div class="table-responsive">
                    <table class="table table-hover mb-0 findings-table">
                        <thead>
                            <tr>
                                <th scope="col">Risk</th>
                                <th scope="col">Kural</th>
                                <th scope="col">Açıklama</th>
                                <th scope="col">Konum</th>
                                <th scope="col">Kod</th>
                            </tr>
                        </thead>
                        <tbody>
                            {{range .Findings}}
                            <tr class="finding-row-{{toLower (string .Rule.Level)}}">
                                <td>
                                    <span class="risk-badge risk-{{toLower (string .Rule.Level)}}">
                                        {{if eq (toLower (string .Rule.Level)) "critical"}}
                                            <i class="bi bi-exclamation-triangle-fill"></i>
                                        {{else if eq (toLower (string .Rule.Level)) "medium"}}
                                            <i class="bi bi-exclamation-triangle"></i>
                                        {{else}}
                                            <i class="bi bi-info-circle"></i>
                                        {{end}}
                                        {{string .Rule.Level}}
                                    </span>
                                </td>
                                <td>{{.Rule.ID}}</td>
                                <td>{{.Rule.Description}}</td>
                                <td>{{.FilePath}}:{{.LineNumber}}</td>
                                <td><div class="finding-code">{{.LineContent}}</div></td>
                            </tr>
                            {{end}}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
        {{else}}
        <div class="no-findings">
            <i class="bi bi-check-circle text-success fs-1"></i>
            <h2 class="mt-3 text-success">Güvenlik açığı bulunamadı!</h2>
            <p class="text-muted">Taranan tüm dosyalar güvenlik kontrollerinden geçti.</p>
        </div>
        {{end}}
    </main>

    <footer class="footer">
        <div class="container">
            <p class="mb-0">BashLeaks ile oluşturuldu &copy; {{.Year}} | Shell Script Güvenlik Analiz Aracı</p>
        </div>
    </footer>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>`

	tmpl, err := template.New("html").Funcs(template.FuncMap{
		"toLower": strings.ToLower,
		"string":  func(v interface{}) string { return fmt.Sprintf("%v", v) },
		"Year":    func() int { return time.Now().Year() },
	}).Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("html şablonu ayrıştırılamadı: %w", err)
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

// printMarkdown, raporu Markdown formatında yazdırır
func (r *Report) printMarkdown(w io.Writer) error {
	fmt.Fprintf(w, "# BashLeaks Tarama Raporu\n\n")
	fmt.Fprintf(w, "Tarama Zamanı: %s\n\n", r.ScanTime.Format("2006-01-02 15:04:05"))

	fmt.Fprintf(w, "## Özet\n\n")
	fmt.Fprintf(w, "- Taranan Dosya Sayısı: %d\n", r.SummaryInfo.TotalFiles)
	fmt.Fprintf(w, "- Açık Bulunan Dosya Sayısı: %d\n", r.SummaryInfo.FilesWithFindings)
	fmt.Fprintf(w, "- Kritik Risk: %d\n", r.SummaryInfo.CriticalCount)
	fmt.Fprintf(w, "- Orta Risk: %d\n", r.SummaryInfo.MediumCount)
	fmt.Fprintf(w, "- Düşük Risk: %d\n\n", r.SummaryInfo.LowCount)

	if len(r.Findings) == 0 {
		fmt.Fprintf(w, "## Güvenlik açığı bulunamadı!\n")
		return nil
	}

	fmt.Fprintf(w, "## Bulunan Güvenlik Açıkları\n\n")

	fmt.Fprintf(w, "| Risk | Kural ID | Açıklama | Dosya | Satır | İçerik |\n")
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

// SaveToFile, raporu bir dosyaya kaydeder
func (r *Report) SaveToFile(format Format, filePath string) error {
	// Dizini kontrol et ve gerekirse oluştur
	dir := filepath.Dir(filePath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("dizin oluşturulamadı: %w", err)
		}
	}

	// Dosyayı aç veya oluştur
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("dosya oluşturulamadı: %w", err)
	}
	defer file.Close()

	// Raporu yazdır
	if err := r.Print(format, file); err != nil {
		return fmt.Errorf("rapor yazma hatası: %w", err)
	}

	return nil
}
