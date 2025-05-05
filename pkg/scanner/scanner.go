package scanner

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/raventrk/bashleaks/pkg/rules"
	"mvdan.cc/sh/v3/syntax"
)

var (
	shebangRegex = regexp.MustCompile(`^#!.*\b(bash|sh|ksh|zsh)\b`)
	ignoreRegex  = regexp.MustCompile(`#\s*bashleaks:ignore`)
)

// Scanner, shell script dosyalarını tarar
type Scanner struct {
	Rules       []rules.Rule
	IgnoreFiles []string
}

// NewScanner, yeni bir tarayıcı oluşturur
func NewScanner() *Scanner {
	return &Scanner{
		Rules: rules.GetAllRules(),
	}
}

// ScanFile, tek bir dosyayı tarar
func (s *Scanner) ScanFile(filePath string) ([]rules.Finding, error) {
	// Dosyayı açalım
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Dosya içeriğini okuyalım
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	// Dosya bir bash script mi kontrol edelim
	if !s.isShellScript(filePath, content) {
		return nil, nil
	}

	// AST'yi parse edelim
	r := strings.NewReader(string(content))
	f, err := syntax.NewParser().Parse(r, filePath)
	if err != nil {
		// AST parse başarısız olsa bile devam edelim, satır satır tarayalım
		return s.scanByLine(filePath)
	}

	// Hem AST hem satır tabanlı taramayı çalıştıralım ve sonuçları birleştirelim
	astFindings, err := s.scanByAST(f, filePath, string(content))
	if err != nil {
		return s.scanByLine(filePath)
	}

	lineFindings, err := s.scanByLine(filePath)
	if err != nil {
		return astFindings, nil
	}

	// Bulguları birleştir (çift bulguları önlemek için basit deduplikasyon yapalım)
	return mergeFindings(astFindings, lineFindings), nil
}

// mergeFindings, iki findings listesini birleştirir ve duplikasyonları önler
func mergeFindings(a, b []rules.Finding) []rules.Finding {
	if len(a) == 0 {
		return b
	}
	if len(b) == 0 {
		return a
	}

	// Basit bir deduplikasyon yaklaşımı kullanılıyor
	// Aynı kuralı aynı dosya ve satır numarasında birden fazla raporlamamak için
	merged := make([]rules.Finding, len(a))
	copy(merged, a)

	seen := make(map[string]bool)
	for _, finding := range a {
		key := finding.Rule.ID() + "|" + finding.FilePath + "|" + strconv.Itoa(finding.LineNumber)
		seen[key] = true
	}

	for _, finding := range b {
		key := finding.Rule.ID() + "|" + finding.FilePath + "|" + strconv.Itoa(finding.LineNumber)
		if !seen[key] {
			merged = append(merged, finding)
			seen[key] = true
		}
	}

	return merged
}

// scanByAST, AST kullanarak güvenlik açıklarını tespit eder
func (s *Scanner) scanByAST(f *syntax.File, filePath, contentStr string) ([]rules.Finding, error) {
	var findings []rules.Finding
	contentLines := strings.Split(contentStr, "\n")

	// AST ziyaretçisi (syntax.Visitor) oluştur
	astVisitor := func(node syntax.Node) bool {
		// Node nil ise işlem yapma
		if node == nil {
			return true
		}

		// Node'un satır numarasını al
		pos := node.Pos()
		// Pos nil kontrolü
		if !pos.IsValid() {
			return true
		}

		lineNumber := int(pos.Line())
		if lineNumber <= 0 || lineNumber > len(contentLines) {
			return true // Devam et
		}

		line := contentLines[lineNumber-1]

		// Bu satır için ignore kontrolü
		if ignoreRegex.MatchString(line) {
			return true // Bu satırı atla
		}

		// Farklı node türlerine göre kontroller
		switch x := node.(type) {
		case *syntax.CallExpr:
			s.checkCommand(x, filePath, lineNumber, line, &findings)
		case *syntax.BinaryCmd:
			s.checkPipeline(x, filePath, lineNumber, line, &findings)
		case *syntax.DeclClause:
			s.checkVariables(x, filePath, lineNumber, line, &findings)
		case *syntax.FuncDecl:
			s.checkFunctionDecl(x, filePath, lineNumber, line, &findings)
		case *syntax.TestClause:
			s.checkTestClause(x, filePath, lineNumber, line, &findings)
		}

		return true // Alt düğümleri ziyaret etmeye devam et
	}

	syntax.Walk(f, astVisitor)
	return findings, nil
}

// checkCommand, bir komut çağrısını kontrol eder
func (s *Scanner) checkCommand(cmd *syntax.CallExpr, filePath string, lineNum int, lineContent string, findings *[]rules.Finding) {
	if len(cmd.Args) == 0 {
		return
	}

	// Komut adını al - mvdan.cc/sh/v3/syntax kütüphanesine göre düzenleme
	if len(cmd.Args) > 0 && len(cmd.Args[0].Parts) > 0 {
		if lit, ok := cmd.Args[0].Parts[0].(*syntax.Lit); ok {
			cmdName := lit.Value

			// Tehlikeli komutlar için kontroller
			switch cmdName {
			case "eval", "source", "exec":
				finding := rules.Finding{
					Rule: &rules.BaseRule{
						RuleID:          "BASH-AST-EVAL-001",
						RuleDescription: "AST: Tehlikeli " + cmdName + " komutu kullanımı",
						RuleLevel:       rules.RiskLevelCritical,
						Pattern:         nil,
					},
					FilePath:    filePath,
					LineNumber:  lineNum,
					LineContent: lineContent,
					Ignored:     false,
				}
				*findings = append(*findings, finding)
			case "curl", "wget":
				// Pipe kontrolü için tam satırı kontrol et
				if strings.Contains(lineContent, "|") && (strings.Contains(lineContent, "sh") || strings.Contains(lineContent, "bash")) {
					finding := rules.Finding{
						Rule: &rules.BaseRule{
							RuleID:          "BASH-AST-CURL-001",
							RuleDescription: "AST: Curl/wget çıktısını doğrudan shell'e yönlendirme",
							RuleLevel:       rules.RiskLevelCritical,
							Pattern:         nil,
						},
						FilePath:    filePath,
						LineNumber:  lineNum,
						LineContent: lineContent,
						Ignored:     false,
					}
					*findings = append(*findings, finding)
				}
			case "chmod":
				if len(cmd.Args) > 1 && len(cmd.Args[1].Parts) > 0 {
					if permLit, ok := cmd.Args[1].Parts[0].(*syntax.Lit); ok {
						permValue := permLit.Value
						if strings.Contains(permValue, "777") || strings.Contains(permValue, "+s") {
							finding := rules.Finding{
								Rule: &rules.BaseRule{
									RuleID:          "BASH-AST-CHMOD-001",
									RuleDescription: "AST: Güvensiz chmod kullanımı",
									RuleLevel:       rules.RiskLevelMedium,
									Pattern:         nil,
								},
								FilePath:    filePath,
								LineNumber:  lineNum,
								LineContent: lineContent,
								Ignored:     false,
							}
							*findings = append(*findings, finding)
						}
					}
				}
			case "dd":
				if strings.Contains(lineContent, "of=/dev/") {
					finding := rules.Finding{
						Rule: &rules.BaseRule{
							RuleID:          "BASH-AST-DD-001",
							RuleDescription: "AST: Disk üzerine tehlikeli dd yazımı",
							RuleLevel:       rules.RiskLevelCritical,
							Pattern:         nil,
						},
						FilePath:    filePath,
						LineNumber:  lineNum,
						LineContent: lineContent,
						Ignored:     false,
					}
					*findings = append(*findings, finding)
				}
			case "rm":
				if strings.Contains(lineContent, "*") && (strings.Contains(lineContent, "-rf") || strings.Contains(lineContent, "-fr")) {
					finding := rules.Finding{
						Rule: &rules.BaseRule{
							RuleID:          "BASH-AST-RM-001",
							RuleDescription: "AST: Tehlikeli rm -rf * kullanımı",
							RuleLevel:       rules.RiskLevelCritical,
							Pattern:         nil,
						},
						FilePath:    filePath,
						LineNumber:  lineNum,
						LineContent: lineContent,
						Ignored:     false,
					}
					*findings = append(*findings, finding)
				}
			}
		}
	}
}

// checkPipeline, pipeline'ları kontrol eder
func (s *Scanner) checkPipeline(binary *syntax.BinaryCmd, filePath string, lineNum int, lineContent string, findings *[]rules.Finding) {
	// Syntax.BinaryCmd.Op artık Syntax.OpType tipi
	if binary.Op != syntax.AndStmt && binary.Op != syntax.OrStmt {
		// Pipe işlemi sadece satır içeriğine bakarak kontrol edilebilir
		if !strings.Contains(lineContent, "|") {
			return
		}

		// BinaryCmd'nin sağ tarafındaki komut, artık doğrudan bir interface değil
		// Basit olarak satır içeriğini kontrol edelim
		if strings.Contains(lineContent, "| sh") || strings.Contains(lineContent, "| bash") {
			finding := rules.Finding{
				Rule: &rules.BaseRule{
					RuleID:          "BASH-AST-PIPE-001",
					RuleDescription: "AST: Çıktıyı doğrudan shell'e yönlendirme",
					RuleLevel:       rules.RiskLevelCritical,
					Pattern:         nil,
				},
				FilePath:    filePath,
				LineNumber:  lineNum,
				LineContent: lineContent,
				Ignored:     false,
			}
			*findings = append(*findings, finding)
		}
	}
}

// checkVariables, değişken tanımlamalarını kontrol eder
func (s *Scanner) checkVariables(decl *syntax.DeclClause, filePath string, lineNum int, lineContent string, findings *[]rules.Finding) {
	// mvdan.cc/sh/v3 API'sindeki değişiklikler için güncelleme
	// Satır içeriğini kullanarak hassas değişken kontrolleri yapalım
	line := strings.TrimSpace(lineContent)

	// Değişken tanımlama kontrolü
	if strings.Contains(line, "=") {
		// Hassas değişken adlarını kontrol et
		sensitiveVars := []string{"PASSWORD", "PASSWD", "SECRET", "KEY", "TOKEN", "API_KEY", "APIKEY"}
		for _, sensitive := range sensitiveVars {
			if strings.Contains(strings.ToUpper(line), sensitive+"=") {
				finding := rules.Finding{
					Rule: &rules.BaseRule{
						RuleID:          "BASH-AST-CRED-001",
						RuleDescription: "AST: Hardcoded hassas değişken tespit edildi",
						RuleLevel:       rules.RiskLevelCritical,
						Pattern:         nil,
					},
					FilePath:    filePath,
					LineNumber:  lineNum,
					LineContent: lineContent,
					Ignored:     false,
				}
				*findings = append(*findings, finding)
				break
			}
		}

		// History değişkenlerini kontrol et
		historyVars := []string{"HISTFILE", "HISTFILESIZE", "HISTSIZE"}
		for _, histVar := range historyVars {
			if strings.Contains(line, histVar+"=") {
				finding := rules.Finding{
					Rule: &rules.BaseRule{
						RuleID:          "BASH-AST-HIST-001",
						RuleDescription: "AST: Bash history log manipülasyonu",
						RuleLevel:       rules.RiskLevelMedium,
						Pattern:         nil,
					},
					FilePath:    filePath,
					LineNumber:  lineNum,
					LineContent: lineContent,
					Ignored:     false,
				}
				*findings = append(*findings, finding)
				break
			}
		}
	}
}

// checkFunctionDecl, fonksiyon tanımlamalarını kontrol eder
func (s *Scanner) checkFunctionDecl(fn *syntax.FuncDecl, filePath string, lineNum int, lineContent string, findings *[]rules.Finding) {
	// Shellshock tarzı fonksiyon tanımlamalarını kontrol et
	if strings.Contains(lineContent, "() {") && strings.Contains(lineContent, ":;};") {
		finding := rules.Finding{
			Rule: &rules.BaseRule{
				RuleID:          "BASH-AST-SHOCK-001",
				RuleDescription: "AST: Potansiyel Shellshock açığı",
				RuleLevel:       rules.RiskLevelCritical,
				Pattern:         nil,
			},
			FilePath:    filePath,
			LineNumber:  lineNum,
			LineContent: lineContent,
			Ignored:     false,
		}
		*findings = append(*findings, finding)
	}
}

// checkTestClause, test ifadelerini (if, while vb.) kontrol eder
func (s *Scanner) checkTestClause(test *syntax.TestClause, filePath string, lineNum int, lineContent string, findings *[]rules.Finding) {
	// Alıntılanmamış değişkenleri kontrol et
	if strings.Contains(lineContent, "[ $") && (strings.Contains(lineContent, " = ") || strings.Contains(lineContent, "== ") || strings.Contains(lineContent, "!= ")) {
		finding := rules.Finding{
			Rule: &rules.BaseRule{
				RuleID:          "BASH-AST-QUOTE-001",
				RuleDescription: "AST: Alıntılanmamış değişken kullanımı",
				RuleLevel:       rules.RiskLevelLow,
				Pattern:         nil,
			},
			FilePath:    filePath,
			LineNumber:  lineNum,
			LineContent: lineContent,
			Ignored:     false,
		}
		*findings = append(*findings, finding)
	}
}

// ScanDirectory, bir dizini ve alt dizinlerini tarar
func (s *Scanner) ScanDirectory(dirPath string) ([]rules.Finding, error) {
	var findings []rules.Finding

	// .bashleaksignore dosyasını kontrol edelim
	ignoreFile := filepath.Join(dirPath, ".bashleaksignore")
	if _, err := os.Stat(ignoreFile); err == nil {
		s.loadIgnoreFile(ignoreFile)
	}

	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		// Dosya .bashleaksignore listesinde mi kontrol edelim
		if s.isIgnored(path) {
			return nil
		}

		// Dosyayı tarayalım
		fileFindings, err := s.ScanFile(path)
		if err != nil {
			return err
		}

		findings = append(findings, fileFindings...)
		return nil
	})

	return findings, err
}

// isShellScript, dosyanın bir shell script olup olmadığını kontrol eder
func (s *Scanner) isShellScript(filePath string, content []byte) bool {
	// Uzantıya göre kontrol
	if strings.HasSuffix(strings.ToLower(filePath), ".sh") {
		return true
	}

	// İlk satırda shebang mi var kontrol
	if len(content) > 0 {
		scanner := bufio.NewScanner(strings.NewReader(string(content)))
		if scanner.Scan() {
			firstLine := scanner.Text()
			return shebangRegex.MatchString(firstLine)
		}
	}

	return false
}

// scanByLine, dosyayı satır satır tarar
func (s *Scanner) scanByLine(filePath string) ([]rules.Finding, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var findings []rules.Finding
	scanner := bufio.NewScanner(file)
	lineNumber := 0

	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()

		// Bu satırın ignore edilmesi gerekiyor mu?
		if ignoreRegex.MatchString(line) {
			continue
		}

		// Tüm kuralları kontrol edelim
		for _, rule := range s.Rules {
			if rule.Match(line) {
				findings = append(findings, rules.Finding{
					Rule:        rule,
					FilePath:    filePath,
					LineNumber:  lineNumber,
					LineContent: line,
					Ignored:     false,
				})
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return findings, nil
}

// loadIgnoreFile, .bashleaksignore dosyasını yükler
func (s *Scanner) loadIgnoreFile(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			s.IgnoreFiles = append(s.IgnoreFiles, line)
		}

	}

	return scanner.Err()
}

// isIgnored, dosyanın ignore edilip edilmeyeceğini kontrol eder
func (s *Scanner) isIgnored(filePath string) bool {
	for _, pattern := range s.IgnoreFiles {
		matched, err := filepath.Match(pattern, filepath.Base(filePath))
		if err == nil && matched {
			return true
		}
	}
	return false
}
