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
	// Regex to identify PowerShell files
	powershellCommentRegex = regexp.MustCompile(`^\s*#\s.*`)
)

// Scanner, scans shell script files
type Scanner struct {
	Rules       []rules.Rule
	IgnoreFiles []string
}

// NewScanner, creates a new scanner
func NewScanner() *Scanner {
	return &Scanner{
		Rules: rules.GetAllRules(),
	}
}

// ScanFile, scans a single file
func (s *Scanner) ScanFile(filePath string) ([]rules.Finding, error) {
	// Open the file
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Read file content
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	// Check if the file is a shell script or PowerShell script
	if !s.isShellScript(filePath, content) && !s.isPowerShellScript(filePath, content) {
		return nil, nil
	}

	// If it's a PowerShell file, only do line-based scanning
	if s.isPowerShellScript(filePath, content) {
		return s.scanByLine(filePath)
	}

	// Parse AST for shell scripts
	r := strings.NewReader(string(content))
	f, err := syntax.NewParser().Parse(r, filePath)
	if err != nil {
		// If AST parsing fails, continue with line-by-line scanning
		return s.scanByLine(filePath)
	}

	// Run both AST and line-based scanning and combine the results
	astFindings, err := s.scanByAST(f, filePath, string(content))
	if err != nil {
		return s.scanByLine(filePath)
	}

	lineFindings, err := s.scanByLine(filePath)
	if err != nil {
		return astFindings, nil
	}

	// Merge findings (simple deduplication to avoid duplicate findings)
	return mergeFindings(astFindings, lineFindings), nil
}

// mergeFindings, merges two finding lists and prevents duplications
func mergeFindings(a, b []rules.Finding) []rules.Finding {
	if len(a) == 0 {
		return b
	}
	if len(b) == 0 {
		return a
	}

	// Simple deduplication approach
	// To avoid reporting the same rule on the same file and line number multiple times
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

// scanByAST, detects security vulnerabilities using AST
func (s *Scanner) scanByAST(f *syntax.File, filePath, contentStr string) ([]rules.Finding, error) {
	var findings []rules.Finding
	contentLines := strings.Split(contentStr, "\n")

	// Create AST visitor (syntax.Visitor)
	astVisitor := func(node syntax.Node) bool {
		// If node is nil, don't process
		if node == nil {
			return true
		}

		// Get node's line number
		pos := node.Pos()
		// Check if Pos is nil
		if !pos.IsValid() {
			return true
		}

		lineNumber := int(pos.Line())
		if lineNumber <= 0 || lineNumber > len(contentLines) {
			return true // Continue
		}

		line := contentLines[lineNumber-1]

		// Check for ignore on this line
		if ignoreRegex.MatchString(line) {
			return true // Skip this line
		}

		// Checks for different node types
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

		return true // Continue to visit child nodes
	}

	syntax.Walk(f, astVisitor)
	return findings, nil
}

// checkCommand, checks a command call
func (s *Scanner) checkCommand(cmd *syntax.CallExpr, filePath string, lineNum int, lineContent string, findings *[]rules.Finding) {
	if len(cmd.Args) == 0 {
		return
	}

	// Get command name - adjusted for mvdan.cc/sh/v3/syntax library
	if len(cmd.Args) > 0 && len(cmd.Args[0].Parts) > 0 {
		if lit, ok := cmd.Args[0].Parts[0].(*syntax.Lit); ok {
			cmdName := lit.Value

			// Checks for dangerous commands
			switch cmdName {
			case "eval", "source", "exec":
				finding := rules.Finding{
					Rule: &rules.BaseRule{
						RuleID:          "BASH-AST-EVAL-001",
						RuleDescription: "AST: Dangerous " + cmdName + " command usage",
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
				// Check full line for pipe
				if strings.Contains(lineContent, "|") && (strings.Contains(lineContent, "sh") || strings.Contains(lineContent, "bash")) {
					finding := rules.Finding{
						Rule: &rules.BaseRule{
							RuleID:          "BASH-AST-CURL-001",
							RuleDescription: "AST: Redirecting curl/wget output directly to shell",
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
									RuleDescription: "AST: Insecure chmod usage",
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
							RuleDescription: "AST: Dangerous DD writing to disk",
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
							RuleDescription: "AST: Dangerous rm -rf * usage",
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

// checkPipeline, checks pipelines
func (s *Scanner) checkPipeline(binary *syntax.BinaryCmd, filePath string, lineNum int, lineContent string, findings *[]rules.Finding) {
	// Syntax.BinaryCmd.Op is now Syntax.OpType type
	if binary.Op != syntax.AndStmt && binary.Op != syntax.OrStmt {
		// Pipe operation can be checked by looking at line content
		if !strings.Contains(lineContent, "|") {
			return
		}

		// BinaryCmd's right side command is no longer a direct interface
		// Let's simply check the line content
		if strings.Contains(lineContent, "| sh") || strings.Contains(lineContent, "| bash") {
			finding := rules.Finding{
				Rule: &rules.BaseRule{
					RuleID:          "BASH-AST-PIPE-001",
					RuleDescription: "AST: Redirecting output directly to shell",
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

// checkVariables, checks variable declarations
func (s *Scanner) checkVariables(decl *syntax.DeclClause, filePath string, lineNum int, lineContent string, findings *[]rules.Finding) {
	// Update for changes in mvdan.cc/sh/v3 API
	// Use line content to check for sensitive variables
	line := strings.TrimSpace(lineContent)

	// Check variable definition
	if strings.Contains(line, "=") {
		// Check for sensitive variable names
		sensitiveVars := []string{"PASSWORD", "PASSWD", "SECRET", "KEY", "TOKEN", "API_KEY", "APIKEY"}
		for _, sensitive := range sensitiveVars {
			if strings.Contains(strings.ToUpper(line), sensitive+"=") {
				finding := rules.Finding{
					Rule: &rules.BaseRule{
						RuleID:          "BASH-AST-CRED-001",
						RuleDescription: "AST: Hardcoded sensitive variable detected",
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

		// Check history variables
		historyVars := []string{"HISTFILE", "HISTFILESIZE", "HISTSIZE"}
		for _, histVar := range historyVars {
			if strings.Contains(line, histVar+"=") {
				finding := rules.Finding{
					Rule: &rules.BaseRule{
						RuleID:          "BASH-AST-HIST-001",
						RuleDescription: "AST: Bash history log manipulation",
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

// checkFunctionDecl, checks function declarations
func (s *Scanner) checkFunctionDecl(fn *syntax.FuncDecl, filePath string, lineNum int, lineContent string, findings *[]rules.Finding) {
	// Check for Shellshock-style function definitions
	if strings.Contains(lineContent, "() {") && strings.Contains(lineContent, ":;};") {
		finding := rules.Finding{
			Rule: &rules.BaseRule{
				RuleID:          "BASH-AST-SHOCK-001",
				RuleDescription: "AST: Potential Shellshock vulnerability",
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

// checkTestClause, checks test clauses (if, while, etc.)
func (s *Scanner) checkTestClause(test *syntax.TestClause, filePath string, lineNum int, lineContent string, findings *[]rules.Finding) {
	// Check for unquoted variables
	if strings.Contains(lineContent, "[ $") && (strings.Contains(lineContent, " = ") || strings.Contains(lineContent, "== ") || strings.Contains(lineContent, "!= ")) {
		finding := rules.Finding{
			Rule: &rules.BaseRule{
				RuleID:          "BASH-AST-QUOTE-001",
				RuleDescription: "AST: Unquoted variable usage",
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

// ScanDirectory, scans a directory and its subdirectories
func (s *Scanner) ScanDirectory(dirPath string) ([]rules.Finding, error) {
	var findings []rules.Finding

	// Check for .bashleaksignore file
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

		// Check if file is in .bashleaksignore list
		if s.isIgnored(path) {
			return nil
		}

		// Scan the file
		fileFindings, err := s.ScanFile(path)
		if err != nil {
			return err
		}

		findings = append(findings, fileFindings...)
		return nil
	})

	return findings, err
}

// isPowerShellScript, checks if the file is a PowerShell script
func (s *Scanner) isPowerShellScript(filePath string, content []byte) bool {
	// Check by extension
	if strings.HasSuffix(strings.ToLower(filePath), ".ps1") {
		return true
	}

	// Check first few lines for PowerShell comment
	if len(content) > 0 {
		scanner := bufio.NewScanner(strings.NewReader(string(content)))
		lineCount := 0
		for scanner.Scan() && lineCount < 5 {
			line := scanner.Text()
			if powershellCommentRegex.MatchString(line) {
				return true
			}
			lineCount++
		}
	}

	return false
}

// isShellScript, checks if the file is a shell script
func (s *Scanner) isShellScript(filePath string, content []byte) bool {
	// Check by extension
	if strings.HasSuffix(strings.ToLower(filePath), ".sh") {
		return true
	}

	// Check if first line has shebang
	if len(content) > 0 {
		scanner := bufio.NewScanner(strings.NewReader(string(content)))
		if scanner.Scan() {
			firstLine := scanner.Text()
			return shebangRegex.MatchString(firstLine)
		}
	}

	return false
}

// scanByLine, scans a file line by line
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

		// Should this line be ignored?
		if ignoreRegex.MatchString(line) {
			continue
		}

		// Check all rules
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

// loadIgnoreFile, loads .bashleaksignore file
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

// isIgnored, checks if a file should be ignored
func (s *Scanner) isIgnored(filePath string) bool {
	for _, pattern := range s.IgnoreFiles {
		matched, err := filepath.Match(pattern, filepath.Base(filePath))
		if err == nil && matched {
			return true
		}
	}
	return false
}
