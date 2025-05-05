package rules

import (
	"regexp"
	"strings"
)

// Risk levels
type RiskLevel string

const (
	RiskLevelCritical RiskLevel = "Critical"
	RiskLevelMedium   RiskLevel = "Medium"
	RiskLevelLow      RiskLevel = "Low"
)

// Finding, a security vulnerability found during scanning
type Finding struct {
	Rule        Rule
	FilePath    string
	LineNumber  int
	LineContent string
	Ignored     bool
}

// Rule, a security vulnerability detection rule
type Rule interface {
	ID() string
	Description() string
	Level() RiskLevel
	Match(content string) bool
}

// BaseRule, basic implementation for all rules
type BaseRule struct {
	RuleID          string
	RuleDescription string
	RuleLevel       RiskLevel
	Pattern         *regexp.Regexp
}

// Global variable to store all rules
var allRules []Rule

// registerRule registers a new rule
func registerRule(rule Rule) {
	allRules = append(allRules, rule)
}

func (r *BaseRule) ID() string {
	return r.RuleID
}

func (r *BaseRule) Description() string {
	return r.RuleDescription
}

func (r *BaseRule) Level() RiskLevel {
	return r.RuleLevel
}

func (r *BaseRule) Match(content string) bool {
	return r.Pattern.MatchString(content)
}

// CustomRule, rule with custom matching logic
type CustomRule struct {
	BaseRule
}

// Match checks content against the rule
func (r *CustomRule) Match(content string) bool {
	// First check basic regex
	if !r.Pattern.MatchString(content) {
		return false
	}

	// If it's BASH-TEMP-002 rule, check for mktemp -p
	if r.RuleID == "BASH-TEMP-002" {
		// If -p parameter exists, consider it safe
		if strings.Contains(content, "mktemp") && strings.Contains(content, "-p") {
			return false
		}
		// Otherwise, consider it unsafe
		return true
	}

	// For other rules, regular regex check is sufficient
	return true
}

// GetAllRules returns all defined rules
func GetAllRules() []Rule {
	// If rules not yet defined, define them
	if len(allRules) == 0 {
		// Define basic rules
		initCoreRules()
	}
	return allRules
}

// initCoreRules defines basic security rules
func initCoreRules() {
	// BASH EVAL usage - Critical
	registerRule(&BaseRule{
		RuleID:          "BASH-EVAL-001",
		RuleDescription: "Dangerous eval usage detected",
		RuleLevel:       RiskLevelCritical,
		Pattern:         regexp.MustCompile(`\beval\b`),
	})

	// BASH EXEC usage - Critical
	registerRule(&BaseRule{
		RuleID:          "BASH-EXEC-001",
		RuleDescription: "Dangerous exec usage detected",
		RuleLevel:       RiskLevelCritical,
		Pattern:         regexp.MustCompile(`\bexec\b\s+`),
	})

	// BASH Curl/Wget Pipe - Critical
	registerRule(&BaseRule{
		RuleID:          "BASH-CURL-001",
		RuleDescription: "Redirecting curl/wget output directly to shell detected",
		RuleLevel:       RiskLevelCritical,
		Pattern:         regexp.MustCompile(`(curl|wget).*\|\s*(ba)?sh`),
	})

	// BASH Chmod 777 - Medium
	registerRule(&BaseRule{
		RuleID:          "BASH-CHMOD-001",
		RuleDescription: "Insecure chmod 777 usage detected",
		RuleLevel:       RiskLevelMedium,
		Pattern:         regexp.MustCompile(`chmod\s+([0-7])*777\b`),
	})

	// BASH Hardcoded Credentials - Critical
	registerRule(&BaseRule{
		RuleID:          "BASH-CREDS-001",
		RuleDescription: "Hardcoded credentials detected",
		RuleLevel:       RiskLevelCritical,
		Pattern:         regexp.MustCompile(`(password|passwd|pwd|key|token|secret|credential)s?\s*=\s*["']`),
	})

	// BASH Temporary File Usage - Medium
	registerRule(&BaseRule{
		RuleID:          "BASH-TEMP-001",
		RuleDescription: "Insecure temporary file usage detected",
		RuleLevel:       RiskLevelMedium,
		Pattern:         regexp.MustCompile(`(\/tmp\/[a-zA-Z0-9_]+)`),
	})

	// BASH Wildcard Glob - Medium
	registerRule(&BaseRule{
		RuleID:          "BASH-GLOB-001",
		RuleDescription: "Dangerous wildcard glob usage detected",
		RuleLevel:       RiskLevelMedium,
		Pattern:         regexp.MustCompile(`(rm|chown|chmod)\s+-[rRf]*\s+\*`),
	})

	// BASH Sudo NOPASSWD - Medium
	registerRule(&BaseRule{
		RuleID:          "BASH-SUDO-001",
		RuleDescription: "Sudo NOPASSWD usage detected",
		RuleLevel:       RiskLevelMedium,
		Pattern:         regexp.MustCompile(`NOPASSWD\s*:\s*ALL`),
	})

	// BASH History Deletion - Medium
	registerRule(&BaseRule{
		RuleID:          "BASH-HIST-001",
		RuleDescription: "Bash history manipulation detected",
		RuleLevel:       RiskLevelMedium,
		Pattern:         regexp.MustCompile(`(HISTFILE|HISTSIZE|HISTFILESIZE)\s*=\s*(\/dev\/null|0)`),
	})

	// BASH Unsafe Variable Usage - Medium
	registerRule(&BaseRule{
		RuleID:          "BASH-VAR-001",
		RuleDescription: "Unquoted or unsafe variable usage",
		RuleLevel:       RiskLevelMedium,
		Pattern:         regexp.MustCompile(`\$[a-zA-Z0-9_]+\s`),
	})

	// BASH ShellShock - Critical
	registerRule(&BaseRule{
		RuleID:          "BASH-SHOCK-001",
		RuleDescription: "Potential ShellShock vulnerability detected",
		RuleLevel:       RiskLevelCritical,
		Pattern:         regexp.MustCompile(`\(\)\s*{\s*:;\s*};\s*`),
	})

	// BASH setuid/setgid - Medium
	registerRule(&BaseRule{
		RuleID:          "BASH-SETUID-001",
		RuleDescription: "Setuid/Setgid script usage detected",
		RuleLevel:       RiskLevelMedium,
		Pattern:         regexp.MustCompile(`chmod\s+[ug]\+s`),
	})

	// BASH /tmp Race Condition - Medium
	registerRule(&CustomRule{
		BaseRule: BaseRule{
			RuleID:          "BASH-TEMP-002",
			RuleDescription: "Temporary file usage vulnerable to race condition",
			RuleLevel:       RiskLevelMedium,
			Pattern:         regexp.MustCompile(`\bmktemp\b`),
		},
	})

	// BASH dd command usage - Critical
	registerRule(&BaseRule{
		RuleID:          "BASH-DD-001",
		RuleDescription: "Dangerous DD writing to disk detected",
		RuleLevel:       RiskLevelCritical,
		Pattern:         regexp.MustCompile(`\bdd\b.*\bof=/dev/(hd|sd|mmcblk)`),
	})

	// BASH Unquoted Variable - Low
	registerRule(&BaseRule{
		RuleID:          "BASH-QUOTE-001",
		RuleDescription: "Unquoted variable usage",
		RuleLevel:       RiskLevelLow,
		Pattern:         regexp.MustCompile(`echo\s+\$[a-zA-Z0-9_]+`),
	})

	// BASH Environment Variable Injection - Medium
	registerRule(&BaseRule{
		RuleID:          "BASH-ENV-001",
		RuleDescription: "Environment variable injection risk",
		RuleLevel:       RiskLevelMedium,
		Pattern:         regexp.MustCompile(`\$\{?[a-zA-Z_][a-zA-Z0-9_]*\}?=(.*\$|\()`),
	})

	// BASH Arbitrary Code Execution - Critical
	registerRule(&BaseRule{
		RuleID:          "BASH-EXEC-002",
		RuleDescription: "Arbitrary code execution risk detected",
		RuleLevel:       RiskLevelCritical,
		Pattern:         regexp.MustCompile(`\$\((.*\$[a-zA-Z0-9_]+.*)\)`),
	})

	// AST Parse Rules
	registerRule(&BaseRule{
		RuleID:          "BASH-AST-EVAL-001",
		RuleDescription: "AST: Dangerous eval command usage",
		RuleLevel:       RiskLevelCritical,
		Pattern:         regexp.MustCompile(`.*`), // Left to AST analysis
	})

	registerRule(&BaseRule{
		RuleID:          "BASH-AST-CURL-001",
		RuleDescription: "AST: Curl/wget output directly to shell",
		RuleLevel:       RiskLevelCritical,
		Pattern:         regexp.MustCompile(`.*`), // Left to AST analysis
	})

	registerRule(&BaseRule{
		RuleID:          "BASH-AST-PIPE-001",
		RuleDescription: "AST: Redirecting output directly to shell",
		RuleLevel:       RiskLevelCritical,
		Pattern:         regexp.MustCompile(`.*`), // Left to AST analysis
	})
}

// Legacy rule functions below maintained for backward compatibility

// NewEvalRule eval usage rule
func NewEvalRule() Rule {
	return &BaseRule{
		RuleID:          "BASH-EVAL-001",
		RuleDescription: "Dangerous eval usage detected",
		RuleLevel:       RiskLevelCritical,
		Pattern:         regexp.MustCompile(`\beval\s+[\"\']?.*[\"\']?`),
	}
}

// NewExecRule exec usage rule
func NewExecRule() Rule {
	return &BaseRule{
		RuleID:          "BASH-EXEC-001",
		RuleDescription: "Dangerous exec usage detected",
		RuleLevel:       RiskLevelCritical,
		Pattern:         regexp.MustCompile(`\bexec\s+.*`),
	}
}

// NewCurlPipeRule curl pipe usage rule
func NewCurlPipeRule() Rule {
	return &BaseRule{
		RuleID:          "BASH-CURL-001",
		RuleDescription: "Redirecting curl/wget output directly to shell detected",
		RuleLevel:       RiskLevelCritical,
		Pattern:         regexp.MustCompile(`(curl|wget).*\s*\|\s*(ba)?sh`),
	}
}

// NewChmodInsecureRule insecure chmod rule
func NewChmodInsecureRule() Rule {
	return &BaseRule{
		RuleID:          "BASH-CHMOD-001",
		RuleDescription: "Insecure chmod 777 usage detected",
		RuleLevel:       RiskLevelMedium,
		Pattern:         regexp.MustCompile(`chmod\s+([0-7]?[0-7][7][7]|a[=+]rwx|o[=+]rwx)`),
	}
}

// NewHardcodedCredentialRule hardcoded credentials rule
func NewHardcodedCredentialRule() Rule {
	return &BaseRule{
		RuleID:          "BASH-CREDS-001",
		RuleDescription: "Hardcoded credentials detected",
		RuleLevel:       RiskLevelCritical,
		Pattern:         regexp.MustCompile(`(password|passwd|pwd|user|username|apikey|api_key|token|secret|key)=['"]?[^'"${}()\s]+['"]?`),
	}
}

// NewTempFileRule insecure temp file creation rule
func NewTempFileRule() Rule {
	return &BaseRule{
		RuleID:          "BASH-TEMP-001",
		RuleDescription: "Insecure temporary file usage detected",
		RuleLevel:       RiskLevelMedium,
		Pattern:         regexp.MustCompile(`\b(\/tmp\/[a-zA-Z0-9_\.]+|\/var\/tmp\/[a-zA-Z0-9_\.]+)`),
	}
}

// NewWildcardGlobRule dangerous glob usage rule
func NewWildcardGlobRule() Rule {
	return &BaseRule{
		RuleID:          "BASH-GLOB-001",
		RuleDescription: "Dangerous wildcard glob usage detected",
		RuleLevel:       RiskLevelMedium,
		Pattern:         regexp.MustCompile(`rm\s+(-[rfv]+\s+)*[\/\w]*[\*\?]`),
	}
}

// NewSudoNopasswordRule sudo NOPASSWD usage rule
func NewSudoNopasswordRule() Rule {
	return &BaseRule{
		RuleID:          "BASH-SUDO-001",
		RuleDescription: "Sudo NOPASSWD usage detected",
		RuleLevel:       RiskLevelMedium,
		Pattern:         regexp.MustCompile(`sudo\s+.*NOPASSWD`),
	}
}

// NewHistoryModificationRule history modification rule
func NewHistoryModificationRule() Rule {
	return &BaseRule{
		RuleID:          "BASH-HIST-001",
		RuleDescription: "Bash history manipulation detected",
		RuleLevel:       RiskLevelMedium,
		Pattern:         regexp.MustCompile(`(HISTFILE|HISTSIZE|HISTFILESIZE)=`),
	}
}

// NewUnsafeVariableExpansionRule unsafe variable usage rule
func NewUnsafeVariableExpansionRule() Rule {
	return &BaseRule{
		RuleID:          "BASH-VAR-001",
		RuleDescription: "Unquoted or unsafe variable usage detected",
		RuleLevel:       RiskLevelMedium,
		Pattern:         regexp.MustCompile(`\b(cp|mv|rm|cat)\s+[^"']*\$[a-zA-Z0-9_]+[^"']*`),
	}
}

// NewShellShockRule shellshock vulnerability rule
func NewShellShockRule() Rule {
	return &BaseRule{
		RuleID:          "BASH-SHOCK-001",
		RuleDescription: "Potential ShellShock vulnerability detected",
		RuleLevel:       RiskLevelCritical,
		Pattern:         regexp.MustCompile(`\(\)\s*{\s*:;\s*}\s*;`),
	}
}

// NewSetuidScriptRule setuid script usage rule
func NewSetuidScriptRule() Rule {
	return &BaseRule{
		RuleID:          "BASH-SETUID-001",
		RuleDescription: "Setuid/Setgid script usage detected",
		RuleLevel:       RiskLevelMedium,
		Pattern:         regexp.MustCompile(`chmod\s+[u|g]\+s`),
	}
}

// NewUnsafeTmpUsageRule unsafe /tmp usage rule
func NewUnsafeTmpUsageRule() Rule {
	// Simple regex to detect mktemp command
	return &CustomRule{
		BaseRule: BaseRule{
			RuleID:          "BASH-TEMP-002",
			RuleDescription: "Temporary file usage vulnerable to race condition",
			RuleLevel:       RiskLevelMedium,
			Pattern:         regexp.MustCompile(`\bmktemp\b`),
		},
	}
}

// NewDDOverwriteRule dd command misuse rule
func NewDDOverwriteRule() Rule {
	return &BaseRule{
		RuleID:          "BASH-DD-001",
		RuleDescription: "Dangerous DD writing to disk detected",
		RuleLevel:       RiskLevelCritical,
		Pattern:         regexp.MustCompile(`\bdd\s+.*of=/dev/(sd|hd|xvd|nvme)`),
	}
}

// NewUnquotedVariableRule unquoted variable rule
func NewUnquotedVariableRule() Rule {
	return &BaseRule{
		RuleID:          "BASH-QUOTE-001",
		RuleDescription: "Unquoted variable usage detected",
		RuleLevel:       RiskLevelLow,
		Pattern:         regexp.MustCompile(`if\s+\[\s+\$[a-zA-Z0-9_]+\s+[=!]`),
	}
}

// NewEnvVarInjectionRule environment variable injection rule
func NewEnvVarInjectionRule() Rule {
	return &BaseRule{
		RuleID:          "BASH-ENV-001",
		RuleDescription: "Environment variable injection risk detected",
		RuleLevel:       RiskLevelMedium,
		Pattern:         regexp.MustCompile(`\bsource\s+\$[A-Za-z0-9_]+`),
	}
}

// NewArbitraryCodeExecutionRule arbitrary code execution rule
func NewArbitraryCodeExecutionRule() Rule {
	return &BaseRule{
		RuleID:          "BASH-EXEC-002",
		RuleDescription: "Arbitrary code execution risk detected",
		RuleLevel:       RiskLevelCritical,
		Pattern: regexp.MustCompile(`\$\(.*\$(\w+).*\)|` +
			`\` + "`" + `.*\$(\w+).*\` + "`"),
	}
}
