package rules

import (
	"regexp"
)

// File containing PowerShell rules

func init() {
	// Register PowerShell rules
	registerPowerShellRules()
}

// registerPowerShellRules registers security rules for PowerShell
func registerPowerShellRules() {
	// Invoke-Expression usage (similar to eval)
	registerRule(&BaseRule{
		RuleID:          "PS-INVOKE-001",
		RuleDescription: "PowerShell: Dangerous Invoke-Expression usage",
		RuleLevel:       RiskLevelCritical,
		Pattern:         regexp.MustCompile(`(?i)(Invoke-Expression|\$\(.+\)|\biex\b)`),
	})

	// Remote script download and execution
	registerRule(&BaseRule{
		RuleID:          "PS-REMOTE-001",
		RuleDescription: "PowerShell: Downloading and executing scripts from internet",
		RuleLevel:       RiskLevelCritical,
		Pattern:         regexp.MustCompile(`(?i)(Invoke-(WebRequest|RestMethod).*\|\s*Invoke-Expression|iwr.*\|\s*iex)`),
	})

	// Start-Process command
	registerRule(&BaseRule{
		RuleID:          "PS-EXEC-001",
		RuleDescription: "PowerShell: Dangerous process execution",
		RuleLevel:       RiskLevelCritical,
		Pattern:         regexp.MustCompile(`(?i)(Start-Process\s+.*\s+-ArgumentList)`),
	})

	// Hardcoded credentials
	registerRule(&BaseRule{
		RuleID:          "PS-CREDS-001",
		RuleDescription: "PowerShell: Hardcoded credentials",
		RuleLevel:       RiskLevelCritical,
		Pattern:         regexp.MustCompile(`(?i)(\$.*[Pp]ass(word)?|\$.*[Kk]ey|\$.*[Ss]ecret|\$.*[Tt]oken).*=\s*["']`),
	})

	// File permissions
	registerRule(&BaseRule{
		RuleID:          "PS-ACL-001",
		RuleDescription: "PowerShell: Modifying file permissions",
		RuleLevel:       RiskLevelMedium,
		Pattern:         regexp.MustCompile(`(?i)(icacls.*\/grant\s+[Ee]very(one|body)|Set-Acl)`),
	})

	// PowerShell history clearing
	registerRule(&BaseRule{
		RuleID:          "PS-HIST-001",
		RuleDescription: "PowerShell: History clearing attempt",
		RuleLevel:       RiskLevelMedium,
		Pattern:         regexp.MustCompile(`(?i)(Clear-History|Remove-Item.*\\ConsoleHost_history\.txt)`),
	})

	// Command Injection risk
	registerRule(&BaseRule{
		RuleID:          "PS-CMD-001",
		RuleDescription: "PowerShell: Command injection risk",
		RuleLevel:       RiskLevelCritical,
		Pattern:         regexp.MustCompile(`(?i)(Invoke-Expression.*\$.+;.*|iex.*\$.+;.*)`),
	})
}
