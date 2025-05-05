package rules

import (
	"regexp"
	"strings"
)

// Risk düzeyleri
type RiskLevel string

const (
	RiskLevelCritical RiskLevel = "Critical"
	RiskLevelMedium   RiskLevel = "Medium"
	RiskLevelLow      RiskLevel = "Low"
)

// Finding, tarama esnasında bulunan güvenlik açığı
type Finding struct {
	Rule        Rule
	FilePath    string
	LineNumber  int
	LineContent string
	Ignored     bool
}

// Rule, bir güvenlik açığı tespit kuralı
type Rule interface {
	ID() string
	Description() string
	Level() RiskLevel
	Match(content string) bool
}

// BaseRule, tüm kurallar için temel uygulama
type BaseRule struct {
	RuleID          string
	RuleDescription string
	RuleLevel       RiskLevel
	Pattern         *regexp.Regexp
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

// CustomRule, özel karşılaştırma mantığı içeren kural
type CustomRule struct {
	BaseRule
}

// Match, içeriği kurala göre kontrol eder
func (r *CustomRule) Match(content string) bool {
	// Önce temel regex kontrolü yapalım
	if !r.Pattern.MatchString(content) {
		return false
	}

	// Eğer BASH-TEMP-002 kuralı ise mktemp -p kontrolü yapalım
	if r.RuleID == "BASH-TEMP-002" {
		// Eğer -p parametresi varsa, güvenli kabul edelim
		if strings.Contains(content, "mktemp") && strings.Contains(content, "-p") {
			return false
		}
		// -p parametresi yoksa, güvensiz kabul edelim
		return true
	}

	// Diğer kurallar için normal regex kontrolü yeterli
	return true
}

// GetAllRules tüm tanımlı kuralları döndürür
func GetAllRules() []Rule {
	return []Rule{
		NewEvalRule(),
		NewExecRule(),
		NewCurlPipeRule(),
		NewChmodInsecureRule(),
		NewHardcodedCredentialRule(),
		NewTempFileRule(),
		NewWildcardGlobRule(),
		NewSudoNopasswordRule(),
		NewHistoryModificationRule(),
		NewUnsafeVariableExpansionRule(),
		NewShellShockRule(),
		NewSetuidScriptRule(),
		NewUnsafeTmpUsageRule(),
		NewDDOverwriteRule(),
		NewUnquotedVariableRule(),
		NewEnvVarInjectionRule(),
		NewArbitraryCodeExecutionRule(),
	}
}

// NewEvalRule eval kullanımı kuralı
func NewEvalRule() Rule {
	return &BaseRule{
		RuleID:          "BASH-EVAL-001",
		RuleDescription: "Tehlikeli eval kullanımı tespit edildi",
		RuleLevel:       RiskLevelCritical,
		Pattern:         regexp.MustCompile(`\beval\s+[\"\']?.*[\"\']?`),
	}
}

// NewExecRule exec kullanımı kuralı
func NewExecRule() Rule {
	return &BaseRule{
		RuleID:          "BASH-EXEC-001",
		RuleDescription: "Tehlikeli exec kullanımı tespit edildi",
		RuleLevel:       RiskLevelCritical,
		Pattern:         regexp.MustCompile(`\bexec\s+.*`),
	}
}

// NewCurlPipeRule curl pipe kullanımı kuralı
func NewCurlPipeRule() Rule {
	return &BaseRule{
		RuleID:          "BASH-CURL-001",
		RuleDescription: "Curl/wget çıktısını doğrudan shell'e yönlendirme tespit edildi",
		RuleLevel:       RiskLevelCritical,
		Pattern:         regexp.MustCompile(`(curl|wget).*\s*\|\s*(ba)?sh`),
	}
}

// NewChmodInsecureRule güvensiz chmod kuralı
func NewChmodInsecureRule() Rule {
	return &BaseRule{
		RuleID:          "BASH-CHMOD-001",
		RuleDescription: "Güvensiz chmod 777 kullanımı tespit edildi",
		RuleLevel:       RiskLevelMedium,
		Pattern:         regexp.MustCompile(`chmod\s+([0-7]?[0-7][7][7]|a[=+]rwx|o[=+]rwx)`),
	}
}

// NewHardcodedCredentialRule sabit tanımlı kimlik bilgileri kuralı
func NewHardcodedCredentialRule() Rule {
	return &BaseRule{
		RuleID:          "BASH-CREDS-001",
		RuleDescription: "Hardcoded kimlik bilgileri tespit edildi",
		RuleLevel:       RiskLevelCritical,
		Pattern:         regexp.MustCompile(`(password|passwd|pwd|user|username|apikey|api_key|token|secret|key)=['"]?[^'"${}()\s]+['"]?`),
	}
}

// NewTempFileRule güvensiz temp dosya oluşturma kuralı
func NewTempFileRule() Rule {
	return &BaseRule{
		RuleID:          "BASH-TEMP-001",
		RuleDescription: "Güvensiz geçici dosya kullanımı tespit edildi",
		RuleLevel:       RiskLevelMedium,
		Pattern:         regexp.MustCompile(`\b(\/tmp\/[a-zA-Z0-9_\.]+|\/var\/tmp\/[a-zA-Z0-9_\.]+)`),
	}
}

// NewWildcardGlobRule tehlikeli glob kullanım kuralı
func NewWildcardGlobRule() Rule {
	return &BaseRule{
		RuleID:          "BASH-GLOB-001",
		RuleDescription: "Tehlikeli wildcard glob kullanımı tespit edildi",
		RuleLevel:       RiskLevelMedium,
		Pattern:         regexp.MustCompile(`rm\s+(-[rfv]+\s+)*[\/\w]*[\*\?]`),
	}
}

// NewSudoNopasswordRule sudo NOPASSWD kullanım kuralı
func NewSudoNopasswordRule() Rule {
	return &BaseRule{
		RuleID:          "BASH-SUDO-001",
		RuleDescription: "Sudo NOPASSWD kullanımı tespit edildi",
		RuleLevel:       RiskLevelMedium,
		Pattern:         regexp.MustCompile(`sudo\s+.*NOPASSWD`),
	}
}

// NewHistoryModificationRule history değiştirme kuralı
func NewHistoryModificationRule() Rule {
	return &BaseRule{
		RuleID:          "BASH-HIST-001",
		RuleDescription: "Bash history log manipülasyonu tespit edildi",
		RuleLevel:       RiskLevelMedium,
		Pattern:         regexp.MustCompile(`(HISTFILE|HISTSIZE|HISTFILESIZE)=`),
	}
}

// NewUnsafeVariableExpansionRule güvensiz değişken kullanımı kuralı
func NewUnsafeVariableExpansionRule() Rule {
	return &BaseRule{
		RuleID:          "BASH-VAR-001",
		RuleDescription: "Alıntısız veya güvensiz değişken kullanımı tespit edildi",
		RuleLevel:       RiskLevelMedium,
		Pattern:         regexp.MustCompile(`\b(cp|mv|rm|cat)\s+[^"']*\$[a-zA-Z0-9_]+[^"']*`),
	}
}

// NewShellShockRule shellshock açığı kuralı
func NewShellShockRule() Rule {
	return &BaseRule{
		RuleID:          "BASH-SHOCK-001",
		RuleDescription: "Potansiyel Shellshock açığı tespit edildi",
		RuleLevel:       RiskLevelCritical,
		Pattern:         regexp.MustCompile(`\(\)\s*{\s*:;\s*}\s*;`),
	}
}

// NewSetuidScriptRule setuid betik kullanımı kuralı
func NewSetuidScriptRule() Rule {
	return &BaseRule{
		RuleID:          "BASH-SETUID-001",
		RuleDescription: "Setuid/Setgid betik kullanımı tespit edildi",
		RuleLevel:       RiskLevelMedium,
		Pattern:         regexp.MustCompile(`chmod\s+[u|g]\+s`),
	}
}

// NewUnsafeTmpUsageRule güvensiz /tmp kullanımı kuralı
func NewUnsafeTmpUsageRule() Rule {
	// Basit bir regex ile mktemp komutunu tespit ederiz
	return &CustomRule{
		BaseRule: BaseRule{
			RuleID:          "BASH-TEMP-002",
			RuleDescription: "Race condition'a açık geçici dosya kullanımı tespit edildi",
			RuleLevel:       RiskLevelMedium,
			Pattern:         regexp.MustCompile(`\bmktemp\b`),
		},
	}
}

// NewDDOverwriteRule dd komut yanlış kullanımı kuralı
func NewDDOverwriteRule() Rule {
	return &BaseRule{
		RuleID:          "BASH-DD-001",
		RuleDescription: "Disk üzerine tehlikeli dd yazımı tespit edildi",
		RuleLevel:       RiskLevelCritical,
		Pattern:         regexp.MustCompile(`\bdd\s+.*of=/dev/(sd|hd|xvd|nvme)`),
	}
}

// NewUnquotedVariableRule alıntılanmamış değişken kuralı
func NewUnquotedVariableRule() Rule {
	return &BaseRule{
		RuleID:          "BASH-QUOTE-001",
		RuleDescription: "Alıntılanmamış değişken kullanımı tespit edildi",
		RuleLevel:       RiskLevelLow,
		Pattern:         regexp.MustCompile(`if\s+\[\s+\$[a-zA-Z0-9_]+\s+[=!]`),
	}
}

// NewEnvVarInjectionRule çevre değişkeni enjeksiyon kuralı
func NewEnvVarInjectionRule() Rule {
	return &BaseRule{
		RuleID:          "BASH-ENV-001",
		RuleDescription: "Çevre değişkeni enjeksiyon riski tespit edildi",
		RuleLevel:       RiskLevelMedium,
		Pattern:         regexp.MustCompile(`\bsource\s+\$[A-Za-z0-9_]+`),
	}
}

// NewArbitraryCodeExecutionRule keyfi kod çalıştırma kuralı
func NewArbitraryCodeExecutionRule() Rule {
	return &BaseRule{
		RuleID:          "BASH-EXEC-002",
		RuleDescription: "Keyfi kod çalıştırma riski tespit edildi",
		RuleLevel:       RiskLevelCritical,
		Pattern: regexp.MustCompile(`\$\(.*\$(\w+).*\)|` +
			`\` + "`" + `.*\$(\w+).*\` + "`"),
	}
}
