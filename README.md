# 🔍 BashLeaks

BashLeaks is a static analysis tool that scans shell script files to detect potentially dangerous and exploitable command patterns. It can be integrated into CI/CD processes and is designed to automate script security.

<p align="center">
  <img src="docs/images/bashleaks_logo.png" alt="BashLeaks Logo" width="200" />
</p>

## 🎯 Features

- ⚠️ **Powerful Risk Detection**: Detects common security vulnerabilities such as `eval`, `exec`, `curl | sh`, `chmod 777`, hardcoded credentials.
- 🧠 **AST-Based Scanning**: Uses mvdan.cc/sh library to perform Abstract Syntax Tree analysis of shell scripts for more precise detection.
- 🔒 **Risk Classification**: Findings are prioritized as Critical, Medium, and Low.
- 🧩 **Modular Scanning Engine**: Each security rule is defined as a separate module, easily extensible.
- 📊 **Advanced Reporting**: Modern terminal output, interactive HTML reports, JSON/YAML, and Markdown format support.
- 📊 **Metric Visualization**: Visual dashboard of vulnerabilities found in reports.
- 🧪 **CI/CD Integration**: Control pipeline success based on security risks with the `--fail-on` flag.
- 📁 **Automatic File Detection**: Automatically finds files with `.sh` extension and those containing shebang.
- 🚫 **Flexible Ignore System**: Provides flexibility with `.bashleaksignore` or inline `# bashleaks:ignore`.
- 📈 **Prometheus Support**: Export metrics like number of scanned files and vulnerabilities to Prometheus.

## 🚀 Installation

### Download Ready Binary

You can download the latest version from the [Releases](https://github.com/raventrk/bashleaks/releases) page.

```bash
# Linux/MacOS
curl -L https://github.com/raventrk/bashleaks/releases/latest/download/bashleaks-$(uname -s)-$(uname -m) -o bashleaks
chmod +x bashleaks
sudo mv bashleaks /usr/local/bin/

# Windows
# Place the downloaded bashleaks.exe file in a folder that's in your PATH
```

### Installation with Go

```bash
go install github.com/raventrk/bashleaks@latest
```

### Manual Compilation

```bash
git clone https://github.com/raventrk/bashleaks
cd bashleaks
go build -o bashleaks cmd/bashleaks/main.go
```

## 📖 Usage Guide

### Basic Usage

```bash
# Scan a single file
bashleaks /path/to/script.sh

# Scan a directory
bashleaks /path/to/scripts/

# Get output in a specific format
bashleaks -f json /path/to/script.sh
# or
bashleaks --format json /path/to/script.sh

# Save report to a file
bashleaks -f html -o report.html /path/to/scripts/
# or
bashleaks --format html --output report.html /path/to/scripts/
```

### Command Line Options

```
Usage:
  bashleaks [file or directory] [flags]
  bashleaks [command]

Flags:
      --fail-on string        Fails if vulnerabilities are found at specified risk level or above: critical, medium, low
  -f, --format string         Report format: text, json, yaml, html, markdown (default "text")
  -h, --help                  Shows help
      --metrics-addr string   Address for listening Prometheus metrics (e.g. :9090)
  -o, --output string         Report file (uses stdout if not specified)
  -v, --verbose               Verbose logging
```

### Output Formats

BashLeaks can produce reports in various formats:

- **text**: Colorful and organized terminal output (default)
- **json**: JSON format for integration with CI/CD systems and other tools
- **yaml**: YAML format for configuration files
- **html**: Interactive and visual HTML report, includes metric dashboard
- **markdown**: Documentation-friendly Markdown format

### CI/CD Integration

GitHub Actions workflow example:

```yaml
name: BashLeaks Security Scan

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Go
        uses: actions/setup-go@v4
        with:
          go-version: '1.20'
          
      - name: Install BashLeaks
        run: go install github.com/raventrk/bashleaks@latest
        
      - name: Run BashLeaks Scan
        run: bashleaks --fail-on critical -f json -o scan-results.json ./scripts
        
      - name: Upload scan results
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: bashleaks-results
          path: scan-results.json
```

### Using Ignore

You can use two methods to exclude certain rules or files from scanning:

1. **Line-based ignore**: Add `# bashleaks:ignore` comment to prevent a particular line from being detected:

```bash
API_KEY="my-secret-key" # bashleaks:ignore
```

2. **File-based ignore**: Create a `.bashleaksignore` file in the project root directory:

```
# Exclude file by specifying full path
/path/to/excluded/file.sh

# Glob pattern support
**/vendor/*.sh
**/node_modules/**

# Exclude special script folder
scripts/legacy/*
```

## 🛠️ Technology Stack

- **Language**: Go
- **Parsing**: Bash AST analysis support with mvdan.cc/sh
- **CLI**: spf13/cobra
- **Logging**: zerolog
- **UI**: Bootstrap 5 for HTML reports
- **Testing**: stretchr/testify
- **Metrics**: Prometheus Exporter

## 📋 Security Rules

BashLeaks detects the following common security vulnerabilities:

| Rule ID | Description | Risk Level |
|----------|----------|---------------|
| BASH-EVAL-001 | Dangerous eval usage | Critical |
| BASH-EXEC-001 | Dangerous exec usage | Critical |
| BASH-EXEC-002 | Arbitrary code execution risk | Critical |
| BASH-CURL-001 | Redirecting curl/wget output directly to shell | Critical |
| BASH-CREDS-001 | Hardcoded credentials | Critical |
| BASH-DD-001 | Dangerous dd writing to disk | Critical |
| BASH-SHOCK-001 | Potential Shellshock vulnerability | Critical |
| BASH-CHMOD-001 | Unsafe chmod 777 usage | Medium |
| BASH-TEMP-001 | Unsafe temporary file usage | Medium |
| BASH-TEMP-002 | Temporary file usage vulnerable to race condition | Medium |
| BASH-GLOB-001 | Dangerous wildcard glob usage | Medium |
| BASH-SUDO-001 | Sudo NOPASSWD usage | Medium |
| BASH-HIST-001 | Bash history log manipulation | Medium |
| BASH-VAR-001 | Unquoted or unsafe variable usage | Medium |
| BASH-SETUID-001 | Setuid/Setgid script usage | Medium |
| BASH-ENV-001 | Environment variable injection risk | Medium |
| BASH-QUOTE-001 | Unquoted variable usage | Low |

## 🧪 Test Files

The repository includes sample shell script files to test BashLeaks capabilities:

- **test_files/insecure.sh**: Sample script containing various security vulnerabilities.
- **test_files/secure.sh**: Sample demonstrating secure shell script writing practices.
- **test_files/mixed.sh**: Sample containing both secure and insecure code, also showing the use of `bashleaks:ignore`.

You can test the tool's capabilities by scanning these files with BashLeaks:

```bash
bashleaks test_files/insecure.sh
bashleaks test_files/secure.sh -f html -o secure_report.html
bashleaks test_files/mixed.sh -f json
```

## 🌱 Best Practices

Follow these security practices when writing shell scripts:

1. **Always use quotes when expanding variables**: `"${variable}"` 
2. **Avoid using eval and exec**
3. **Use `mktemp -p` for temporary files**
4. **Give minimum required permissions with chmod** (instead of 777)
5. **Don't pipe command outputs directly to bash**
6. **Use environment variables instead of hardcoded credentials**
7. **Be careful when using wildcard glob**
8. **Avoid bash history manipulation**
9. **Always validate inputs**
10. **Use set -e and set -o pipefail**

## 🤝 Contributing

Feel free to contribute! 

1. Fork the repo
2. Create a new feature branch (`git checkout -b feature/amazing-rule`)
3. Commit your changes (`git commit -am 'New rule: detect exec usage'`)
4. Push the branch (`git push origin feature/amazing-rule`)
5. Create a Pull Request

## 📄 License

MIT License

## 📞 Contact

For questions or suggestions, you can open an issue or contact the project maintainer. 