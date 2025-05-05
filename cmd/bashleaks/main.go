package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/raventrk/bashleaks/pkg/report"
	"github.com/raventrk/bashleaks/pkg/rules"
	"github.com/raventrk/bashleaks/pkg/scanner"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var (
	// Version information
	version = "1.0.0"

	// Prometheus metrics
	scannedFiles = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "bashleaks_scanned_files_total",
		Help: "Total number of scanned files",
	})

	findingsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "bashleaks_findings_total",
			Help: "Total number of security vulnerabilities found by risk level",
		},
		[]string{"level"},
	)

	// Command-line flags
	flagOutputFormat string
	flagOutputFile   string
	flagFailOn       string
	flagMetricsAddr  string
	flagVerbose      bool
)

func init() {
	// Prometheus registrations
	prometheus.MustRegister(scannedFiles)
	prometheus.MustRegister(findingsTotal)

	// Root command flags
	rootCmd.PersistentFlags().StringVarP(&flagOutputFormat, "format", "f", "text", "Report format: text, json, yaml, html, markdown")
	rootCmd.PersistentFlags().StringVarP(&flagOutputFile, "output", "o", "", "Report file (uses stdout if not specified)")
	rootCmd.PersistentFlags().StringVar(&flagFailOn, "fail-on", "", "Fails if vulnerabilities are found at specified risk level or above: critical, medium, low")
	rootCmd.PersistentFlags().StringVar(&flagMetricsAddr, "metrics-addr", "", "Address for listening Prometheus metrics (e.g. :9090)")
	rootCmd.PersistentFlags().BoolVarP(&flagVerbose, "verbose", "v", false, "Verbose logging")

	// Add subcommands
	rootCmd.AddCommand(versionCmd)
}

// Main root command
var rootCmd = &cobra.Command{
	Use:   "bashleaks [file or directory]",
	Short: "Static analysis tool to detect security vulnerabilities in shell scripts",
	Long: `BashLeaks is a static analysis tool that scans shell script files to detect
potentially dangerous and exploitable command patterns. It can be integrated into
CI/CD processes and is designed to automate script security.`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// Configure logging
		setupLogging()

		// Start metrics server (if specified)
		if flagMetricsAddr != "" {
			go startMetricsServer(flagMetricsAddr)
		}

		// Check command arguments
		// Is the format parameter valid?
		validFormats := []string{"text", "json", "yaml", "html", "markdown"}
		formatValid := false

		// Convert format to lowercase
		flagOutputFormat = strings.ToLower(flagOutputFormat)

		// If -format flag is parsed incorrectly (e.g., "ormat")
		// and needs to be corrected in the args list, we could do it here
		// But the safest solution is to inform the user about proper usage

		// Check what's currently in flagOutputFormat
		if flagOutputFormat != "text" && flagOutputFormat != "json" &&
			flagOutputFormat != "yaml" && flagOutputFormat != "html" &&
			flagOutputFormat != "markdown" {
			// Assume user was trying to use -format flag
			log.Warn().Str("invalid-format", flagOutputFormat).Msg("Invalid format, correct usage: -f html or --format html")
			// Use text as default format
			flagOutputFormat = "text"
		}

		for _, f := range validFormats {
			if flagOutputFormat == f {
				formatValid = true
				break
			}
		}

		if !formatValid {
			return fmt.Errorf("invalid format: %s. Supported formats: text, json, yaml, html, markdown", flagOutputFormat)
		}

		// Scan all specified files/directories
		var allFindings []rules.Finding
		totalFiles := 0

		for _, path := range args {
			findings, fileCount, err := scanPath(path)
			if err != nil {
				log.Error().Err(err).Str("path", path).Msg("Scanning error")
				return err
			}

			allFindings = append(allFindings, findings...)
			totalFiles += fileCount
		}

		// Create report
		r := report.NewReport(allFindings, totalFiles)

		// Print report
		if err := outputReport(r); err != nil {
			log.Error().Err(err).Msg("Report output error")
			return err
		}

		// Exit code for CI/CD
		handleExitCode(r)
		return nil
	},
}

// Version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Shows version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("BashLeaks %s\n", version)
	},
}

// setupLogging sets up logging configuration
func setupLogging() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	if flagVerbose {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	} else {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}

	consoleWriter := zerolog.ConsoleWriter{Out: os.Stderr}
	log.Logger = zerolog.New(consoleWriter).With().Timestamp().Logger()
}

// startMetricsServer starts HTTP server for Prometheus metrics
func startMetricsServer(addr string) {
	http.Handle("/metrics", promhttp.Handler())
	err := http.ListenAndServe(addr, nil)
	if err != nil {
		log.Error().Err(err).Str("addr", addr).Msg("Failed to start metrics server")
	}
}

// scanPath scans the specified file or directory
func scanPath(path string) ([]rules.Finding, int, error) {
	fileInfo, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, 0, fmt.Errorf("file/directory not found: %s", path)
		}
		return nil, 0, fmt.Errorf("could not get file/directory info: %w", err)
	}

	s := scanner.NewScanner()
	var findings []rules.Finding
	fileCount := 0

	if fileInfo.IsDir() {
		log.Info().Str("path", path).Msg("Scanning directory")
		results, err := s.ScanDirectory(path)
		if err != nil {
			return nil, 0, fmt.Errorf("directory scanning error: %w", err)
		}
		findings = results

		// Calculate number of scanned files
		err = filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !info.IsDir() {
				fileCount++
			}
			return nil
		})

		if err != nil {
			return nil, 0, err
		}
	} else {
		log.Info().Str("path", path).Msg("Scanning file")
		results, err := s.ScanFile(path)
		if err != nil {
			return nil, 0, fmt.Errorf("file scanning error: %w", err)
		}
		findings = results
		fileCount = 1
	}

	// Update metrics
	scannedFiles.Add(float64(fileCount))
	for _, finding := range findings {
		findingsTotal.WithLabelValues(string(finding.Rule.Level())).Inc()
	}

	log.Info().
		Int("findings", len(findings)).
		Int("files", fileCount).
		Str("path", path).
		Msg("Scanning completed")

	return findings, fileCount, nil
}

// outputReport outputs the report in the specified format
func outputReport(r *report.Report) error {
	format := report.Format(flagOutputFormat)

	if flagOutputFile == "" {
		// Print to stdout
		return r.Print(format, os.Stdout)
	}

	// Write to file
	err := r.SaveToFile(format, flagOutputFile)
	if err != nil {
		return fmt.Errorf("error creating report file: %w", err)
	}

	log.Info().
		Str("format", string(format)).
		Str("output", flagOutputFile).
		Msg("Report successfully created")

	return nil
}

// handleExitCode sets exit code based on findings and --fail-on flag
func handleExitCode(r *report.Report) {
	if flagFailOn == "" {
		return
	}

	// Convert fail-on flag to lowercase and find the corresponding risk level
	var failLevel rules.RiskLevel
	switch strings.ToLower(flagFailOn) {
	case "critical":
		failLevel = rules.RiskLevelCritical
	case "medium":
		failLevel = rules.RiskLevelMedium
	case "low":
		failLevel = rules.RiskLevelLow
	default:
		log.Warn().Str("level", flagFailOn).Msg("Invalid risk level for --fail-on. Using 'critical' as default.")
		failLevel = rules.RiskLevelCritical
	}

	// Set exit code based on findings
	exitCode := 0
	for _, finding := range r.Findings {
		// Skip ignored findings
		if finding.Ignored {
			continue
		}

		// Check if finding level is at or above the specified failure level
		switch failLevel {
		case rules.RiskLevelLow:
			exitCode = 1 // All levels cause failure
		case rules.RiskLevelMedium:
			if finding.Rule.Level() == rules.RiskLevelMedium || finding.Rule.Level() == rules.RiskLevelCritical {
				exitCode = 1
			}
		case rules.RiskLevelCritical:
			if finding.Rule.Level() == rules.RiskLevelCritical {
				exitCode = 1
			}
		}

		// If we already decided to exit with error, no need to check further
		if exitCode != 0 {
			break
		}
	}

	if exitCode != 0 {
		log.Warn().Str("level", string(failLevel)).Msg("Vulnerabilities found at or above specified risk level")
		os.Exit(exitCode)
	}
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
