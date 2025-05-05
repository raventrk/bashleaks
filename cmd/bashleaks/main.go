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
	// Versiyon bilgisi
	version = "1.0.0"

	// Prometheus metrikleri
	scannedFiles = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "bashleaks_scanned_files_total",
		Help: "Taranan toplam dosya sayısı",
	})

	findingsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "bashleaks_findings_total",
			Help: "Risk seviyelerine göre bulunan toplam güvenlik açığı sayısı",
		},
		[]string{"level"},
	)

	// Komut satırı flag'leri
	flagOutputFormat string
	flagOutputFile   string
	flagFailOn       string
	flagMetricsAddr  string
	flagVerbose      bool
)

func init() {
	// Prometheus kayıt işlemleri
	prometheus.MustRegister(scannedFiles)
	prometheus.MustRegister(findingsTotal)

	// Kök komut flag'leri
	rootCmd.PersistentFlags().StringVarP(&flagOutputFormat, "format", "f", "text", "Rapor formatı: text, json, yaml, html, markdown")
	rootCmd.PersistentFlags().StringVarP(&flagOutputFile, "output", "o", "", "Rapor dosyası (belirtilmezse stdout kullanılır)")
	rootCmd.PersistentFlags().StringVar(&flagFailOn, "fail-on", "", "Belirtilen risk seviyesinde veya üstünde hata var ise başarısız olur: critical, medium, low")
	rootCmd.PersistentFlags().StringVar(&flagMetricsAddr, "metrics-addr", "", "Prometheus metriklerini dinlemek için adres (örn. :9090)")
	rootCmd.PersistentFlags().BoolVarP(&flagVerbose, "verbose", "v", false, "Detaylı log gösterimi")

	// Alt komutları ekle
	rootCmd.AddCommand(versionCmd)
}

// Ana root komut
var rootCmd = &cobra.Command{
	Use:   "bashleaks [dosya ya da dizin]",
	Short: "Shell script güvenlik açıklarını tespit etmek için statik analiz aracı",
	Long: `BashLeaks, shell script dosyalarınızı tarayarak potansiyel olarak tehlikeli
ve kötüye kullanılabilir komut kalıplarını tespit eden bir statik analiz aracıdır.
CI/CD süreçlerine entegre edilebilir, script güvenliğini otomatikleştirmek için tasarlanmıştır.`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// Log yapılandırması
		setupLogging()

		// Metrics sunucusunu başlat (eğer belirtilmişse)
		if flagMetricsAddr != "" {
			go startMetricsServer(flagMetricsAddr)
		}

		// Komut argümanlarını kontrol et
		// Format parametresi geçerli mi?
		validFormats := []string{"text", "json", "yaml", "html", "markdown"}
		formatValid := false

		// Formatı küçük harfe çevirelim
		flagOutputFormat = strings.ToLower(flagOutputFormat)

		// Eğer -format flag'i eksik/hatalı olarak parse edilmişse (örn. "ormat")
		// ve args listesinde bunun düzeltilmesi gerekiyorsa, bu kısımda düzeltebiliriz
		// Ancak bu durumda en güvenli çözüm kullanıcıyı doğru kullanım konusunda bilgilendirmek

		// Şu anda flagOutputFormat içinde ne var kontrol edelim
		if flagOutputFormat != "text" && flagOutputFormat != "json" &&
			flagOutputFormat != "yaml" && flagOutputFormat != "html" &&
			flagOutputFormat != "markdown" {
			// Kullanıcının -format flag'ini kullanmaya çalıştığını varsayalım
			log.Warn().Str("invalid-format", flagOutputFormat).Msg("Geçersiz format, doğru kullanım: -f html veya --format html")
			// Varsayılan format olarak text kullanalım
			flagOutputFormat = "text"
		}

		for _, f := range validFormats {
			if flagOutputFormat == f {
				formatValid = true
				break
			}
		}

		if !formatValid {
			return fmt.Errorf("geçersiz format: %s. Desteklenen formatlar: text, json, yaml, html, markdown", flagOutputFormat)
		}

		// Tüm belirtilen dosya/dizinleri tara
		var allFindings []rules.Finding
		totalFiles := 0

		for _, path := range args {
			findings, fileCount, err := scanPath(path)
			if err != nil {
				log.Error().Err(err).Str("path", path).Msg("Tarama hatası")
				return err
			}

			allFindings = append(allFindings, findings...)
			totalFiles += fileCount
		}

		// Rapor oluştur
		r := report.NewReport(allFindings, totalFiles)

		// Raporu yazdır
		if err := outputReport(r); err != nil {
			log.Error().Err(err).Msg("Rapor yazdırma hatası")
			return err
		}

		// CI/CD için çıkış kodu
		handleExitCode(r)
		return nil
	},
}

// Versiyon komutu
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Versiyon bilgisini gösterir",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("BashLeaks %s\n", version)
	},
}

// setupLogging, log yapılandırmasını ayarlar
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

// startMetricsServer, Prometheus metrikleri için HTTP sunucusunu başlatır
func startMetricsServer(addr string) {
	http.Handle("/metrics", promhttp.Handler())
	err := http.ListenAndServe(addr, nil)
	if err != nil {
		log.Error().Err(err).Str("addr", addr).Msg("Metrics sunucusu başlatılamadı")
	}
}

// scanPath, belirtilen dosya veya dizini tarar
func scanPath(path string) ([]rules.Finding, int, error) {
	fileInfo, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, 0, fmt.Errorf("dosya/dizin bulunamadı: %s", path)
		}
		return nil, 0, fmt.Errorf("dosya/dizin bilgisi alınamadı: %w", err)
	}

	s := scanner.NewScanner()
	var findings []rules.Finding
	fileCount := 0

	if fileInfo.IsDir() {
		log.Info().Str("path", path).Msg("Dizin taranıyor")
		results, err := s.ScanDirectory(path)
		if err != nil {
			return nil, 0, fmt.Errorf("dizin tarama hatası: %w", err)
		}
		findings = results

		// Taranan dosya sayısını hesapla
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
		log.Info().Str("path", path).Msg("Dosya taranıyor")
		results, err := s.ScanFile(path)
		if err != nil {
			return nil, 0, fmt.Errorf("dosya tarama hatası: %w", err)
		}
		findings = results
		fileCount = 1
	}

	// Metrikleri güncelle
	scannedFiles.Add(float64(fileCount))
	for _, finding := range findings {
		findingsTotal.WithLabelValues(string(finding.Rule.Level())).Inc()
	}

	log.Info().
		Int("findings", len(findings)).
		Int("files", fileCount).
		Str("path", path).
		Msg("Tarama tamamlandı")

	return findings, fileCount, nil
}

// outputReport, raporu belirtilen formatta çıktı olarak verir
func outputReport(r *report.Report) error {
	format := report.Format(flagOutputFormat)

	if flagOutputFile == "" {
		// stdout'a yazdır
		return r.Print(format, os.Stdout)
	}

	// Dosyaya yazdır
	err := r.SaveToFile(format, flagOutputFile)
	if err != nil {
		return fmt.Errorf("rapor dosyası oluşturma hatası: %w", err)
	}

	log.Info().
		Str("format", string(format)).
		Str("output", flagOutputFile).
		Msg("Rapor başarıyla oluşturuldu")

	return nil
}

// handleExitCode, CI/CD entegrasyonu için uygun çıkış kodunu belirler
func handleExitCode(r *report.Report) {
	if flagFailOn == "" {
		return
	}

	var shouldFail bool

	switch strings.ToLower(flagFailOn) {
	case "critical":
		shouldFail = r.SummaryInfo.CriticalCount > 0
	case "medium":
		shouldFail = r.SummaryInfo.CriticalCount > 0 || r.SummaryInfo.MediumCount > 0
	case "low":
		shouldFail = r.SummaryInfo.CriticalCount > 0 || r.SummaryInfo.MediumCount > 0 || r.SummaryInfo.LowCount > 0
	default:
		log.Warn().Str("fail-on", flagFailOn).Msg("Geçersiz fail-on değeri, çıkış başarılı olacak")
		return
	}

	if shouldFail {
		log.Warn().
			Str("fail-on", flagFailOn).
			Int("critical", r.SummaryInfo.CriticalCount).
			Int("medium", r.SummaryInfo.MediumCount).
			Int("low", r.SummaryInfo.LowCount).
			Msg("Güvenlik açıkları bulundu, çıkış başarısız olacak")
		os.Exit(1)
	}
}

func main() {
	// Eğer argümanlar arasında "-format" varsa, bunu düzeltelim
	// Bu tarz bir kurtarma mekanizması için en uygun yer main fonksiyonu
	for i, arg := range os.Args {
		if arg == "-format" && i+1 < len(os.Args) {
			// -format html -> --format html olarak düzelt
			os.Args[i] = "--format"
			// Bir sonraki argüman zaten doğru olduğu için dokunmayız
			break
		}
	}

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
