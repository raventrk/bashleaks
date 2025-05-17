use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "bashleaks",
    author = "RavenTrk",
    version,
    about = "Bash scriptlerde güvenlik açıklarını ve gizli bilgi sızıntılarını tespit eder",
    long_about = "Bash script'lerdeki güvenlik açıklarını, gizli bilgi sızıntılarını ve potansiyel tehlikeli komut kullanımlarını tespit etmek amacıyla geliştirilmiş statik analiz ve runtime izleme aracı."
)]
pub struct Args {
    #[command(subcommand)]
    pub command: Commands,

    /// Detaylı log seviyesi
    #[arg(short, long, global = true)]
    pub verbose: bool,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Bash scriptleri statik olarak analiz eder
    Analyze {
        /// Analiz edilecek Bash script veya dizin yolu
        #[arg(value_name = "PATH")]
        path: PathBuf,

        /// Dizin içindeki tüm Bash scriptleri recursive olarak analiz eder
        #[arg(short, long)]
        recursive: bool,

        /// Çıktı formatı
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Cli)]
        output: OutputFormat,

        /// Çıktı dosyası (belirtilmezse stdout'a yazdırılır)
        #[arg(short = 'f', long)]
        output_file: Option<PathBuf>,

        /// Sadece belirtilen risk seviyesindeki veya üstündeki bulguları raporlar
        #[arg(short = 'l', long)]
        risk_level: Option<RiskLevel>,
    },

    /// Bash scripti çalışma zamanında izler ve potansiyel güvenlik risklerini tespit eder
    Monitor {
        /// İzlenecek ve çalıştırılacak Bash script yolu
        #[arg(value_name = "PATH")]
        path: PathBuf,
    },
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum OutputFormat {
    /// Komut satırına renkli çıktı
    Cli,
    /// JSON formatında çıktı
    Json,
    /// HTML formatında rapor
    Html,
}

impl std::fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutputFormat::Cli => write!(f, "cli"),
            OutputFormat::Json => write!(f, "json"),
            OutputFormat::Html => write!(f, "html"),
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum RiskLevel {
    /// Düşük risk seviyesi
    Low,
    /// Orta risk seviyesi
    Medium,
    /// Yüksek risk seviyesi
    High,
    /// Kritik risk seviyesi
    Critical,
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RiskLevel::Low => write!(f, "low"),
            RiskLevel::Medium => write!(f, "medium"),
            RiskLevel::High => write!(f, "high"),
            RiskLevel::Critical => write!(f, "critical"),
        }
    }
} 