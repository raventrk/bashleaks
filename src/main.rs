use anyhow::Result;
use clap::Parser;
use log::info;

mod analyzer;
mod cli;
mod models;
mod parser;
mod reporters;
mod rules;
mod runtime;
mod utils;

use analyzer::BashAnalyzer;
use cli::Args;
use reporters::Reporter;
use runtime::RuntimeMonitor;

fn main() -> Result<()> {
    // Logger'ı başlat
    env_logger::init();

    // Komut satırı argümanlarını işle
    let args = Args::parse();

    // Verbose modu varsa ekstra log seviyesini ayarla
    if args.verbose {
        std::env::set_var("RUST_LOG", "debug");
    } else {
        std::env::set_var("RUST_LOG", "info");
    }

    // Komut tipine göre işlem yap
    match &args.command {
        cli::Commands::Analyze {
            path,
            recursive,
            output,
            output_file,
            risk_level,
        } => {
            info!("Bash script analizi başlatılıyor: {:?}", path);
            info!("Recursive: {}", recursive);
            info!("Çıktı formatı: {}", output);
            if let Some(file) = output_file {
                info!("Çıktı dosyası: {}", file.display());
            }
            if let Some(level) = risk_level {
                info!("Risk seviyesi: {}", level);
            }
            
            // Analiz işlemi
            analyze_scripts(path, *recursive, *output, output_file.as_deref(), risk_level.map(|r| convert_risk_level(r)))?;
        }
        cli::Commands::Monitor { path } => {
            info!("Runtime izleme başlatılıyor: {:?}", path);
            
            // Runtime izleme işlemi
            monitor_script(path)?;
        }
    }

    Ok(())
}

/// CLI risk seviyesini model risk seviyesine dönüştürür
fn convert_risk_level(risk_level: cli::RiskLevel) -> models::RiskLevel {
    match risk_level {
        cli::RiskLevel::Low => models::RiskLevel::Low,
        cli::RiskLevel::Medium => models::RiskLevel::Medium,
        cli::RiskLevel::High => models::RiskLevel::High,
        cli::RiskLevel::Critical => models::RiskLevel::Critical,
    }
}

/// Bash script analizini gerçekleştirir
fn analyze_scripts(
    path: &std::path::Path,
    recursive: bool,
    output_format: cli::OutputFormat,
    output_file: Option<&std::path::Path>,
    risk_level: Option<models::RiskLevel>,
) -> Result<()> {
    // Analyzer oluştur
    let mut analyzer = BashAnalyzer::new()?;
    
    // Analiz işlemini gerçekleştir
    let report = analyzer.analyze(path, recursive, risk_level)?;
    
    // Rapor oluştur
    let reporter = Reporter::new(report);
    reporter.generate_report(output_format, output_file)?;
    
    Ok(())
}

/// Bash scriptini çalışma zamanında izler
fn monitor_script(path: &std::path::Path) -> Result<()> {
    let monitor = RuntimeMonitor::new();
    monitor.monitor_script(path)?;
    Ok(())
}
