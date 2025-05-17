use crate::cli::OutputFormat;
use crate::models::{AnalysisReport, RiskLevel};
use anyhow::Result;
use colored::{Color, Colorize};
use serde_json;
use std::fs;
use std::path::Path;
use tera::{Context, Tera};

/// Rapor oluşturucu
pub struct Reporter {
    report: AnalysisReport,
}

impl Reporter {
    /// Yeni bir Reporter örneği oluşturur
    pub fn new(report: AnalysisReport) -> Self {
        Self { report }
    }
    
    /// Raporu belirtilen formata göre oluşturur
    pub fn generate_report(&self, format: OutputFormat, output_file: Option<&Path>) -> Result<()> {
        match format {
            OutputFormat::Cli => self.generate_cli_report(),
            OutputFormat::Json => self.generate_json_report(output_file),
            OutputFormat::Html => self.generate_html_report(output_file),
        }
    }
    
    /// CLI formatında rapor oluşturur
    fn generate_cli_report(&self) -> Result<()> {
        println!("{}", "\n🔍 BashLeaks Analiz Raporu 🔍".bold());
        println!("{}: {}", "Analiz başlangıç zamanı".bold(), self.report.start_time);
        println!("{}: {}", "Analiz bitiş zamanı".bold(), self.report.end_time);
        println!("{}: {:.2} saniye", "Analiz süresi".bold(), self.report.duration_seconds);
        println!("{}: {}", "Analiz edilen script sayısı".bold(), self.report.total_scripts);
        println!("{}: {}\n", "Toplam bulgu sayısı".bold(), self.report.total_findings);
        
        // Risk seviyelerine göre bulgu sayıları
        println!("{}", "Risk Seviyelerine Göre Bulgular:".bold());
        println!("  {} {}", "Kritik:".color(Color::BrightRed).bold(), self.report.findings_by_risk_level.critical);
        println!("  {} {}", "Yüksek:".color(Color::Red).bold(), self.report.findings_by_risk_level.high);
        println!("  {} {}", "Orta:".color(Color::Yellow).bold(), self.report.findings_by_risk_level.medium);
        println!("  {} {}\n", "Düşük:".color(Color::Green).bold(), self.report.findings_by_risk_level.low);
        
        // Bulguları risk seviyesine göre sırala
        let mut sorted_findings = self.report.findings.clone();
        sorted_findings.sort_by(|a, b| b.risk_level.cmp(&a.risk_level));
        
        // Bulgular
        println!("{}", "Bulgular:".bold());
        for (i, finding) in sorted_findings.iter().enumerate() {
            println!("{}: {}", "Bulgu".bold(), i + 1);
            println!("  {}: {}", "Dosya".bold(), finding.file_path.display());
            println!("  {}: {}", "Satır".bold(), finding.line);
            
            // Risk seviyesine göre renklendirme
            let risk_color = match finding.risk_level {
                RiskLevel::Critical => Color::BrightRed,
                RiskLevel::High => Color::Red,
                RiskLevel::Medium => Color::Yellow,
                RiskLevel::Low => Color::Green,
            };
            
            let risk_level = match finding.risk_level {
                RiskLevel::Critical => "Kritik",
                RiskLevel::High => "Yüksek",
                RiskLevel::Medium => "Orta",
                RiskLevel::Low => "Düşük",
            };
            
            println!("  {}: {}", "Risk Seviyesi".bold(), risk_level.color(risk_color).bold());
            println!("  {}: {:.1}", "Risk Skoru".bold(), finding.risk_score);
            println!("  {}: {}", "Açıklama".bold(), finding.description);
            
            if let Some(recommendation) = &finding.recommendation {
                println!("  {}: {}", "Tavsiye".bold(), recommendation);
            }
            
            println!("  {}: \n{}\n", "Kod Parçası".bold(), finding.code_snippet);
        }
        
        Ok(())
    }
    
    /// JSON formatında rapor oluşturur
    fn generate_json_report(&self, output_file: Option<&Path>) -> Result<()> {
        let json = serde_json::to_string_pretty(&self.report)?;
        
        if let Some(file_path) = output_file {
            fs::write(file_path, json)?;
            println!("JSON raporu başarıyla oluşturuldu: {}", file_path.display());
        } else {
            println!("{}", json);
        }
        
        Ok(())
    }
    
    /// HTML formatında rapor oluşturur
    fn generate_html_report(&self, output_file: Option<&Path>) -> Result<()> {
        // HTML şablonu
        let html_template = r#"
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BashLeaks Analiz Raporu</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        h1, h2, h3 {
            color: #2c3e50;
        }
        .summary {
            background-color: #f8f9fa;
            border-radius: 5px;
            padding: 15px;
            margin-bottom: 20px;
        }
        .finding {
            background-color: #fff;
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 15px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .critical {
            border-left: 5px solid #d9534f;
        }
        .high {
            border-left: 5px solid #f0ad4e;
        }
        .medium {
            border-left: 5px solid #5bc0de;
        }
        .low {
            border-left: 5px solid #5cb85c;
        }
        .risk-badge {
            display: inline-block;
            padding: 5px 10px;
            border-radius: 3px;
            color: white;
            font-weight: bold;
        }
        .risk-critical {
            background-color: #d9534f;
        }
        .risk-high {
            background-color: #f0ad4e;
        }
        .risk-medium {
            background-color: #5bc0de;
        }
        .risk-low {
            background-color: #5cb85c;
        }
        pre {
            background-color: #f8f9fa;
            padding: 10px;
            border-radius: 5px;
            overflow-x: auto;
        }
        .stats {
            display: flex;
            flex-wrap: wrap;
            gap: 20px;
            margin-bottom: 20px;
        }
        .stat-box {
            flex: 1;
            min-width: 200px;
            padding: 15px;
            background-color: #f8f9fa;
            border-radius: 5px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .recommendation {
            background-color: #eaf7ff;
            padding: 10px;
            border-radius: 5px;
            margin-top: 10px;
        }
    </style>
</head>
<body>
    <h1>🔍 BashLeaks Analiz Raporu</h1>
    
    <div class="summary">
        <h2>Özet</h2>
        <p><strong>Analiz başlangıç zamanı:</strong> {{ report.start_time }}</p>
        <p><strong>Analiz bitiş zamanı:</strong> {{ report.end_time }}</p>
        <p><strong>Analiz süresi:</strong> {{ report.duration_seconds | round(precision=2) }} saniye</p>
        <p><strong>Analiz edilen script sayısı:</strong> {{ report.total_scripts }}</p>
        <p><strong>Toplam bulgu sayısı:</strong> {{ report.total_findings }}</p>
    </div>
    
    <div class="stats">
        <div class="stat-box">
            <h3>Risk Seviyelerine Göre Bulgular</h3>
            <p><span class="risk-badge risk-critical">Kritik</span> {{ report.findings_by_risk_level.critical }}</p>
            <p><span class="risk-badge risk-high">Yüksek</span> {{ report.findings_by_risk_level.high }}</p>
            <p><span class="risk-badge risk-medium">Orta</span> {{ report.findings_by_risk_level.medium }}</p>
            <p><span class="risk-badge risk-low">Düşük</span> {{ report.findings_by_risk_level.low }}</p>
        </div>
    </div>
    
    <h2>Bulgular</h2>
    
    {% for finding in findings %}
    <div class="finding {{ finding.risk_level | lower }}">
        <h3>Bulgu #{{ loop.index }}</h3>
        <p><strong>Dosya:</strong> {{ finding.file_path }}</p>
        <p><strong>Satır:</strong> {{ finding.line }}</p>
        <p>
            <strong>Risk Seviyesi:</strong> 
            <span class="risk-badge risk-{{ finding.risk_level | lower }}">
                {{ finding.risk_level_name }}
            </span>
        </p>
        <p><strong>Risk Skoru:</strong> {{ finding.risk_score | round(precision=1) }}</p>
        <p><strong>Açıklama:</strong> {{ finding.description }}</p>
        
        {% if finding.recommendation %}
        <div class="recommendation">
            <p><strong>Tavsiye:</strong> {{ finding.recommendation }}</p>
        </div>
        {% endif %}
        
        <p><strong>Kod Parçası:</strong></p>
        <pre>{{ finding.code_snippet }}</pre>
    </div>
    {% endfor %}
</body>
</html>
        "#;
        
        // Şablon motoru
        let mut tera = Tera::default();
        tera.add_raw_template("report", html_template)?;
        
        // Verileri hazırla
        let mut context = Context::new();
        context.insert("report", &self.report);
        
        // Risk seviyesi adları ekle
        let mut findings_with_names = Vec::new();
        for finding in &self.report.findings {
            let mut finding_map = serde_json::to_value(finding)?;
            let risk_level_name = match finding.risk_level {
                RiskLevel::Critical => "Kritik",
                RiskLevel::High => "Yüksek",
                RiskLevel::Medium => "Orta",
                RiskLevel::Low => "Düşük",
            };
            
            if let serde_json::Value::Object(ref mut map) = finding_map {
                map.insert("risk_level_name".to_string(), serde_json::Value::String(risk_level_name.to_string()));
            }
            
            findings_with_names.push(finding_map);
        }
        
        // Risk seviyesine göre sırala
        findings_with_names.sort_by(|a, b| {
            if let (Some(a_level), Some(b_level)) = (
                a.get("risk_level").and_then(|v| v.as_str()),
                b.get("risk_level").and_then(|v| v.as_str())
            ) {
                b_level.cmp(a_level)
            } else {
                std::cmp::Ordering::Equal
            }
        });
        
        context.insert("findings", &findings_with_names);
        
        // HTML oluştur
        let html = tera.render("report", &context)?;
        
        if let Some(file_path) = output_file {
            fs::write(file_path, html)?;
            println!("HTML raporu başarıyla oluşturuldu: {}", file_path.display());
        } else {
            println!("{}", html);
        }
        
        Ok(())
    }
} 