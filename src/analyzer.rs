use crate::models::{AnalysisReport, Finding, FindingType, FindingsByRiskLevel, RiskLevel};
use crate::parser::BashParser;
use crate::rules::{COMMAND_INJECTION_PATTERNS, DANGEROUS_COMMANDS, NETWORK_SECURITY_PATTERNS, SECRET_PATTERNS, UNSAFE_FILE_OPERATIONS};
use anyhow::Result;
use chrono::Local;
use log::{debug, info};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;
use tree_sitter::TreeCursor;
use walkdir::WalkDir;

/// Bash script analizörü
pub struct BashAnalyzer {
    parser: BashParser,
}

impl BashAnalyzer {
    /// Yeni bir BashAnalyzer örneği oluşturur
    pub fn new() -> Result<Self> {
        let parser = BashParser::new()?;
        Ok(Self { parser })
    }

    /// Belirtilen yoldaki Bash script(ler)ini analiz eder
    pub fn analyze<P: AsRef<Path>>(&mut self, path: P, recursive: bool, risk_level: Option<RiskLevel>) -> Result<AnalysisReport> {
        let path = path.as_ref();
        let start_time = Instant::now();
        let start_time_formatted = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        
        info!("Analiz başlatılıyor: {:?}", path);
        
        let script_paths = self.find_script_files(path, recursive)?;
        let total_scripts = script_paths.len();
        
        info!("{} adet Bash script bulundu", total_scripts);
        
        // Seri olarak scriptleri analiz et (paralel işleme kaldırıldı)
        let mut all_findings = Vec::new();
        
        for script_path in &script_paths {
            match self.analyze_script(script_path) {
                Ok(mut script_findings) => {
                    // Risk seviyesi filtrelemesi
                    if let Some(min_risk) = risk_level {
                        script_findings.retain(|finding| finding.risk_level >= min_risk);
                    }
                    all_findings.extend(script_findings);
                }
                Err(err) => {
                    debug!("Script analiz edilirken hata oluştu: {:?} - {}", script_path, err);
                }
            }
        }
        
        let total_findings = all_findings.len();
        
        // Risk seviyelerine göre bulgu sayılarını hesapla
        let mut findings_by_risk_level = FindingsByRiskLevel::default();
        for finding in &all_findings {
            match finding.risk_level {
                RiskLevel::Critical => findings_by_risk_level.critical += 1,
                RiskLevel::High => findings_by_risk_level.high += 1,
                RiskLevel::Medium => findings_by_risk_level.medium += 1,
                RiskLevel::Low => findings_by_risk_level.low += 1,
            }
        }
        
        let end_time_formatted = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        let duration = start_time.elapsed().as_secs_f64();
        
        info!("Analiz tamamlandı. Toplam {} bulgu tespit edildi.", total_findings);
        
        Ok(AnalysisReport {
            analyzed_files: script_paths,
            total_scripts,
            findings: all_findings,
            total_findings,
            findings_by_risk_level,
            start_time: start_time_formatted,
            end_time: end_time_formatted,
            duration_seconds: duration,
        })
    }
    
    /// Tek bir Bash scriptini analiz eder
    fn analyze_script<P: AsRef<Path>>(&mut self, script_path: P) -> Result<Vec<Finding>> {
        let script_path = script_path.as_ref();
        let mut findings = Vec::new();
        
        debug!("Script analiz ediliyor: {:?}", script_path);
        
        let content = fs::read_to_string(script_path)?;
        let tree = self.parser.parse(&content)?;
        let mut cursor = tree.walk();
        
        // Komut düğümlerini bul ve analiz et
        self.analyze_node(&mut cursor, script_path, &content, &mut findings);
        
        // Regex tabanlı analizler
        self.analyze_secrets(script_path, &content, &mut findings);
        self.analyze_command_injection(script_path, &content, &mut findings);
        self.analyze_file_operations(script_path, &content, &mut findings);
        self.analyze_network_security(script_path, &content, &mut findings);
        
        Ok(findings)
    }
    
    /// Syntax ağacını dolaşarak düğümleri analiz eder
    fn analyze_node(&mut self, cursor: &mut TreeCursor, file_path: &Path, content: &str, findings: &mut Vec<Finding>) {
        let node = cursor.node();
        
        // Komut düğümlerini analiz et
        if node.kind() == "command" {
            if let Some(command_name) = self.parser.extract_command_name(node, content) {
                if let Some((risk_level, description, recommendation)) = DANGEROUS_COMMANDS.get(command_name) {
                    let line = node.start_position().row + 1;
                    let column = node.start_position().column + 1;
                    
                    // Kod parçasını al (komutun bulunduğu satır ve 2 satır öncesi/sonrası)
                    let code_snippet = BashParser::get_code_snippet(content, line, 2);
                    
                    findings.push(Finding {
                        finding_type: FindingType::DangerousCommand,
                        risk_level: *risk_level,
                        file_path: file_path.to_path_buf(),
                        line,
                        column: Some(column),
                        code_snippet,
                        description: description.to_string(),
                        recommendation: Some(recommendation.to_string()),
                        risk_score: Self::calculate_risk_score(*risk_level),
                    });
                }
            }
        }
        
        // Alt düğümlere doğru ilerlemeye devam et
        if cursor.goto_first_child() {
            loop {
                self.analyze_node(cursor, file_path, content, findings);
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
            cursor.goto_parent();
        }
    }
    
    /// Gizli bilgi sızıntılarını analiz eder
    fn analyze_secrets(&mut self, file_path: &Path, content: &str, findings: &mut Vec<Finding>) {
        for (pattern, finding_type, risk_level, description, recommendation) in SECRET_PATTERNS.iter() {
            for capture in pattern.captures_iter(content) {
                let secret_match = capture.get(0).unwrap();
                let start_pos = secret_match.start();
                
                // Eşleşmenin satır numarasını hesapla
                let mut line = 1;
                let mut column = 1;
                for (i, c) in content.char_indices() {
                    if i >= start_pos {
                        break;
                    }
                    if c == '\n' {
                        line += 1;
                        column = 1;
                    } else {
                        column += 1;
                    }
                }
                
                // Kod parçasını al
                let code_snippet = BashParser::get_code_snippet(content, line, 2);
                
                findings.push(Finding {
                    finding_type: finding_type.clone(),
                    risk_level: *risk_level,
                    file_path: file_path.to_path_buf(),
                    line,
                    column: Some(column),
                    code_snippet,
                    description: description.to_string(),
                    recommendation: Some(recommendation.to_string()),
                    risk_score: Self::calculate_risk_score(*risk_level),
                });
            }
        }
    }
    
    /// Komut enjeksiyonu risklerini analiz eder
    fn analyze_command_injection(&mut self, file_path: &Path, content: &str, findings: &mut Vec<Finding>) {
        for (pattern, risk_level, description, recommendation) in COMMAND_INJECTION_PATTERNS.iter() {
            for capture in pattern.captures_iter(content) {
                let injection_match = capture.get(0).unwrap();
                let start_pos = injection_match.start();
                
                // Eşleşmenin satır numarasını hesapla
                let mut line = 1;
                let mut column = 1;
                for (i, c) in content.char_indices() {
                    if i >= start_pos {
                        break;
                    }
                    if c == '\n' {
                        line += 1;
                        column = 1;
                    } else {
                        column += 1;
                    }
                }
                
                // Kod parçasını al
                let code_snippet = BashParser::get_code_snippet(content, line, 2);
                
                findings.push(Finding {
                    finding_type: FindingType::CommandInjectionRisk,
                    risk_level: *risk_level,
                    file_path: file_path.to_path_buf(),
                    line,
                    column: Some(column),
                    code_snippet,
                    description: description.to_string(),
                    recommendation: Some(recommendation.to_string()),
                    risk_score: Self::calculate_risk_score(*risk_level),
                });
            }
        }
    }
    
    /// Dosya işlemlerini analiz eder
    fn analyze_file_operations(&mut self, file_path: &Path, content: &str, findings: &mut Vec<Finding>) {
        for (pattern, risk_level, description, recommendation) in UNSAFE_FILE_OPERATIONS.iter() {
            for capture in pattern.captures_iter(content) {
                let op_match = capture.get(0).unwrap();
                let start_pos = op_match.start();
                
                // Eşleşmenin satır numarasını hesapla
                let mut line = 1;
                let mut column = 1;
                for (i, c) in content.char_indices() {
                    if i >= start_pos {
                        break;
                    }
                    if c == '\n' {
                        line += 1;
                        column = 1;
                    } else {
                        column += 1;
                    }
                }
                
                // Kod parçasını al
                let code_snippet = BashParser::get_code_snippet(content, line, 2);
                
                findings.push(Finding {
                    finding_type: FindingType::FilePermissionIssue,
                    risk_level: *risk_level,
                    file_path: file_path.to_path_buf(),
                    line,
                    column: Some(column),
                    code_snippet,
                    description: description.to_string(),
                    recommendation: Some(recommendation.to_string()),
                    risk_score: Self::calculate_risk_score(*risk_level),
                });
            }
        }
    }
    
    /// Ağ güvenliği sorunlarını analiz eder
    fn analyze_network_security(&mut self, file_path: &Path, content: &str, findings: &mut Vec<Finding>) {
        for (pattern, risk_level, description, recommendation) in NETWORK_SECURITY_PATTERNS.iter() {
            for capture in pattern.captures_iter(content) {
                let net_match = capture.get(0).unwrap();
                let start_pos = net_match.start();
                
                // Eşleşmenin satır numarasını hesapla
                let mut line = 1;
                let mut column = 1;
                for (i, c) in content.char_indices() {
                    if i >= start_pos {
                        break;
                    }
                    if c == '\n' {
                        line += 1;
                        column = 1;
                    } else {
                        column += 1;
                    }
                }
                
                // Kod parçasını al
                let code_snippet = BashParser::get_code_snippet(content, line, 2);
                
                findings.push(Finding {
                    finding_type: FindingType::InsecureNetworkAccess,
                    risk_level: *risk_level,
                    file_path: file_path.to_path_buf(),
                    line,
                    column: Some(column),
                    code_snippet,
                    description: description.to_string(),
                    recommendation: Some(recommendation.to_string()),
                    risk_score: Self::calculate_risk_score(*risk_level),
                });
            }
        }
    }
    
    /// Bash script dosyalarını bulur
    fn find_script_files<P: AsRef<Path>>(&self, path: P, recursive: bool) -> Result<Vec<PathBuf>> {
        let path = path.as_ref();
        let mut script_paths = Vec::new();
        
        if path.is_file() {
            // Tek bir dosya
            if self.is_bash_script(path) {
                script_paths.push(path.to_path_buf());
            }
        } else if path.is_dir() {
            // Dizin
            let walker = if recursive {
                WalkDir::new(path)
            } else {
                WalkDir::new(path).max_depth(1)
            };
            
            for entry in walker.into_iter().filter_map(|e| e.ok()) {
                let entry_path = entry.path();
                if entry_path.is_file() && self.is_bash_script(entry_path) {
                    script_paths.push(entry_path.to_path_buf());
                }
            }
        }
        
        Ok(script_paths)
    }
    
    /// Dosyanın Bash script olup olmadığını kontrol eder
    fn is_bash_script<P: AsRef<Path>>(&self, path: P) -> bool {
        let path = path.as_ref();
        
        // Dosya uzantısına göre kontrol
        if let Some(ext) = path.extension() {
            if ext == "sh" || ext == "bash" {
                return true;
            }
        }
        
        // Shebang kontrolü
        if let Ok(content) = fs::read_to_string(path) {
            let first_line = content.lines().next().unwrap_or("");
            if first_line.starts_with("#!/bin/bash") || first_line.starts_with("#!/bin/sh") {
                return true;
            }
        }
        
        false
    }
    
    /// Risk puanını hesaplar (CVSS benzeri, 0.0-10.0 arası)
    fn calculate_risk_score(risk_level: RiskLevel) -> f32 {
        match risk_level {
            RiskLevel::Critical => 9.0 + (rand::random::<f32>() * 1.0), // 9.0-10.0
            RiskLevel::High => 7.0 + (rand::random::<f32>() * 2.0),     // 7.0-9.0
            RiskLevel::Medium => 4.0 + (rand::random::<f32>() * 3.0),   // 4.0-7.0
            RiskLevel::Low => 1.0 + (rand::random::<f32>() * 3.0),      // 1.0-4.0
        }
    }
} 