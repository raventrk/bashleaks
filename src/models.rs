use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Analiz sonucunda tespit edilen bulgu
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Bulgunun tipi
    pub finding_type: FindingType,
    
    /// Risk seviyesi
    pub risk_level: RiskLevel,
    
    /// Etkilenen dosya
    pub file_path: PathBuf,
    
    /// Satır numarası
    pub line: usize,
    
    /// Sütun numarası
    pub column: Option<usize>,
    
    /// Bulunan kod parçası
    pub code_snippet: String,
    
    /// Bulgu açıklaması
    pub description: String,
    
    /// Bulgu için önerilen çözüm
    pub recommendation: Option<String>,
    
    /// Risk skoru (CVSS benzeri, 0.0-10.0 arası)
    pub risk_score: f32,
}

/// Bulgu tipleri
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FindingType {
    /// Tehlikeli komut kullanımı
    DangerousCommand,
    
    /// Gizli bilgi sızıntısı
    HardcodedSecret,
    
    /// Input validasyon eksikliği
    InputValidationMissing,
    
    /// Hassas dosya erişimi
    SensitiveFileAccess,
    
    /// Güvensiz ağ erişimi
    InsecureNetworkAccess,
    
    /// Komut enjeksiyonu riski
    CommandInjectionRisk,
    
    /// Yetkisiz erişim riski
    PrivilegeEscalationRisk,
    
    /// Dosya izinleri hatası
    FilePermissionIssue,
    
    /// Diğer güvenlik riskleri
    OtherSecurityRisk,
}

/// Risk seviyeleri
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    /// Düşük risk
    Low,
    
    /// Orta risk
    Medium,
    
    /// Yüksek risk
    High,
    
    /// Kritik risk
    Critical,
}

/// Analiz raporu
#[derive(Debug, Serialize, Deserialize)]
pub struct AnalysisReport {
    /// Analiz edilen dosyalar
    pub analyzed_files: Vec<PathBuf>,
    
    /// Toplam script sayısı
    pub total_scripts: usize,
    
    /// Bulunan bulgular
    pub findings: Vec<Finding>,
    
    /// Toplam bulgu sayısı
    pub total_findings: usize,
    
    /// Risk seviyelerine göre bulgu sayıları
    pub findings_by_risk_level: FindingsByRiskLevel,
    
    /// Analiz başlangıç zamanı
    pub start_time: String,
    
    /// Analiz bitiş zamanı
    pub end_time: String,
    
    /// Analiz süresi (saniye)
    pub duration_seconds: f64,
}

/// Risk seviyelerine göre bulgu sayıları
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct FindingsByRiskLevel {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
} 