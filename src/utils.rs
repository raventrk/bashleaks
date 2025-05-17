use crate::cli::RiskLevel;
use std::path::Path;

/// Bir dosya yolunun uzantısını kontrol eder
pub fn has_extension<P: AsRef<Path>>(path: P, extension: &str) -> bool {
    path.as_ref()
        .extension()
        .map_or(false, |ext| ext == extension)
}

/// Bir karakter dizisinde kaç satır olduğunu sayar
pub fn count_lines(s: &str) -> usize {
    s.lines().count()
}

/// Bir dosyanın sonundaki yeni satır karakterlerini sayar
pub fn count_trailing_newlines(s: &str) -> usize {
    s.chars().rev().take_while(|c| *c == '\n').count()
}

/// Risk seviyesini adlandırır
pub fn risk_level_name(level: RiskLevel) -> &'static str {
    match level {
        RiskLevel::Critical => "Kritik",
        RiskLevel::High => "Yüksek",
        RiskLevel::Medium => "Orta",
        RiskLevel::Low => "Düşük",
    }
}

/// RiskLevel türünü string'den çevirir
pub fn parse_risk_level(s: &str) -> Option<RiskLevel> {
    match s.to_lowercase().as_str() {
        "critical" | "kritik" => Some(RiskLevel::Critical),
        "high" | "yüksek" => Some(RiskLevel::High),
        "medium" | "orta" => Some(RiskLevel::Medium),
        "low" | "düşük" => Some(RiskLevel::Low),
        _ => None,
    }
}

/// String içindeki özel karakterleri escape eder
pub fn escape_html(s: &str) -> String {
    s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\"", "&quot;")
        .replace("'", "&#39;")
}

/// Belirtilen konumdaki satır numarasını hesaplar
pub fn get_line_number(content: &str, byte_offset: usize) -> usize {
    if byte_offset >= content.len() {
        return count_lines(content);
    }
    
    content[..byte_offset].chars().filter(|&c| c == '\n').count() + 1
}

/// Belirtilen satır numarasının başlangıç bayt indeksini bulur
pub fn get_line_start_offset(content: &str, line: usize) -> Option<usize> {
    if line == 0 {
        return None;
    }
    
    if line == 1 {
        return Some(0);
    }
    
    let mut current_line = 1;
    for (i, c) in content.char_indices() {
        if c == '\n' {
            current_line += 1;
            if current_line == line {
                return Some(i + 1);
            }
        }
    }
    
    None
}

/// Karakterleri çevreleyen tırnak işaretlerini kaldırır
pub fn strip_quotes(s: &str) -> &str {
    let s = s.trim();
    
    if (s.starts_with('\'') && s.ends_with('\'')) || (s.starts_with('"') && s.ends_with('"')) {
        &s[1..s.len() - 1]
    } else {
        s
    }
} 