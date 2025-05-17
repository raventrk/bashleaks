use anyhow::Result;
use log::debug;
use std::fs;
use std::path::Path;
use tree_sitter::{Node, Parser, Tree};

/// Bash script parser yapısı
pub struct BashParser {
    parser: Parser,
}

impl BashParser {
    /// Yeni bir BashParser örneği oluşturur
    pub fn new() -> Result<Self> {
        let mut parser = Parser::new();
        
        // tree-sitter-bash 0.23.3 sürümünde LANGUAGE sabitini kullanıyoruz
        parser
            .set_language(tree_sitter_bash::language())
            .map_err(|e| anyhow::anyhow!("Dil ayarlanırken hata oluştu: {}", e))?;
        Ok(Self { parser })
    }

    /// Bash scriptini parse eder ve syntax ağacını döndürür
    pub fn parse(&mut self, script_content: &str) -> Result<Tree> {
        self.parser
            .parse(script_content, None)
            .ok_or_else(|| anyhow::anyhow!("Script parse edilemedi"))
    }

    /// Verilen yoldaki Bash scriptini okur ve parse eder
    pub fn parse_file<P: AsRef<Path>>(&mut self, file_path: P) -> Result<Tree> {
        let file_path = file_path.as_ref();
        debug!("Script dosyası parse ediliyor: {:?}", file_path);
        
        let content = fs::read_to_string(file_path)
            .map_err(|e| anyhow::anyhow!("Dosya okunamadı {}: {}", file_path.display(), e))?;
        
        self.parse(&content)
    }

    /// İlgili kodu ve satır numarasını kullanarak kod parçasını (snippet) alır
    pub fn get_code_snippet(content: &str, line: usize, context_lines: usize) -> String {
        let lines: Vec<&str> = content.lines().collect();
        let start_line = if line > context_lines { line - context_lines } else { 0 };
        let end_line = std::cmp::min(line + context_lines, lines.len());
        
        lines[start_line..end_line].join("\n")
    }
    
    /// Bir düğümden komut adını ayıklar
    pub fn extract_command_name<'a>(&self, node: Node, source: &'a str) -> Option<&'a str> {
        if node.kind() == "command" {
            // Komut düğümünün ilk çocuğu (command_name) alınır
            let command_name = node.child(0)?;
            if command_name.kind() == "command_name" {
                let range = command_name.range();
                return Some(&source[range.start_byte..range.end_byte]);
            }
        }
        None
    }
    
    /// Bir düğümden argümanları ayıklar
    pub fn extract_command_arguments<'a>(&self, node: Node, source: &'a str) -> Vec<&'a str> {
        let mut arguments = Vec::new();
        
        // Komutun tüm çocukları üzerinde döngü
        let child_count = node.child_count();
        for i in 1..child_count {  // 0. indeks komut adı, 1'den başlayarak argümanlar
            if let Some(child) = node.child(i) {
                if child.kind() == "word" || child.kind() == "string" {
                    let range = child.range();
                    arguments.push(&source[range.start_byte..range.end_byte]);
                }
            }
        }
        
        arguments
    }
} 