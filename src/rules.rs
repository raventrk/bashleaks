use crate::models::{FindingType, RiskLevel};
use lazy_static::lazy_static;
use regex::Regex;
use std::collections::HashMap;

/// Tehlikeli Bash komutları ve risk seviyeleri
lazy_static! {
    pub static ref DANGEROUS_COMMANDS: HashMap<&'static str, (RiskLevel, &'static str, &'static str)> = {
        let mut map = HashMap::new();
        
        // (Risk Seviyesi, Açıklama, Tavsiye)
        map.insert("eval", (
            RiskLevel::High, 
            "eval komutu, kullanıcı girdisini doğrudan çalıştıran ve command injection saldırılarına açık tehlikeli bir komuttur.",
            "eval yerine daha güvenli alternatifler kullanın. Mutlaka kullanılması gerekiyorsa, girdiyi sıkı bir şekilde doğrulayın."
        ));
        
        map.insert("source", (
            RiskLevel::Medium, 
            "source komutu, harici bir script'i mevcut ortama yükler ve güvensiz kod çalıştırma riski oluşturabilir.",
            "Güvenilir kaynaklardan gelen scriptleri yükleyin ve çalıştırmadan önce içeriğini kontrol edin."
        ));
        
        map.insert("exec", (
            RiskLevel::High, 
            "exec komutu, mevcut shell'i yeni bir komutla değiştirir ve tehlikeli yetki yükseltmelerine yol açabilir.",
            "Gerekli değilse exec kullanmayın. Kullanmanız gerekiyorsa, çalıştırılan komutları doğrulayın."
        ));
        
        map.insert("sudo", (
            RiskLevel::Medium, 
            "sudo komutu, yüksek yetkilerle komut çalıştırır ve yanlış kullanımda sistem güvenliğini tehlikeye atabilir.",
            "sudo kullanımını minimumda tutun ve sadece gerekli komutlar için kullanın."
        ));
        
        map.insert("chmod", (
            RiskLevel::Medium, 
            "chmod komutu, dosya izinlerini değiştirir ve yanlış kullanımda güvenlik risklerine yol açabilir.",
            "Dosya izinlerini en az ayrıcalık prensibine göre ayarlayın (örn. 777 yerine daha kısıtlayıcı izinler)."
        ));
        
        map.insert("curl", (
            RiskLevel::Medium, 
            "curl komutu, harici kaynaklardan veri indirir ve güvenli olmayan bağlantılar üzerinden sızıntılara neden olabilir.",
            "HTTPS kullanın ve indirilen içeriği doğrulayın. --insecure parametresinden kaçının."
        ));
        
        map.insert("wget", (
            RiskLevel::Medium, 
            "wget komutu, harici kaynaklardan veri indirir ve güvenli olmayan bağlantılar üzerinden sızıntılara neden olabilir.",
            "HTTPS kullanın ve indirilen içeriği doğrulayın. --no-check-certificate parametresinden kaçının."
        ));
        
        map.insert("rm", (
            RiskLevel::Medium, 
            "rm komutu, özellikle -rf parametresiyle kullanıldığında geri alınamaz veri kayıplarına neden olabilir.",
            "rm -rf kullanırken çok dikkatli olun ve değişkenlerle kullanmaktan kaçının (örn. rm -rf $VAR/*)."
        ));
        
        map.insert(">", (
            RiskLevel::Low, 
            "Yönlendirme operatörleri (>, >>) dosya üzerine yazma veya silme riskleri oluşturabilir.",
            "Özellikle sistem dosyalarına yazarken dikkatli olun ve yedekleme yapın."
        ));
        
        map.insert("base64", (
            RiskLevel::Low, 
            "base64 komutu, gizli bilgilerin kodlanması için kullanılabilir ve potansiyel bir gizli bilgi sızıntısı olabilir.",
            "Hassas verileri kodlamak yerine güvenli şifreleme yöntemleri ve anahtar yönetimi kullanın."
        ));
        
        map
    };
}

/// Gizli bilgi kalıpları (regex)
lazy_static! {
    pub static ref SECRET_PATTERNS: Vec<(Regex, FindingType, RiskLevel, &'static str, &'static str)> = {
        vec![
            // (Regex Pattern, Bulgu Tipi, Risk Seviyesi, Açıklama, Tavsiye)
            (
                Regex::new(r#"(?i)(?:password|passwd|pwd)\s*=\s*['"](.*?)['"]"#).unwrap(),
                FindingType::HardcodedSecret,
                RiskLevel::Critical,
                "Script içinde hardcoded parola tespit edildi.",
                "Parolaları asla script içine yazmayın. Bunun yerine ortam değişkenleri veya güvenli bir vault kullanın."
            ),
            (
                Regex::new(r#"(?i)(?:api[-_]?key|apikey|api[-_]?token|access[-_]?token|secret[-_]?key)\s*=\s*['"](.*?)['"]"#).unwrap(),
                FindingType::HardcodedSecret,
                RiskLevel::Critical,
                "Script içinde hardcoded API key/token tespit edildi.",
                "API anahtarlarını asla script içine yazmayın. Bunun yerine ortam değişkenleri veya güvenli bir vault kullanın."
            ),
            (
                Regex::new(r#"(?i)(?:private[-_]?key|ssh[-_]?key)\s*=\s*['"](.*?)['"]"#).unwrap(),
                FindingType::HardcodedSecret,
                RiskLevel::Critical,
                "Script içinde hardcoded private key tespit edildi.",
                "Private key'leri asla script içine yazmayın. Bunun yerine güvenli dosya izinleri olan ayrı dosyalarda saklayın."
            ),
            (
                Regex::new(r#"(?i)(?:aws[-_]?access[-_]?key[-_]?id)\s*=\s*['"](.*?)['"]"#).unwrap(),
                FindingType::HardcodedSecret,
                RiskLevel::Critical,
                "Script içinde hardcoded AWS access key tespit edildi.",
                "AWS anahtarlarını asla script içine yazmayın. AWS IAM roles veya ortam değişkenleri kullanın."
            ),
            (
                Regex::new(r#"https?://(?:[^:@/]+:[^:@/]+@)"#).unwrap(),
                FindingType::HardcodedSecret,
                RiskLevel::High,
                "URL içinde kimlik bilgileri (kullanıcı adı:parola) tespit edildi.",
                "URL'lerde kimlik bilgilerini asla hardcoded olarak kullanmayın."
            ),
        ]
    };
}

/// Komut enjeksiyonu riski kalıpları
lazy_static! {
    pub static ref COMMAND_INJECTION_PATTERNS: Vec<(Regex, RiskLevel, &'static str, &'static str)> = {
        vec![
            // (Regex Pattern, Risk Seviyesi, Açıklama, Tavsiye)
            (
                Regex::new(r#"eval\s+[\$"].*\$\{?[a-zA-Z0-9_]+\}?"#).unwrap(),
                RiskLevel::Critical,
                "Kullanıcı girdisi eval komutu içinde kullanılıyor.",
                "Kullanıcı girdisini asla doğrudan eval içinde kullanmayın. Alternatif güvenli yöntemler tercih edin."
            ),
            (
                Regex::new(r#"(?:^|\s)(?:bash|sh)\s+-c\s+["']?.*\$\{?[a-zA-Z0-9_]+\}?"#).unwrap(),
                RiskLevel::High,
                "Kabuk çağrısı, kullanıcı girdisi ile birlikte kullanılıyor.",
                "Kabuk çağrılarında kullanıcı girdisini doğrudan kullanmak yerine parametreleri doğrulayın."
            ),
            (
                Regex::new(r#"(?:^|\s)(?:exec|system)\s+["']?.*\$\{?[a-zA-Z0-9_]+\}?"#).unwrap(),
                RiskLevel::High,
                "Sistem komutu, kullanıcı girdisi ile birlikte kullanılıyor.",
                "Sistem komutlarında kullanıcı girdisini doğrudan kullanmak yerine parametreleri doğrulayın."
            ),
        ]
    };
}

/// Güvensiz dosya işlemleri kalıpları
lazy_static! {
    pub static ref UNSAFE_FILE_OPERATIONS: Vec<(Regex, RiskLevel, &'static str, &'static str)> = {
        vec![
            // (Regex Pattern, Risk Seviyesi, Açıklama, Tavsiye)
            (
                Regex::new(r#"rm\s+-[rf]{1,2}\s+(?:/|\$HOME|\$\{HOME\}|~)"#).unwrap(),
                RiskLevel::Critical,
                "Tehlikeli rm komutu, kök dizin veya ev dizinini hedef alıyor.",
                "rm -rf komutunu kök dizin veya ev dizininde kullanmaktan kaçının ve güvenlik kontrolleri ekleyin."
            ),
            (
                Regex::new(r#"chmod\s+-[R]{0,1}\s+(?:777|a\+[rwx]{1,3})\s+["']?(?:/[^\s]+)"#).unwrap(),
                RiskLevel::High,
                "Tehlikeli chmod komutu tüm kullanıcılara tam erişim veriyor.",
                "chmod 777 yerine daha kısıtlayıcı izinler kullanın ve en az ayrıcalık prensibini uygulayın."
            ),
            (
                Regex::new(r#">\s+/(?:etc|bin|sbin|usr|var)/"#).unwrap(),
                RiskLevel::High,
                "Sistem dizinlerindeki dosyaların üzerine yazılıyor.",
                "Sistem dizinlerine yazma işlemlerini minimize edin ve gerektiğinde yedekleme yapın."
            ),
        ]
    };
}

/// Ağ güvenliği kalıpları
lazy_static! {
    pub static ref NETWORK_SECURITY_PATTERNS: Vec<(Regex, RiskLevel, &'static str, &'static str)> = {
        vec![
            // (Regex Pattern, Risk Seviyesi, Açıklama, Tavsiye)
            (
                Regex::new(r#"curl\s+.*--insecure|-k"#).unwrap(),
                RiskLevel::High,
                "curl komutu, SSL sertifika doğrulamasını devre dışı bırakıyor.",
                "SSL sertifika doğrulamasını devre dışı bırakmayın, bu MITM saldırılarına açık hale getirir."
            ),
            (
                Regex::new(r#"wget\s+.*--no-check-certificate"#).unwrap(),
                RiskLevel::High,
                "wget komutu, SSL sertifika doğrulamasını devre dışı bırakıyor.",
                "SSL sertifika doğrulamasını devre dışı bırakmayın, bu MITM saldırılarına açık hale getirir."
            ),
            (
                Regex::new(r#"ssh\s+.*-o\s+StrictHostKeyChecking=no"#).unwrap(),
                RiskLevel::Medium,
                "SSH komutu, host key doğrulamasını devre dışı bırakıyor.",
                "SSH host key doğrulamasını devre dışı bırakmak, güvenlik risklerine neden olabilir."
            ),
        ]
    };
} 