# 🔍 BashLeaks

![License](https://img.shields.io/badge/license-MIT-blue)
![Version](https://img.shields.io/badge/version-0.1.0-green)
![Build](https://img.shields.io/badge/build-passing-brightgreen)

<p align="center">
  <img src="https://via.placeholder.com/150?text=BashLeaks" alt="BashLeaks Logo" width="150"/>
</p>

Bash script'lerdeki güvenlik açıklarını, gizli bilgi sızıntılarını ve potansiyel tehlikeli komut kullanımlarını tespit etmek amacıyla geliştirilmiş, yüksek performanslı ve güvenilir bir statik analiz aracı. BashLeaks, tree-sitter tabanlı güçlü syntax analizi ve akıllı regex pattern'leri kullanarak bash scriptlerin derinlemesine güvenlik analizini sağlar.

## 📋 İçindekiler

- [Özellikler](#özellikler)
- [Kurulum](#kurulum)
- [Kullanım](#kullanım)
- [Nasıl Çalışır](#nasıl-çalışır)
- [Konfigürasyon](#konfigürasyon)
- [Geliştirme](#geliştirme)
- [Katkıda Bulunma](#katkıda-bulunma)
- [Lisans](#lisans)

## ✨ Özellikler

### 1. Statik Bash Script Analizi
- **Bash Script Parsing**: Tree-sitter tabanlı gelişmiş Bash syntax ağacı çıkarma ve script içi yapısal analiz.
- **Riskli Komut Tespiti**: `eval`, `curl`, `wget`, `sudo`, `rm -rf` gibi tehlikeli ve kötüye kullanılmaya açık komutların algılanması.
- **Gizli Değişken ve Parametre Kontrolü**: Parola, token, API key gibi gizli bilgilerin doğrudan script içinde hardcoded kullanımını tespit eder.
- **Input Validasyon Eksikliği**: Kullanıcı girdilerinin doğrudan shell komutlarına iletilmesi (command injection riski) durumlarını tespit eder.
- **Dosya ve Ağ Erişimleri**: Kritik dosya sistemlerine erişim ve network işlemleri analiz edilerek potansiyel veri sızıntıları belirler.

### 2. Runtime İzleme (Gelişmiş Özellik)
- **Dosya Sistemi İzleme**: Script tarafından oluşturulan, okunan veya değiştirilen dosyaların gerçek zamanlı takibi.
- **Süreç ve Sistem Çağrısı İzleme**: Script'in çalıştırdığı alt süreçlerin davranış analizi.
- **Log Analizi**: Sistem logları ve uygulama loglarından anormal aktivitelerin tespiti.

### 3. Çoklu Çıktı Formatları
- **JSON Raporlama**: Detaylı analiz sonuçları, bulgular, uyarılar ve risk dereceleri JSON formatında.
- **HTML Raporlama**: Okunabilir, renk kodlu ve kategorize edilmiş analiz sonuçları ile interaktif HTML raporlar.
- **CLI & API Kullanımı**: Hem komut satırından hem de programatik olarak kullanılabilir.

### 4. Özgün ve Yenilikçi Özellikler
- **Risk Seviyesi Skorlaması**: Tespit edilen her risk için CVSS benzeri bir skor hesaplayarak önceliklendirme.
- **Otomatik Düzeltme Önerileri**: Güvenlik açıkları için kod örnekleri ve iyileştirme tavsiyeleri.
- **Modüler Tasarım**: Yeni analiz modülleri kolayca eklenebilir, genişletilebilir yapı.
- **Ekip İşbirliği Desteği**: Raporların paylaşımı ve ekip içi inceleme için JSON tabanlı veri değişimi.

## 🚀 Kurulum

### Gereksinimler

- Rust 1.50 veya üzeri
- Cargo
- Tree-sitter ve tree-sitter-bash bağımlılıkları

### Cargo ile Kurulum

```bash
cargo install bashleaks
```

### Manuel Kurulum

```bash
# Depoyu klonlayın
git clone https://github.com/username/bashleaks.git

# Proje dizinine girin
cd bashleaks

# Bağımlılıkları indirin ve kurun
cargo build --release

# Çalıştırılabilir dosyayı path'e ekleyin
sudo cp target/release/bashleaks /usr/local/bin/
```

## 📊 Kullanım

### Temel Kullanım

Tek bir bash scriptini analiz etmek için:

```bash
bashleaks analyze script.sh
```

Bir dizindeki tüm bash scriptlerini analiz etmek için:

```bash
bashleaks analyze --recursive /path/to/scripts/
```

### Çıktı Formatları

CLI çıktısı (varsayılan):

```bash
bashleaks analyze script.sh
```

JSON formatında rapor oluşturmak için:

```bash
bashleaks analyze script.sh --output json --output-file report.json
```

HTML formatında rapor oluşturmak için:

```bash
bashleaks analyze script.sh --output html --output-file report.html
```

### Filtreleme

Sadece belirli risk seviyesindeki veya üstündeki bulguları görmek için:

```bash
bashleaks analyze script.sh --risk-level high
```

### Runtime İzleme

Bir scripti çalışma zamanında izlemek için:

```bash
bashleaks monitor script.sh
```

## 🛠️ Nasıl Çalışır

BashLeaks, bash scriptlerini analiz ederken iki ana yaklaşım kullanır:

1. **Syntax Analizi**: Tree-sitter kütüphanesi ile scriptlerin syntax ağacını çıkarır ve bu yapıyı kullanarak komutları, değişkenleri ve kontrol yapılarını belirler.

2. **Pattern Eşleştirme**: Önceden tanımlanmış güvenlik açığı kalıplarını (regex tabanlı) kullanarak potansiyel riskleri tespit eder.

### Akış Şeması

```
+-------------+     +----------------+     +---------------+
| Bash Script | --> | Syntax Parsing | --> | AST Traversal |
+-------------+     +----------------+     +---------------+
                                                  |
+------------+     +----------------+     +-------v-------+
| Report Gen | <-- | Risk Analysis  | <-- | Pattern Match |
+------------+     +----------------+     +---------------+
```

## ⚙️ Konfigürasyon

BashLeaks, ihtiyaçlarınıza göre özelleştirilebilir. Konfigürasyon dosyası (`.bashleaksrc`) oluşturarak veya ortam değişkenleri kullanarak aracı özelleştirebilirsiniz.

### Konfigürasyon Dosyası Örneği

```toml
[general]
default_output = "cli"
log_level = "info"

[rules]
ignore_rules = ["RULE001", "RULE002"]
custom_rules_path = "/path/to/custom/rules"

[output]
json_indent = 2
html_template = "/path/to/custom/template.html"
```

## 👨‍💻 Geliştirme

### Bağımlılıkları Yükleme

```bash
# Geliştirme bağımlılıklarını yükleme
cargo install --path .
```

### Testleri Çalıştırma

```bash
# Tüm testleri çalıştırma
cargo test

# Belirli bir test çalıştırma
cargo test test_name
```

### Dokümantasyon Oluşturma

```bash
# API dokümantasyonu oluşturma
cargo doc --open
```

## 🤝 Katkıda Bulunma

Katkılarınızı bekliyoruz! Aşağıdaki adımları izleyerek projeye katkıda bulunabilirsiniz:

1. Bu depoyu forklayın
2. Özellik dalı oluşturun (`git checkout -b yeni-ozellik`)
3. Değişikliklerinizi commit edin (`git commit -am 'Yeni özellik: X özelliği eklendi'`)
4. Dalınızı push edin (`git push origin yeni-ozellik`)
5. Pull Request oluşturun

Katkıda bulunmadan önce lütfen [Katkıda Bulunma Rehberi](CONTRIBUTING.md) dosyasını okuyun.

## 📝 Yapılacaklar

- [ ] Daha kapsamlı test senaryoları ekleme
- [ ] Docker desteği
- [ ] CI/CD entegrasyonu
- [ ] Çoklu dil desteği (İngilizce, Türkçe, vb.)
- [ ] Daha detaylı HTML rapor şablonu
- [ ] Güvenlik kuralları veritabanının genişletilmesi

## 📄 Lisans

Bu proje MIT lisansı altında lisanslanmıştır. Daha fazla bilgi için [LICENSE](LICENSE) dosyasına bakın.

## 🙏 Teşekkürler

- Tree-sitter ekibine, harika syntax analiz kütüphanesi için
- Rust topluluğuna, mükemmel belgelendirme ve desteklerinden dolayı

---

<p align="center">
  Developed with ❤️ by BashLeaks Team
</p> 
