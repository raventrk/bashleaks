# BashLeaks

Bash script'lerdeki güvenlik açıklarını, gizli bilgi sızıntılarını ve potansiyel tehlikeli komut kullanımlarını tespit etmek amacıyla geliştirilmiş, yüksek performanslı ve güvenilir bir analiz aracı.

## Özellikler

### 1. Statik Bash Script Analizi
- **Bash Script Parsing**: Tree-sitter tabanlı gelişmiş Bash syntax ağacı çıkarma ve script içi yapısal analiz.
- **Riskli Komut Tespiti**: eval, curl, wget, sudo, rm -rf gibi tehlikeli ve kötüye kullanılmaya açık komutların algılanması.
- **Gizli Değişken ve Parametre Kontrolü**: Parola, token, API key gibi gizli bilgilerin doğrudan script içinde hardcoded kullanımı.
- **Input Validasyon Eksikliği**: Kullanıcı girdilerinin doğrudan shell komutlarına iletilmesi (command injection riski).
- **Dosya ve Ağ Erişimleri**: Kritik dosya sistemlerine erişim ve network işlemleri analiz edilerek potansiyel veri sızıntıları tespiti.

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

## Kullanım

```bash
# Tek bir dosyayı analiz et
bashleaks analyze script.sh

# Bir dizindeki tüm Bash scriptleri analiz et
bashleaks analyze --recursive /path/to/scripts/

# JSON formatında rapor oluştur
bashleaks analyze script.sh --output json --output-file report.json

# HTML formatında rapor oluştur
bashleaks analyze script.sh --output html --output-file report.html

# Runtime izleme ile analiz et
bashleaks monitor script.sh

# Risk seviyesine göre sadece yüksek riskli bulguları göster
bashleaks analyze script.sh --risk-level high
```

## Kurulum

```bash
# Cargo ile kurulum
cargo install bashleaks

# Manuel kurulum
git clone https://github.com/username/bashleaks.git
cd bashleaks
cargo build --release
```

## Geliştirme

```bash
# Testleri çalıştır
cargo test

# Dokümantasyon oluştur
cargo doc --open
```

## Lisans

MIT 