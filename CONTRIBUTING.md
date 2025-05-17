# Katkıda Bulunma Rehberi

BashLeaks projesine katkıda bulunmak istediğiniz için teşekkür ederiz! Katkılarınız sayesinde bu aracı daha da geliştirmek ve daha fazla kullanıcıya fayda sağlamak istiyoruz.

## 📋 İçindekiler
- [Davranış Kuralları](#davranış-kuralları)
- [Katkı Süreci](#katkı-süreci)
- [Geliştirme Ortamı](#geliştirme-ortamı)
- [Pull Request Gönderme](#pull-request-gönderme)
- [Kodlama Standartları](#kodlama-standartları)
- [Test Etme](#test-etme)

## 🤝 Davranış Kuralları

Bu projeye katkıda bulunan herkes, [Davranış Kuralları](CODE_OF_CONDUCT.md)'na uymayı kabul etmiş sayılır. Lütfen diğer katkıda bulunanlara saygılı olun ve profesyonel bir ortam sağlamaya yardımcı olun.

## 🔄 Katkı Süreci

1. Üzerinde çalışmak istediğiniz konuyu [Issue sayfası](https://github.com/username/bashleaks/issues)'nda bulun veya yeni bir issue oluşturun.
2. Repoyu forklayın ve çalışmanız için yeni bir dal (branch) oluşturun:
   ```bash
   git checkout -b <dal-adı>
   ```
3. Değişikliklerinizi yapın ve gerekli testleri ekleyin.
4. Kodunuzu commitleyin:
   ```bash
   git commit -m "Açıklayıcı commit mesajı"
   ```
5. Değişikliklerinizi forkunuza push edin:
   ```bash
   git push origin <dal-adı>
   ```
6. GitHub üzerinden bir Pull Request oluşturun.

## 💻 Geliştirme Ortamı

### Kurulum

1. Repoyu klonlayın:
   ```bash
   git clone https://github.com/username/bashleaks.git
   cd bashleaks
   ```

2. Bağımlılıkları yükleyin:
   ```bash
   cargo build
   ```

3. Kodunuzu test edin:
   ```bash
   cargo test
   ```

### Bağımlılıklar

- Rust 1.50 veya üzeri
- Cargo
- Tree-sitter ve tree-sitter-bash

## 📝 Pull Request Gönderme

Pull request'ler için şu adımları izleyin:

1. Kodunuzun mevcut testleri geçtiğinden emin olun.
2. Yeni özellikler için testler ekleyin.
3. Dokümantasyonu güncelleyin.
4. Değişikliklerinizi açıklayan bir PR açıklaması yazın.
5. PR'nizin başlığı açıklayıcı olsun ve issue numarasını içersin (örn. "Fix #42: Eval komut tespiti iyileştirildi").

## 📏 Kodlama Standartları

BashLeaks projesinde şu kodlama standartlarını takip ediyoruz:

### Rust Kodlama Standartları

- Kodunuzu rustfmt ile formatlayın:
  ```bash
  cargo fmt
  ```

- Clippy ile kod kalitesini kontrol edin:
  ```bash
  cargo clippy
  ```

- Fonksiyonlar ve modüller için dokümantasyon yorumları ekleyin.
- Değişken isimleri açıklayıcı olmalı ve Rust isimlendirme kurallarına uygun olmalı.
- Tip güvenliği için Result ve Option tiplerini kullanın.

### Commit Standartları

Commit mesajlarınız şu formatta olmalı:

```
<tip>: <kısa açıklama>

<detaylı açıklama>
```

Tip şunlardan biri olabilir:
- `feat`: Yeni bir özellik
- `fix`: Hata düzeltmesi
- `docs`: Sadece dokümantasyon değişiklikleri
- `style`: Kod işlevini değiştirmeyen formatlamalar
- `refactor`: İşlevselliği değiştirmeyen kod yeniden yapılandırması
- `test`: Test ekleme veya düzenleme
- `chore`: Geliştirme sürecine ilişkin değişiklikler

## 🧪 Test Etme

Yeni özellikler veya hata düzeltmeleri eklerken daima testler ekleyin. Testler `tests/` dizininde olmalıdır.

### Birim Testleri

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_feature() {
        // Test kodunuz
        assert_eq!(expected, actual);
    }
}
```

### Entegrasyon Testleri

`tests/` dizininde yeni bir dosya oluşturun:

```rust
use bashleaks::{Analyzer, Finding};

#[test]
fn test_analyzer_with_sample_script() {
    // Test kodunuz
}
```

## 🙏 Teşekkürler

BashLeaks'e katkıda bulunarak daha güvenli Bash script geliştirme ekosistemine katkı sağlıyorsunuz. Zamanınız ve çabanız için teşekkür ederiz!

---

Bu rehberle ilgili herhangi bir sorunuz varsa, lütfen iletişime geçmekten çekinmeyin. 