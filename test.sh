#!/bin/bash

echo "=== Test Script Başladı ==="

# Kritik: eval kullanımı
USER_INPUT="echo 'Bu zararsız bir komut'"
eval $USER_INPUT  # Güvenlik açığı: eval kullanımı - BASH-EVAL-001

# Kritik: Hardcoded credentials
API_KEY="sk_live_51AB32OINGDSFh82hjfdsSDFSDF"
DATABASE_PASSWORD="Passw0rd123!"

# Kritik: curl çıktısını doğrudan shell'e piping
echo "Uzak betik çalıştırılıyor..."
curl -s https://example.com/remote_script.sh | bash  # Güvenlik açığı: BASH-CURL-001

# Kritik: exec kullanımı
exec bash -c "echo Bu komut güvenlik açığına yol açabilir"  # Güvenlik açığı: BASH-EXEC-001

# Orta: chmod 777 kullanımı
echo "Dosya izinlerini değiştirme"
chmod 777 /tmp/testfile.txt  # Güvenlik açığı: BASH-CHMOD-001

# Orta: Güvensiz geçici dosya kullanımı
TEMP_FILE="/tmp/user_data_$$.txt"  # Güvenlik açığı: BASH-TEMP-001

# Orta: Tırnak işareti kullanılmayan değişkenler
USER_PATH=$PATH  # Güvenlik açığı: BASH-VAR-001

# Orta: Command injection riski
FILENAME=$(ls -la | grep $1)  # Güvenlik açığı: BASH-VAR-001

# Düşük: Alıntılanmamış değişken kullanımı
echo Merhaba $USER  # Güvenlik açığı: BASH-QUOTE-001

# Potansiyel shell komut enjeksiyonu
USER_COMMAND="ls -la"
$USER_COMMAND "; rm -rf /tmp/important_file"  # Güvenlik açığı: Komut enjeksiyonu

# Bash geçmişini devre dışı bırakma
HISTSIZE=0  # Güvenlik açığı: BASH-HIST-001

echo "=== Test Script Bitti ==="