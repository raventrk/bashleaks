#!/bin/bash

# Bu script birkaç güvenlik açığı içermektedir ve test amacıyla kullanılmaktadır.

# Güvensiz API key tanımı - Hardcoded Secret
API_KEY="1234567890abcdefghijklmn"
PASSWORD="super_secret_password"

# Tehlikeli komut kullanımı - eval
userInput="echo Hello World"
eval $userInput

# Güvensiz curl kullanımı - SSL doğrulama kapalı
curl -k https://example.com

# Tehlikeli rm kullanımı
rm -rf ./temp/

# Komut enjeksiyonu riski
filename="test.txt"
cat $filename | grep "pattern"

# Güvensiz dosya izinleri
chmod 777 ./temp

# URL içinde kimlik bilgileri
wget https://user:password@example.com/file.zip

# Kabuk çağrısı, kullanıcı girdisiyle
command="ls -la"
sh -c "$command"

echo "Script tamamlandı!" 