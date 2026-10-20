# Güvenlik Politikası

## Açık bildirme
Bir güvenlik açığı bulursan **herkese açık issue açma**. GitHub'ın "Report a vulnerability" (Security > Advisories) özelliğiyle özel olarak bildir. Mümkünse tekrar üretme adımlarını ve etkilenen sürümü yaz.

## Kapsam
Aracın kendi güvenliği önemlidir: kural dosyası ayrıştırma, log ayrıştırma, rapor üretimi (XSS), dosya/klasör tarama ve sıkıştırılmış dosya işleme kapsam içindedir.

## Tasarım ilkeleri
- Log ve kural dosyaları güvenilmez girdi sayılır; `yaml.safe_load`, alan beyaz listesi, boyut ve satır sınırları kullanılır.
- Tüm log kaynaklı değerler rapora HTML-escape edilerek yazılır.
- Klasör taramada sembolik bağlar takip edilmez.
