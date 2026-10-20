# log-hunter

Linux `auth.log` kayıtlarını **Sigma tarzı YAML kurallarıyla** tarayan, tespitleri **MITRE ATT&CK** tekniklerine eşleyen ve **HTML / JSON / SARIF** çıktı üreten hafif, açık kaynaklı bir log tarama motoru. Hem komut satırı aracı hem Python kütüphanesi olarak kullanılır.

## Özellikler
- **Tarama motoru**: dosya veya klasör (özyinelemeli), döndürülmüş loglar (`auth.log.1`) ve `.gz` desteği
- **Dosyalar arası korelasyon**: saldırının yarısı `auth.log`, yarısı `auth.log.1` içinde olsa da yakalanır
- **Kural tipleri**: `match` (tek olay), `threshold` (zaman penceresinde eşik), `followed_by` (olay zinciri, örn. brute-force sonrası başarılı giriş)
- **Kuralları genişletme**: kod yazmadan YAML ekleyerek; yeni log biçimleri için parser eklenti noktası
- **SARIF çıktısı**: GitHub Code Scanning ve diğer araçlarla uyumlu
- **Güvenli tasarım**: girdiyi güvenilmez sayar (aşağıya bak)

## Kurulum
```bash
pip install .            # veya geliştirme için: pip install -e . -r requirements-dev.txt
```

## Komut satırı
```bash
log-hunter /var/log/auth.log --html rapor.html
log-hunter /var/log --sarif sonuc.sarif --min-severity high --fail-on-alert
log-hunter samples/auth.log --year 2026        # sahte örnek veriyle deneme
```
Çıkış kodları: `0` temiz · `1` uyarı var (`--fail-on-alert` ile) · `2` hata veya eksik tarama.

## Kütüphane olarak
```python
from log_hunter import Scanner, load_rules

result = Scanner(load_rules(), year=2026).scan(["/var/log"])
for alert in result.alerts:
    print(alert.severity, alert.rule_id, alert.key, alert.mitre)
print(result.errors)   # okunamayan / sınırı aşan dosyalar
```

## GitHub Code Scanning ile kullanım
```yaml
- run: pip install log-hunter && log-hunter logs/ --sarif results.sarif
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: results.sarif }
```
Not: SARIF konumları verdiğin yol biçiminde yazılır; GitHub için repo köküne göre göreli yol ver.

## Dahil kurallar
| ID | Tespit | MITRE |
|----|--------|-------|
| LH-001 | SSH brute-force (60 sn'de 5+ başarısız giriş) | T1110 |
| LH-002 | Brute-force sonrası başarılı giriş | T1110 |
| LH-003 | Root ile SSH girişi | T1078 |
| LH-004 | Kullanıcı adı taraması | T1110 |
| LH-005 | Reddedilen sudo | T1548.003 |

## Kural yazma
```yaml
id: LH-010
title: Örnek kural
severity: high            # low | medium | high | critical
mitre: T1110
type: threshold           # match | threshold
where: {event_type: ssh_failed}
group_by: source_ip
threshold: 5
window_seconds: 60
```
Kendi kurallarını `--rules klasör/` ile ver. Ayrıntı için [CONTRIBUTING.md](CONTRIBUTING.md).

## Güvenlik tasarımı
- Kural dosyaları `yaml.safe_load` + alan beyaz listesiyle okunur; kural dosyasından kod çalışmaz
- Log satırı uzunluğu, dosya başına bayt ve dosya sayısı sınırlıdır; `.gz` için **açılmış** boyut sınırlanır (zip-bomb)
- Klasör taramada sembolik bağlar takip edilmez
- Okunamayan/sınırı aşan dosya sessizce geçilmez; hata olarak bildirilir ve çıkış kodu `2` olur
- Rapordaki tüm log kaynaklı değerler HTML-escape edilir, sayfada CSP vardır
- Repoda gerçek log/anahtar yok; `samples/` yalnızca sahte veri içerir (RFC 5737 IP aralıkları)

Güvenlik açığı bildirimi için [SECURITY.md](SECURITY.md).

## Sınırlar / yol haritası
- Şu an yalnızca `auth.log` (syslog) biçimi; Windows `.evtx` planlanıyor
- Syslog'ta yıl ve saat dilimi yok; Aralık→Ocak geçişi ele alınmıyor
- Tespitler basit kurallara dayanır; üretim SOC'unun yerine geçmez, ön eleme aracıdır

## Etik kullanım
Yalnızca **kendi sistemlerinizin** veya analiz yetkiniz olan logların incelenmesi için kullanın.

## Lisans
MIT, bkz. [LICENSE](LICENSE).
