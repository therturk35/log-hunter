# Katkı Rehberi

## Geliştirme ortamı
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e . -r requirements-dev.txt
pytest -q
```

## Yeni kural eklemek (en kolay katkı)
`log_hunter/builtin_rules/` altına bir YAML dosyası ekle (örnek için `LH-001-ssh-bruteforce.yml`).
- `id` benzersiz olmalı (`LH-0xx`), `mitre` geçerli teknik kimliği olmalı (örn. `T1110`).
- Kuralı doğrulayan bir test ve (gerekirse) `samples/auth.log` içine **sahte** örnek satır ekle.

## Yeni log biçimi eklemek
`log_hunter.parsers.register_parser(ad, fonksiyon)` ile parser kaydedilir. İmza: `fn(lines, year, source) -> list[Event]`.

## Kurallar
- Gerçek log, IP, parola veya anahtar **asla** commit etme; örneklerde RFC 5737 IP aralıklarını kullan (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).
- Her değişiklik testle gelsin; PR'dan önce `pytest -q` geçmeli.
