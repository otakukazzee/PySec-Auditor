# Playbook — Panduan Operasional 🧭

> Tujuan: Panduan singkat bagaimana menggunakan PySec Auditor untuk audit defensif.

## 1) Kasus: Cek header keamanan
- Jalankan: `python run.py -u example.com -l en`
- Periksa bagian "Critical Security Header Analysis".

## 2) Kasus: Cek Path Traversal (Query)
- Pastikan target memiliki query parameters.
- Jalankan tool dan perhatikan bagian "Path Traversal".

## 3) Ekspor laporan
- Tambahkan opsi `-o report.json` atau `-o report.html`.

## Catatan penting
- Tool ini dibuat untuk tujuan pembelajaran dan defensive security. Jangan lakukan pengujian tanpa izin.
