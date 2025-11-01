# ⚡ PySec Auditor — Web Security Toolkit 🔐

> **"Automate. Detect. Defend."**  
> _A modular Python toolkit for auditing HTTP headers, cookies, TLS, and web misconfigurations._

---

## 🧠 Tentang Proyek

**PySec Auditor** adalah toolkit keamanan yang dirancang untuk membantu _defender_, _pentester_, dan _developer security-minded_ dalam melakukan **audit keamanan web**.  
Dibangun dengan Python dan **Rich UI**, alat ini menampilkan hasil audit secara interaktif dan dapat diekspor ke berbagai format laporan.

> 💡 Project ini bersifat **open-source**, berlisensi **MIT**, dan dikembangkan oleh **Sardidev ❤️**

---

## 🚀 Fitur Utama

| Kategori                        | Fitur                                                                                                                                |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| 🔐 **Header Security Audit**    | Pemeriksaan otomatis terhadap header penting seperti **HSTS**, **CSP**, **X-Frame-Options**, **X-Content-Type-Options**, dan lainnya |
| 🍪 **Cookie Analyzer**          | Analisis atribut **Secure**, **HttpOnly**, dan **SameSite** untuk setiap cookie                                                      |
| 🌍 **CORS & Exposure Check**    | Deteksi konfigurasi CORS yang lemah dan file sensitif seperti `.git`, `.env`, `robots.txt`, `backup.zip`                             |
| 🧩 **Path Traversal Test**      | Pengujian parameter query terhadap potensi eksploitasi direktori traversal                                                           |
| 🔒 **TLS & Cipher Suite Audit** | Pemeriksaan sertifikat SSL/TLS, masa berlaku, dan cipher yang digunakan                                                              |
| 📦 **Output & Reporting**       | Ekspor hasil audit ke **JSON** atau **HTML report** dengan tampilan profesional                                                      |

---

## ⚙️ Cara Menjalankan

### lihat dokumentasi lengkap di [document/setup.md](document/setup.md)

1. **Instal dependensi:**
   ```bash
   python install.py
   ```
2. **Jalankan audit:**

   ```bash
   python run.py -u https://example.com -o report.json -l id
   ```

3. **Output:**
   - `JSON` → hasil mentah untuk integrasi CI/CD
   - `HTML` → laporan interaktif dengan visualisasi keamanan

---

## 🧭 Struktur Proyek

```
PySec_Auditor/
├── run.py                  # Entry point utama
├── src/                    # Folder berisi semua modul audit
│   ├── core/               # Logika inti (header, cookie, TLS, traversal)
│   ├── utils/              # Fungsi pendukung & formatter
│   └── output/             # Ekspor laporan & tampilan Rich
└── document/               # Dokumentasi & panduan penggunaan
    ├── README.md
    ├── setup.md
    └── playbook.md
```

---

## 🧩 Integrasi & CI/CD

- 💥 Dapat digunakan dalam pipeline keamanan DevSecOps
- ⚙️ Dukungan **pytest** untuk pengujian otomatis
- 🔁 Cocok dikombinasikan dengan **Burp**, **ZAP**, atau **Nikto**

[![pytest](https://img.shields.io/badge/test-pytest-brightgreen?logo=python&logoColor=white)](https://docs.pytest.org/)
[![license](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-yellow?logo=python)]()
[![security](https://img.shields.io/badge/security-checked-success)]()

---

## 🧱 Rekomendasi Penggunaan

> ⚠️ **Gunakan hanya untuk aset yang Anda miliki atau memiliki izin eksplisit untuk diuji.**

- 🧪 Ideal untuk pembelajaran dan simulasi audit keamanan web
- 🛡️ Gunakan di lingkungan yang terkontrol (_lab / staging_)
- 🔧 Tambahkan logging, retry, dan konfigurasi lanjutan untuk produksi
- 🔍 Integrasikan dengan sistem keamanan Anda untuk _continuous monitoring_

---

## 📜 Lisensi

Lisensi: **MIT License**  
Developed with ❤️ by **Sardidev**

---

## 🌐 Quotes for Hackers

> “The quieter you become, the more you are able to hear — and the safer your system becomes.”

> "In the middle of every difficulty lies opportunity."

---

# Contributors

💡 Terima kasih kepada semua kontributor luar biasa yang telah membantu membangun, menguji, dan meningkatkan PySec Auditor.

<table align="center">
      <tr>
        <td align="center">
          <a href="https://github.com/otakukazzee">
            <img
              src="https://github.com/otakukazzee.png"
              width="80px;"
              style="border-radius: 50%; border: 2px solid #444"
            />
            <br />
            <sub><b>otakukazzee</b></sub>
          </a>
          <br />
          <sub>🚀 Project Lead • 💻 Maintainer • Developer • Penetration Tester</sub>
        </td>
        <td align="center">
          <a href="https://github.com/xnuvers007">
            <img
              src="https://github.com/xnuvers007.png"
              width="80px;"
              style="border-radius: 50%; border: 2px solid #444"
            />
            <br />
            <sub>
              <b>xnuvers007</b>
            </sub>
          </a>
          <br />
          <sub>🧠 Security Researcher • 🧩 Developer • 🔍 Penetration Tester</sub>
        </td>
      </tr>
</table>
