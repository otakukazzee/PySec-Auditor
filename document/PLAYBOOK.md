# 📘 **PYSEC Auditor – Enterprise Playbook**
### Panduan Operasional Profesional untuk Keamanan Perusahaan

Playbook ini dibuat untuk memberikan alur kerja operasional yang standar, konsisten, dan optimal saat menggunakan PYSEC Auditor dalam lingkungan produksi atau enterprise.

---

# 🧩 **1. Preparation & Environment Setup**

## ✔ Checklist Awal:
- `config/keys.json` sudah terisi API key valid.
- `config/admin.json` berisi admin key untuk fitur premium.
- Install Python dependencies.
- Akses jaringan stabil untuk OSINT.

### Contoh `keys.json`
```json
{
  "shodan": "YOUR_SHODAN_KEY",
  "virustotal": "YOUR_VT_KEY",
  "hunter": "YOUR_HUNTER_KEY"
}
```

### Contoh `admin.json`
```json
{
  "admin_key": "ADMIN12345"
}
```

---

# 🔍 **2. Reconnaissance / OSINT Phase**

## 🎯 Tujuan:
- Mengumpulkan informasi tanpa interaksi agresif.
- Identifikasi permukaan serangan awal.

### Perintah:
```bash
python3 run.py --osint example.com
python3 run.py --subscan example.com
python3 run.py --dnsmap example.com
```

### Output:
- Subdomain list
- DNS mapping
- Metadata exposures
- Potensi risiko awal

---

# 🛡️ **3. Vulnerability Analysis Phase**

### 🔧 Modul yang Digunakan:
- Port scanner
- Service enumeration
- Banner grabber
- CVE correlation engine

### Perintah:
```bash
python3 run.py --scan example.com
python3 run.py --fullscan example.com
```

### Output:
- Risk scoring
- Severity mapping
- CVE listing + rekomendasi
- Threat exposure summary

---

# 🧪 **4. Validation Phase (Admin Mode)**

### Penting:
Hanya user dengan admin key dapat mengakses fase ini.

### Perintah:
```bash
python3 run.py --admin --key ADMIN12345 --verify example.com
```

Fitur admin:
- Detailed exploit verification (non-destructive)
- Deep packet-based analysis
- Extended CVE justification
- Internal analyzer logging

---

# 🧾 **5. Reporting Phase**

### Generate laporan:
```bash
python3 run.py --export report.html
```

Report mencakup:
- Executive summary
- Risk heatmap
- Detailed technical notes
- Severity highlights
- Timeline aktivitas scanning

---

# 🤖 **6. CI/CD Automation**

Cocok untuk:
- GitHub Actions
- GitLab CI
- Jenkins
- Cron-based monitoring

### Contoh automation:
```bash
python3 run.py --scan target.com --export logs/report_$(date +%F).html
```

---

# 📌 **Best Practices**
- Lakukan OSINT sebelum active scanning.
- Simpan API key di environment variable bila mungkin.
- Gunakan admin mode hanya untuk analisis lanjutan.
- Simpan hasil scan terarsip dengan aman.
