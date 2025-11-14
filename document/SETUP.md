# ⚙️ **PYSEC Auditor – Setup, Installation & Configuration Guide**

Panduan lengkap instalasi dan konfigurasi PYSEC Auditor untuk memastikan performa optimal dan keamanan maksimal.

---

# 🧰 **1. System Requirements**

### 📌 Software:
- Python 3.9 atau lebih tinggi
- pip / venv
- Internet (untuk OSINT API)

### 📌 Python Dependencies:
```
pip install -r requirements.txt
```

---

# 📦 **2. Installation**

```bash
git clone https://github.com/yourrepo/PySec-Auditor
cd PySec-Auditor
pip install -r requirements.txt
```

---

# 🔑 **3. API Key Configuration**

API key diperlukan untuk modul OSINT.  
Tersimpan dalam:

```
config/keys.json
```

### Contoh:
```json
{
  "shodan": "YOUR_SHODAN_KEY",
  "virustotal": "YOUR_VIRUSTOTAL_KEY",
  "hunter": "YOUR_HUNTER_KEY"
}
```

Jika tidak diisi → modul OSINT akan dinonaktifkan otomatis.

---

# 🔐 **4. Admin Mode Setup**

Admin key digunakan untuk fitur premium dan analisis lanjutan.

Lokasi:
```
config/admin.json
```

### Contoh:
```json
{
  "admin_key": "ADMIN12345"
}
```

### Cara memakai:
```bash
python3 run.py --admin --key ADMIN12345
```

---

# ▶️ **5. Basic Usage**

### Help menu:
```bash
python3 run.py --help
```

### OSINT:
```bash
python3 run.py --osint domain.com
```

### Vulnerability scan:
```bash
python3 run.py --scan target.com
```

### Full analysis:
```bash
python3 run.py --fullscan target.com
```

---

# 🌍 **6. Language Configuration**

Ubah bahasa:
```bash
python3 run.py --lang en
```

File bahasa:
```
src/language.py
```

---

# 📊 **7. HTML Report Generator**

### Generate laporan:
```bash
python3 run.py --export report.html
```

Fitur:
- Responsive
- Estetika modern
- Severity coloring
- Siap diprint ke PDF

---

# 🛠️ **8. Troubleshooting**

| Masalah | Penyebab | Solusi |
|--------|----------|--------|
| API tidak berfungsi | Key kosong / invalid | Cek `keys.json` |
| Admin gagal | Key salah | Cek `admin.json` |
| Module error | Dependency kurang | Jalankan reinstall |
| Permission Termux | storage belum diizinkan | `termux-setup-storage` |

---

# 🎉 **Setup Complete**
PYSEC siap digunakan untuk kebutuhan analisis keamanan profesional Anda.
