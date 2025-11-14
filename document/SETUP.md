# PySec Auditor — Setup Guide
A professional setup guide for installing, configuring, and running PySec Auditor.

---

# 🧰 1. Requirements
### System Requirements
- Python 3.9+
- Linux / Termux / Windows / macOS
- Internet connection (for API modules)

### Python Dependencies
- rich
- pyfiglet
- requests
- beautifulsoup4
- aiohttp
- colorama

Install with:
```bash
pip install -r requirements.txt
```

---

# ⚙️ 2. Installation
```bash
git clone https://github.com/your-repo/PySec-Auditor
cd PySec-Auditor
pip install -r requirements.txt
```

---

# ▶️ 3. Running the Application
Basic usage:
```bash
python3 run.py
```

Display help:
```bash
python3 run.py --help
```

Run scanner:
```bash
python3 run.py --scan target.com
```

---

# 🌐 4. Language Configuration
Modify `src/language.py` to customize:
- English (en)
- Indonesian (in)
- Spanish (es)
- Arabic (ar)
- And more…

Enable language:
```bash
python3 run.py --lang en
```

---

# 📄 5. HTML Report Setup
Reports are generated with:
- Responsive layout
- Modern design
- CSS‑based severity highlighting

Output example:
```bash
python3 run.py --export report.html
```

---

# 🧩 6. Developer Notes
To add a new module:
1. Create a folder under `src/yourmodule`.
2. Add a Python class with `run()` method.
3. Import it inside `run.py`.

---

# 🛠️ 7. Troubleshooting
| Issue | Fix |
|-------|------|
| Missing dependencies | Re‑run `pip install -r requirements.txt` |
| Termux permission error | Run `termux-setup-storage` |
| Encoding issues | Use UTF‑8 environment |

---

# ✔️ Installation Complete
You're ready to run PySec Auditor professionally!
