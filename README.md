# PySec Auditor
## Modern & Professional Security Auditing Toolkit

PySec Auditor is a modular, multilingual, and automation‑ready security assessment toolkit designed for penetration testers, security engineers, red‑team members, and developers who need a clean, powerful, and extensible command‑line workflow.

### ✨ Key Features
- **Modular Architecture:** All features live inside `/src` for clean development and maintenance.
- **Modern CLI UX:** Built using `rich`, `pyfiglet`, and enhanced colorized outputs.
- **Automation Ready:** Supports API integrations, logging, reporting, and advanced analytics.
- **Multilingual Support:** English, Indonesian, Spanish, Arabic, and more via `language.py`.
- **HTML Reporting:** Clean, responsive, modern UI for exported audit reports.
- **Extensible:** Add new modules with minimal boilerplate using the built‑in module handler.

### 📁 Project Structure
```
PySec-Auditor/
│── run.py
│── src/
│   ├── scanner/
│   ├── utils/
│   ├── reports/
│   ├── language.py
│   └── ...
│── docs/
│── README.md
│── SETUP.md
│── PLAYBOOK.md
```

### 📘 Documentation
- **Setup Guide:** `SETUP.md`
- **Playbook / Workflow Guide:** `PLAYBOOK.md`
- **Developer Notes:** `/docs/`

---

## 🚀 Quick Start
```bash
python3 run.py --help
python3 run.py --scan target.com
python3 run.py --export report.html
```

## 🧩 Contributing
Contributions are welcome. Follow style guidelines and ensure code formatting using `black`.

## 📄 License
MIT License.
