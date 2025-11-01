import os
import sys
import subprocess
from sys import platform
from pathlib import Path

def run_command(command, cwd=None):
    try:
        subprocess.check_call(command, shell=(platform == "win32"), cwd=cwd)
    except subprocess.CalledProcessError as e:
        print(f"❌ Terjadi kesalahan saat menjalankan: {command}\n{e}")
        sys.exit(1)

def create_venv(venv_path):
    print("🧱 Membuat virtual environment...")
    run_command([sys.executable, "-m", "venv", venv_path])
    print("✅ Virtual environment berhasil dibuat.")

def install_requirements(python_exec):
    print("📦 Menginstal dependensi dari requirements.txt ...")
    run_command([python_exec, "-m", "pip", "install", "-r", "requirements.txt"])
    print("✅ Semua dependensi berhasil diinstal.\n")

def main():
    print("=" * 60)
    print("⚡ PySec Auditor — Environment Setup 🔐")
    print("=" * 60)

    choice = input("\nApakah Anda ingin menggunakan virtual environment? (y/n): ").strip().lower()

    python_exec = sys.executable  # default: global Python

    if choice == "y":
        venv_dir = Path("venv")
        python_exec = venv_dir / "Scripts" / "python.exe" if platform == "win32" else venv_dir / "bin" / "python"

        if not venv_dir.exists():
            create_venv(venv_dir)
        else:
            print("⚙️ Virtual environment sudah ada, menggunakan yang lama.")

        # Pastikan pip up-to-date
        run_command([str(python_exec), "-m", "pip", "install", "--upgrade", "pip"])
        install_requirements(str(python_exec))
    else:
        print("⚙️ Menggunakan environment global.")
        install_requirements(python_exec)

    # Jalankan program utama
    print("🚀 Menjalankan PySec Auditor...\n\n")
    run_command([str(python_exec), "run.py", "--help"])

    print("\n✅ Setup selesai. Anda siap menggunakan PySec Auditor!")

if __name__ == "__main__":
    main()
    if platform == "win32":
        activate_path = os.path.join("venv", "Scripts", "activate.bat")
        print(f"\n💡 Untuk masuk ke environment, jalankan:")
        print(f"   {activate_path}\n")
        
        choice = input("Ingin langsung masuk ke virtual environment sekarang? (y/n): ").strip().lower()
        if choice == "y":
            subprocess.call(["cmd.exe", "/k", activate_path])
    else:
        activate_path = os.path.join("venv", "bin", "activate")
        print(f"\n💡 Untuk masuk ke environment, jalankan di terminal:")
        print(f"   source {activate_path}\n")
