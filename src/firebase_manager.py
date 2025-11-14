# ==============================================================
# src/firebase_manager.py
# PySec-Auditor Firebase Manager v12.1 — Stable
# --------------------------------------------------------------
# Menangani semua operasi premium key:
#  - validate_key()
#  - add_key()
#  - list_keys()
#  - revoke_key()
#  - test_connection()
# --------------------------------------------------------------
# Menggunakan Firebase Realtime Database REST API.
# Membaca konfigurasi otomatis dari file .env
# ==============================================================

import os
import json
import datetime
import requests
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

console = Console()

# ==============================================================
# 🔧 Load environment
# ==============================================================
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass  # optional

FIREBASE_URL = os.getenv("FIREBASE_URL")
FIREBASE_KEY = os.getenv("FIREBASE_KEY")

# ==============================================================
# 🔗 Helper: Build URL
# ==============================================================
def _build_url(path: str) -> str:
    if not FIREBASE_URL:
        console.print(
            Panel.fit(
                Text(
                    "[bold red]❌ FIREBASE_URL tidak ditemukan![/bold red]\n\n"
                    "Tambahkan konfigurasi ke file .env seperti:\n"
                    "[green]FIREBASE_URL=https://your-project.firebaseio.com[/green]",
                    justify="center",
                ),
                title="[yellow]Firebase Config Error[/yellow]",
                border_style="red",
            )
        )
        raise RuntimeError("FIREBASE_URL not set")

    url = f"{FIREBASE_URL.rstrip('/')}/{path}.json"
    if FIREBASE_KEY:
        url += f"?auth={FIREBASE_KEY}"
    return url

# ==============================================================
# 🔍 Test Connection
# ==============================================================
def test_connection(timeout=6):
    try:
        url = _build_url("")
        r = requests.get(url, timeout=timeout)
        if r.status_code == 200:
            return True, "Connected to Firebase (HTTP 200)"
        return False, f"HTTP {r.status_code}: {r.text[:200]}"
    except Exception as e:
        return False, str(e)

# ==============================================================
# ✅ Validate Key
# ==============================================================
def validate_key(user_key: str):
    """
    Validasi key premium dari Firebase.
    Mengembalikan tuple (True, data_dict) jika valid,
    atau (False, reason) jika tidak valid.
    """
    try:
        url = _build_url(f"premium_keys/{user_key}")
        r = requests.get(url, timeout=10)

        if r.status_code != 200:
            return False, f"HTTP {r.status_code}: {r.text}"

        data = r.json()
        if not data:
            return False, "Key tidak ditemukan di database."

        if not data.get("is_active", True):
            return False, "Key tidak aktif (sudah dicabut)."

        plan = data.get("plan", "15day")
        created_at = data.get("created_at")

        if not created_at:
            data["remaining_days"] = "unknown"
            return True, data

        # Hitung sisa hari
        try:
            created = datetime.datetime.fromisoformat(created_at.replace("Z", ""))
        except Exception:
            data["remaining_days"] = "unknown"
            return True, data

        now = datetime.datetime.utcnow()
        if plan == "unlimited":
            remaining = float("inf")
        else:
            duration = 15 if plan == "15day" else 30
            remaining = duration - (now - created).days

        if remaining <= 0 and plan != "unlimited":
            revoke_key(user_key)
            return False, "Key sudah kedaluwarsa."

        data["remaining_days"] = "∞" if plan == "unlimited" else int(remaining)
        return True, data

    except Exception as e:
        return False, str(e)

# ==============================================================
# 🟢 Add Key
# ==============================================================
def add_key(user_key: str, plan="15day"):
    """
    Tambahkan / perbarui key di Firebase.
    """
    try:
        url = _build_url(f"premium_keys/{user_key}")
        payload = {
            "plan": plan,
            "created_at": datetime.datetime.utcnow().isoformat() + "Z",
            "is_active": True,
        }

        r = requests.put(url, json=payload, timeout=10)
        if r.status_code in (200, 201):
            console.print(
                Panel.fit(
                    f"[bold green]✅ Key berhasil ditambahkan:[/bold green] [white]{user_key}[/white]\nPlan: [cyan]{plan}[/cyan]",
                    title="[green]Firebase Update[/green]",
                )
            )
            return True, r.text
        else:
            return False, f"HTTP {r.status_code}: {r.text}"

    except Exception as e:
        return False, str(e)

# ==============================================================
# 🟠 List Keys
# ==============================================================
def list_keys(limit=100):
    try:
        url = _build_url("premium_keys")
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            data = r.json() or {}
            console.print(
                Panel.fit(
                    f"[bold cyan]📋 Ditemukan {len(data)} key di Firebase[/bold cyan]",
                    title="[cyan]Firebase Keys[/cyan]",
                )
            )
            for key, val in list(data.items())[:limit]:
                console.print(
                    f"[bold]{key}[/bold] → Plan: [green]{val.get('plan')}[/green], "
                    f"Active: {'✅' if val.get('is_active', True) else '❌'}, "
                    f"Created: [yellow]{val.get('created_at')}[/yellow]"
                )
            return True, data
        else:
            return False, f"HTTP {r.status_code}: {r.text}"
    except Exception as e:
        return False, str(e)

# ==============================================================
# 🔴 Revoke Key
# ==============================================================
def revoke_key(key: str):
    """
    Nonaktifkan key (is_active=False)
    """
    try:
        url = _build_url(f"premium_keys/{key}")
        payload = {"is_active": False}
        r = requests.patch(url, json=payload, timeout=10)
        if r.status_code in (200, 204):
            console.print(
                Panel.fit(
                    f"[red]Key {key} berhasil dinonaktifkan.[/red]",
                    title="[yellow]Key Revoked[/yellow]",
                )
            )
            return True, r.text
        else:
            return False, f"HTTP {r.status_code}: {r.text}"
    except Exception as e:
        return False, str(e)

# ==============================================================
# 🚀 Test Mode
# ==============================================================
if __name__ == "__main__":
    console.print("[bold cyan]Firebase Manager v12.1 Self-Test[/bold cyan]")
    ok, msg = test_connection()
    console.print(f"Connection test: {ok} - {msg}")
