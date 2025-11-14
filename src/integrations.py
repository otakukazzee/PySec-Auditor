"""
Integration wrappers for external tools (if available on PATH).
Wrappers only call the tools; they do not require them to be installed.
"""
import subprocess, shutil, os
from .utils import which

def run_subprocess(cmd, timeout=300):
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return proc.returncode, proc.stdout, proc.stderr
    except FileNotFoundError:
        return 127, "", f"Command not found: {cmd[0]}"
    except subprocess.TimeoutExpired as e:
        return 124, "", str(e)
    except Exception as e:
        return 1, "", str(e)

def nmap_scan(target, args=None, output_file=None):
    cmd = ["nmap"]
    if args:
        cmd += args.split()
    cmd += [target]
    if output_file:
        cmd += ["-oN", output_file]
    return run_subprocess(cmd)

def nikto_scan(url, output_file=None):
    cmd = ["nikto", "-h", url]
    if output_file:
        cmd += ["-o", output_file]
    return run_subprocess(cmd)

def nuclei_scan(target, template=None, output_file=None):
    cmd = ["nuclei", "-u", target]
    if template:
        cmd += ["-t", template]
    if output_file:
        cmd += ["-o", output_file]
    return run_subprocess(cmd)

def curl_request(url, params=None):
    cmd = ["curl", "-sS", "-L", url]
    if params:
        cmd += params.split()
    return run_subprocess(cmd)
