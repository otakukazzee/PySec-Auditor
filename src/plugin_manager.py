
# src/plugin_manager.py - optional integration with external scanners (nuclei, nikto).
import shutil, subprocess, os
def run_nikto_from_env(target_url):
    nikto_bin = shutil.which("nikto") or os.environ.get("PYSEC_NIKTO_BIN")
    out = {}
    if not nikto_bin:
        out['nikto'] = "not_installed"
        return out
    try:
        p = subprocess.run([nikto_bin, "-host", target_url.replace("https://","").replace("http://","")], capture_output=True, text=True, timeout=300)
        out['nikto'] = p.stdout[:2000]
    except Exception as e:
        out['nikto_error'] = str(e)
    return out

def run_nuclei_from_env(target_url):
    nuclei_bin = shutil.which("nuclei") or os.environ.get("PYSEC_NUCLEI_BIN")
    templates = os.environ.get("PYSEC_NUCLEI_TEMPLATES")
    out = {}
    if not nuclei_bin:
        out['nuclei'] = "not_installed"
        return out
    try:
        cmd = [nuclei_bin, "-u", target_url]
        if templates:
            cmd += ["-t", templates]
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        out['nuclei'] = p.stdout[:2000]
    except Exception as e:
        out['nuclei_error'] = str(e)
    return out
