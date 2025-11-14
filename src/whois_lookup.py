
# src/whois_lookup.py - whois helper
import subprocess, shutil, socket, re
def whois_lookup(domain, timeout=10):
    result = {'raw': None, 'parsed': {}}
    whois_cmd = shutil.which("whois")
    if whois_cmd:
        try:
            p = subprocess.run([whois_cmd, domain], capture_output=True, text=True, timeout=timeout)
            result['raw'] = p.stdout
        except Exception as e:
            result['raw'] = str(e)
    else:
        try:
            s = socket.create_connection(("whois.iana.org", 43), timeout=timeout)
            s.sendall((domain + "\r\n").encode())
            data = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
            result['raw'] = data.decode(errors='ignore')
        except Exception as e:
            result['raw'] = str(e)
    return result
