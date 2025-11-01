import socket, ssl
from concurrent.futures import ThreadPoolExecutor, as_completed

MAX_WORKERS = 50  # default max threads untuk network I/O

def get_ip_address(hostname: str) -> dict:
    try:
        ip = socket.gethostbyname(hostname)
        return {"hostname": hostname, "ip_address": ip, "status": "OK"}
    except socket.gaierror as e:
        return {"hostname": hostname, "error": f"DNS Lookup Failed: {e}"}

def get_dns_records(hostname: str) -> dict:
    try:
        import dns.resolver
    except Exception:
        return {"error": "dnspython not installed. pip install dnspython to enable DNS record lookup."}

    records = {}
    types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]
    resolver = dns.resolver.Resolver()
    
    def resolve_type(t):
        try:
            answers = resolver.resolve(hostname, t, lifetime=3)
            return t, [r.to_text() for r in answers]
        except Exception:
            return t, []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [executor.submit(resolve_type, t) for t in types]
        for f in as_completed(futures):
            t, res = f.result()
            records[t] = res

    return {"hostname": hostname, "records": records}

def reverse_dns(ip: str) -> dict:
    try:
        host, aliases, ips = socket.gethostbyaddr(ip)
        return {"ip": ip, "ptr": host, "aliases": aliases, "status": "OK"}
    except Exception as e:
        return {"ip": ip, "error": f"Reverse DNS failed: {e}"}

def whois_lookup(domain: str) -> dict:
    try:
        import whois
    except Exception:
        return {"error": "python-whois not installed. pip install python-whois to enable WHOIS lookups."}
    try:
        w = whois.whois(domain)
        return {
            "domain": domain,
            "domain_name": w.domain_name,
            "registrar": w.registrar,
            "whois_text_preview": (w.text[:200] + "...") if getattr(w, "text", None) else None
        }
    except Exception as e:
        return {"error": f"WHOIS lookup failed: {e}"}

def port_scan_parallel(host: str, ports=None, timeout=0.5, max_workers=MAX_WORKERS) -> dict:
    if ports is None:
        ports = [21,22,23,25,53,80,110,143,443,445,3306,3389,8080,8443]

    open_ports = []

    def scan_port(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((host, port)) == 0:
                    return port
        except:
            return None

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(scan_port, p) for p in ports]
        for f in as_completed(futures):
            result = f.result()
            if result:
                open_ports.append(result)

    return {"host": host, "open_ports": sorted(open_ports)}

def banner_grab_parallel(host: str, ports, timeout=2.0, max_workers=MAX_WORKERS) -> list:
    results = []

    def grab(port):
        try:
            with socket.socket() as s:
                s.settimeout(timeout)
                s.connect((host, port))
                try:
                    data = s.recv(2048)
                    banner = data.decode(errors='ignore').strip()
                except:
                    banner = ""
            return {"host": host, "port": port, "banner": banner}
        except Exception as e:
            return {"host": host, "port": port, "error": str(e)}

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(grab, p) for p in ports]
        for f in as_completed(futures):
            results.append(f.result())

    return results

def enumerate_subdomains_parallel(domain: str, wordlist_path: str, max_workers=MAX_WORKERS) -> dict:
    found = []
    candidates = []

    try:
        with open(wordlist_path, 'r', encoding='utf-8') as f:
            for line in f:
                label = line.strip()
                if label and not label.startswith('#'):
                    candidates.append(f"{label}.{domain}")
    except FileNotFoundError:
        return {"error": f"Wordlist not found: {wordlist_path}"}

    def resolve(subdomain):
        try:
            ip = socket.gethostbyname(subdomain)
            return {"subdomain": subdomain, "ip": ip}
        except:
            return None

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(resolve, c) for c in candidates]
        for f in as_completed(futures):
            res = f.result()
            if res:
                found.append(res)

    return {"domain": domain, "found": found}

def get_cert_sans(hostname: str) -> dict:
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                san = cert.get('subjectAltName', [])
                sans = [entry[1] for entry in san if entry and len(entry) >= 2]
                return {"hostname": hostname, "subjectAltName": sans}
    except Exception as e:
        return {"hostname": hostname, "error": f"Cert SAN extraction failed: {e}"}
