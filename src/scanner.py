import ssl, socket, urllib.parse, re, requests
from datetime import datetime
from bs4 import BeautifulSoup

WEAK_CIPHERS = [
    'RC4', 'DES', '3DES', 'MD5', 'NULL', 'EXPORT', 'ADH',
    'AECDH', 'DHE_DSS', 'IDEA', 'SEED', 'CAMELLIA', 'ECDHE_RSA_WITH_AES_128_CBC_SHA'
]

def get_tls_info(hostname: str) -> dict:
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                subject_list = cert.get('subject', [])
                subject = dict(x[0] for x in subject_list).get('commonName', 'N/A')
                issuer_list = cert.get('issuer', [])
                issuer = dict(x[0] for x in issuer_list).get('organizationName', 'N/A')
                valid_until = cert.get('notAfter')
                try:
                    valid_dt = datetime.strptime(valid_until, r'%b %d %H:%M:%S %Y %Z')
                    valid_str = valid_dt.strftime("%Y-%m-%d")
                    days_remaining = (valid_dt - datetime.now()).days
                except Exception:
                    valid_str = valid_until
                    days_remaining = "N/A"
                return {"subject": subject, "issuer": issuer, "valid_until": valid_str, "days_remaining": days_remaining}
    except Exception as e:
        return {"error": f"TLS Error: {e}"}

def check_tls_ciphers(hostname: str) -> dict:
    results = {"weak_ciphers_found": [], "supported_ciphers_count": 0, "status": "N/A"}
    if not hostname: return {"status": "Hostname invalid."}
    try:
        context = ssl.create_default_context()
        context.set_ciphers('ALL:@SECLEVEL=0')
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                results['cipher_negotiated'] = ssock.cipher()
                results['status'] = "Koneksi TLS berhasil."
            supported_ciphers = []
            for weak_cipher in WEAK_CIPHERS:
                try:
                    test_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    test_context.set_ciphers(weak_cipher)
                    with socket.create_connection((hostname, 443), timeout=2) as sock:
                        with test_context.wrap_socket(sock, server_hostname=hostname) as ssock:
                            supported_ciphers.append(ssock.cipher()[0])
                except Exception:
                    pass
            results["weak_ciphers_found"] = sorted(list(set(supported_ciphers)))
            results["supported_ciphers_count"] = len(results["weak_ciphers_found"])
            if results["supported_ciphers_count"] > 0:
                results["assessment"] = "CRITICAL INSECURE: Server supports weak Cipher Suites."
            else:
                results["assessment"] = "OK: Server does not support known weak Cipher Suites."
    except Exception as e:
        results["status"] = f"TLS Error during cipher audit: {e}"
        results["assessment"] = "Failed to test Cipher Suites."
    return results

def analyze_cookies(response) -> dict:
    try:
        cookies_raw = response.raw.headers.getlist('Set-Cookie')
    except Exception:
        single_cookie_str = response.headers.get('Set-Cookie')
        cookies_raw = [single_cookie_str] if single_cookie_str else []
    if not any(cookies_raw): return {"status": "No Set-Cookie header found."}
    cookie_results = {}
    import re
    for cookie_str in cookies_raw:
        if not cookie_str: continue
        parts = cookie_str.split(';', 1)
        cookie_name = parts[0].split('=', 1)[0].strip()
        attributes_part = parts[1].strip() if len(parts) > 1 else ""
        attributes_part_lower = attributes_part.lower()
        cookie_detail = {"is_secure": True, "attributes": {}}
        cookie_detail['attributes']['HttpOnly'] = 'httponly' in attributes_part_lower
        cookie_detail['attributes']['Secure'] = 'secure' in attributes_part_lower
        if not cookie_detail['attributes']['HttpOnly'] or not cookie_detail['attributes']['Secure']:
            cookie_detail['is_secure'] = False
        samesite_match = re.search(r'SameSite=([A-Za-z]+)', attributes_part, re.IGNORECASE)
        if samesite_match:
            samesite_value = samesite_match.group(1).upper()
            cookie_detail['attributes']['SameSite'] = samesite_value
            if samesite_value == 'NONE' and not cookie_detail['attributes']['Secure']:
                 cookie_detail['is_secure'] = False
        else:
            cookie_detail['attributes']['SameSite'] = "MISSING"
            cookie_detail['is_secure'] = False
        cookie_results[cookie_name] = cookie_detail
    return cookie_results

def check_allowed_methods(url: str) -> dict:
    results = {"allowed_methods": [], "dangerous_methods": []}
    try:
        response = requests.options(url, timeout=5)
        results["status_code"] = response.status_code
        allowed_methods = [m for m in response.headers.get('Allow', '').upper().replace(' ', '').split(',') if m]
        results["allowed_methods"] = sorted(list(set(allowed_methods)))
        for method in ['PUT', 'DELETE', 'TRACE', 'CONNECT']:
            if method in results["allowed_methods"]:
                results["dangerous_methods"].append(method)
    except requests.exceptions.RequestException:
        results["error"] = "OPTIONS request failed."
    return results

def check_exposure(base_url: str) -> dict:
    results = {"exposed_paths": [], "protected_paths": [], "not_found": []}
    # sensitive_paths = [".git/config", ".env", "robots.txt", "sitemap.xml", "admin/", "README.md"]
    default_paths = [".git/config", ".env", "robots.txt", "sitemap.xml", "admin/", "README.md"]
    sensitive_paths = []
    try:
        with open(r'wordlist\file_exposure.txt', 'r', encoding='utf-8') as f:
            for line in f:
                path = line.strip()
                if path and not path.startswith('#'):
                    sensitive_paths.append(path)
    except FileNotFoundError:
        print(f"[!] File wordlist {r'wordlist\file_exposure.txt'} tidak ditemukan.")
        sensitive_paths = default_paths

    for path in sensitive_paths:
        target_url = urllib.parse.urljoin(base_url, path)
        try:
            method_func = requests.get if path.endswith('/') else requests.head
            method_name = method_func.__name__.upper()
            response = method_func(target_url, allow_redirects=False, timeout=5)
            if 200 <= response.status_code < 300:
                results["exposed_paths"].append({"path": path, "status": response.status_code, "method": method_name})
            elif response.status_code in [401, 403]:
                results["protected_paths"].append({"path": path, "status": response.status_code, "method": method_name})
            else:
                results["not_found"].append({"path": path, "status": response.status_code, "method": method_name})
        except requests.exceptions.RequestException:
            pass
    return results

def check_cors_insecurity(url: str, response_headers: dict) -> dict:
    cors_audit = {"status": "Not Tested (GET Request)", "result": "OK"}
    aca_origin = response_headers.get('Access-Control-Allow-Origin')
    aca_credentials = response_headers.get('Access-Control-Allow-Credentials')
    cors_audit['aca_origin'] = aca_origin if aca_origin else 'MISSING'
    cors_audit['aca_credentials'] = aca_credentials if aca_credentials else 'MISSING'
    cors_audit['status'] = "Tested (GET Request)"
    if not aca_origin:
        cors_audit['result'] = "Access-Control-Allow-Origin MISSING (Default OK)"
        return cors_audit
    if aca_origin == '*':
        cors_audit['result'] = "[INSECURE] Wildcard (*) allowed. This is a SERIOUS CORS misconfiguration."
        return cors_audit
    test_origin = "http://evil.com"
    try:
        test_response = requests.get(url, headers={'Origin': test_origin}, timeout=5, verify=False)
        test_aca_origin = test_response.headers.get('Access-Control-Allow-Origin')
        if test_aca_origin == test_origin:
             cors_audit['result'] = "[CRITICAL INSECURE] Malicious origin reflected. VERY HIGH CORS risk."
             return cors_audit
    except requests.exceptions.RequestException:
        pass
    cors_audit['result'] = "Access-Control-Allow-Origin found, but no clear wildcard or reflection risk."
    return cors_audit

def check_information_leakage(response_headers: dict) -> dict:
    leakage_headers = ["X-Powered-By", "Via", "X-AspNet-Version", "X-Generator", "P3P"]
    results = {"leaked_headers": {}, "status": "OK"}
    for header in leakage_headers:
        value = response_headers.get(header)
        if value:
            results["leaked_headers"][header] = {"value": value, "warning": f"Header {header} exposes technology or vendor details."}
            results["status"] = "WARNING: Information leakage header found."
    server_value = response_headers.get('Server', 'MISSING')
    if server_value != 'MISSING' and len(server_value) > 0:
        results["leaked_headers"]["Server"] = {"value": server_value, "warning": "Server header exposes server/proxy details."}
        if results["status"] == "OK": results["status"] = "WARNING: Information leakage header found."
    if not results["leaked_headers"]:
        results["status"] = "OK: No obvious information leakage headers found."
    return results

def check_specific_security_headers(response_headers: dict) -> dict:
    results = {}
    security_headers = {
        "X-XSS-Protection": "1; mode=block",
        "X-Content-Type-Options": "nosniff",
        "Strict-Transport-Security": "max-age",
        "Content-Security-Policy": "script-src",
        "X-Frame-Options": "DENY",
    }
    for header, expected_part in security_headers.items():
        value = response_headers.get(header)
        if header in ["X-XSS-Protection", "X-Content-Type-Options"]:
            if value:
                is_valid = value.lower() == expected_part.lower()
                results[header] = {"value": value, "status": "OK" if is_valid else "INSECURE"}
            else:
                results[header] = {"value": "MISSING", "status": "CRITICAL MISSING"}
        elif header == "Strict-Transport-Security":
            if value and expected_part in value.lower():
                results[header] = {"value": value, "status": "OK"}
            else:
                results[header] = {"value": "MISSING/INSECURE", "status": "CRITICAL MISSING (HSTS)"}
        elif header == "Content-Security-Policy":
            if value and expected_part in value.lower():
                results[header] = {"value": value, "status": "OK (Found)"}
            else:
                results[header] = {"value": "MISSING", "status": "CRITICAL MISSING (CSP)"}
        elif header == "X-Frame-Options":
            if value and (value.upper() == 'DENY' or 'SAMEORIGIN' in value.upper()):
                results[header] = {"value": value, "status": "OK"}
            else:
                results[header] = {"value": "MISSING/INSECURE", "status": "CRITICAL MISSING (XFO)"}
    results["Content-Type"] = {"value": response_headers.get('Content-Type', 'MISSING'), "status": "OK" if response_headers.get('Content-Type') else "MISSING"}
    return results


def check_http_version(url: str, timeout: int = 5) -> dict:
    """
    Check the HTTP protocol version used by the target server.
    Returns HTTP/1.0, 1.1, 2 or 3 if available.
    """
    import requests
    try:
        with requests.Session() as s:
            r = s.get(url, timeout=timeout, stream=True)
            version_map = {
                10: "HTTP/1.0",
                11: "HTTP/1.1",
                20: "HTTP/2",
                30: "HTTP/3"
            }
            ver = version_map.get(getattr(r.raw, "version", None), "UNKNOWN")
            return {
                "status": "OK",
                "http_version": ver,
                "url": url
            }
    except Exception as e:
        return {
            "status": f"ERROR: {str(e)}",
            "http_version": "UNKNOWN",
            "url": url
        }


def check_http_version(url: str, timeout: int = 5) -> dict:
    """
    Check the HTTP protocol version used by the target server.
    Returns HTTP/1.0, 1.1, 2 or 3 if available.
    """
    import requests
    try:
        with requests.Session() as s:
            r = s.get(url, timeout=timeout, stream=True)
            version_map = {
                10: "HTTP/1.0",
                11: "HTTP/1.1",
                20: "HTTP/2",
                30: "HTTP/3"
            }
            ver = version_map.get(getattr(r.raw, "version", None), "UNKNOWN")
            return {
                "status": "OK",
                "http_version": ver,
                "url": url
            }
    except Exception as e:
        return {
            "status": f"ERROR: {str(e)}",
            "http_version": "UNKNOWN",
            "url": url
        }