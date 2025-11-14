import socket, ssl, re, requests
from urllib.parse import urljoin, urlparse
def get_tls_info(hostname, port=443, timeout=6):
    info = {'host': hostname, 'port': port}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                info['issuer']=dict(x[0] for x in cert.get('issuer', ()))
                info['subject']=dict(x[0] for x in cert.get('subject', ()))
                info['notBefore']=cert.get('notBefore'); info['notAfter']=cert.get('notAfter')
                info['san']=cert.get('subjectAltName', ())
    except Exception as e:
        info['error'] = str(e)
    return info
COMMON_PORTS = [21,22,23,25,53,80,110,143,443,445,3389,8080,8443]
def port_scan(host, ports=None, timeout=0.6):
    ports = ports or COMMON_PORTS; results={}
    for p in ports:
        s=socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(timeout)
        try: s.connect((host,p)); results[p]='open'; s.close()
        except Exception: results[p]='closed'
    return results
def fetch_sitemap(base_url, timeout=8):
    sitemap_url = urljoin(base_url, '/sitemap.xml')
    try:
        r = requests.get(sitemap_url, timeout=timeout)
        if r.status_code == 200: return {'url': sitemap_url, 'content': r.text}
    except Exception as e:
        return {'error': str(e)}
    return None
def check_exposure(url):
    host = urlparse(url).scheme + '://' + urlparse(url).hostname
    paths = ['/robots.txt','/.git/config','/.env','/backup.zip','/admin/']
    findings={}
    for p in paths:
        try:
            r = requests.get(host+p, timeout=6, allow_redirects=False)
            if r.status_code < 400: findings[p]={'status': r.status_code, 'len': len(r.content)}
        except Exception:
            pass
    return findings
