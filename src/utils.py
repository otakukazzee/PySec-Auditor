# utility helpers
from urllib.parse import urlparse
def normalize_url(u: str):
    if not u: return u
    u = u.strip()
    if not u.startswith('http://') and not u.startswith('https://'): u = 'http://' + u
    return u
def extract_hostname(url: str):
    try:
        p = urlparse(url if url else '')
        return p.hostname or url
    except Exception:
        return url
