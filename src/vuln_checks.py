from typing import Dict,Any,Optional
def xss_check(target: str, requester: Optional[object]=None, param: str='q', progress_callback: Optional[callable]=None) -> Dict[str,Any]:
    payloads = ['<script>alert(1)</script>','" onmouseover="alert(1)"']
    findings=[]; tested=[]
    try:
        from .requester import Requester
        if requester is None:
            requester = Requester()
        for p in payloads:
            tested.append(p)
            r = requester.get(target, params={param:p})
            if p in (r.text or ''):
                findings.append({'payload':p,'url':getattr(r,'url',target),'status':r.status_code})
            if progress_callback:
                try:
                    progress_callback(1)
                except Exception:
                    pass
    except Exception:
        pass
    return {'tested':tested,'findings':findings}

def csp_check(headers: dict) -> Dict[str,Any]:
    csp = headers.get('Content-Security-Policy') or headers.get('content-security-policy') or ''
    issues=[]
    if not csp:
        issues.append('CSP missing')
    else:
        if 'unsafe-inline' in csp:
            issues.append('CSP allows unsafe-inline')
    return {'csp':csp,'issues':issues}

def clickjacking_check(headers: dict) -> Dict[str,Any]:
    xfo = headers.get('X-Frame-Options') or headers.get('x-frame-options') or ''
    issues=[]
    if not xfo:
        issues.append('X-Frame-Options missing')
    return {'x-frame-options':xfo,'issues':issues}

def rate_limit_check(headers: dict) -> Dict[str,Any]:
    keys=['X-RateLimit-Limit','X-RateLimit-Remaining','Retry-After']
    found={}
    for k in keys:
        v = headers.get(k) or headers.get(k.lower())
        if v:
            found[k]=v
    issues=[]
    if not found:
        issues.append('No rate-limit headers detected')
    return {'headers_found':found,'issues':issues}

def sitemap_check(base_url: str) -> Dict[str,Any]:
    from urllib.parse import urlparse, urljoin
    findings=[]
    parsed = urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    for c in ['/sitemap.xml','/robots.txt','/sitemap_index.xml']:
        try:
            from .requester import Requester
            r = Requester().get(urljoin(base,c))
            if r and r.status_code==200:
                findings.append({'path':c,'status':r.status_code,'size':len(r.text or '')})
        except Exception:
            continue
    return {'checked':['/sitemap.xml','/robots.txt'],'findings':findings}
