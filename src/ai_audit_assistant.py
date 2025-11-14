def suggest_fixes(scan_result: dict):
    recs=[]; score=0
    finds = scan_result.get('Findings',{})
    tls = finds.get('tls') or {}
    if tls.get('notAfter'): score+=5
    sh = finds.get('security_headers') or {}
    if sh.get('missing'): recs.append('Add missing security headers: '+', '.join(sh.get('missing'))); score+=20
    cors = finds.get('cors') or {}
    if cors.get('insecure_wildcard'): recs.append('Restrict CORS origins and disable credentials with wildcard'); score+=20
    if score>=60: severity='high'
    elif score>=25: severity='medium'
    else: severity='low'
    return {'risk_score': score, 'severity': severity, 'recommendations': recs}
