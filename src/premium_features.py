from .free_features import run_free_scan
from .scanner import check_exposure, check_exposure as probe
from .requester import http_request
from .cve_manager import match_cves_by_keyword
from .ai_audit_assistant import suggest_fixes
from .utils import normalize_url, extract_hostname
def run_premium_scan(url: str, output_prefix='report'):
    url = normalize_url(url); res = run_free_scan(url); res['Scan_Type']='premium'; res['Premium']=True
    try: res['Findings']['cors'] = __import__('src.scanner', fromlist=['']).check_exposure(url)
    except Exception as e: res['Findings']['cors_error']=str(e)
    try:
        host = extract_hostname(url)
        res['Findings']['deep_ports'] = __import__('src.scanner', fromlist=['']).port_scan(host, timeout=0.4)
    except Exception as e: res['Findings']['deep_ports_error']=str(e)
    try:
        ai = suggest_fixes(res); res['AI_Summary']=ai
    except Exception:
        pass
    try:
        cves = match_cves_by_keyword(extract_hostname(url) or ''); 
        if cves: res['CVE_Matches']=cves
    except Exception:
        pass
    return res
