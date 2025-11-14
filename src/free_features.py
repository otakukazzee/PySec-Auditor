from .requester import http_request
from .scanner import get_tls_info, check_exposure, fetch_sitemap, port_scan, check_exposure as exposure
from .utils import normalize_url, extract_hostname
def run_free_scan(url: str):
    url = normalize_url(url); host = extract_hostname(url)
    res = {'Target':url,'Scan_Type':'free','Timestamp':None,'Findings':{}}
    res['Timestamp'] = __import__('datetime').datetime.now().__str__()
    try: res['Findings']['tls'] = get_tls_info(host) if url.startswith('https://') else {}
    except Exception as e: res['Findings']['tls_error']=str(e)
    try: res['Findings']['sitemap'] = fetch_sitemap(url)
    except Exception as e: res['Findings']['sitemap_error']=str(e)
    try: res['Findings']['ports'] = port_scan(host)
    except Exception as e: res['Findings']['ports_error']=str(e)
    try: res['Findings']['exposure'] = exposure(url)
    except Exception as e: res['Findings']['exposure_error']=str(e)
    return res
