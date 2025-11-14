import time
from .firebase_manager import validate_key
from .premium_features import run_premium_scan
from .free_features import run_free_scan
from .reporter import generate_reports
def run_daemon(url, interval, key=None, output_prefix='continuous'):
    print(f"Starting continuous scans for {url} every {interval}s (CTRL+C to stop)")
    try:
        while True:
            ok=False
            if key: ok,_ = validate_key(key)
            if ok: res = run_premium_scan(url, output_prefix=output_prefix)
            else: res = run_free_scan(url)
            generate_reports(res, output_prefix=output_prefix)
            print('Scan complete; sleeping...'); time.sleep(interval)
    except KeyboardInterrupt:
        print('Stopped continuous scan by user')