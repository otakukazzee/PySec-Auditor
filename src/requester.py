import requests
DEFAULT_HEADERS = {'User-Agent': 'PySec-Auditor/11.0'}
def http_request(method, url, timeout=15, allow_redirects=True, headers=None):
    res = {'ok': False, 'status': None, 'headers': None, 'body': None, 'text': None, 'error': None}
    try:
        hdrs = DEFAULT_HEADERS.copy(); 
        if headers: hdrs.update(headers)
        r = requests.request(method, url, timeout=timeout, allow_redirects=allow_redirects, headers=hdrs)
        res.update({'ok': True, 'status': r.status_code, 'headers': dict(r.headers), 'body': r.content, 'text': r.text})
    except Exception as e:
        res['error'] = str(e)
    return res
def head_request(url, timeout=8):
    try:
        r = requests.head(url, timeout=timeout, allow_redirects=True, headers=DEFAULT_HEADERS)
        return {'status': r.status_code, 'headers': dict(r.headers)}
    except Exception as e:
        return {'error': str(e)}
def download_file(url, dest_path, timeout=30):
    try:
        r = requests.get(url, timeout=timeout, stream=True)
        if r.status_code == 200:
            with open(dest_path, 'wb') as fh:
                for chunk in r.iter_content(8192): fh.write(chunk)
            return {'ok': True, 'path': dest_path}
        return {'ok': False, 'status': r.status_code}
    except Exception as e:
        return {'error': str(e)}
