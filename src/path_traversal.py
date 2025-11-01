import urllib.parse
import requests

def check_path_traversal_query(url: str, initial_status: int, timeout: int=5) -> dict:
    results = {"status": "OK", "test_payload": None, "vulnerability": "NOT DETECTED", "details": []}
    parsed_url = urllib.parse.urlparse(url)
    query_params = urllib.parse.parse_qs(parsed_url.query)
    if not query_params:
        results["status"] = "SKIPPED: No query parameters to test."
        return results
    # payload = "../../../../../etc/passwd"
    default_payload = "../../../../../etc/passwd"
    payload = []
    try:
        with open(r'wordlist\path_traversal.txt', 'r', encoding='utf-8') as f:
            for line in f:
                path = line.strip()
                # if path and not path.startswith('#'):
                if path:
                    payload.append(path)
    except FileNotFoundError:
        print(f"[!] File wordlist {r'wordlist\path_traversal.txt'} tidak ditemukan.")
        payload = default_payload
    except Exception as e:
        print(f"[!] Terjadi kesalahan saat membaca file wordlist: {e}")
        payload = default_payload

    results["test_payload"] = payload
    vulnerable_params = []
    for param_name in query_params.keys():
        for p in payload:
            test_query = query_params.copy()
            test_query[param_name] = [p]
            new_query = urllib.parse.urlencode(test_query, doseq=True)
            test_url = parsed_url._replace(query=new_query).geturl()
            try:
                test_response = requests.get(test_url, timeout=timeout, verify=False, allow_redirects=False)
                if test_response.status_code == 200:
                    vulnerable_params.append(f"Parameter '{param_name}' changed status to 200 with payload '{p}'. Manual verification needed.")
                elif test_response.status_code != initial_status and test_response.status_code not in [404, 400, 403]:
                    vulnerable_params.append(f"Parameter '{param_name}' changed status to {test_response.status_code} with payload '{p}' (Original {initial_status}). Manual verification needed.")
            except requests.exceptions.RequestException:
                pass

    if vulnerable_params:
        results["vulnerability"] = "POTENTIAL VULNERABILITY"
        results["details"] = vulnerable_params
        results["status"] = "CRITICAL WARNING"
    return results
