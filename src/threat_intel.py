import socket, requests
def lookup_domain(domain):
    info={'domain':domain}
    try:
        ip=socket.gethostbyname(domain); info['resolved_ip']=ip
    except Exception as e:
        info['resolved_error']=str(e)
    return info
def check_abuseipdb(ip, api_key=None):
    out={'ip':ip}
    if api_key:
        try:
            headers={'Key':api_key,'Accept':'application/json'}
            r = requests.get(f'https://api.abuseipdb.com/api/v2/check?ipAddress={ip}', headers=headers, timeout=12)
            if r.status_code==200: out['abuseipdb']=r.json()
        except Exception as e:
            out['abuseipdb_error']=str(e)
    return out
