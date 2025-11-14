import json, requests
def match_cves_by_keyword(keyword, max_results=50):
    try:
        data = json.load(open('cves.json','r',encoding='utf-8'))
    except Exception:
        return []
    if not keyword: return []
    kw = keyword.lower(); matches=[]
    for e in data:
        if kw in json.dumps(e).lower():
            matches.append(e)
            if len(matches)>=max_results: break
    return matches
def update_from_nvd(save_path='nvd_recent.json'):
    url = 'https://services.nvd.nist.gov/rest/json/cves/1.0'
    try:
        r = requests.get(url, timeout=30)
        if r.status_code==200:
            with open(save_path,'w',encoding='utf-8') as f: f.write(r.text)
            return {'ok':True,'path':save_path}
        return {'ok':False,'status':r.status_code}
    except Exception as e:
        return {'error':str(e)}
