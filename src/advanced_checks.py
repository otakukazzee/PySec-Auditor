from typing import Dict, Any, List, Optional, Callable
import concurrent.futures, os
from .requester import Requester
SQLI_PAYLOADS = [
    "' OR '1'='1",
    '" OR "1"="1"',
    "' OR 1=1--",
    "' OR sleep(5)--",
]
OPEN_REDIRECT_PAYLOADS = ['http://example.com','//example.com','https://example.com/%2f%2e%2e']
COMMON_DIRS = ['admin','login','uploads','images','css','js','backup','old','test','dev','api','config']

def sqli_check(target: str, requester: Optional[Requester]=None, param: str='q', timeout: int=10, progress_callback: Optional[Callable[[int], None]]=None) -> Dict[str,Any]:
    if requester is None:
        requester = Requester(timeout=timeout)
    findings=[]; tested=[]
    for p in SQLI_PAYLOADS:
        tested.append(p)
        try:
            r = requester.get(target, params={param:p})
            body = r.text or ''
            errors = ['sql syntax','mysql','syntax error','unknown column','sqlstate','pdoexception']
            if any(e in body.lower() for e in errors):
                findings.append({'payload':p,'url':getattr(r,'url',target),'status':r.status_code,'evidence':'sql error in response'})
        except Exception:
            continue
        if progress_callback:
            try:
                progress_callback(1)
            except Exception:
                pass
    return {'tested':tested,'findings':findings}

def sqli_timing_check(target: str, requester: Optional[Requester]=None, param: str='q', sleep_payload: str="' OR sleep(5)--", timeout: int=15, progress_callback: Optional[Callable[[int], None]]=None) -> Dict[str,Any]:
    if requester is None:
        requester = Requester(timeout=timeout)
    baseline=None
    try:
        r = requester.get(target, params={param:'test'})
        baseline = getattr(r,'elapsed',None).total_seconds() if getattr(r,'elapsed',None) else None
    except Exception:
        baseline=None
    findings=[]
    try:
        import time as _time
        start=_time.time()
        r2 = requester.get(target, params={param:sleep_payload}, timeout=timeout)
        elapsed = getattr(r2,'elapsed',None).total_seconds() if getattr(r2,'elapsed',None) else (_time.time()-start)
        if baseline is not None and elapsed - baseline > 3.0:
            findings.append({'payload':sleep_payload,'url':getattr(r2,'url',target),'status':r2.status_code,'evidence':f'timing delta {elapsed-baseline:.2f}s'})
    except Exception:
        pass
    if progress_callback:
        try:
            progress_callback(2)
        except Exception:
            pass
    return {'tested':[sleep_payload],'findings':findings,'baseline':baseline}

def open_redirect_check(target: str, requester: Optional[Requester]=None, param: str='next', timeout: int=10, progress_callback: Optional[Callable[[int], None]]=None) -> Dict[str,Any]:
    if requester is None:
        requester = Requester(timeout=timeout)
    findings=[]; tested=[]
    for p in OPEN_REDIRECT_PAYLOADS:
        tested.append(p)
        try:
            r = requester.get(target, params={param:p}, allow_redirects=False)
            loc = r.headers.get('Location') or r.headers.get('location')
            if loc and any(d in loc for d in ['example.com','http://','https://','//']):
                findings.append({'payload':p,'url':getattr(r,'url',target),'status':r.status_code,'location':loc})
        except Exception:
            continue
        if progress_callback:
            try:
                progress_callback(1)
            except Exception:
                pass
    return {'tested':tested,'findings':findings}

def dir_bruteforce(base_url: str, requester: Optional[Requester]=None, wordlist: Optional[List[str]]=None, threads: int=5, timeout: int=8, progress_callback: Optional[Callable[[int], None]]=None) -> Dict[str,Any]:
    if requester is None:
        requester = Requester(timeout=timeout)
    if wordlist is None or len(wordlist)==0:
        wordlist = COMMON_DIRS
    findings=[]; tested=[]
    base = base_url.rstrip('/')
    def probe(p):
        url = base + '/' + p.lstrip('/')
        try:
            r = requester.get(url, allow_redirects=True)
            if progress_callback:
                try:
                    progress_callback(1)
                except Exception:
                    pass
            if r.status_code in (200,301,302,403):
                return (p,r.status_code,len(r.text or ''))
            return None
        except Exception:
            if progress_callback:
                try:
                    progress_callback(1)
                except Exception:
                    pass
            return None
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(probe,p):p for p in wordlist}
        for fut in concurrent.futures.as_completed(futures):
            res = fut.result()
            if res:
                p,status,size = res
                findings.append({'path':p,'status':status,'size':size})
            tested.append(futures[fut])
    return {'tested':tested,'findings':findings,'count':len(tested)}

def load_wordlist_from_file(path: str) -> List[str]:
    if not os.path.exists(path):
        return []
    with open(path,'r',encoding='utf-8',errors='ignore') as fh:
        return [l.strip() for l in fh if l.strip() and not l.strip().startswith('#')]
