import shutil, subprocess
def _binary_exists(name: str) -> bool:
    return shutil.which(name) is not None
def run_nmap_tls_enum(host: str, port: int = 443, output_file: str = None, timeout: int = 300) -> str:
    if not _binary_exists('nmap'):
        return 'NMAP_NOT_FOUND'
    cmd = ['nmap','-sV','--script','ssl-enum-ciphers','-p',str(port),host,'-oJ',output_file or '-']
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.stdout + '\n' + p.stderr
    except Exception as e:
        return f'ERROR: {e}'
def run_testssl(host: str, port: int = 443, output_file: str = None, timeout: int = 300) -> str:
    for name in ('testssl','testssl.sh'):
        if _binary_exists(name):
            cmd = [name, host+':'+str(port)]
            if output_file:
                cmd += ['--jsonfile', output_file]
            try:
                p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
                return p.stdout + '\n' + p.stderr
            except Exception as e:
                return f'ERROR: {e}'
    return 'TESTSSL_NOT_FOUND'