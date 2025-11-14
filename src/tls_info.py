
# src/tls_info.py - safe TLS info retrieval
import ssl, socket
def get_tls_cert_and_cipher(hostname, port=443, timeout=5):
    out = {'cert': None, 'cipher': None, 'error': None}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                out['cipher'] = ssock.cipher()
                out['cert'] = ssock.getpeercert()
    except Exception as e:
        out['error'] = str(e)
    return out
