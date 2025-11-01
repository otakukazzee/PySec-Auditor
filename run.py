#!/usr/bin/env python3
import argparse, sys, urllib.parse
from src.language import set_language, get_msg
from src.utils import clear_screen, display_ascii_art
from src.requester import create_session, safe_get
from src.scanner import (check_allowed_methods, analyze_cookies, check_specific_security_headers,
                         check_exposure, check_cors_insecurity, check_information_leakage,
                         get_tls_info, check_tls_ciphers, check_http_version)
from src.path_traversal import check_path_traversal_query
from src import __version__ as VERSION
from src.output import export_results, check_specific_security_headers_rich_output, analyze_cookies_rich_output
from src.network_tools import (
    get_ip_address,
    get_dns_records,
    reverse_dns,
    whois_lookup,
    port_scan_parallel as port_scan,
    banner_grab_parallel as banner_grab,
    enumerate_subdomains_parallel as enumerate_subdomains,
    get_cert_sans
)

from rich.console import Console
from rich.panel import Panel
console = Console()

def check_http_security(url: str, timeout: int, output_path: str = None):
    audit_data = {"Target": url, "Audit_Time": __import__('datetime').datetime.now().isoformat()}
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    parsed_url = urllib.parse.urlparse(url)
    hostname = parsed_url.netloc
    console.print(Panel(f"{get_msg('target_info')}: [bold blue]{url}[/bold blue] | {get_msg('host_info')}: [bold cyan]{hostname}[/bold cyan]",
                        title=f"[bold yellow]{get_msg('version_title')}[/bold yellow]", border_style="cyan"))
    session = create_session()
    try:
        response = safe_get(session, url, timeout=timeout, allow_redirects=True, stream=True)
        initial_status_code = response.status_code
        console.print(Panel(f"{get_msg('status_code')} [bold]{response.status_code}[/] | {get_msg('response_time')}: [dim]{response.elapsed.total_seconds():.3f}s[/dim]",
                            title=f"[bold white on blue]{get_msg('connection_title')}[/bold white on blue]"))
        # HTTP Version & Alt-Svc (delegated to scanner.get_http_version if implemented)
        audit_data["Security_Headers"] = check_specific_security_headers(response.headers)
        console.print(check_specific_security_headers_rich_output(audit_data["Security_Headers"]))
        audit_data["Cookie_Audit"] = analyze_cookies(response)
        console.print(analyze_cookies_rich_output(audit_data["Cookie_Audit"]))
        audit_data["Allowed_Methods"] = check_allowed_methods(url)
        audit_data["Exposure"] = check_exposure(url)
        audit_data["CORS"] = check_cors_insecurity(url, response.headers)
        audit_data["Leakage"] = check_information_leakage(response.headers)
        audit_data["Path_Traversal_Check"] = check_path_traversal_query(url, initial_status_code)
        # TLS
        if parsed_url.scheme == 'https':
            audit_data["TLS_Info"] = get_tls_info(hostname)
            audit_data["TLS_Cipher_Audit"] = check_tls_ciphers(hostname)
        if output_path:
            export_results(audit_data, output_path)
    except Exception as e:
        console.print(Panel(f"{get_msg('error_connect_fail')} {url}\\n[dim]{e}[/dim]", title=f"[bold red]{get_msg('error_connection')}[/bold red]", border_style="red"))

def main():
    parser = argparse.ArgumentParser(description="PySec Auditor: Alat Audit Keamanan HTTP & TLS Defensif.", epilog="Contoh: python run.py -u example.com -o report.json -l en", add_help=False)
    parser.add_argument('-u', '--url', type=str, help='URL target atau nama domain yang akan diaudit (misal: google.com atau https://google.com)')
    parser.add_argument('-o', '--output', type=str, default=None, help='Jalur file untuk ekspor (misal: report.json atau laporan.html)')
    parser.add_argument('-t', '--timeout', type=int, default=15, help='Timeout koneksi dalam detik (default: 15)')
    parser.add_argument('-l', '--lang', type=str, default='id', choices=['id', 'en'], help='Pilih bahasa antarmuka (id: Indonesia, en: English). Default: id')
    parser.add_argument('-h', '--help', action='store_true', help='Tampilkan pesan bantuan ini dan keluar')
    parser.add_argument('-d', '--domain', type=str, help='Nama domain atau host yang akan diaudit', required=True)
    parser.add_argument('-p', '--ports', nargs='+', type=int, default=[21,22,23,25,53,80,110,143,443,445,3306,3389,8080,8443], help='Daftar port untuk port scan')
    parser.add_argument('-s', '--subdomains', type=str, default=None, help='Jalur wordlist subdomain')

    args = parser.parse_args()

    set_language(args.lang)
    clear_screen()
    display_ascii_art()
    if args.help:
        parser.print_help()
        sys.exit(0)
    if not args.url:
        console.print(Panel(get_msg("error_url_missing"), border_style="red"))
        sys.exit(1)
    
    audit_results = {}
    
    if args.url:
        check_http_security(args.url, args.timeout, args.output)

    # check_http_security(args.url, args.timeout, args.output)

    hostname = args.domain
    console.print(Panel(f"[bold yellow]Starting Network Audit[/bold yellow] for: [bold blue]{hostname}[/bold blue]", border_style="magenta"))

    audit_results['IP_Address'] = get_ip_address(hostname)
    console.print(f"[bold cyan]IP Address:[/bold cyan] {audit_results['IP_Address']}")

    audit_results['DNS_Records'] = get_dns_records(hostname)
    console.print(f"[bold cyan]DNS Records:[/bold cyan] {audit_results['DNS_Records']}")

    if 'ip_address' in audit_results['IP_Address']:
        ip = audit_results['IP_Address']['ip_address']
        audit_results['Reverse_DNS'] = reverse_dns(ip)
        console.print(f"[bold cyan]Reverse DNS:[/bold cyan] {audit_results['Reverse_DNS']}")

    audit_results['WHOIS'] = whois_lookup(hostname)
    console.print(f"[bold cyan]WHOIS:[/bold cyan] {audit_results['WHOIS']}")

    audit_results['Open_Ports'] = port_scan(hostname, ports=args.ports, timeout=args.timeout)
    console.print(f"[bold cyan]Open Ports:[/bold cyan] {audit_results['Open_Ports']}")

    # Banner grab paralel
    banners = banner_grab(hostname, args.ports)
    audit_results['Banners'] = {b['port']: b['banner'] for b in banners if b.get('banner')}
    console.print(f"[bold cyan]Service Banners:[/bold cyan] {audit_results['Banners']}")

    # Subdomain enumeration paralel
    if args.subdomains:
        audit_results['Subdomains'] = enumerate_subdomains(hostname, args.subdomains)
        console.print(f"[bold cyan]Found Subdomains:[/bold cyan] {audit_results['Subdomains']}")

    audit_results['Cert_SANs'] = get_cert_sans(hostname)
    console.print(f"[bold cyan]Certificate SANs:[/bold cyan] {audit_results['Cert_SANs']}")

    if args.output:
        try:
            import json
            with open(args.output, 'w', encoding='utf-8') as f:
                json.dump(audit_results, f, indent=4)
            console.print(Panel(f"Hasil audit berhasil disimpan di [bold green]{args.output}[/bold green]", border_style="green"))
        except Exception as e:
            console.print(Panel(f"Gagal menyimpan hasil audit: {e}", border_style="red"))

if __name__ == "__main__":
    main()
