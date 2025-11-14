#!/usr/bin/env python3
import argparse, sys, json, datetime
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
try:
    from pyfiglet import Figlet
except Exception:
    Figlet = None
from src import (
    firebase_manager, free_features, premium_features, reporter,
    ai_audit_assistant, cve_manager, threat_intel, continuous_scan, language
)
console = Console()
def get_device_info():
    import platform, socket, uuid
    info = {}
    info['device_name'] = platform.node()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.connect(('8.8.8.8', 80))
        info['local_ip'] = s.getsockname()[0]; s.close()
    except Exception:
        info['local_ip'] = '127.0.0.1'
    info['os'] = platform.platform()
    info['python'] = platform.python_version()
    mac = uuid.getnode()
    info['mac'] = ':'.join([f"{(mac>>i)&0xff:02x}" for i in range(40,-1,-8)])
    return info
def show_banner(is_premium=False, lang='en'):
    console.clear()
    title = language.t('app_title', lang)
    if Figlet:
        try:
            fig = Figlet(font='slant'); console.print(f"[bold cyan]{fig.renderText(title)}[/bold cyan]")
        except Exception:
            console.print(f"[bold cyan]{title}[/bold cyan]")
    else:
        console.print(f"[bold cyan]{title}[/bold cyan]")
    console.print(Panel.fit(f"[bold white]🛡️  {title} — Premium+ Edition[/bold white]\n[cyan]{language.t('description', lang)}[/cyan]", border_style='bright_blue', title='v11.0'))
    info = get_device_info(); t = Table(title='Device Info', show_edge=False, box=None)
    t.add_column('Field', style='bold'); t.add_column('Value')
    for k,v in info.items(): t.add_row(k, str(v))
    console.print(t)
    if is_premium: console.print(Panel('💎 [magenta]Premium Mode Active — Full features unlocked[/magenta]', border_style='magenta'))
    else: console.print(Panel('🔓 [yellow]Free Mode — limited features. Use -k <KEY> to enable Premium.[/yellow]', border_style='yellow'))
    console.rule()
def build_parser(lang='en'):
    parser = argparse.ArgumentParser(description=language.t('description', lang), epilog='Examples: python3 run.py -u example.com -k YOUR_KEY --deep --intel --report full', formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('-u','--url', help=language.t('arg_url', lang), required=False)
    parser.add_argument('-k','--key', help=language.t('arg_key', lang), required=False)
    parser.add_argument('--deep', action='store_true', help=language.t('arg_deep', lang))
    parser.add_argument('--intel', action='store_true', help=language.t('arg_intel', lang))
    parser.add_argument('--report', choices=['summary','full'], help=language.t('arg_report', lang))
    parser.add_argument('--continuous', type=int, help=language.t('arg_continuous', lang))
    parser.add_argument('--api', help=language.t('arg_api', lang))
    parser.add_argument('--update', help=language.t('arg_update', lang), required=False)
    parser.add_argument('--output', help=language.t('arg_output', lang), required=False)
    parser.add_argument('-L','--lang', help='Language (en,id,es,ar,fr,de,pt)', default=lang)
    return parser
def main():
    pre = argparse.ArgumentParser(add_help=False); pre.add_argument('-L','--lang', default='en')
    known, _ = pre.parse_known_args(); lang = known.lang or 'en'
    parser = build_parser(lang=lang); args = parser.parse_args()
    is_premium=False; plan=None
    if args.key:
        ok, rec = firebase_manager.validate_key(args.key)
        if ok: is_premium=True; plan=rec.get('plan')
    show_banner(is_premium, lang=lang)
    if args.api:
        try:
            req = json.load(open(args.api,'r',encoding='utf-8')); url=req.get('url'); key=req.get('key'); ok=False
            if key: ok, _ = firebase_manager.validate_key(key)
            if ok: res = premium_features.run_premium_scan(url, output_prefix=(args.output or 'api_report'))
            else: res = free_features.run_free_scan(url)
            print(json.dumps(res, indent=2, default=str)); sys.exit(0)
        except Exception as e:
            console.print(f"[red]API mode error:[/red] {e}"); sys.exit(2)
    if not args.url:
        console.print(f"[red]{language.t('error_no_url', lang)}[/red]"); sys.exit(1)
    if args.continuous:
        if not is_premium: console.print(f"[red]{language.t('continuous_requires_premium', lang)}[/red]"); sys.exit(2)
        console.print(f"[cyan]Starting continuous scans every {args.continuous} seconds...[/cyan]")
        continuous_scan.run_daemon(args.url, args.continuous, key=args.key, output_prefix=(args.output or 'continuous'))
    try:
        if is_premium and args.deep:
            console.print(f"[green]{language.t('running_premium', lang)}[/green]")
            res = premium_features.run_premium_scan(args.url, output_prefix=(args.output or f"report_{datetime.datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"))
        elif is_premium:
            console.print(f"[green]{language.t('running_premium', lang)}[/green]")
            res = premium_features.run_premium_scan(args.url, output_prefix=(args.output or f"report_{datetime.datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"))
        else:
            console.print(f"[yellow]{language.t('running_free', lang)}[/yellow]")
            res = free_features.run_free_scan(args.url)
    except Exception as e:
        console.print(f"[red]Scan execution error:[/red] {e}"); sys.exit(3)
    try:
        if isinstance(res, dict):
            console.print('[bold]Summary:[/bold]')
            console.print(f"Target: {res.get('Target')}"); console.print(f"Scan type: {res.get('Scan_Type')}")
            if res.get('Findings'): console.print(f"Findings: {', '.join(res.get('Findings').keys())}")
            if is_premium:
                try:
                    suggestions = ai_audit_assistant.suggest_fixes(res)
                    if isinstance(suggestions, dict):
                        console.print(Panel(f"Risk score: {suggestions.get('risk_score')} - Severity: {suggestions.get('severity')}", title=language.t('ai_summary_title', lang), border_style='red'))
                        for rec in suggestions.get('recommendations', []): console.print(f" - {rec}")
                    if args.intel:
                        intel = threat_intel.lookup_domain(res.get('Target')); 
                        if intel: console.print(Panel(str(intel), title=language.t('threat_intel_title', lang), border_style='magenta'))
                    cves = cve_manager.match_cves_by_keyword(res.get('Target') or ''); 
                    if cves: console.print(f"[red]CVE matches found: {len(cves)}[/red]")
                except Exception as e:
                    console.print(f"[red]Postprocessing error:[/red] {e}")
    except Exception as e:
        console.print(f"[red]Display error:[/red] {e}")
    try:
        if args.report:
            out = reporter.generate_reports(res, output_prefix=(args.output or f"report_{datetime.datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"))
            console.print(f"[green]{language.t('report_generated', lang)}[/green] {out}")
    except Exception as e:
        console.print(f"[red]Report error:[/red] {e}")
if __name__ == '__main__':
    main()
