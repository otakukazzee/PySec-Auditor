import json, datetime, os
HTML_TEMPLATE = '''<!doctype html><html><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/><title>{title}</title><style>body{font-family:Inter,Arial;background:#071028;color:#e6eef8;padding:20px} .container{max-width:1100px;margin:0 auto} .section{background:#021029;padding:12px;border-radius:8px;margin-bottom:12px} pre{white-space:pre-wrap}</style></head><body><div class="container"><h1>{title}</h1><div>Generated: {generated} • Target: {target}</div>{body}</div></body></html>'''
def format_html_report(result: dict, title='Report'):
    target = result.get('Target') or 'unknown'; gen = datetime.datetime.utcnow().isoformat()+'Z'
    body = ''
    finds = result.get('Findings') or {}
    for k,v in finds.items():
        body += f'<div class="section"><h3>{k}</h3><pre>{json.dumps(v, indent=2, default=str)}</pre></div>'
    body += f'<div class="section"><h3>Raw</h3><pre>{json.dumps(result, indent=2, default=str)}</pre></div>'
    return HTML_TEMPLATE.format(title=title, generated=gen, target=target, body=body)
def save_reports(result: dict, output_prefix='report'):
    ensure = os.path.exists('reports') or os.makedirs('reports', exist_ok=True)
    ts = datetime.datetime.utcnow().strftime('%Y%m%d_%H%M%SZ')
    j = os.path.join('reports', f"{output_prefix}_{ts}.json"); 
    with open(j,'w',encoding='utf-8') as f: json.dump(result, f, indent=2, default=str)
    html = format_html_report(result, title=output_prefix)
    h = os.path.join('reports', f"{output_prefix}_{ts}.html"); open(h,'w',encoding='utf-8').write(html)
    return {'json': j, 'html': h}
