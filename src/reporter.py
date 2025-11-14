import os, json
from .output import format_html_report, save_reports as save_reports_impl
def generate_reports(result: dict, output_prefix='report'):
    try:
        out = save_reports_impl(result, output_prefix=output_prefix)
        return out
    except Exception as e:
        return {'error': str(e)}
def export_pdf(html_path, out_pdf):
    import shutil, subprocess
    wk = shutil.which('wkhtmltopdf') or shutil.which('wkhtmltopdf.exe')
    if not wk: return {'ok':False,'error':'wkhtmltopdf not found'}
    try:
        subprocess.check_call([wk, html_path, out_pdf])
        return {'ok':True,'path':out_pdf}
    except Exception as e:
        return {'ok':False,'error':str(e)}
