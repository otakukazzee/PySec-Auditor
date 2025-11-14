from flask import Flask, render_template_string, jsonify
import json
from pathlib import Path
app = Flask(__name__)
RESULTS_DIR = Path('results')
INDEX = """<!doctype html><html><head><meta charset='utf-8'><title>PySec-Auditor Viewer</title></head><body><h2>Reports</h2><ul>{% for f in files %}<li><a href='/report/{{f}}'>{{f}}</a></li>{% endfor %}</ul></body></html>"""
@app.route('/')
def index():
    files = [p.name for p in RESULTS_DIR.glob('*.json')]
    return render_template_string(INDEX, files=files)
@app.route('/report/<path:fname>')
def report(fname):
    f = RESULTS_DIR / fname
    if not f.exists():
        return 'Not found', 404
    return jsonify(json.loads(f.read_text(encoding='utf-8')))
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)