from flask import Flask, request, jsonify, render_template, abort
import json
import os
from src.waf_core import WAFCore

app = Flask(__name__)

config = {
    'block_mode': True,
    'log_file': 'logs/waf.log',
    'ip_whitelist': ['127.0.0.1'],
    'ip_blacklist': [],
    'rate_limit_threshold': 100,
    'rate_limit_window': 60
}

waf = WAFCore('D:\waf_m\model\waf_model.pkl', config)

@app.before_request
def waf_middleware():
    if request.path.startswith('/static') or request.path == '/favicon.ico':
        return None
    
    if request.path.startswith('/api/waf'):
        return None
    
    request_data = {
        'client_ip': request.remote_addr,
        'method': request.method,
        'url': request.url,
        'headers': dict(request.headers),
        'payload': request.get_data(as_text=True) or request.query_string.decode('utf-8')
    }
    
    result = waf.process_request(request_data)
    
    if not result['allowed']:
        return jsonify({
            'error': 'Request blocked by WAF',
            'reason': result['reason']
        }), 403

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/api/waf/stats')
def waf_stats():
    return jsonify(waf.get_stats())

@app.route('/api/waf/recent_attacks')
def recent_attacks():
    limit = request.args.get('limit', 10, type=int)
    return jsonify(waf.get_recent_attacks(limit))

@app.route('/api/waf/toggle_enabled', methods=['POST'])
def toggle_enabled():
    enabled = waf.toggle_enabled()
    return jsonify({'enabled': enabled})

@app.route('/api/waf/toggle_block_mode', methods=['POST'])
def toggle_block_mode():
    block_mode = waf.toggle_block_mode()
    return jsonify({'block_mode': block_mode})

@app.route('/api/waf/whitelist', methods=['POST'])
def add_to_whitelist():
    data = request.get_json()
    if not data or 'ip' not in data:
        return jsonify({'error': 'IP address is required'}), 400
    
    waf.add_to_whitelist(data['ip'])
    return jsonify({'success': True})

@app.route('/api/waf/blacklist', methods=['POST'])
def add_to_blacklist():
    data = request.get_json()
    if not data or 'ip' not in data:
        return jsonify({'error': 'IP address is required'}), 400
    
    waf.add_to_blacklist(data['ip'])
    return jsonify({'success': True})

@app.route('/test/sql_injection')
def test_sql_injection():
    query = request.args.get('query', "' OR '1'='1")
    return f"SQL Query: {query}"

@app.route('/test/xss')
def test_xss():
    input_text = request.args.get('input', "<script>alert('XSS')</script>")
    return f"Input: {input_text}"

@app.route('/test/path_traversal')
def test_path_traversal():
    file_path = request.args.get('file', "../../../etc/passwd")
    return f"File Path: {file_path}"

if __name__ == '__main__':
    os.makedirs('logs', exist_ok=True)
    app.run(debug=True, host='0.0.0.0', port=5000)
