import sys
import os

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from flask import Flask, render_template, jsonify, request
from src.Database.database import get_recent_alerts, get_all_blocked_ips, get_stats_over_time, unblock_ip_manual

app = Flask(__name__)

@app.route('/')
def dashboard():
    """Renders the main dashboard page."""
    return render_template('dashboard.html')

@app.route('/api/stats')
def api_stats():
    """Returns global stats and timeline for charts."""
    stats = get_stats_over_time()
    return jsonify(stats)

@app.route('/api/alerts')
def api_alerts():
    """Returns the most recent alerts."""
    alerts = get_recent_alerts(limit=100)
    return jsonify(alerts)

@app.route('/api/blocked')
def api_blocked():
    """Returns currently blocked IPs."""
    blocked = get_all_blocked_ips()
    return jsonify(blocked)

@app.route('/api/unblock/<ip>', methods=['POST'])
def api_unblock(ip):
    """Manually unblocks an IP."""
    try:
        unblock_ip_manual(ip)
        return jsonify({"status": "success", "message": f"IP {ip} unblocked successfully."})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
