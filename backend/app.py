"""
IoT HoneyNet - Attack Detection & Enrichment
Flask API + WebSocket Server + SQLite Database
Production-ready with geoIP/enrichment—only real requests logged!
"""

import os
import datetime
import sqlite3
from flask import Flask, request, jsonify, render_template_string
from flask_socketio import SocketIO, emit
import requests

# Initialize Flask app
app = Flask(__name__)

# Environment config
if 'DYNO' in os.environ:  # Heroku
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'production-secret-key-change-me')
    DEBUG_MODE = False
elif 'RAILWAY_ENVIRONMENT' in os.environ:  # Railway
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'production-secret-key-change-me')
    DEBUG_MODE = False
else:  # Local dev
    app.config['SECRET_KEY'] = 'development-secret-key'
    DEBUG_MODE = True

# SocketIO setup
socketio = SocketIO(
    app, cors_allowed_origins="*", async_mode="eventlet",
    logger=DEBUG_MODE, engineio_logger=DEBUG_MODE
)

# CORS support
try:
    from flask_cors import CORS
    CORS(app, origins="*")
except ImportError:
    @app.after_request
    def add_cors_headers(response):
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
        return response

DB_FILE = 'honeypot.db'

def init_db():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    cursor = conn.cursor()
    # Attacks table, with real enrichment fields
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS attacks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            country TEXT,
            city TEXT,
            region TEXT,
            latitude REAL,
            longitude REAL,
            isp TEXT,
            org TEXT,
            asn TEXT,
            user_agent TEXT,
            method TEXT,
            path TEXT,
            severity TEXT,
            status TEXT
        )
    ''')
    # Devices table—unchanged
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS devices (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            type TEXT NOT NULL,
            status TEXT NOT NULL,
            attacks INTEGER DEFAULT 0,
            ip TEXT NOT NULL,
            location TEXT NOT NULL,
            last_seen TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()
    print("✅ Database initialized successfully")

def setup_sample_devices():
    # No change—keeps your device registry; you can skip if you want!
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    cursor = conn.cursor()
    sample_devices = [
        ("cam-001", "Security Camera #1", "camera", "online", 0, "192.168.1.101", "Front Entrance", datetime.datetime.now().isoformat()),
        ("router-001", "WiFi Router", "router", "online", 0, "192.168.1.1", "Server Room", datetime.datetime.now().isoformat()),
        ("lock-001", "Smart Lock", "lock", "online", 0, "192.168.1.104", "Main Door", datetime.datetime.now().isoformat()),
        ("therm-001", "Smart Thermostat", "thermostat", "offline", 0, "192.168.1.102", "Living Room", datetime.datetime.now().isoformat()),
        ("cam-002", "Security Camera #2", "camera", "online", 0, "192.168.1.105", "Back Yard", datetime.datetime.now().isoformat()),
        ("plug-001", "Smart Plug #1", "plug", "online", 0, "192.168.1.106", "Kitchen", datetime.datetime.now().isoformat())
    ]
    for device in sample_devices:
        cursor.execute('INSERT OR REPLACE INTO devices VALUES (?, ?, ?, ?, ?, ?, ?, ?)', device)
    conn.commit()
    conn.close()
    print("✅ Sample devices created successfully")

def enrich_ip(ip):
    url = f"http://ip-api.com/json/{ip}?fields=status,country,city,regionName,lat,lon,isp,org,as,query"
    try:
        resp = requests.get(url, timeout=3)
        data = resp.json()
        if data.get("status") == "success":
            return {
                "country": data.get("country", "--"),
                "city": data.get("city", "--"),
                "region": data.get("regionName", "--"),
                "latitude": data.get("lat"),
                "longitude": data.get("lon"),
                "isp": data.get("isp", "--"),
                "org": data.get("org", "--"),
                "asn": data.get("as", "--"),
            }
    except Exception as e:
        print("GeoIP/API error:", str(e))
    return dict(country="--", city="--", region="--", latitude=None, longitude=None, isp="--", org="--", asn="--")

# ------------- API & Demo Endpoints -------------

@app.route('/')
def index():
    html = '''
    <html>
    <head><title>IoT HoneyNet Backend API</title></head>
    <body style="font-family:Arial;background:#0f1419;color:#8dceb9;text-align:center;padding:80px;">
        <h1>🛡️ IoT HoneyNet Backend API</h1>
        <div style="background:#204b3d;border-radius:8px;padding:30px;margin:20px auto;max-width:600px;">
            <h2 style="color:#0bda49;">✅ Server is Running</h2>
            <p>Ready to detect and log real attackers 🕵️‍♂️</p>
            <ul style="text-align:left;max-width:400px;margin:auto;">
                <li>/api/attacks — Get recent attacks</li>
                <li>/api/stats — Get stats</li>
                <li>/api/devices — (optional) Managed honeypots</li>
                <li>/honeypot/&lt;path&gt; — Demo endpoint for logging/triggering attacks</li>
            </ul>
        </div>
    </body>
    </html>
    '''
    return render_template_string(html)

@app.route('/honeypot/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'])
def honeypot_endpoint(path):
    # Logs real inbound requests as attacks
    source_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    user_agent = request.headers.get('User-Agent', 'Unknown')
    geo = enrich_ip(source_ip)
    attack_data = {
        'timestamp': datetime.datetime.now().isoformat(),
        'source_ip': source_ip,
        'country': geo['country'],
        'city': geo['city'],
        'region': geo['region'],
        'latitude': geo['latitude'],
        'longitude': geo['longitude'],
        'isp': geo['isp'],
        'org': geo['org'],
        'asn': geo['asn'],
        'user_agent': user_agent,
        'method': request.method,
        'path': path,
        'severity': "High" if request.method in ['POST', 'PUT', 'DELETE'] else "Low",
        'status': 'detected'
    }
    # Log to DB
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO attacks 
        (timestamp, source_ip, country, city, region, latitude, longitude, isp, org, asn, user_agent, method, path, severity, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        attack_data['timestamp'], attack_data['source_ip'], attack_data['country'], attack_data['city'],
        attack_data['region'], attack_data['latitude'], attack_data['longitude'], attack_data['isp'],
        attack_data['org'], attack_data['asn'], attack_data['user_agent'], attack_data['method'],
        attack_data['path'], attack_data['severity'], attack_data['status']
    ))
    conn.commit()
    conn.close()

    # WebSocket broadcast
    socketio.emit('new_attack', attack_data)
    return jsonify({'received': True, 'attack_logged': attack_data}), 201

@app.route('/api/stats', methods=['GET'])
def get_stats():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute('SELECT COUNT(*) FROM attacks')
    total_attacks = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(DISTINCT source_ip) FROM attacks')
    unique_ips = cursor.fetchone()[0]
    conn.close()
    threat_level = 'High' if total_attacks > 30 else 'Medium' if total_attacks > 10 else 'Low'
    return jsonify({
        'total_attacks': total_attacks,
        'unique_ips': unique_ips,
        'threat_level': threat_level,
        'server_time': datetime.datetime.now().isoformat()
    })

@app.route('/api/attacks', methods=['GET'])
def get_attacks():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM attacks ORDER BY timestamp DESC LIMIT 50')
    rows = cursor.fetchall()
    conn.close()
    attack_list = [
        {
            'id': row[0], 'timestamp': row[1], 'source_ip': row[2],
            'country': row[3], 'city': row[4], 'region': row[5],
            'latitude': row[6], 'longitude': row[7], 'isp': row[8], 'org': row[9],
            'asn': row[10], 'user_agent': row[11], 'method': row[12], 'path': row[13],
            'severity': row[14], 'status': row[15]
        }
        for row in rows
    ]
    return jsonify(attack_list)

@app.route('/api/devices', methods=['GET'])
def get_devices():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM devices')
    devices = cursor.fetchall()
    conn.close()
    device_list = []
    for device in devices:
        device_list.append({
            'id': device[0], 'name': device[1], 'type': device[2], 'status': device[3],
            'attacks': device[4], 'ip': device[5], 'location': device[6], 'last_seen': device[7]
        })
    return jsonify(device_list)

# ------------------ WebSocket Handlers ------------------

@socketio.on('connect')
def handle_connect():
    print('🔌 Client connected to WebSocket')
    emit('status', {
        'message': 'Connected to IoT HoneyNet Live Feed',
        'server_time': datetime.datetime.now().isoformat()
    })

@socketio.on('disconnect')
def handle_disconnect():
    print('🔌 Client disconnected from WebSocket')

@socketio.on('request_latest_attacks')
def handle_request_latest_attacks():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM attacks ORDER BY timestamp DESC LIMIT 10')
    rows = cursor.fetchall()
    conn.close()
    attack_list = [
        {
            'id': row[0], 'timestamp': row[1], 'source_ip': row[2],
            'country': row[3], 'city': row[4], 'region': row[5], 'latitude': row[6],
            'longitude': row[7], 'isp': row[8], 'org': row[9], 'asn': row[10],
            'user_agent': row[11], 'method': row[12], 'path': row[13],
            'severity': row[14], 'status': row[15]
        }
        for row in rows
    ]
    emit('latest_attacks', attack_list)

def initialize_application():
    print("🚀 Starting IoT HoneyNet Backend Server...")
    print("🔧 Initializing database...")
    init_db()
    setup_sample_devices()
    print("✅ Honeynet initialized. Ready for live, real attack detection.")
    print("🌐 Server running and accessible at deployed public URL.")

if __name__ == '__main__':
    initialize_application()
    port = int(os.environ.get('PORT', 5000))
    socketio.run(app, debug=False, host='0.0.0.0', port=port)
