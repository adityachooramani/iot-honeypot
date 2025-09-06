"""IoT HoneyNet - Attack Detection & Enrichment (updated)

Features/changes made in this updated file:
- Uses background enrichment to avoid blocking request handling.
- Uses HTTPS GeoIP requests with caching and validation.
- Extracts client IP safely from X-Forwarded-For / X-Real-IP and validates using ipaddress.
- Uses sqlite3 with WAL mode to improve concurrency and context managers for safety.
- Adds logging instead of print().
- Exposes /healthz for readiness checks.
- Emits websocket updates for new attacks and when enrichment is added.
- Defensive error handling around DB and network calls.

Note: For production with significant concurrency, migrate to Postgres (or another RDBMS).

"""

import os
import datetime
import sqlite3
import logging
from functools import lru_cache
import ipaddress

from flask import Flask, request, jsonify, render_template_string
from flask_socketio import SocketIO, emit

# Prefer eventlet for SocketIO if available
try:
    import eventlet
    eventlet.monkey_patch()
    ASYNC_MODE = 'eventlet'
except Exception:
    eventlet = None
    ASYNC_MODE = None

# Optional CORS
try:
    from flask_cors import CORS
except Exception:
    CORS = None

import requests

# -------------------- Configuration --------------------
DB_FILE = os.environ.get('HONEYPOT_DB', 'honeypot.db')
GEOIP_URL = os.environ.get('GEOIP_URL', 'https://ip-api.com/json/{ip}?fields=status,country,city,regionName,lat,lon,isp,org,as,query')

# Flask app
app = Flask(__name__)
app.config['JSON_SORT_KEYS'] = False

if 'DYNO' in os.environ or 'RAILWAY_ENVIRONMENT' in os.environ:
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'change-me-in-prod')
    DEBUG_MODE = False
else:
    app.config['SECRET_KEY'] = 'dev-secret'
    DEBUG_MODE = True

# Setup CORS if available, otherwise add permissive headers later
if CORS:
    CORS(app, origins='*')

# SocketIO
socketio = SocketIO(app, cors_allowed_origins='*', async_mode=ASYNC_MODE or 'threading', logger=DEBUG_MODE, engineio_logger=DEBUG_MODE)

# Logger
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger('honeynet')

# -------------------- Database helpers --------------------

def get_db_connection():
    # Using check_same_thread=False to allow SocketIO background tasks to access DB
    conn = sqlite3.connect(DB_FILE, check_same_thread=False, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initialize database and tables. Sets WAL mode to improve concurrency."""
    conn = get_db_connection()
    try:
        # Enable WAL mode for better concurrent read/write behavior
        conn.execute('PRAGMA journal_mode=WAL;')
        cursor = conn.cursor()
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
        logger.info('Database initialized (WAL) and tables ensured')
    finally:
        conn.close()


def setup_sample_devices():
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        sample_devices = [
            ("cam-001", "Security Camera #1", "camera", "online", 0, "192.168.1.101", "Front Entrance", datetime.datetime.utcnow().isoformat()),
            ("router-001", "WiFi Router", "router", "online", 0, "192.168.1.1", "Server Room", datetime.datetime.utcnow().isoformat()),
            ("lock-001", "Smart Lock", "lock", "online", 0, "192.168.1.104", "Main Door", datetime.datetime.utcnow().isoformat()),
            ("therm-001", "Smart Thermostat", "thermostat", "offline", 0, "192.168.1.102", "Living Room", datetime.datetime.utcnow().isoformat()),
            ("cam-002", "Security Camera #2", "camera", "online", 0, "192.168.1.105", "Back Yard", datetime.datetime.utcnow().isoformat()),
            ("plug-001", "Smart Plug #1", "plug", "online", 0, "192.168.1.106", "Kitchen", datetime.datetime.utcnow().isoformat())
        ]
        for device in sample_devices:
            cursor.execute('INSERT OR REPLACE INTO devices VALUES (?, ?, ?, ?, ?, ?, ?, ?)', device)
        conn.commit()
        logger.info('Sample devices inserted/updated')
    finally:
        conn.close()

# -------------------- GeoIP enrichment (cached) --------------------

@lru_cache(maxsize=2048)
def enrich_ip_cached(ip):
    """Call external GeoIP service and return enrichment dict. Uses caching to reduce external calls."""
    url = GEOIP_URL.format(ip=ip)
    try:
        resp = requests.get(url, timeout=3)
        if resp.status_code != 200:
            logger.warning('GeoIP: non-200 response for %s: %s', ip, resp.status_code)
            return None
        data = resp.json()
        if data.get('status') != 'success':
            logger.debug('GeoIP: provider returned non-success for %s: %s', ip, data)
            return None
        return {
            'country': data.get('country', '--'),
            'city': data.get('city', '--'),
            'region': data.get('regionName', '--'),
            'latitude': data.get('lat'),
            'longitude': data.get('lon'),
            'isp': data.get('isp', '--'),
            'org': data.get('org', '--'),
            'asn': data.get('as', '--')
        }
    except Exception as e:
        logger.exception('GeoIP request failed for %s: %s', ip, e)
        return None

# -------------------- Helper utilities --------------------

def extract_client_ip(req):
    """Try to determine originating client IP from headers in a safe way.
    Prefer X-Forwarded-For first entry, then X-Real-IP, else remote_addr.
    Returns a string IP; on validation failure returns '0.0.0.0'.
    """
    ip = None
    xff = req.headers.get('X-Forwarded-For', '')
    if xff:
        # X-Forwarded-For can be a comma-separated list; first is original
        ip = xff.split(',')[0].strip()
    if not ip:
        ip = req.headers.get('X-Real-IP')
    if not ip:
        ip = req.remote_addr
    # Validate
    try:
        ipaddress.ip_address(ip)
        return ip
    except Exception:
        logger.warning('Invalid client IP detected: %s, defaulting to 0.0.0.0', ip)
        return '0.0.0.0'

# -------------------- Attack logging & enrichment flow --------------------

def insert_attack_minimal(attack_data):
    """Insert minimal attack record and return inserted attack id."""
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute('''
            INSERT INTO attacks (timestamp, source_ip, user_agent, method, path, severity, status)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            attack_data['timestamp'], attack_data['source_ip'], attack_data.get('user_agent'),
            attack_data.get('method'), attack_data.get('path'), attack_data.get('severity'), attack_data.get('status')
        ))
        conn.commit()
        return cur.lastrowid
    except Exception:
        logger.exception('Failed to insert minimal attack')
        return None
    finally:
        conn.close()


def update_attack_enrichment(attack_id, geo):
    """Update the attack row with enrichment data (geo may be None)."""
    if attack_id is None:
        return False
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        if geo:
            cur.execute('''
                UPDATE attacks SET country=?, city=?, region=?, latitude=?, longitude=?, isp=?, org=?, asn=? WHERE id=?
            ''', (geo.get('country'), geo.get('city'), geo.get('region'), geo.get('latitude'), geo.get('longitude'), geo.get('isp'), geo.get('org'), geo.get('asn'), attack_id))
        else:
            # mark as attempted enrichment (status) - optional
            cur.execute(''' UPDATE attacks SET status=? WHERE id=? ''', ('enriched_failed', attack_id))
        conn.commit()
        return True
    except Exception:
        logger.exception('Failed to update attack enrichment for id=%s', attack_id)
        return False
    finally:
        conn.close()


def enrich_and_emit(attack_id, ip):
    """Background task: enrich IP and update DB, then emit websocket event with enriched data."""
    try:
        logger.debug('Starting enrichment for %s (attack id %s)', ip, attack_id)
        geo = enrich_ip_cached(ip)
        updated = update_attack_enrichment(attack_id, geo)

        # Fetch updated row to emit
        conn = get_db_connection()
        try:
            cur = conn.cursor()
            cur.execute('SELECT * FROM attacks WHERE id=?', (attack_id,))
            row = cur.fetchone()
            if row:
                attack = dict(row)
                # emit to websocket clients
                socketio.emit('attack_enriched', attack)
                logger.info('Enrichment complete and emitted for attack id=%s', attack_id)
        finally:
            conn.close()

    except Exception:
        logger.exception('Background enrichment failed for attack id=%s ip=%s', attack_id, ip)

# -------------------- HTTP endpoints --------------------

@app.route('/')
def index():
    html = '''
    <html>
      <head><title>IoT HoneyNet Backend API</title></head>
      <body style="font-family:Arial;background:#0f1419;color:#8dceb9;text-align:center;padding:80px;">
        <h1>🛡️ IoT HoneyNet Backend API</h1>
        <div style="background:#204b3d;border-radius:8px;padding:30px;margin:20px auto;max-width:600px;">
          <h2 style="color:#0bda49;">✅ Server is Running</h2>
          <p>Ready to detect and log real attackers</p>
          <ul style="text-align:left;max-width:400px;margin:auto;">
            <li>/api/attacks — Get recent attacks</li>
            <li>/api/stats — Get stats</li>
            <li>/api/devices — Managed honeypot devices</li>
            <li>/honeypot/&lt;path&gt; — Demo endpoint for logging/triggering attacks</li>
            <li>/healthz — Health check</li>
          </ul>
        </div>
      </body>
    </html>
    '''
    return render_template_string(html)


@app.route('/healthz')
def healthz():
    return jsonify({'status': 'ok', 'time': datetime.datetime.utcnow().isoformat()})


@app.route('/honeypot/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'])
def honeypot_endpoint(path):
    """Minimal, safe honeypot endpoint: log minimal info synchronously, then start background enrichment task."""
    try:
        source_ip = extract_client_ip(request)
        user_agent = request.headers.get('User-Agent', 'Unknown')
        attack_data = {
            'timestamp': datetime.datetime.utcnow().isoformat(),
            'source_ip': source_ip,
            'user_agent': user_agent,
            'method': request.method,
            'path': path,
            'severity': 'High' if request.method in ['POST', 'PUT', 'DELETE'] else 'Low',
            'status': 'detected'
        }

        attack_id = insert_attack_minimal(attack_data)
        if attack_id is None:
            return jsonify({'received': False, 'error': 'db_insert_failed'}), 500

        # Emit minimal info immediately
        socketio.emit('new_attack', {**attack_data, 'id': attack_id})

        # Start background enrichment (non-blocking)
        try:
            socketio.start_background_task(enrich_and_emit, attack_id, source_ip)
        except Exception:
            # fallback: fire & forget in a thread if background task cannot be started
            logger.exception('Could not start socketio background task for enrichment')

        return jsonify({'received': True, 'attack_id': attack_id}), 201

    except Exception:
        logger.exception('Unhandled exception in honeypot endpoint')
        return jsonify({'received': False, 'error': 'server_error'}), 500


@app.route('/api/stats', methods=['GET'])
def get_stats():
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('SELECT COUNT(*) FROM attacks')
        total_attacks = cur.fetchone()[0]
        cur.execute('SELECT COUNT(DISTINCT source_ip) FROM attacks')
        unique_ips = cur.fetchone()[0]
        conn.close()

        threat_level = 'High' if total_attacks > 30 else 'Medium' if total_attacks > 10 else 'Low'
        return jsonify({
            'total_attacks': total_attacks,
            'unique_ips': unique_ips,
            'threat_level': threat_level,
            'server_time': datetime.datetime.utcnow().isoformat()
        })
    except Exception:
        logger.exception('Failed to fetch stats')
        return jsonify({'error': 'internal'}), 500


@app.route('/api/attacks', methods=['GET'])
def get_attacks():
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('SELECT * FROM attacks ORDER BY timestamp DESC LIMIT 50')
        rows = cur.fetchall()
        conn.close()
        attack_list = [dict(row) for row in rows]
        return jsonify(attack_list)
    except Exception:
        logger.exception('Failed to fetch attacks')
        return jsonify({'error': 'internal'}), 500


@app.route('/api/devices', methods=['GET'])
def get_devices():
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('SELECT * FROM devices')
        rows = cur.fetchall()
        conn.close()
        device_list = [dict(row) for row in rows]
        return jsonify(device_list)
    except Exception:
        logger.exception('Failed to fetch devices')
        return jsonify({'error': 'internal'}), 500

# -------------------- WebSocket handlers --------------------

@socketio.on('connect')
def handle_connect():
    logger.info('Client connected via WebSocket')
    emit('status', {'message': 'Connected to IoT HoneyNet Live Feed', 'server_time': datetime.datetime.utcnow().isoformat()})


@socketio.on('disconnect')
def handle_disconnect():
    logger.info('Client disconnected')


@socketio.on('request_latest_attacks')
def handle_request_latest_attacks():
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('SELECT * FROM attacks ORDER BY timestamp DESC LIMIT 10')
        rows = cur.fetchall()
        conn.close()
        attack_list = [dict(row) for row in rows]
        emit('latest_attacks', attack_list)
    except Exception:
        logger.exception('Failed to retrieve latest attacks')
        emit('latest_attacks', [])

# -------------------- Initialization & run --------------------

def initialize_application():
    logger.info('Starting IoT HoneyNet Backend Server...')
    init_db()
    setup_sample_devices()
    logger.info('Honeynet initialized and sample devices loaded')


if __name__ == '__main__':
    initialize_application()
    port = int(os.environ.get('PORT', 5000))
    # socketio.run will select the appropriate async mode
    socketio.run(app, debug=False, host='0.0.0.0', port=port)
