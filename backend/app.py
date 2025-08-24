"""
IoT HoneyNet - Complete Backend Server
Flask API + WebSocket Server + SQLite Database
Production-ready deployment for hosting platforms
"""

import os
import datetime
import random
import sqlite3
import threading
import time
from flask import Flask, jsonify, render_template_string
from flask_socketio import SocketIO, emit

# Initialize Flask app
app = Flask(__name__)

# Configuration for different environments
if 'DYNO' in os.environ:  # Heroku
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'production-secret-key-change-me')
    DEBUG_MODE = False
elif 'RAILWAY_ENVIRONMENT' in os.environ:  # Railway
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'production-secret-key-change-me')
    DEBUG_MODE = False
else:  # Local development
    app.config['SECRET_KEY'] = 'development-secret-key'
    DEBUG_MODE = True

# Initialize SocketIO with proper configuration
socketio = SocketIO(
    app, 
    cors_allowed_origins="*", 
    async_mode="eventlet",
    logger=DEBUG_MODE,
    engineio_logger=DEBUG_MODE
)

# Try to import and use Flask-CORS, fall back to manual CORS if not available
try:
    from flask_cors import CORS
    CORS(app, origins="*")
    print("✅ Flask-CORS loaded successfully")
except ImportError:
    print("⚠️  Flask-CORS not available, using manual CORS headers")
    
    @app.after_request
    def add_cors_headers(response):
        """Add CORS headers manually if flask-cors is not available."""
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
        return response


def init_db():
    """
    Initialize the SQLite database with required tables.
    Creates attacks and devices tables if they don't exist.
    """
    conn = sqlite3.connect('honeypot.db', check_same_thread=False)
    cursor = conn.cursor()
    
    # Create attacks table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS attacks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            target_device TEXT NOT NULL,
            attack_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            status TEXT NOT NULL,
            country TEXT NOT NULL
        )
    ''')
    
    # Create devices table
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
    """
    Insert sample IoT devices into the database.
    Creates honeypot devices for testing and demonstration.
    """
    conn = sqlite3.connect('honeypot.db', check_same_thread=False)
    cursor = conn.cursor()
    
    sample_devices = [
        ('cam-001', 'Security Camera #1', 'camera', 'online', 0, '192.168.1.101', 
         'Front Entrance', datetime.datetime.now().isoformat()),
        ('router-001', 'WiFi Router', 'router', 'online', 0, '192.168.1.1', 
         'Server Room', datetime.datetime.now().isoformat()),
        ('lock-001', 'Smart Lock', 'lock', 'online', 0, '192.168.1.104', 
         'Main Door', datetime.datetime.now().isoformat()),
        ('therm-001', 'Smart Thermostat', 'thermostat', 'offline', 0, '192.168.1.102', 
         'Living Room', datetime.datetime.now().isoformat()),
        ('cam-002', 'Security Camera #2', 'camera', 'online', 0, '192.168.1.105', 
         'Back Yard', datetime.datetime.now().isoformat()),
        ('plug-001', 'Smart Plug #1', 'plug', 'online', 0, '192.168.1.106', 
         'Kitchen', datetime.datetime.now().isoformat())
    ]
    
    for device in sample_devices:
        cursor.execute('INSERT OR REPLACE INTO devices VALUES (?, ?, ?, ?, ?, ?, ?, ?)', device)
    
    conn.commit()
    conn.close()
    print("✅ Sample devices created successfully")


def generate_random_ip():
    """
    Generate a random IP address for attack simulation.
    
    Returns:
        str: Random IP address in format 'xxx.xxx.xxx.xxx'
    """
    # Generate more realistic IP ranges
    ip_ranges = [
        (1, 255, 1, 255, 1, 255, 1, 255),      # Any IP
        (192, 192, 168, 168, 1, 1, 1, 255),   # Local network
        (10, 10, 0, 255, 0, 255, 1, 255),     # Private network
        (172, 172, 16, 31, 0, 255, 1, 255),   # Private network
    ]
    
    range_choice = random.choice(ip_ranges)
    return f"{random.randint(range_choice[0], range_choice[1])}.{random.randint(range_choice[2], range_choice[3])}.{random.randint(range_choice[4], range_choice[5])}.{random.randint(range_choice[6], range_choice[7])}"


def get_latest_attack():
    """
    Get the latest attack from the database with thread-safe connection.
    
    Returns:
        tuple or None: Latest attack record or None if no attacks found
    """
    try:
        conn = sqlite3.connect('honeypot.db', check_same_thread=False)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM attacks ORDER BY timestamp DESC LIMIT 1')
        result = cursor.fetchone()
        conn.close()
        return result
    except Exception as e:
        print(f"❌ Database error getting latest attack: {e}")
        return None


def simulate_attacks():
    """
    Background thread function to simulate IoT attacks.
    Generates realistic attack data and stores in database.
    """
    attack_types = ['DDoS', 'Brute Force', 'Malware', 'SQL Injection', 'XSS', 'Port Scan', 'Ransomware', 'Phishing']
    devices = ['Security Camera #1', 'WiFi Router', 'Smart Lock', 'Smart Thermostat', 'Security Camera #2', 'Smart Plug #1']
    countries = ['CN', 'RU', 'US', 'IN', 'BR', 'DE', 'KR', 'JP', 'FR', 'GB', 'CA', 'AU']
    severities = ['High', 'Medium', 'Low']
    
    last_attack_id = None
    
    while True:
        try:
            # Generate random attack data
            attack_data = {
                'timestamp': datetime.datetime.now().isoformat(),
                'source_ip': generate_random_ip(),
                'target_device': random.choice(devices),
                'attack_type': random.choice(attack_types),
                'severity': random.choice(severities),
                'status': 'blocked',
                'country': random.choice(countries)
            }
            
            # Insert into database
            conn = sqlite3.connect('honeypot.db', check_same_thread=False)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO attacks (timestamp, source_ip, target_device, attack_type, severity, status, country)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                attack_data['timestamp'],
                attack_data['source_ip'],
                attack_data['target_device'],
                attack_data['attack_type'],
                attack_data['severity'],
                attack_data['status'],
                attack_data['country']
            ))
            
            attack_id = cursor.lastrowid
            conn.commit()
            conn.close()
            
            print(f"🚨 Simulated attack: {attack_data['attack_type']} from {attack_data['source_ip']}")
            
            # Broadcast to WebSocket clients if it's a new attack
            if last_attack_id != attack_id:
                attack_data['id'] = attack_id
                socketio.emit('new_attack', attack_data)
                print(f"📡 Broadcasted attack via WebSocket: {attack_data['attack_type']}")
                last_attack_id = attack_id
            
        except Exception as e:
            print(f"❌ Error simulating attack: {e}")
        
        # Wait 5-15 seconds before next attack
        time.sleep(random.randint(5, 15))


# ═══════════════════════════════════════════════════════════════════
# REST API ROUTES
# ═══════════════════════════════════════════════════════════════════

@app.route('/')
def index():
    """
    Serve a simple API status page.
    """
    html_template = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>IoT HoneyNet API</title>
        <style>
            body { font-family: Arial, sans-serif; background: #0f1419; color: #8dceb9; padding: 50px; }
            .container { max-width: 800px; margin: 0 auto; text-align: center; }
            .status { background: #204b3d; padding: 20px; border-radius: 10px; margin: 20px 0; }
            .endpoint { background: #1a2e26; padding: 15px; margin: 10px; border-radius: 5px; text-align: left; }
            .success { color: #0bda49; }
            .warning { color: #ffa500; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🛡️ IoT HoneyNet Backend API</h1>
            <div class="status">
                <h2 class="success">✅ Server is Running</h2>
                <p>Real-time IoT attack monitoring system</p>
            </div>
            
            <h3>Available API Endpoints:</h3>
            <div class="endpoint">
                <strong>GET /api/stats</strong><br>
                Get dashboard statistics (total attacks, devices, threat level)
            </div>
            <div class="endpoint">
                <strong>GET /api/attacks</strong><br>
                Get recent attack logs (latest 50 attacks)
            </div>
            <div class="endpoint">
                <strong>GET /api/devices</strong><br>
                Get all IoT honeypot devices status
            </div>
            
            <div class="status">
                <h3>WebSocket Connection</h3>
                <p class="warning">Connect to same URL for real-time attack updates</p>
                <p>Event: <code>new_attack</code></p>
            </div>
            
            <p><em>Built with Flask + SocketIO + SQLite</em></p>
        </div>
    </body>
    </html>
    '''
    return render_template_string(html_template)


@app.route('/api/stats', methods=['GET'])
def get_stats():
    """
    Get dashboard statistics.
    
    Returns:
        JSON: Dashboard statistics including attack counts and device status
    """
    try:
        conn = sqlite3.connect('honeypot.db', check_same_thread=False)
        cursor = conn.cursor()
        
        # Get total attacks
        cursor.execute('SELECT COUNT(*) FROM attacks')
        total_attacks = cursor.fetchone()[0]
        
        # Get unique IPs
        cursor.execute('SELECT COUNT(DISTINCT source_ip) FROM attacks')
        unique_ips = cursor.fetchone()[0]
        
        # Get active devices
        cursor.execute('SELECT COUNT(*) FROM devices WHERE status = "online"')
        active_devices = cursor.fetchone()[0]
        
        # Get recent attacks (last hour)
        one_hour_ago = (datetime.datetime.now() - datetime.timedelta(hours=1)).isoformat()
        cursor.execute('SELECT COUNT(*) FROM attacks WHERE timestamp > ?', (one_hour_ago,))
        recent_attacks = cursor.fetchone()[0]
        
        conn.close()
        
        # Determine threat level based on recent attacks
        if recent_attacks > 20:
            threat_level = 'High'
        elif recent_attacks > 5:
            threat_level = 'Medium'
        else:
            threat_level = 'Low'
        
        return jsonify({
            'total_attacks': total_attacks,
            'unique_ips': unique_ips,
            'active_devices': active_devices,
            'recent_attacks': recent_attacks,
            'threat_level': threat_level,
            'server_time': datetime.datetime.now().isoformat()
        })
    
    except Exception as e:
        print(f"❌ Error getting stats: {e}")
        return jsonify({'error': 'Failed to retrieve statistics'}), 500


@app.route('/api/attacks', methods=['GET'])
def get_attacks():
    """
    Get recent attack logs from database.
    
    Returns:
        JSON: List of recent attacks (max 50)
    """
    try:
        conn = sqlite3.connect('honeypot.db', check_same_thread=False)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM attacks ORDER BY timestamp DESC LIMIT 50')
        attacks = cursor.fetchall()
        conn.close()
        
        # Convert to JSON format
        attack_list = []
        for attack in attacks:
            attack_list.append({
                'id': attack[0],
                'timestamp': attack[1],
                'source_ip': attack[2],
                'target_device': attack[3],
                'attack_type': attack[4],
                'severity': attack[5],
                'status': attack[6],
                'country': attack[7]
            })
        
        return jsonify(attack_list)
    
    except Exception as e:
        print(f"❌ Error getting attacks: {e}")
        return jsonify({'error': 'Failed to retrieve attacks'}), 500


@app.route('/api/devices', methods=['GET'])
def get_devices():
    """
    Get all devices from database.
    
    Returns:
        JSON: List of all IoT devices
    """
    try:
        conn = sqlite3.connect('honeypot.db', check_same_thread=False)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM devices')
        devices = cursor.fetchall()
        conn.close()
        
        device_list = []
        for device in devices:
            device_list.append({
                'id': device[0],
                'name': device[1],
                'type': device[2],
                'status': device[3],
                'attacks': device[4],
                'ip': device[5],
                'location': device[6],
                'last_seen': device[7]
            })
        
        return jsonify(device_list)
    
    except Exception as e:
        print(f"❌ Error getting devices: {e}")
        return jsonify({'error': 'Failed to retrieve devices'}), 500


# ═══════════════════════════════════════════════════════════════════
# WEBSOCKET EVENT HANDLERS
# ═══════════════════════════════════════════════════════════════════

@socketio.on('connect')
def handle_connect():
    """
    Handle new WebSocket client connections.
    Sends welcome message to connected client.
    """
    print('🔌 Client connected to WebSocket')
    emit('status', {
        'message': 'Connected to IoT HoneyNet Live Feed',
        'server_time': datetime.datetime.now().isoformat()
    })


@socketio.on('disconnect')
def handle_disconnect():
    """
    Handle WebSocket client disconnections.
    Log disconnection event.
    """
    print('🔌 Client disconnected from WebSocket')


@socketio.on('request_latest_attacks')
def handle_request_latest_attacks():
    """
    Handle client request for latest attacks.
    Sends the most recent 10 attacks to the requesting client.
    """
    try:
        conn = sqlite3.connect('honeypot.db', check_same_thread=False)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM attacks ORDER BY timestamp DESC LIMIT 10')
        attacks = cursor.fetchall()
        conn.close()
        
        attack_list = []
        for attack in attacks:
            attack_list.append({
                'id': attack[0],
                'timestamp': attack[1],
                'source_ip': attack[2],
                'target_device': attack[3],
                'attack_type': attack[4],
                'severity': attack[5],
                'status': attack[6],
                'country': attack[7]
            })
        
        emit('latest_attacks', attack_list)
        print(f"📤 Sent {len(attack_list)} latest attacks to client")
        
    except Exception as e:
        print(f"❌ Error sending latest attacks: {e}")
        emit('error', {'message': 'Failed to retrieve latest attacks'})


# ═══════════════════════════════════════════════════════════════════
# APPLICATION STARTUP
# ═══════════════════════════════════════════════════════════════════

def initialize_application():
    """
    Initialize the application with database and background services.
    """
    print("🚀 Starting IoT HoneyNet Backend Server...")
    print("🔧 Initializing database...")
    
    # Initialize database and sample data
    init_db()
    setup_sample_devices()
    
    print("🎯 Starting attack simulation...")
    # Start attack simulation in background thread
    attack_thread = threading.Thread(target=simulate_attacks, daemon=True)
    attack_thread.start()
    
    print("✅ All systems initialized successfully!")
    
    if DEBUG_MODE:
        print("🌐 Server running at http://localhost:5000")
        print("📡 WebSocket available at same URL")
    else:
        port = os.environ.get('PORT', 5000)
        print(f"🌐 Production server starting on port {port}")
    
    print("📊 API endpoints available:")
    print("   - GET  /              (server status page)")
    print("   - GET  /api/stats     (dashboard statistics)")
    print("   - GET  /api/attacks   (attack logs)")
    print("   - GET  /api/devices   (device status)")
    print("📡 WebSocket events:")
    print("   - connect            (client connection)")
    print("   - new_attack         (real-time attack broadcast)")
    print("   - request_latest_attacks (get recent attacks)")


if __name__ == '__main__':
    # Initialize application
    initialize_application()
    
    # Start the server
    port = int(os.environ.get('PORT', 5000))
    
    if DEBUG_MODE:
        print("💡 Development mode - Press Ctrl+C to stop")
        socketio.run(app, debug=True, host='0.0.0.0', port=port)
    else:
        print("🚀 Production mode - Optimized for deployment")
        socketio.run(app, debug=False, host='0.0.0.0', port=port)
