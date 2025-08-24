"""
IoT HoneyNet WebSocket Server
Real-time attack broadcasting system using Flask-SocketIO
"""

import sqlite3
import threading
import time
from flask import Flask
from flask_socketio import SocketIO, emit

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")


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
        print(f"Database error: {e}")
        return None


@socketio.on('connect')
def handle_connect():
    """
    Handle new WebSocket client connections.
    Sends welcome message to connected client.
    """
    print('🔌 Client connected to WebSocket')
    emit('status', {'message': 'Connected to IoT HoneyNet Live Feed'})


@socketio.on('disconnect')
def handle_disconnect():
    """
    Handle WebSocket client disconnections.
    Log disconnection event.
    """
    print('🔌 Client disconnected')


def broadcast_attack_updates():
    """
    Continuously broadcast new attack updates to all connected clients.
    Runs in a background thread and checks for new attacks every 5 seconds.
    """
    last_attack_id = None
    
    while True:
        try:
            latest_attack = get_latest_attack()
            
            # Only broadcast if we have a new attack
            if latest_attack and (last_attack_id is None or latest_attack[0] != last_attack_id):
                attack_data = {
                    'id': latest_attack[0],
                    'timestamp': latest_attack[1],
                    'source_ip': latest_attack[2],
                    'target_device': latest_attack[3],
                    'attack_type': latest_attack[4],
                    'severity': latest_attack[5],
                    'status': latest_attack[6],
                    'country': latest_attack[7]
                }
                
                # Broadcast to all connected clients
                socketio.emit('new_attack', attack_data)
                print(f'📡 Broadcasted attack: {attack_data["attack_type"]} from {attack_data["source_ip"]}')
                
                last_attack_id = latest_attack[0]
                
        except Exception as e:
            print(f"❌ Error broadcasting attack: {e}")
        
        time.sleep(5)  # Check every 5 seconds


if __name__ == '__main__':
    print('🌐 Starting IoT HoneyNet WebSocket Server...')
    print('📡 Server will run on http://localhost:5001')
    
    # Start background thread for real-time updates
    broadcast_thread = threading.Thread(target=broadcast_attack_updates, daemon=True)
    broadcast_thread.start()
    
    print('✅ Background broadcast thread started')
    print('🎯 Waiting for WebSocket connections...')
    
    # Start the Flask-SocketIO server
    socketio.run(app, host='0.0.0.0', port=5001, debug=True)
