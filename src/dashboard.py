"""
Flask Dashboard for Blockchain Log Management System
Real-time monitoring of logs, anomalies, and IoT device trust scores
"""

from flask import Flask, render_template, jsonify # Flask: Web framework to create routes (/, /api/stats, etc.) and serve HTML
import threading # To run background log simulation without blocking the web server
import time # to add delays in the background simulation
from datetime import datetime

# Import the core system (assuming it's in the same directory)
# from blockchain_log_system import LogManagementSystem

app = Flask(__name__)

# Global system instance
system = None
recent_events = []
MAX_EVENTS = 50

def initialize_system():
    """Initialize the log management system"""
    global system 
    from Blockchain_Log_Management import LogManagementSystem
    system = LogManagementSystem() # Will hold the LogManagementSystem instance.
    system.initialize()
    # Generates 100 normal logs. Trains the ML anomaly detector on normal behavior.

def background_monitor(): # This runs in a separate thread to simulate log generation continuously.
    """Background thread to simulate continuous log monitoring"""
    global recent_events
    
    while True:
        # Generate random log (80% normal, 20% attack)
        import random
        if random.random() < 0.8:
            log = system.log_generator.generate_normal_log()
        else:
            attack_type = random.choice([
    "brute_force",
    "ddos",
    "data_exfiltration",
    "false_positive",
    "log_deletion",
    "log_modification"
])

            log = system.log_generator.generate_attack_log(attack_type)
        
        # Process log
        result = system.process_log(log) 
        # Processes log: Stores its hash on blockchain, Runs anomaly detection, Updates trust score
        
        # Add to recent events
        event = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "device_id": result["device_id"],
            "is_anomaly": result["is_anomaly"],
            "anomaly_type": result["anomaly_type"],
            "trust_score": result["trust_score"],
            "device_status": result["device_status"],
            "log_hash": result["log_hash"]
        }
        # Keeps the most recent logs at the top.
        # Lomits to max_events
        recent_events.insert(0, event)
        if len(recent_events) > MAX_EVENTS:
            recent_events.pop()
        
        # Sleep for a bit (adjust for demo speed)
        time.sleep(2)

@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('dashboard.html')

@app.route('/api/stats')
def get_stats():
    """Get current system statistics"""
    # Counts total logs and anomalies.
    total_logs = len(system.local_logs)
    anomalies = sum(1 for event in recent_events if event["is_anomaly"])
    
    # Device trust scores
    devices = {}
    for device_id in system.log_generator.device_ids:
        devices[device_id] = {
            "trust_score": system.trust_scorer.get_score(device_id),
            "status": system.trust_scorer.get_status(device_id)
        }
    # Loops over devices to get their current trust scores and status.
    return jsonify({
        "total_logs": total_logs,
        "total_anomalies": anomalies,
        "blockchain_blocks": len(system.blockchain.chain),
        "devices": devices
    })
# Sends structured JSON back to the frontend.

@app.route('/api/events')
def get_events():
    """Get recent events"""
    return jsonify({"events": recent_events[:20]}) # Returns the last 20 events for the dashboard.

@app.route('/api/verify/<int:log_index>')
def verify_log(log_index):
    """Verify a specific log against blockchain"""
    if log_index < len(system.local_logs):
        log = system.local_logs[log_index]  
        verified, message = system.blockchain.verify_log(log)
        return jsonify({
            "verified": verified,
            "message": message,
            "log": log
        }) # Returns whether the log is tampered or valid.
    return jsonify({"error": "Log not found"}), 404

def create_html_template():
    """Create the HTML template for the dashboard"""
    html_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Blockchain Log Management Dashboard</title>
    <link href="https://fonts.googleapis.com/css2?family=Open+Sans:wght@300;400;600&display=swap" rel="stylesheet">

    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Open Sans', sans-serif;
        }
        
        body {
            background: #d8f3d8;    /* light green */
            color: #000;           /* black text */
            padding: 20px;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
        }

        header {
            text-align: center;
            margin-bottom: 30px;
        }

        header h1 {
            font-size: 2.4em;
            font-weight: 600;
            margin-bottom: 5px;
        }

        header p {
            font-size: 1.1em;
            opacity: 0.8;
        }

        /* STATS GRID */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
            gap: 25px;
            margin-bottom: 35px;
        }

        .stat-card {
            background: #fcd6e3;  /* light pink */
            border-radius: 15px;
            padding: 25px;
            border: 2px solid #f7b7cd;
            text-align: center;
        }

        .stat-card h3 {
            text-transform: uppercase;
            letter-spacing: 1px;
            font-size: 0.9em;
            margin-bottom: 10px;
            font-weight: 600;
        }

        .stat-card .value {
            font-size: 2.4em;
            font-weight: bold;
        }

        /* MAIN GRID */
        .main-grid {
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 25px;
        }

        .panel {
            background: #fcd6e3; /* light pink */
            padding: 25px;
            border-radius: 15px;
            border: 2px solid #f7b7cd;
        }

        .panel h2 {
            margin-bottom: 20px;
            font-size: 1.4em;
            font-weight: 600;
        }

        /* EVENTS */
        .event {
            background: #ffd6e0;
            padding: 15px;
            border-radius: 10px;
            margin-bottom: 12px;
            border-left: 5px solid #7bb661;
        }

        .event.anomaly {
            border-left-color: #e80000;
            background: #ffc4c4;
        }

        .time {
            font-size: 0.85em;
            opacity: 0.7;
        }

        .device {
            font-weight: bold;
            margin-top: 5px;
        }

        /* DEVICES */
        .device-item {
            background: #ffd6e0;
            padding: 15px;
            border-radius: 10px;
            margin-bottom: 12px;
        }

        .device-item .device-id {
            font-weight: 600;
            margin-bottom: 10px;
        }

        .trust-bar {
            background: #ffe6ef;
            height: 20px;
            border-radius: 10px;
            overflow: hidden;
        }

        .trust-fill {
            height: 100%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 0.8em;
            font-weight: bold;
            transition: width 0.3s ease;
            color: white;
        }

        .trust-high {
            background: #4CAF50;
        }

        .trust-medium {
            background: #FF9800;
        }

        .trust-low {
            background: #f44336;
        }

        .status-badge {
            padding: 5px 10px;
            font-size: 0.8em;
            border-radius: 5px;
            display: inline-block;
            margin-top: 8px;
            font-weight: bold;
            color: white;
        }

        .status-healthy {
            background: #4CAF50;
        }

        .status-warning {
            background: #FF9800;
        }

        .status-critical {
            background: #f44336;
        }

        @media (max-width: 768px) {
            .main-grid {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>

<body>
    <div class="container">
        <header>
            <h1>🔐 Blockchain Log Management System</h1>
            <p>Real-time Network Forensics with ML Anomaly Detection</p>
        </header>

        <div class="stats-grid">
            <div class="stat-card">
                <h3>Total Logs</h3>
                <div class="value" id="total-logs">0</div>
            </div>
            <div class="stat-card">
                <h3>Anomalies Detected</h3>
                <div class="value" id="total-anomalies">0</div>
            </div>
            <div class="stat-card">
                <h3>Blockchain Blocks</h3>
                <div class="value" id="blockchain-blocks">0</div>
            </div>
        </div>

        <div class="main-grid">
            <div class="panel">
                <h2>📊 Recent Events</h2>
                <div id="events-container"></div>
            </div>

            <div class="panel">
                <h2>🛡️ IoT Device Trust Scores</h2>
                <div id="devices-container"></div>
            </div>
        </div>
    </div>

    <script>
        function updateDashboard() {
            fetch('/api/stats')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('total-logs').textContent = data.total_logs;
                    document.getElementById('total-anomalies').textContent = data.total_anomalies;
                    document.getElementById('blockchain-blocks').textContent = data.blockchain_blocks;

                    const devicesContainer = document.getElementById('devices-container');
                    devicesContainer.innerHTML = '';

                    for (const [deviceId, deviceData] of Object.entries(data.devices)) {
                        const score = deviceData.trust_score;

                        let trustClass = 'trust-high';
                        let statusClass = 'status-healthy';

                        if (score < 30) {
                            trustClass = 'trust-low';
                            statusClass = 'status-critical';
                        } else if (score < 60) {
                            trustClass = 'trust-medium';
                            statusClass = 'status-warning';
                        }

                        devicesContainer.innerHTML += `
                            <div class="device-item">
                                <div class="device-id">${deviceId}</div>
                                <div class="trust-bar">
                                    <div class="trust-fill ${trustClass}" style="width: ${score}%">${score}</div>
                                </div>
                                <span class="status-badge ${statusClass}">${deviceData.status}</span>
                            </div>
                        `;
                    }
                });

            fetch('/api/events')
                .then(response => response.json())
                .then(data => {
                    const eventsContainer = document.getElementById('events-container');
                    eventsContainer.innerHTML = '';

                    data.events.forEach(event => {
                        const anomalyClass = event.is_anomaly ? 'anomaly' : '';

                        eventsContainer.innerHTML += `
                            <div class="event ${anomalyClass}" style="${event.is_anomaly ? '' : 'background:#c8f7c5; border-left-color:#3fa63f;'}">
                                <div class="time">${event.timestamp}</div>
                                <div class="device">${event.device_id}</div>
                                <div class="status">
                                    ${event.is_anomaly ? '⚠️ ' + event.anomaly_type : '✅ Normal Operation'}
                                    | Trust: ${event.trust_score}
                                </div>
                            </div>
                        `;
                    });
                });
        }

        updateDashboard();
        setInterval(updateDashboard, 2000);
    </script>

</body>
</html>"""

    return html_content

if __name__ == '__main__':
    # Initialize system
    initialize_system() # Initializes the system (ML + log generator).
    
    # Starts background thread to simulate logs continuously.
    monitor_thread = threading.Thread(target=background_monitor, daemon=True)
    monitor_thread.start() 
    
    print("🚀 Starting dashboard on http://127.0.0.1:5000") # Starts background thread to simulate logs continuously
    app.run(debug=True, use_reloader=False)
