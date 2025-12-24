"""
Blockchain-Backed Router Log Management System
Core implementation with ML anomaly detection and IoT trust scoring
Updated to work with Hardhat blockchain
"""
# Import useful libraries
import hashlib  # for making unique hashes
import json # for reading and writing JSON - Javascript Object Notation - store and exchange data.
import time # for time stamps
import requests  # for sending HTTP requests
from datetime import datetime # for date and time
from collections import defaultdict # for easy default dictionary 
import numpy as np  # for numbers and arrays
from sklearn.ensemble import IsolationForest # ML model - Scikit-Learn's a collection of ML algorithms that use multiple models together
# Isolation Forest = an algorithm to detect anomalies (weird behavior)

# ==================== LOG GENERATOR ====================
class LogGenerator:
    """Simulates router/firewall/IoT device logs"""
    
    def __init__(self):
        self.device_ids = [f"IOT-{i:03d}" for i in range(1, 11)] # list of 10 IoT devices - IOT-001 to IOT-010
        self.normal_ips = ["192.168.1.10", "192.168.1.20", "192.168.1.30"] # safe IPs - safe internal network IPs
        self.attacker_ips = ["203.0.113.5", "198.51.100.42"]  # bad attacker IPs - represent suspicious sources.
        
    def generate_normal_log(self):
        device = np.random.choice(self.device_ids) # chooses a random IoT device 
        ip = np.random.choice(self.normal_ips)   # assigns one normal IP
        action = np.random.choice(["login_success", "data_transfer", "heartbeat"])    # selects random action
        packets = np.random.randint(50, 200) # It generates packets between 50–200 (normal traffic)
        
        # It returns a dictionary containing: timestamp, device id, source IP, action, packets, failed attempts, log type
        return {
            "timestamp": datetime.now().isoformat(), # time now
            "device_id": device,   # which device
            "source_ip": ip, # IP address
            "action": action, # what it did
            "packets": packets,  # number of packets
            "failed_attempts": 0,  # no failed logins
            "type": "normal" # this is a normal log
        }
    
    # six types of attack scenarios
    def generate_attack_log(self, attack_type="brute_force"): 
        device = np.random.choice(self.device_ids) # random device
        ip = np.random.choice(self.attacker_ips)  # attacker IP
        # Brute force attack - Someone is repeatedly trying to log in — password guessing attack.
        if attack_type == "brute_force":
            return {
                "timestamp": datetime.now().isoformat(),
                "device_id": device,
                "source_ip": ip,
                "action": "login_failed",  # failed login
                "packets": np.random.randint(10, 50),  # small packets
                "failed_attempts": np.random.randint(5, 20),  # many fails
                "type": "brute_force"    
            }
        # DDoS attack - Device is flooded with traffic.
        elif attack_type == "ddos":
            return {
                "timestamp": datetime.now().isoformat(),
                "device_id": device,
                "source_ip": ip,
                "action": "traffic_spike",  # huge traffic
                "packets": np.random.randint(1000, 5000),   # large packets
                "failed_attempts": 0,
                "type": "ddos"
            }
        # Data exfiltration attack - Log is normal but ML model may still think it's suspicious.
        elif attack_type == "data_exfiltration":
            return {
                "timestamp": datetime.now().isoformat(),
                "device_id": device,
                "source_ip": ip,
                "action": "large_data_transfer",
                "packets": np.random.randint(800, 1500),
                "failed_attempts": 0,
                "type": "data_exfiltration"
            }
        # False positive attack 
        # Appears normal but misdetected by ML
        elif attack_type == "false_positive":
            return {
                "timestamp": datetime.now().isoformat(),
                "device_id": device,
                "source_ip": ip,
                "action": "heartbeat",              # looks normal
                "packets": np.random.randint(80, 120),
                "failed_attempts": 0,
                "type": "false_positive"
            }
        # Log deletion attack - Indicates someone is trying to delete or erase logs.
        elif attack_type == "log_deletion":
            return {
                "timestamp": datetime.now().isoformat(),
                "device_id": device,
                "source_ip": ip,
                "action": "log_deletion_event",    # delete logs
                "packets": 0,
                "failed_attempts": 0,
                "type": "log_deletion"
            }
         # Log modification attack - Logs have been tampered with.
        elif attack_type == "log_modification":
            return {
                "timestamp": datetime.now().isoformat(),
                "device_id": device,
                "source_ip": ip,
                "action": "log_modification_event",    # change logs
                "packets": np.random.randint(5, 20),
                "failed_attempts": 0,
                "type": "log_modification"
            }

# ==================== BLOCKCHAIN ====================
class SimpleBlockchain:
    """
    This class provides:
    - A simulated blockchain log store
    - OR real connection to Hardhat blockchain (if running)

    Every log is hashed, and the hash is appended to the chain.
    This makes logs tamper-evident.
    """
    # rpc_url is the URL of your blockchain node (default is Hardhat running locally at 127.0.0.1:8545).
    # RPC = Remote Procedure Call ;
    # It’s a way for a program to call a function/method on another server as if it were local.
    def __init__(self, rpc_url="http://127.0.0.1:8545"): 
        self.rpc_url = rpc_url    # Blockchain RPC endpoint
        # JSON-RPC is often used in blockchain nodes, web servers, or APIs to send requests and get responses.
        self.request_id = 0   # JSON-RPC request index - It’s a specific type of RPC that uses JSON as the message format.
        self.chain = []       # Local blockchain simulation
        self.log_hashes = {}    # Maps hash -> block index
        
        # Check if Hardhat blockchain is running
        self.connected = self._check_connection()
        if self.connected:
            print("✅ Connected to Hardhat blockchain")
            print(f"🔢 Current block: {self._get_block_number()}")
        else:
            print("⚠️  Running in offline mode (blockchain simulator)")
            print("   Tip: Start Hardhat with 'npx hardhat node' for full blockchain features")
        
    def _check_connection(self):
        """
        Sends a 'eth_blockNumber' request to check if Hardhat is active.
        If request succeeds → connected.
        """
        try:
            result = self._rpc_call("eth_blockNumber")
            return result is not None
        except:
            return False
    
    
    def _rpc_call(self, method, params=None):
        """
        Sends a JSON-RPC request.
        Used for communication with Hardhat blockchain.
        """
        if params is None:
            params = []
         # JSON-RPC standard request body - Send a request to Hardhat node using JSON-RPC and get a response.
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": self.request_id
        }
        self.request_id += 1
        # Send POST request
        try:
            response = requests.post(self.rpc_url, json=payload, timeout=2) # sends an HTTP POST request to a server
            return response.json().get("result") # converts the response from JSON string to Python dict
        except:
            return None
    
    def _get_block_number(self):
        """Returns latest blockchain block number."""
        result = self._rpc_call("eth_blockNumber")
        if result:
            return int(result, 16) # hex to integer
        return 0
    
    def _store_on_hardhat(self, log_hash, device_id):
        """
        Sends transaction to Hardhat blockchain.
        Stores log hash inside dummy transaction data.
        """
        if not self.connected:
            return None
        
        accounts = self._rpc_call("eth_accounts")
        if not accounts:
            return None
        
        tx_params = { 
            "from": accounts[0], # sending account (the first account from Hardhat)
            "to": accounts[0], # receiving account (dummy transfer so same account)
            "data": "0x" + log_hash[:64],  # first 64 chars of hash
            "gas": "0x5208"   # fixed gas
        }
        
        try: # Sends the transaction via JSON-RPC eth_sendTransaction.
            tx_hash = self._rpc_call("eth_sendTransaction", [tx_params])
            return tx_hash
        except:
            return None
    
    def add_log_hash(self, log_data):
        """
        Adds a new log hash to blockchain.

        Steps:
        1. Convert log → JSON string (sorted)
        2. Compute SHA-256 hash
        3. Append block to local chain
        4. (If running Hardhat) store hash in a blockchain txn
        """
        log_str = json.dumps(log_data, sort_keys=True)  # Sort keys ensures deterministic hashing
        log_hash = hashlib.sha256(log_str.encode()).hexdigest()  # Compute SHA-256 hash
        
        # Create local blockchain block
        block = {
            "index": len(self.chain),
            "timestamp": time.time(),
            "log_hash": log_hash,
            "device_id": log_data.get("device_id"),
            "prev_hash": self.chain[-1]["log_hash"] if self.chain else "0"
        }
        # Store on real blockchain if connected
        if self.connected:
            self._store_on_hardhat(log_hash, log_data.get("device_id"))
        # Add block locally
        self.chain.append(block)
        # Keep lookup table : Maps the hash → its index in the chain.
        self.log_hashes[log_hash] = len(self.chain) - 1
        return log_hash
    
    def verify_log(self, log_data):
        """
        Checks if a given log matches stored blockchain hash.
        Detects tampering.
        """
        log_str = json.dumps(log_data, sort_keys=True)
        log_hash = hashlib.sha256(log_str.encode()).hexdigest()
        
        # Checks if this hash exists in the local blockchain. If yes → log is valid.
        if log_hash in self.log_hashes:
            return True, "Log verified on blockchain"
        else:
            return False, "TAMPERING DETECTED: Log hash not found on blockchain"


# ==================== ML ANOMALY DETECTOR ====================
class AnomalyDetector:  # unsupervised machine learning
    # Isolation Forest, an unsupervised ML model.
    # It learns normal behavior and 
    # flags anything strange.
    
    def __init__(self):
        # contamination=0.1 → assumes 10% logs are anomalies
        self.model = IsolationForest(contamination=0.1, random_state=42)
        self.is_trained = False # Flag to check whether the model has been trained.
        
    def train(self, normal_logs):
        """Trains the ML model using ONLY normal logs."""
        features = self._extract_features(normal_logs) # Converts normal logs into numerical features for ML
        self.model.fit(features) # Trains the Isolation Forest model using normal log features only.
        self.is_trained = True # marks model as trained 
        
    def detect(self, log):
        """
        Predicts if a new log is normal (1) or anomaly (-1).
        Isolation Forest returns:
        - 1 : normal
        - -1 : anomaly
        """
        if not self.is_trained:
            return 1, "Model not trained"
        
        feature = self._extract_features([log]) # Extract features for the new log.
        prediction = self.model.predict(feature)[0] # predicts  1 → normal log ; -1 anamoly
        
        if prediction == -1:
            return -1, self._classify_anomaly(log)  
        return 1, "Normal behavior"
    
    def _extract_features(self, logs):
        """
        Converts logs → numerical features for ML.

        Features used:
        1. packets count
        2. failed login attempts
        3. whether action == login_failed
        """
        features = []
        for log in logs:
            features.append([
                log.get("packets", 0), # packets → number of packets in the log.
                log.get("failed_attempts", 0), # failed_attempts → failed login attempts.
                1 if log.get("action") == "login_failed" else 0 # login_failed_flag → 1 if login failed, 0 otherwise.
            ])
        return np.array(features) # numpy array as thats required by scikit learn
    
    def _classify_anomaly(self, log):
        """
        Rule-based classification for anomaly explanation.
        ML only detects 'anomaly', not attack type.
        """
        if log.get("action") == "log_deletion_event":
            return "LOG DELETION DETECTED"
        
        if log.get("action") == "log_modification_event":
            return "LOG MODIFICATION DETECTED"

        # High failed logins → brute force
        if log.get("failed_attempts", 0) > 3:
            return "BRUTE FORCE ATTACK"
        
        # Very high packets → DDoS or Data exfiltration
        elif log.get("packets", 0) > 800:
            if log.get("action") == "traffic_spike":
                return "DDOS ATTACK"
            else:
                return "DATA EXFILTRATION"

        return "SUSPICIOUS ACTIVITY"


# ==================== IOT TRUST SCORER ====================
class IoTTrustScorer:
    """
    Assigns each IoT device a 'trust score' (0–100).
    Score decreases when anomalies detected.
    """
    
    def __init__(self):
        self.trust_scores = defaultdict(lambda: 100)  # start all devices at 100
        self.CRITICAL_THRESHOLD = 30
        self.WARNING_THRESHOLD = 60
        
    def update_score(self, device_id, is_anomaly, severity="medium"):
        """
        Adjusts score:
        - High severity attack → -20 points
        - Medium attack → -10
        - Low severity → -5
        - No anomaly → slowly recover (+1)
        """
        if is_anomaly:
            if severity == "high":
                self.trust_scores[device_id] -= 20
            elif severity == "medium":
                self.trust_scores[device_id] -= 10
            else:
                self.trust_scores[device_id] -= 5
        else:
            # Slowly recover trust back to 100
            if self.trust_scores[device_id] < 100:
                self.trust_scores[device_id] += 1
        # Keep score between 0 and 100
        self.trust_scores[device_id] = max(0, min(100, self.trust_scores[device_id]))
        
    def get_status(self, device_id):  # Uses thresholds
        """Returns textual health status based on score."""
        score = self.trust_scores[device_id]
        if score < self.CRITICAL_THRESHOLD:  # Score < 30
            return "CRITICAL - QUARANTINE RECOMMENDED"
        elif score < self.WARNING_THRESHOLD:  # Score 30–59
            return "WARNING - MONITOR CLOSELY"
        else:        # Score ≥ 60
            return "HEALTHY"
    
    def get_score(self, device_id): # Returns the current numeric trust score of a device. - for monitoring
        return self.trust_scores[device_id] 


# ==================== MAIN SYSTEM ====================
class LogManagementSystem:
    """
    This class ties everything together:
    - Generates logs
    - Runs ML detection
    - Updates trust
    - Stores/validates blockchain logs
    """    
    def __init__(self):
        # Creates instances of all modules: blockchain, ML, trust scoring, and log generator.
        # self.local_logs keeps a local copy of every log, which is essential for detecting deletion or modification later.
        self.blockchain = SimpleBlockchain()
        self.anomaly_detector = AnomalyDetector()
        self.trust_scorer = IoTTrustScorer()
        self.log_generator = LogGenerator()
        self.local_logs = []  # store original logs to compare later
        
    def initialize(self):
        """Trains the ML model using 100 normal logs."""
        print("🔧 Initializing system...")
        # Generates 100 normal logs for training ML.
        normal_logs = [self.log_generator.generate_normal_log() for _ in range(100)]
        # Trains the IsolationForest model to learn normal behavior.
        # After this, any log deviating from normal will be detected as anomalous.
        self.anomaly_detector.train(normal_logs)
        print("✅ ML model trained on normal behavior\n")
        
    def process_log(self, log):
        """
        Main function for handling each log:
        - Save log locally
        - Store its hash on blockchain
        - Check anomaly using ML
        - Apply trust score updates
        - Return summarized result
        """
        self.local_logs.append(log)  # Save log locally.
        # Compute a SHA-256 hash and store it in the blockchain
        log_hash = self.blockchain.add_log_hash(log)
        # Uses ML to detect if log is anomalous.
        anomaly_status, anomaly_type = self.anomaly_detector.detect(log)
        is_anomaly = (anomaly_status == -1)
        # Checks if a normal-looking log was mistakenly flagged by ML.
        false_positive = self.detect_false_positive(log, anomaly_type)
        if false_positive:
            anomaly_type = "FALSE POSITIVE"
            is_anomaly = False
        
        # Higher trust penalty for attacks
        # Updates the trust score based on anomaly severity.
        severity = "high" if "ATTACK" in anomaly_type else "medium"
        self.trust_scorer.update_score(log["device_id"], is_anomaly, severity)
        # Update trust score
        trust_score = self.trust_scorer.get_score(log["device_id"])
        device_status = self.trust_scorer.get_status(log["device_id"])
        # Override anomaly type based on exact scenario
        scenario = log.get("type")

        if scenario == "brute_force":
            anomaly_type = "BRUTE FORCE ATTACK"
        elif scenario == "ddos":
            anomaly_type = "DDOS ATTACK"
        elif scenario == "data_exfiltration":
            anomaly_type = "DATA EXFILTRATION"
        elif scenario == "log_deletion":
            anomaly_type = "LOG DELETION DETECTED"
        elif scenario == "log_modification":
            anomaly_type = "LOG MODIFICATION DETECTED"
        elif scenario == "false_positive":
            anomaly_type = "FALSE POSITIVE DETECTED"
        # Return useful summary
        return {
            "log_hash": log_hash[:16] + "...",
            "blockchain_verified": True,
            "is_anomaly": is_anomaly,
            "anomaly_type": anomaly_type if is_anomaly else "None",
            "device_id": log["device_id"],
            "trust_score": trust_score,
            "device_status": device_status
        }
    
    def simulate_tampering(self, log_index):
        # To simulate a malicious change in a log to test the blockchain's tamper-detection.
        # Checks if the given index exists in the list of stored logs.
        if log_index < len(self.local_logs): 
            tampered_log = self.local_logs[log_index].copy() # Makes a copy of the selected log to avoid altering the original.
            tampered_log["action"] = "tampered_action"
            
            # Uses the blockchain's verify_log method to check if the tampered log matches any stored hash.
            verified, message = self.blockchain.verify_log(tampered_log)
            return verified, message
        # log matches blockchain hash (not tampered) --> verified is true
        return None, "Log index out of range"
    
    def check_log_deletion(self):
        # To detect if a log was deleted locally, even though its hash exists on the blockchain.
        alerts = []
        for block in self.blockchain.chain:
            h = block["log_hash"] # h stores the hash of the log in that block.
            
            found = False
            # Checks each local log to see if its hash matches the blockchain hash
            for log in self.local_logs:
                log_str = json.dumps(log, sort_keys=True) # json.dumps(..., sort_keys=True) ensures consistent JSON string order.
                if hashlib.sha256(log_str.encode()).hexdigest() == h: # computes the SHA-256 hash
                    found = True
                    break
            
            if not found:
                alerts.append(f"LOG DELETION DETECTED for device {block['device_id']}")
        
        return alerts if alerts else ["No log deletion detected"]
    
    def check_log_modification(self):
        # To detect if local logs were modified compared to the stored blockchain hash.
        alerts = []
        
        for log in self.local_logs: # loops through all local logs
            log_str = json.dumps(log, sort_keys=True) 
            current_hash = hashlib.sha256(log_str.encode()).hexdigest() # Computes the current SHA-256 hash of each log.
            # If the hash does not exist in blockchain, the log was modified → add alert.
            if current_hash not in self.blockchain.log_hashes:
                alerts.append(f"LOG MODIFICATION DETECTED in device {log['device_id']}")
        
        return alerts if alerts else ["No log modification detected"]

    def detect_false_positive(self, log, anomaly_type):
        # Checks if a log appears normal based on certain rules: 
        # No failed login attempts, packet count<250, action is standard one
        looks_normal = (
            log.get("failed_attempts", 0) == 0 and
            log.get("packets", 0) < 250 and
            log.get("action") in ["login_success", "data_transfer", "heartbeat"]
        )
        
        if anomaly_type != "None" and looks_normal:
            return True
        
        return False


# ==================== DEMO ====================
def run_demo():
    print("=" * 60)
    print("🔐 BLOCKCHAIN-BACKED LOG MANAGEMENT SYSTEM")
    print("=" * 60 + "\n")
    
    system = LogManagementSystem()
    system.initialize()
    
    print("📊 SCENARIO 1: Normal Operation")
    print("-" * 60)
    for i in range(3):
        log = system.log_generator.generate_normal_log()
        result = system.process_log(log)
        print(f"Log {i+1}: {result['device_id']} | Trust: {result['trust_score']} | Status: {result['device_status']}")

    print("\n🚨 SCENARIO 2: Brute Force Attack")
    print("-" * 60)
    for i in range(3):
        log = system.log_generator.generate_attack_log("brute_force")
        result = system.process_log(log)
        print(f"⚠️  BRUTE FORCE | Device: {result['device_id']} | Trust: {result['trust_score']}")

    print("\n🚨 SCENARIO 3: DDoS Attack")
    print("-" * 60)
    log = system.log_generator.generate_attack_log("ddos")
    result = system.process_log(log)
    print(f"⚠️  DDoS | Device: {result['device_id']} | Trust: {result['trust_score']}")

    print("\n🚨 SCENARIO 4: Data Exfiltration")
    print("-" * 60)
    log = system.log_generator.generate_attack_log("data_exfiltration")
    result = system.process_log(log)
    print(f"⚠️  DATA EXFILTRATION | Device: {result['device_id']} | Trust: {result['trust_score']}")

    print("\n🚨 SCENARIO 5: Log Deletion Detection")
    print("-" * 60)
    log = system.log_generator.generate_attack_log("log_deletion")
    result = system.process_log(log)
    print(f"⚠️  LOG DELETION EVENT | Device: {result['device_id']} | Trust: {result['trust_score']}")

    print("\n🚨 SCENARIO 6: Log Modification Detection")
    print("-" * 60)
    log = system.log_generator.generate_attack_log("log_modification")
    result = system.process_log(log)
    print(f"⚠️  LOG MODIFICATION EVENT | Device: {result['device_id']} | Trust: {result['trust_score']}")

    print("\n🔍 Checking manual tampering...")
    verified, message = system.simulate_tampering(0)
    print("Tampering Check:", message)

    print("\nDemo complete.")


if __name__ == "__main__":
    run_demo()
