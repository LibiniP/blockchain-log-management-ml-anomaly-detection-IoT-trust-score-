# Blockchain-Based Secure Logging System with IoT Trust Scoring

## Project Overview

This project implements a secure real-time logging system for IoT and network environments.  
It ensures log integrity using blockchain-backed hashing, detects abnormal behavior using machine learning, and continuously evaluates device reliability through dynamic trust scoring.

The system is designed to:
- Prevent log tampering (modification or deletion)
- Detect cyber-attacks and abnormal behavior in real time
- Track IoT device trustworthiness
- Provide a live monitoring dashboard

---

## System Architecture

The system consists of the following core components:

1. **Log Generator**  
2. **Blockchain Integrity Layer**  
3. **Anomaly Detection Engine**  
4. **Attack Classification Module**  
5. **IoT Device Trust Scoring**  
6. **Real-Time Monitoring Dashboard**  

All components operate in a single pipeline for real-time processing.

---

## Features

### 1. Log Generation
- Simulates logs from 10 IoT devices (IOT-001 to IOT-010)
- Generates structured JSON logs
- Supports both normal and malicious activity
- Log fields include:
  - Timestamp
  - Device ID
  - Packet count
  - Failed login attempts
  - Action type
  - Source IP

### 2. Blockchain Integrity Layer
- Each log is hashed using SHA-256
- Only hashes are stored on the blockchain (not full logs)
- Supports:
  - **Online mode** (Hardhat Ethereum test network)
  - **Offline mode** (internal blockchain simulator)
- Detects:
  - Log modification
  - Log deletion
- Ensures tamper-evident and verifiable logs

### 3. Anomaly Detection
- Uses **Isolation Forest** (unsupervised learning)
- Trained only on normal behavior
- Detects deviations in:
  - Packet volume
  - Failed login attempts
  - Action patterns
- Produces real-time anomaly predictions

### 4. Attack Classification

Detected anomalies are classified into:
- **Brute Force Login Attacks**  
- **Distributed Denial-of-Service (DDoS) Attacks**  
- **Data Exfiltration Attempts**  
- **Log Modification Attempts**  
- **Log Deletion Attempts**  
- **False Positive Anomalies** (reclassified as normal)

### 5. IoT Device Trust Scoring

- Each device starts with a trust score of **100**
- Trust scores update dynamically based on behavior

#### Trust Score Adjustments
- High-severity anomaly: **−20**  
- Medium-severity anomaly: **−10**  
- Low-severity anomaly: **−5**  
- Normal behavior recovery: **+1**  

#### Device States
- **Healthy:** ≥ 60  
- **Warning:** 30–59  
- **Critical:** < 30  

This enables early identification of compromised or risky devices.

### 6. Real-Time Dashboard
- Built using **Flask**
- Displays:
  - Total logs processed
  - Detected anomalies
  - Blockchain block numbers
  - Trust scores of all devices
  - Recent log activity
- Uses REST APIs and background threads
- Updates in real time for continuous monitoring

---

## Technologies Used

- **Python 3.x**  
- **Flask** (Web framework)
- **Scikit-learn** (Machine learning)
- **Pandas** (Data processing)
- **NumPy** (Numerical computing)
- **SHA-256 Cryptography** (Hash generation)
- **Ethereum** (Hardhat Test Network for blockchain)

---

## Installation

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)

### Install Dependencies

```bash
pip install flask scikit-learn pandas numpy
```

For Ethereum blockchain support:
```bash
npm install --save-dev hardhat
npx hardhat node
```

---

## How to Run

### 1. Clone the Repository
```bash
git clone https://github.com/LibiniP/blockchain-log-management-ml-anomaly-detection-IoT-trust-score-.git
cd blockchain-log-management-ml-anomaly-detection-IoT-trust-score-
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Run the Application
```bash
python Blockchain_Log_Management.py  
```

### 4. Access Dashboard
Open your browser and navigate to:
```
http://127.0.0.1:5000
```

---

## System Behavior

- Processes logs in real time with low latency
- Detects tampering immediately via hash mismatch
- Maintains stability during simulated attack scenarios
- Trust scores dynamically adapt to device behavior

---

## Project Structure

```
requirements.txt        # Python dependencies
README.md              # Project documentation
src/
├── Blockchain_Log_Management.py                 # Main application entry point
├── dashboard.py        # IoT log simulation
└── templates/
    └── dashboard.html     # Dashboard UI template
```

---

## Use Cases

- **Secure IoT log monitoring**
- **Network intrusion detection**
- **Log integrity verification**
- **Device behavior analysis**
- **Real-time security monitoring**
- **Compliance and audit trails**

---

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/YourFeature`)
3. Commit your changes (`git commit -m 'Add YourFeature'`)
4. Push to the branch (`git push origin feature/YourFeature`)
5. Open a Pull Request

---
