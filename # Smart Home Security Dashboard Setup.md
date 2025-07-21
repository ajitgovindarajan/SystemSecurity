# Smart Home Security Dashboard Setup

## Requirements

Create a `requirements.txt` file with the following dependencies:

```
flask==2.3.3
flask-socketio==5.3.6
python-nmap==0.7.1
scapy==2.5.0
psutil==5.9.5
requests==2.31.0
```

## Installation Steps

1. **Create project directory:**
   ```bash
   mkdir smart-home-security
   cd smart-home-security
   ```

2. **Create virtual environment:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Install system dependencies:**
   ```bash
   # Ubuntu/Debian
   sudo apt-get install nmap

   # macOS
   brew install nmap

   # Windows - download from https://nmap.org/download.html
   ```

5. **Create directory structure:**
   ```
   smart-home-security/
   ├── app.py                 # Main Python backend
   ├── templates/
   │   └── index.html        # Frontend HTML
   ├── requirements.txt
   └── security_dashboard.db # SQLite database (created automatically)
   ```

## Running the Application

1. **Start the dashboard:**
   ```bash
   python app.py
   ```

2. **Access the dashboard:**
   Open your browser and go to `http://localhost:5000`

3. **Click "Start Monitoring"** to begin scanning your network

## Key Features

### 🔍 Device Discovery
- Automatically scans your local network (192.168.1.0/24 by default)
- Identifies IP addresses, MAC addresses, and device types
- Attempts to resolve hostnames and identify vendors

### 🛡️ Security Assessment
- Calculates security scores based on open ports and vulnerabilities
- Flags devices with common security issues
- Identifies unknown or untrusted devices

### 📊 Real-time Monitoring
- Live dashboard with WebSocket updates
- Continuous network scanning every 30 seconds
- Instant security alerts

### 🚨 Alert System
- Monitors for security threats and anomalies