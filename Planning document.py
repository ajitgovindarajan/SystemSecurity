"""
This project will be the smart home secuitydashboard IndentationError
We need the core features to build first and foremost

First the system needs to have a full system apporach to scan the network for IoT devices
also we need monitor the devie comms and trafic patterns througout the network

Track when ever the devces come online of offline
Identify any suspicious devices
"""
"""
Traffic analysis
captue and analyze packets betwwen the the IoT divces using Scapy
Monitor for unusual data tramsmission patterns
Detect devces communicating with unexpected external sernvers
Flag the unencrytped communications that need to be encrypted
"""

"""
Then we need a vulnerability assessment
check devces for default passwords
scan ports being open and services
Test for common IoT vulnerabilities (weak authentication, firmware issues)
Generate security scores for each device
"""

"""
Set up a real time dashboard

Live network topology visualization
security alerats ad notifications
Device status monitoring
Traffic flow diamgrams also
Historical seurity events as well as a stored history
"""

"""
Backend (Python)
We could use Flask/FastAPI or Streamlit for the web framework
Scay for packet capture
nmap for the network scanning
SQLite for storing device information and alerts
Threading poractices for the continuous monitoring
"""

"""
Frontend
React of Javascript
Chart.js or D3.js for visualization parts
Websocket for the real-ime updates
Then Bootstrap for responsive design
"""