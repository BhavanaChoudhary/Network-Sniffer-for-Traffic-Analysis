# Network Sniffer for Traffic Analysis

This project is a network traffic sniffer built with Python using Flask and Flask-SocketIO. It captures network packets on your machine and displays detailed packet information in a web interface in real-time.

## Features

- Captures Ethernet frames, IPv4 packets, and protocols such as ICMP, TCP, and UDP.
- Displays packet details including source/destination addresses, ports, flags, and data.
- Real-time updates to the web interface using WebSocket.

## Requirements

- Python 3.x
- Administrator/root privileges (required for raw socket access)
- Python packages:
  - flask
  - flask-socketio
  - (optional) eventlet or gevent for improved WebSocket performance

## Installation

1. Clone or download this repository.

2. Install the required Python packages:
   ```bash
   pip install flask flask-socketio
   ```
   Optionally, install eventlet for better SocketIO performance:
   ```bash
   pip install eventlet
   ```

## Running the Application

> **Important:** Running the packet sniffer requires administrator privileges due to raw socket usage.

1. Open your command prompt or terminal as Administrator.

2. Navigate to the project directory:
   ```bash
   D:
   cd "d:/Projects/Network Sniffer for Traffic Analysis"
   ```

3. Run the application:
   ```bash
   python app.py
   ```

4. Open your web browser and go to:
   ```
   http://localhost:5000/
   ```

You should see the Traffic Sniffer web interface displaying captured network packets in real-time.

## Notes

- Make sure no other application is blocking raw socket access.
- This tool is intended for educational and authorized network monitoring purposes only.

## License

This project is provided as-is without any warranty.
