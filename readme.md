# **P2P ISDN Call Tracker Tool**

This project is an **educational tool** designed to help cybersecurity enthusiasts understand how **peer-to-peer (P2P) communication** works during ISDN voice or video calls. It demonstrates how public IP addresses can be exposed when P2P connections are used.  

When making ISDN voice or video calls, the app typically prioritizes direct **peer-to-peer (P2P)** communication to minimize latency and improve call quality. By avoiding relay servers, both devices exchange their **public IP addresses** directly. However, this mechanism could lead to **IP address exposure**, which, in malicious hands, could be used for reconnaissance or other attacks.

This project aims to capture network traffic on a local network, filter out packets related to ISDN calls, and extract the public IP addresses of the devices participating in the call.

---

## **🌟 Motivation**

- **Understanding ISDN P2P Calling**: ISDN's calling feature avoids using a relay server to reduce latency, relying on P2P communication. This means the two participating devices must share their **public IP addresses**.
- **IP Exposure Risks**: While P2P improves performance, exposing public IPs can lead to potential security risks:
  - **Reconnaissance**: Malicious actors can use the IP to locate users geographically or identify their ISPs.
  - **Denial-of-Service (DoS) Attacks**: IP addresses can be targeted in DoS or DDoS attacks.
- **Education and Awareness**: This tool is designed to make users aware of how public IPs can be exposed during P2P communication and how attackers might leverage such information.

---

## **⚙️ Features**

- **Real-time Packet Sniffing**: Captures live network traffic to analyze packets exchanged during ISDN calls.
- **ISDN Traffic Filtering**: Filters packets related to ISDN based on known IP ranges and ports.
- **Network Interface Detection**: Allows users to view and select the network interface for sniffing.
- **Geolocation of IPs**: Retrieves geographical location data (country, city, latitude, and longitude) for captured IPs.
- **Report Generation**:
  - Captured IPs are saved to JSON and CSV reports for further analysis.
  - Full packet logs are stored in `.pcap` format for inspection using tools like Wireshark.

---

## **🚀 How It Works**

1. **Network Interface Selection**:  
   The tool first lists all available network interfaces. For example:
   ```plaintext
   Available network interfaces:
     [0] Ethernet
     [1] Wi-Fi
     [2] Loopback Pseudo-Interface 1
   ```
   The user selects the desired interface (e.g., `Wi-Fi`).

2. **Packet Sniffing**:  
   The tool begins sniffing network packets on the selected interface and filters traffic related to ISDN. ISDN packets are identified based on:
   - **IP Ranges**: Known ISDN IP ranges (e.g., `31.13.64.0/18`, `157.240.0.0/16`).
   - **Ports**: ISDN typically uses UDP with dynamic ports in the range `49152-65535`.

3. **IP Address Extraction**:  
   The tool extracts the source and destination IPs from the captured packets.

4. **Geolocation Analysis**:  
   Public IPs are analyzed using a geolocation database (e.g., MaxMind GeoLite2) to identify the country, city, latitude, and longitude of each IP.

5. **Report Generation**:  
   Captured data is saved as:
   - **JSON Report**: For programmatic analysis.
   - **CSV Report**: For easy visualization and sharing.
   - **PCAP File**: Full packet logs for detailed analysis using Wireshark.

---

## **📋 Setup and Installation**

Follow these steps to set up and run the project on your system:

### **1. Clone the Repository**
```bash
git clone https://github.com/yash-goyal-0910/P2P-ISDN-call-tracer
cd P2P-ISDN-Call-Traceroute
```

### **2. Install Dependencies**
This project requires Python 3.7 or higher. Install the required Python libraries using:
```bash
pip install -r requirements.txt
```

### **3. Install Npcap**
- On Windows, you must install **Npcap** for Scapy to capture network packets.  
- Download and install it from [Npcap's official site](https://nmap.org/npcap/).  
  During installation:
  - Check the option **"Install Npcap in WinPcap API-compatible mode"**.
  - Allow non-administrator users to capture packets (if necessary).

---

## **💻 How to Run**

1. Open a terminal or command prompt in the project directory.

2. Run the script:
   ```bash
   python main.py
   ```

3. The script will display a list of available network interfaces:
   ```plaintext
   Available network interfaces:
     [0] Ethernet
     [1] Wi-Fi
     [2] Loopback Pseudo-Interface 1
   ```

4. Enter the number corresponding to the interface you want to use. For example:
   ```plaintext
   Enter the number of the interface you want to use: 1
   ```

5. The tool will start sniffing packets on the selected interface. Captured ISDN packets will be displayed in real-time, along with extracted IP addresses and geolocation data.

---


### **Sample Output**


```plaintext
Available network interfaces:
[0] Ethernet
[1] Wi-Fi
[2] Loopback Pseudo-Interface 1

Enter the number of the interface you want to use: 1
[+] You selected: Wi-Fi

[*] Starting packet sniffing...
[+] Captured ISDN Packet: 103.21.58.147 -> 182.74.200.67
[+] Captured ISDN Packet: 106.51.75.92 -> 59.144.23.158
[+] IP: 182.74.200.67 - Mumbai, India (19.0760, 72.8777)
[+] IP: 59.144.23.158 - Bhopal, India (23.2599, 77.4126)

```

### **JSON Report**
```json
[
  {
    "ip": "103.21.58.147",
    "country": "India",
    "city": "Mumbai",
    "latitude": 19.0760,
    "longitude": 72.8777
  },
  {
    "ip": "59.144.23.158", 
    "country": "India",
    "city": "Bhopal",
    "latitude": 23.2599,
    "longitude": 77.4126
  }
]
```

### **CSV Report**
```csv
ip,country,city,latitude,longitude
103.21.58.147,India,Mumbai,19.0760,72.8777
59.144.23.158,India,Bhopal,23.2599,77.4126
```

---

### **⚠️ Legal Disclaimer**

This tool is intended for **educational purposes only**. Unauthorized network sniffing or monitoring may violate privacy laws or terms of service agreements. Always ensure you have proper authorization before using this tool in any real-world environment. The authors are not responsible for misuse of this tool.

---

### **Reference-**

https://github.com/arshadakl/Whatsapp-P2P-Traceroute


