# 🛰️ Network Packet Sniffer - Python GUI Tool

A simple **network packet sniffer** built in Python using **Tkinter GUI**.  
It allows you to **monitor incoming and outgoing network packets** on your system in real time, along with details like:

- ✅ Source IP and Destination IP  
- ✅ Source and Destination Port (for TCP/UDP)  
- ✅ Domain name (reverse DNS)  
- ✅ Protocol used (TCP, UDP, ICMP, etc.)  
- ✅ Protocol filtering  
- ✅ Table view with double-click detail popup

---

## 📌 Features

- 🖥️ **Graphical Interface** – Built using Tkinter (no CLI knowledge needed)
- 📶 **Live Packet Capture** – Captures packets directly from your network interface
- 🔍 **Protocol Filter** – Choose between All, TCP, UDP, ICMP
- 🧹 **Clear Table Button** – Quickly reset your view
- 📄 **Detailed Packet Popup** – Double-click any row for full details
- 🧠 **Reverse DNS Lookup** – Tries to get the domain name from destination IP

---

## 🛠️ Requirements

- OS: **Linux Only** (Tested on Kali Linux)
- Python: `3.x`
- Permissions: **Run as root/sudo** (needed to capture raw packets)

> No external libraries required — only built-in modules.

---

## 📂 File Structure

```
📁 Network_Sniffer/
│
├── packet_utils.py          # Logic to parse raw packet data
├── sniffer.py               # Main GUI file
├── README.md                # This file
```

---

## 🚀 How to Run

### 🔧 1. Open Terminal in Project Folder

Navigate to your project directory where `sniffer.py` and `packet_utils.py` are located.

### 🔐 2. Run the GUI Sniffer (as root)

```bash
sudo python3 sniffer.py
```

> You **must use `sudo`** or root privileges to open raw sockets on Linux.

---

## 📸 How it Looks

| Main GUI | Protocol Filter | Detail Popup |
|----------|------------------|---------------|
| ✅ Start/Stop buttons | ✅ Dropdown to select TCP/UDP/etc. | ✅ Full info on double-click |

---

## 🧪 What You Can Do With It

- See live network activity while browsing, streaming, etc.
- Filter out only TCP/UDP packets.
- Analyze which apps or websites your system is connecting to.
- View IPs, ports, and domains of active traffic.
- Learn how packet sniffers and raw sockets work!

---

## ⚠️ Disclaimer

This tool is meant for **educational and personal learning purposes**.  
**Do not use this on networks you do not own or have permission to monitor.**

---

## 💡 Troubleshooting

| Issue | Solution |
|-------|----------|
| ❌ No packets showing | Ensure you're connected to the internet and running as `sudo` |
| ❌ Protocol filter not working | Try switching to `All` and verify packets are arriving |
| ❌ "Permission denied" | Use `sudo python3 sniffer.py` |
| ❌ `packet_utils not found` | Make sure `packet_utils.py` is in the same folder |

---

## 👨‍💻 Author

Built by: `Chandan Raj` 
Feel free to modify and expand this project for deeper packet analysis!
