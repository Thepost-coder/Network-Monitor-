# 🔒 Network Monitor with AI Analysis

A lightweight Python tool that monitors all network connections on your Windows PC in real time, checks them against VirusTotal, and uses Mistral AI to explain anything suspicious — in plain English.

---

## 💡 How It Started

This tool was born out of a simple question — *"After a job interview with screen sharing, weird new windows keep popping up, pictures of your face taken, how do you know my PC is safe?"*

Looking at network connections with tools like GlassWire raised more questions than answers. Unknown domains, raw IP addresses, weird process names — with no easy way to know what was safe and what wasn't.

So this tool was built to do exactly that — monitor, filter, check, and explain — automatically.

---

## ✨ Features

- **Real time monitoring** — scans all active network connections every 5 seconds
- **Domain whitelist** — known safe domains like Google, Microsoft, Cloudflare are filtered out automatically
- **Trusted process whitelist** — antivirus software and known safe apps are excluded
- **IP owner lookup** — raw IP addresses are looked up in real time via [ip-api.com](http://ip-api.com) to find the registered owner
- **VirusTotal integration** — every new flagged connection is checked against 90+ antivirus engines
- **Mistral AI analysis** — every 3 hours, suspicious connections are sent to Mistral AI for a plain English explanation
- **Silent Windows notifications** — toast alerts with no sound when threats are detected or reports are ready
- **CSV logging** — all flagged connections are saved to a CSV file for review
- **Timestamped reports** — each Mistral analysis is saved as a `.txt` report file

---

## 🛠 Requirements

- Windows 10 or 11
- Python 3.8+
- A free [Mistral API key](https://console.mistral.ai)
- A free [VirusTotal API key](https://www.virustotal.com) *(optional — can be disabled)*

---
⚠️ Essential Warnings & Disclaimers
1. The "Plain English" Disclaimer

Privacy Warning: This script sends your network connection metadata (Domain names, IP addresses, and Process names) to third-party APIs (Mistral AI and VirusTotal) for analysis. Do not use this if you are handling highly sensitive or classified data.

2. The API Cost Warning

Since you are using "YOUR_API_KEY_HERE" placeholders, users need to know they are responsible for the costs.
Financial Liability: This tool requires personal API keys. Monitoring high-traffic systems may consume API credits rapidly. The author is not responsible for any charges incurred on your Mistral or VirusTotal accounts.

3. The "Not a Replacement for Antivirus" Note
You don't want someone relying solely on your script and then blaming you when they get a virus.
 Disclaimer: This is a secondary monitoring tool for educational purposes. It is NOT a replacement for a dedicated EDR (Endpoint Detection and Response) or Antivirus solution. Use at your own risk.

4. The "False Positive" Reality: This tool integrates with the VirusTotal API. Many "THREAT" flags are historical or result from shared infrastructure (like Cloudflare or AWS). A "THREAT" flag does not always mean your PC is infected; it means the destination IP has a history in the VirusTotal database.  You can modify the whitelist if you want to avoid those in the future.  

## 📦 Installation

**1. Clone the repository:**
```bash
git clone https://github.com/YOURUSERNAME/network-monitor.git
cd network-monitor
```

**2. Install dependencies:**
```bash
pip install psutil pandas requests winotify
```

Just double-check that you actually have winotify installed on your PC, or the script will error out immediately!
---

## ⚙️ Configuration

Open `network_monitor.py` and edit the config section at the top:

```python
MISTRAL_API_KEY    = "YOUR_MISTRAL_API_KEY_HERE"
VIRUSTOTAL_API_KEY = "YOUR_VIRUSTOTAL_API_KEY_HERE"

ANALYSIS_INTERVAL = 3 * 60 * 60   # how often to run Mistral (seconds)
USE_VIRUSTOTAL    = True           # set to False to disable VirusTotal
```

> ⚠️ **Never share or commit your real API keys to GitHub.**

---




## 🚀 Running the Tool

```bash
python network_monitor.py
```

The CMD window will show all active connections live:

```
TIME       APP                  DOMAIN/IP                        VT         FLAG
----------------------------------------------------------------------
14:23:01   firefox.exe          some-unknown-domain.com          THREAT     FLAGGED
14:23:01   chrome.exe           storage.googleapis.com                      OK
14:23:01   svchost.exe          104.208.203.88                   CLEAN      FLAGGED
```

- **OK** — matched the domain or process whitelist, ignored
- **CLEAN** — checked by VirusTotal, safe
- **THREAT** — flagged by one or more VirusTotal engines
- **UNKNOWN** — not in VirusTotal database
- **FLAGGED** — not whitelisted, logged to CSV

Every 3 hours Mistral AI analyses anything suspicious and saves a plain English report.

---

## 🔧 Customisation

### Adding safe domains to the whitelist
Open `network_monitor.py` and add to `WHITELIST_KEYWORDS`:
```python
WHITELIST_KEYWORDS = [
    "google.com",
    "anthropic.com",   # add your own here
    "151.101",         # IP prefixes work too e.g. Fastly
]
```

### Trusting Windows system processes
Windows system processes like `svchost.exe` and `explorer.exe` are **commented out by default** because malware commonly hijacks them. You can uncomment them in `TRUSTED_PROCESSES` if you want to trust them:
```python
# "svchost.exe",   # uncomment to trust
# "explorer.exe",  # uncomment to trust
```

### Disabling VirusTotal
If you don't have a VirusTotal API key or want to skip VT checks:
```python
USE_VIRUSTOTAL = False
```
All flagged connections will go straight to Mistral instead.

### Changing the analysis interval
Default is every 3 hours. To change:
```python
ANALYSIS_INTERVAL = 60          # 1 minute (good for testing)
ANALYSIS_INTERVAL = 3 * 60 * 60 # 3 hours (default)
ANALYSIS_INTERVAL = 6 * 60 * 60 # 6 hours
```

---

## 📁 Output Files

| File | Description |
|------|-------------|
| `flagged_connections.csv` | All flagged connections with VT results |
| `analysis_YYYYMMDD_HHMMSS.txt` | Mistral AI report for each analysis run |

---

## 🔍 How It Works

```
Connection detected
       ↓
Whitelist check → known safe domain or trusted app? → Skip
       ↓
ipapi.co (HTTPS) → who owns this IP? (real time lookup)
       ↓
VirusTotal → is this domain/IP known malware? (real time)
       ↓
Log to CSV
       ↓
Every 3 hours → Mistral AI explains anything suspicious
       ↓
Silent Windows toast notification + saved report
```

---

## ⚠️ Limitations

- VirusTotal free tier allows **4 lookups per minute** and **500 per day**
- Mistral free tier may be used to improve their models — do not send sensitive data
- IP ownership data from ip-api.com may occasionally be outdated
- This tool monitors connections, it does not block them

---

## 🤝 Contributing

Contributions are welcome! Some ideas for future improvements:

- Auto start on Windows boot via Task Scheduler
- Silent background mode using `pythonw`
- GUI dashboard
- Email reports
- IPv6 support
- Linux/Mac support

---

## 📄 License

MIT License — free to use, modify, and share.

---

*Built by a curious person who just wanted to know what their PC was doing after a job interview.*

