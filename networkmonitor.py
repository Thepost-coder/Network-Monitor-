import psutil
import socket
import csv
import os
import time
import requests
import pandas as pd
from datetime import datetime
from winotify import Notification

# ── CONFIG ─────────────────────────────────────────────────────────────────────
MISTRAL_API_KEY    = "YOUR_MISTRAL_API_KEY_HERE"    # <-- paste your Mistral key
VIRUSTOTAL_API_KEY = "YOUR_VIRUSTOTAL_API_KEY_HERE" # <-- paste your VirusTotal key

MISTRAL_API_URL  = "https://api.mistral.ai/v1/chat/completions"
MISTRAL_MODEL    = "mistral-small-latest"
VIRUSTOTAL_URL   = "https://www.virustotal.com/api/v3"

CSV_FILE          = "flagged_connections.csv"
ANALYSIS_INTERVAL = 3 * 60 * 60   # 3 hours in seconds
APP_ID            = "Network Monitor"

# Set to True to enable VirusTotal checks, False to skip and send straight to Mistral
USE_VIRUSTOTAL = True

# ── DOMAIN WHITELIST ───────────────────────────────────────────────────────────
WHITELIST_KEYWORDS = [
    "google.com", "googleapis.com", "googleusercontent.com",
    "gstatic.com", "googletagmanager.com", "android.l.google",
    "1e100.net",
    "microsoft.com", "windows.com", "windowsupdate.com", "live.com",
    "azure.com", "msftconnecttest.com",
    "cloudflare.com", "cloudflare.net",
    "fastly.net",
    "amazonaws.com",
    "akamai.com", "akamaized.net",
    "linkedin.com",
    "github.com",
    "apple.com",
    "cdn.jsdelivr.net",
    "intercom.com", "intercomcdn.com",
    "sentry.io",
    "hsappstatic.net",
    "licdn.com",
]

# ── TRUSTED PROCESS WHITELIST ──────────────────────────────────────────────────
TRUSTED_PROCESSES = [
    # ── Windows system processes ──────────────────────────────────────────────
    # Uncomment these if you want to trust Windows system processes
    # WARNING: malware often hijacks these — keep commented for better security
    # "svchost.exe",
    # "lsass.exe",
    # "services.exe",
    # "wininit.exe",
    # "winlogon.exe",
    # "explorer.exe",
    # "taskhostw.exe",
    # "spoolsv.exe",
    # "RuntimeBroker.exe",
    # "SearchIndexer.exe",
    # "ctfmon.exe",

    # ── Bitdefender ───────────────────────────────────────────────────────────
    "bdservicehost.exe", "ProductAgentService.exe", "bdagent.exe",
    "bdntwrk.exe", "bdredline.exe", "vsserv.exe", "updatesrv.exe",

    # ── Avast ─────────────────────────────────────────────────────────────────
    "avastui.exe", "avastsvc.exe", "afwserv.exe",
    "aswidsagenta.exe", "aswenginesrv.exe",

    # ── AVG ───────────────────────────────────────────────────────────────────
    "avgui.exe", "avgsvc.exe", "avgsvca.exe", "avgidsagenta.exe",

    # ── Norton / Symantec ─────────────────────────────────────────────────────
    "nortonlifelock.exe", "nortonsecurity.exe", "nsWscSvc.exe",
    "symantec.exe", "ccsvchst.exe",

    # ── Kaspersky ─────────────────────────────────────────────────────────────
    "avp.exe", "avpui.exe", "kavtray.exe",

    # ── Malwarebytes ──────────────────────────────────────────────────────────
    "mbam.exe", "MBAMService.exe", "mbamtray.exe",

    # ── Windows Defender ──────────────────────────────────────────────────────
    "MsMpEng.exe", "MpCmdRun.exe", "SecurityHealthSystray.exe",

    # ── ESET ──────────────────────────────────────────────────────────────────
    "egui.exe", "ekrn.exe",

    # ── McAfee ────────────────────────────────────────────────────────────────
    "mcshield.exe", "mctray.exe", "mcuicnt.exe",

    # ── Trend Micro ───────────────────────────────────────────────────────────
    "pccntmon.exe", "tmbmsrv.exe",

    # ── Browsers ──────────────────────────────────────────────────────────────
    # Uncomment to trust browsers and stop flagging their connections
    # "chrome.exe",
    # "firefox.exe",
    # "msedge.exe",
    # "opera.exe",
    # "brave.exe",
]

# ── HELPERS ────────────────────────────────────────────────────────────────────

def resolve_ip(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ip

def is_raw_ip(value):
    parts = value.split(".")
    return len(parts) == 4 and all(p.isdigit() for p in parts)


"""
Old way of looking up IP with no SSL just Http
def lookup_ip_owner(ip):
    try:
        response = requests.get(
            f"http://ip-api.com/json/{ip}?fields=org,country,isp",
            timeout=5
        )
        if response.status_code == 200:
            data    = response.json()
            org     = data.get("org", "")
            isp     = data.get("isp", "")
            country = data.get("country", "")
            owner   = org or isp or "Unknown owner"
            return f"{owner} | {country}"
    except Exception:
        pass
    return "Unknown owner (lookup failed)"
"""

def lookup_ip_owner(ip):
    try:
        # Use ipapi.co for HTTPS (Privacy)
        response = requests.get(
            f"https://ipapi.co/{ip}/json/", 
            timeout=5,
            headers={'User-Agent': 'Mozilla/5.0'} # Helps avoid being blocked as a bot
        )
        
        if response.status_code == 200:
            data = response.json()
            # If the API returns an error message in the JSON
            if data.get("error"):
                return f"Lookup Limit Hit ({data.get('reason')})"
                
            org     = data.get("org", "")
            asn     = data.get("asn", "")
            country = data.get("country_name", "")
            owner   = org or asn or "Unknown Network"
            return f"{owner} | {country}"
            
        elif response.status_code == 429:
            return "Rate Limited (Too many lookups)"
            
    except Exception as e:
        print(f" [Lookup Debug] Error: {e}")
        
    return "Unknown owner (lookup failed)"

def get_process_name(pid):
    try:
        return psutil.Process(pid).name()
    except Exception:
        return "Unknown"

def is_whitelisted(domain, app=""):
    domain_safe  = any(kw in domain.lower() for kw in WHITELIST_KEYWORDS)
    process_safe = any(p.lower() == app.lower() for p in TRUSTED_PROCESSES)
    return domain_safe or process_safe

def init_csv():
    if not os.path.exists(CSV_FILE):
        with open(CSV_FILE, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "Timestamp", "App", "Local Address", "Remote Address",
                "Domain", "IP Owner", "VT Result", "VT Detections", "Status", "Analyzed"
            ])

def append_to_csv(timestamp, app, local, remote, domain, ip_owner, vt_result, vt_detections):
    with open(CSV_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            timestamp, app, local, remote, domain,
            ip_owner, vt_result, vt_detections, "FLAGGED", "No"
        ])

# ── TOAST NOTIFICATION (silent, no sound) ─────────────────────────────────────

def toast_notify(title, message):
    """Send a silent Windows toast notification — no sound."""
    try:
        toast = Notification(
            app_id=APP_ID,
            title=title,
            msg=message,
            duration="short"
        )
        # No audio set — completely silent
        toast.show()
    except Exception as e:
        print(f"[WARNING] Toast notification failed: {e}")

# ── VIRUSTOTAL ─────────────────────────────────────────────────────────────────

def virustotal_check(domain_or_ip):
    """Check a domain or IP against VirusTotal. Returns (result, detections)."""
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        if is_raw_ip(domain_or_ip):
            url = f"{VIRUSTOTAL_URL}/ip_addresses/{domain_or_ip}"
        else:
            url = f"{VIRUSTOTAL_URL}/domains/{domain_or_ip}"

        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code == 200:
            data       = response.json()
            stats      = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious  = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total      = sum(stats.values()) if stats else 0
            detections = malicious + suspicious

            if detections == 0:
                return "CLEAN", f"0/{total} engines flagged"
            else:
                return "THREAT", f"{detections}/{total} engines flagged"

        elif response.status_code == 404:
            return "UNKNOWN", "Not in VirusTotal database"
        elif response.status_code == 429:
            print("  [VT] Rate limit hit, skipping")
            return "SKIPPED", "Rate limit"
        else:
            return "ERROR", f"VT error {response.status_code}"

    except Exception as e:
        return "ERROR", str(e)

# ── MISTRAL ANALYSIS ───────────────────────────────────────────────────────────

def load_unanalyzed():
    try:
        df = pd.read_csv(CSV_FILE)
        unanalyzed = df[df["Analyzed"] == "No"]
        return df, unanalyzed
    except Exception as e:
        print(f"[ERROR] Could not load CSV: {e}")
        return None, None

def mark_as_analyzed(df):
    df["Analyzed"] = "Yes"
    df.to_csv(CSV_FILE, index=False)

def send_to_mistral(unanalyzed_df):
    if unanalyzed_df.empty:
        print("\n[INFO] No new flagged connections to analyze.")
        return

    if USE_VIRUSTOTAL:
        # Only send THREAT or UNKNOWN to Mistral — skip confirmed CLEAN entries
        to_explain  = unanalyzed_df[unanalyzed_df["VT Result"].isin(["THREAT", "UNKNOWN", "ERROR", "SKIPPED"])]
        clean_count = len(unanalyzed_df) - len(to_explain)
        print(f"\n[INFO] {clean_count} entries confirmed CLEAN by VirusTotal — skipping.")
        print(f"[INFO] {len(to_explain)} entries need Mistral explanation.")
    else:
        # VirusTotal disabled — send everything to Mistral
        to_explain  = unanalyzed_df
        clean_count = 0
        print(f"\n[INFO] VirusTotal disabled — sending all {len(to_explain)} entries to Mistral.")

    if to_explain.empty:
        print("[INFO] Nothing to send to Mistral.")
        toast_notify(
            "Network Monitor - All Clear",
            f"All {clean_count} connections confirmed clean by VirusTotal."
        )
        return

    lines = []
    for _, row in to_explain.iterrows():
        ip_owner   = row.get("IP Owner", "N/A")
        vt_result  = row.get("VT Result", "N/A")
        vt_detect  = row.get("VT Detections", "N/A")
        lines.append(
            f"- App: {row['App']} | Domain/IP: {row['Domain']} "
            f"| Owner: {ip_owner} "
            f"| VirusTotal: {vt_result} ({vt_detect}) "
            f"| Time: {row['Timestamp']}"
        )

    connection_list = "\n".join(lines)

    prompt = f"""You are a cybersecurity assistant. Below is a list of network connections from a Windows PC.

{"Each entry has been checked by VirusTotal. THREAT means antivirus engines flagged it. UNKNOWN means it was not in the VirusTotal database. SKIPPED means VirusTotal was not checked." if USE_VIRUSTOTAL else "These connections were not on the trusted whitelist and need reviewing."}

Please explain each one clearly:
1. What the domain or IP likely is
2. How serious the threat is if flagged
3. What the user should do about it

Keep it simple and clear for a non-technical user.

Connections:
{connection_list}
"""

    print("\n" + "=" * 70)
    print("  SENDING TO MISTRAL FOR ANALYSIS...")
    print("=" * 70)

    toast_notify("Network Monitor", f"Analyzing {len(to_explain)} connections with Mistral...")

    try:
        response = requests.post(
            MISTRAL_API_URL,
            headers={
                "Authorization": f"Bearer {MISTRAL_API_KEY}",
                "Content-Type": "application/json"
            },
            json={
                "model": MISTRAL_MODEL,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 1500
            },
            timeout=30
        )

        if response.status_code == 200:
            result   = response.json()
            analysis = result["choices"][0]["message"]["content"]

            print("\n MISTRAL ANALYSIS REPORT")
            print("-" * 70)
            print(analysis)
            print("-" * 70)

            # Toast based on whether threats were found
            threats = to_explain[to_explain["VT Result"] == "THREAT"] if USE_VIRUSTOTAL else pd.DataFrame()
            if len(threats) > 0:
                toast_notify(
                    "Network Monitor - ALERT",
                    f"{len(threats)} threat(s) detected! Check the report."
                )
            else:
                toast_notify(
                    "Network Monitor - Report Ready",
                    f"{len(to_explain)} connection(s) analyzed. Check the report."
                )

            # Save report
            report_file = f"analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(report_file, "w") as f:
                f.write(f"Analysis Report - {datetime.now()}\n")
                f.write("=" * 70 + "\n\n")
                if USE_VIRUSTOTAL:
                    f.write(f"VirusTotal Clean  : {clean_count}\n")
                    f.write(f"Needs Review      : {len(to_explain)}\n")
                    f.write(f"Confirmed Threats : {len(threats)}\n\n")
                f.write("Connections Sent to Mistral:\n")
                f.write(connection_list + "\n\n")
                f.write("Mistral Response:\n")
                f.write(analysis + "\n")
            print(f"\n[INFO] Report saved to: {report_file}")

        else:
            print(f"[ERROR] Mistral API error: {response.status_code} - {response.text}")

    except Exception as e:
        print(f"[ERROR] Failed to contact Mistral: {e}")

# ── MAIN LOOP ──────────────────────────────────────────────────────────────────

def monitor():
    init_csv()
    seen          = set()
    last_analysis = time.time()

    print("=" * 70)
    print("  NETWORK MONITOR")
    print(f"  CSV file       : {CSV_FILE}")
    print(f"  Mistral report : every 3 hours")

    print(f"  IP lookup      : ipapi.co (HTTPS/Secure)")
    print(f"  VirusTotal     : {'ENABLED' if USE_VIRUSTOTAL else 'DISABLED'}")
    print(f"  Notifications  : silent toast")
    print("=" * 70)
    print(f"{'TIME':<10} {'APP':<25} {'DOMAIN/IP':<35} {'VT':<10} {'FLAG'}")
    print("-" * 70)

    toast_notify("Network Monitor", "Started! Monitoring your network connections.")

    while True:
        try:
            connections = psutil.net_connections(kind="inet")

            for conn in connections:
                if conn.status != "ESTABLISHED" or not conn.raddr:
                    continue

                remote_ip   = conn.raddr.ip
                remote_port = conn.raddr.port
                local_addr  = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
                remote_addr = f"{remote_ip}:{remote_port}"
                pid         = conn.pid

                if remote_ip.startswith("127.") or remote_ip == "::1":
                    continue

                app       = get_process_name(pid)
                domain    = resolve_ip(remote_ip)
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                key       = (app, domain)

                whitelisted = is_whitelisted(domain, app)

                if whitelisted:
                    short_time = datetime.now().strftime("%H:%M:%S")
                    print(f"{short_time:<10} {app:<25} {domain:<35} {'':10} OK")
                    continue

                if key not in seen:
                    seen.add(key)

                    # Real time IP owner lookup
                    if is_raw_ip(domain):
                        print(f"           [Looking up IP owner: {domain}]")
                        ip_owner = lookup_ip_owner(remote_ip)
                        print(f"           [Owner: {ip_owner}]")
                    else:
                        ip_owner = ""

                    # VirusTotal check (if enabled)
                    if USE_VIRUSTOTAL:
                        print(f"           [Checking VirusTotal: {domain}]")
                        vt_result, vt_detections = virustotal_check(domain)
                        print(f"           [VT: {vt_result} - {vt_detections}]")

                        # Immediate silent toast if threat found
                        if vt_result == "THREAT":
                            toast_notify(
                                "Network Monitor - THREAT DETECTED",
                                f"{app} connecting to {domain} — {vt_detections}"
                            )
                    else:
                        vt_result, vt_detections = "SKIPPED", "VT disabled"

                    append_to_csv(timestamp, app, local_addr, remote_addr,
                                  domain, ip_owner, vt_result, vt_detections)

                short_time = datetime.now().strftime("%H:%M:%S")
                print(f"{short_time:<10} {app:<25} {domain:<35} {vt_result:<10} FLAGGED")

            # ── Check if 3 hours have passed ──────────────────────────────────
            elapsed   = time.time() - last_analysis
            remaining = ANALYSIS_INTERVAL - elapsed
            hrs       = int(remaining // 3600)
            mins      = int((remaining % 3600) // 60)
            print(f"  [Next analysis in: {hrs}h {mins}m]")

            if elapsed >= ANALYSIS_INTERVAL:
                df, unanalyzed = load_unanalyzed()
                if df is not None:
                    send_to_mistral(unanalyzed)
                    mark_as_analyzed(df)
                last_analysis = time.time()

            time.sleep(5)
            print("-" * 70)

        except KeyboardInterrupt:
            print("\n[!] Monitor stopped.")
            toast_notify("Network Monitor", "Stopped. Network monitoring ended.")
            break
        except Exception as e:
            print(f"[ERROR] {e}")
            time.sleep(5)

if __name__ == "__main__":
    monitor()