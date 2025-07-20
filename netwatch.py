#!/usr/bin/env python3
import subprocess, time, yaml, json, os, socket, re, requests
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, TimeoutError

hostname_cache = {}

def log(msg, scope="INFO"):
    stamp = datetime.now().strftime("%H:%M:%S")
    print(f"{stamp} [{scope}] {msg}")

def normalize(s):
    return s.lower().strip()

def load_config():
    try:
        with open("config.yaml") as f:
            return yaml.safe_load(f)
    except Exception as e:
        log(f"Could not load config.yaml: {e}", "ERROR")
        return {}

def expand_path(path):
    return os.path.expanduser(path)

def load_known_devices(state_file):
    try:
        with open(state_file, "r") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except:
        return {}

def save_known_devices(state_file, devices):
    try:
        os.makedirs(os.path.dirname(state_file), exist_ok=True)
        with open(state_file, "w") as f:
            json.dump(devices, f, indent=2)
    except:
        pass

def arp_scan(interface):
    try:
        result = subprocess.run(
            ["sudo", "arp-scan", "--interface=" + interface, "--localnet"],
            capture_output=True, text=True
        )
        return result.stdout
    except KeyboardInterrupt:
        log("Scan interrupted.", "EXIT")
        raise
    except:
        return ""

def get_hostname(ip):
    cached = hostname_cache.get(ip)
    if cached and time.time() - cached["ts"] < 600:
        return cached["name"]

    name = None
    try:
        name = socket.gethostbyaddr(ip)[0]
    except:
        pass
    if not name:
        try:
            r = subprocess.run(["avahi-resolve", "-a", ip],
                               capture_output=True, text=True)
            if r.returncode == 0:
                parts = r.stdout.strip().split('\t')
                if len(parts) >= 2:
                    name = parts[1]
        except:
            pass
    if not name:
        try:
            r = subprocess.run(["nmblookup", "-A", ip],
                               capture_output=True, text=True)
            for line in r.stdout.splitlines():
                if "<00>" in line and "<GROUP>" not in line:
                    name = line.strip().split()[0]
                    break
        except:
            pass

    name = name or "Unknown"
    hostname_cache[ip] = {"name": name, "ts": time.time()}
    return name

def load_oui_database(oui_path):
    vendors = {}
    if not os.path.exists(oui_path):
        return vendors
    with open(oui_path) as f:
        for line in f:
            match = re.match(r"^([0-9A-F\-]+)\s+\(base 16\)\s+(.+)$", line.strip())
            if match:
                prefix = match[1].replace("-", "").lower()[0:6]
                name = match[2].strip()
                vendors[prefix] = name
    return vendors

def lookup_vendor(mac, oui_db):
    prefix = mac.replace(":", "").lower()[0:6]
    return oui_db.get(prefix)

def parse_arp_scan_output(output, oui_db):
    devices = {}
    ip_mac_pairs = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0].count('.') == 3:
            ip_mac_pairs.append((parts[0], parts[1]))

    try:
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {ip: executor.submit(get_hostname, ip) for ip, _ in ip_mac_pairs}
            for ip, mac in ip_mac_pairs:
                try:
                    hostname = futures[ip].result(timeout=3)
                except (TimeoutError, KeyboardInterrupt):
                    log(f"Timeout or interrupt during hostname for {ip}", "WARN")
                    hostname = "Unknown"
                vendor = lookup_vendor(mac, oui_db) or "Unknown"
                devices[ip] = {"mac": mac, "hostname": hostname, "vendor": vendor}
    except KeyboardInterrupt:
        log("Interrupt during hostname parsing — shutting down", "EXIT")
        raise

    return devices

def should_alert(ip, device, known_devices, config):
    if ip not in known_devices:
        return True

    mac = device["mac"].lower()
    hostname = device["hostname"].lower()
    vendor = device["vendor"].lower()

    always = config.get("always_alert", {}).get("macs", [])
    suppress = config.get("suppress_flap", {})

    if normalize(mac) in [normalize(m) for m in suppress.get("mac_addresses", [])]:
        log(f"Suppressed by MAC: {mac}", "SUPPRESS")
        return False
    if normalize(vendor) in [normalize(v) for v in suppress.get("vendors", []) if isinstance(v, str)]:
        log(f"Suppressed by Vendor: {vendor}", "SUPPRESS")
        return False
    if normalize(hostname) in [normalize(h) for h in suppress.get("hostnames", []) if isinstance(h, str)]:
        log(f"Suppressed by Hostname: {hostname}", "SUPPRESS")
        return False

    return True

def send_discord_alert(webhook_url, title, color, devices):
    embeds = []
    for ip, d in devices.items():
        embeds.append({
            "title": title,
            "color": color,
            "fields": [
                {"name": "Hostname", "value": d["hostname"], "inline": False},
                {"name": "IP", "value": ip, "inline": False},
                {"name": "MAC", "value": d["mac"], "inline": False},
                {"name": "Vendor", "value": d["vendor"], "inline": False}
            ],
            "timestamp": datetime.utcnow().isoformat()
        })
    try:
        r = requests.post(webhook_url, json={"embeds": embeds})
        if r.status_code not in (200, 204):
            log(f"Discord alert failed: {r.status_code}", "WARN")
    except Exception as e:
        log(f"Alert error: {e}", "ERROR")

def main():
    config = load_config()
    webhook_url = config.get("webhook_url")
    if not webhook_url:
        log("Missing webhook_url in config.yaml", "ERROR")
        return

    poll_interval = config.get("poll_interval", 60)
    interface = config.get("interface", "eth0")
    state_file = expand_path(config.get("state_file", "~/.config/netwatch/known_devices.json"))
    oui_path = expand_path(config.get("oui_file", "oui.txt"))
    oui_db = load_oui_database(oui_path)

    log(f"NetWatch engaged on {interface}, polling every {poll_interval}s", "BOOT")

    log(f"Initial network scan on {interface}...", "SCAN")
    t0 = time.time()
    output = arp_scan(interface)
    log(f"arp-scan completed in {int(time.time() - t0)}s", "PERF")

    t0 = time.time()
    current_devices = parse_arp_scan_output(output, oui_db)
    log(f"parse_arp_scan_output completed in {int(time.time() - t0)}s", "PERF")
    log(f"Initial scan found {len(current_devices)} device{'s' if len(current_devices) != 1 else ''}.", "INIT")

    save_known_devices(state_file, current_devices)
    known_devices = current_devices
    next_scan = time.time()

    try:
        while True:
            wait = max(0, next_scan - time.time())
            time.sleep(wait)
            next_scan += poll_interval

            config = load_config()
            log(f"Scanning network on {interface}...", "SCAN")

            t0 = time.time()
            output = arp_scan(interface)
            log(f"arp-scan completed in {int(time.time() - t0)}s", "PERF")

            t0 = time.time()
            current_devices = parse_arp_scan_output(output, oui_db)
            log(f"parse_arp_scan_output completed in {int(time.time() - t0)}s", "PERF")

            new, gone = {}, {}
            ignored = 0

            for ip, d in current_devices.items():
                if ip not in known_devices:
                    if should_alert(ip, d, known_devices, config):
                        new[ip] = d
                    else:
                        ignored += 1
                else:
                    if not should_alert(ip, d, known_devices, config):
                        ignored += 1

            for ip, d in known_devices.items():
                if ip not in current_devices and should_alert(ip, d, known_devices, config):
                    gone[ip] = d

            log(f"Found {len(new)} new device{'s' if len(new) != 1 else ''}, {len(gone)} disconnected, {ignored} ignored.", "DIFF")

            if new:
                send_discord_alert(webhook_url, "🟢 NetWatch: Device Joined", 65280, new)
            if gone:
                send_discord_alert(webhook_url, "🔴 NetWatch: Device Left", 16711680, gone)

            if new or gone:
                save_known_devices(state_file, current_devices)

            known_devices = current_devices

    except KeyboardInterrupt:
        log("🛑 NetWatch terminated.", "EXIT")

if __name__ == "__main__":
    main()
