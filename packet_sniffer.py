from scapy.all import sniff, IP, TCP
from collections import defaultdict
from datetime import datetime

# ==============================
# Data Structures
# ==============================

ip_ports = defaultdict(set)    # unique ports per IP
ip_counts = defaultdict(int)   # packet count per IP
alerted_ips = set()            # to avoid repeated alerts

LOG_FILE = "alerts.log"


# ==============================
# Packet Processing Function
# ==============================

def packet_callback(packet):

    if packet.haslayer(IP) and packet.haslayer(TCP):

        source_ip = packet[IP].src
        destination_port = packet[TCP].dport

        timestamp = datetime.now().strftime("%H:%M:%S")

        # Track data
        ip_ports[source_ip].add(destination_port)
        ip_counts[source_ip] += 1

        print(f"[{timestamp}] {source_ip} → Port {destination_port}")

        # Detection logic
        if len(ip_ports[source_ip]) > 5 and source_ip not in alerted_ips:

            alert_message = (
                "\n" + "="*40 + "\n"
                "⚠ ALERT: Possible Port Scan Detected\n"
                f"Time: {timestamp}\n"
                f"Attacker IP: {source_ip}\n"
                f"Number of unique ports: {len(ip_ports[source_ip])}\n"
                + "="*40 + "\n"
            )

            print(alert_message)

            # Save to file
            with open(LOG_FILE, "a") as f:
                f.write(alert_message + "\n")

            alerted_ips.add(source_ip)


# ==============================
# Main Program
# ==============================

print("🛡 IDS running... Press CTRL + C to stop\n")

try:
    sniff(iface="eth0", prn=packet_callback)

except KeyboardInterrupt:
    print("\nStopping IDS...")

    print("\n===== TRAFFIC SUMMARY =====")
    for ip, count in ip_counts.items():
        print(f"{ip} → {count} packets")

    if ip_counts:
        top_ip = max(ip_counts, key=ip_counts.get)
        print(f"\nTop Active IP: {top_ip} ({ip_counts[top_ip]} packets)")
