import pyshark
from datetime import datetime

INTERFACE = "any"
LOG_FILE = "/home/ananya-k-m/ctf/custom-ids/wireshark_ids_log.txt"

print("🦈 Wireshark IDS Started...")
print(f"📡 Monitoring: {INTERFACE}")
print("="*50)

def save_log(message):
    with open(LOG_FILE, "a") as f:
        f.write(message + "\n")

def analyze_packet(packet):
    try:
        time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if hasattr(packet, 'tcp') and hasattr(packet, 'ip'):
            dport = str(packet.tcp.dstport)
            sport = str(packet.tcp.srcport)
            if dport == '22' or sport == '22':
                msg = f"🔐 [{time}] SSH Connection Attempt! From: {packet.ip.src} To: {packet.ip.dst}"
                print(msg)
                save_log(msg)

            print(f"DEBUG FLAGS: {packet.tcp.flags}")

            try:
                flags = int(str(packet.tcp.flags), 16)
                if flags & 0x02 and not flags & 0x10:
                    msg = f"🚨 [{time}] PORT SCAN DETECTED! From: {packet.ip.src}"
                    print(msg)
                    save_log(msg)
            except:
                pass

        if hasattr(packet, 'arp'):
            msg = f"⚠️  [{time}] ARP Packet Detected! From: {packet.arp.src_proto_ipv4}"
            print(msg)
            save_log(msg)

    except AttributeError:
        pass

with open(LOG_FILE, "a") as f:
    f.write("\n" + "="*50 + "\n")
    f.write(f"IDS Session: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    f.write("="*50 + "\n")

capture = pyshark.LiveCapture(interface=INTERFACE)
capture.apply_on_packets(analyze_packet)
