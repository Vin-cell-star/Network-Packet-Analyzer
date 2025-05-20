# Network-Packet-Analyzer
from scapy.all import sniff, IP, TCP, UDP, Raw
from datetime import datetime

def packet_callback(packet):
    print("\n" + "-"*50)
    print(f"📅 Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    if IP in packet:
        ip_layer = packet[IP]
        print(f"🌐 IP Packet: {ip_layer.src} → {ip_layer.dst}")
        print(f"📦 Protocol: {packet.proto}")

        # Check for TCP or UDP
        if TCP in packet:
            print("🔒 TCP Packet")
        elif UDP in packet:
            print("📡 UDP Packet")

        # Check if packet has Raw payload
        if Raw in packet:
            payload = packet[Raw].load
            try:
                payload = payload.decode(errors='ignore')
            except Exception:
                payload = str(payload)
            print(f"📝 Payload: {payload}")

def main():
    print("🔍 Starting Packet Sniffer... (Press Ctrl+C to stop)")
    sniff(prn=packet_callback, store=0)

if _name_ == "_main_":
    main()
