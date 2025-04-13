import os
import sys
import time
from scapy.all import IP, TCP, conf
from PacketCapture import PacketCapture
from TrafficAnalyzer import TrafficAnalyzer
from DetectionEngine import DetectionEngine
from AlertSystem import AlertSystem

def check_root():
    if os.geteuid() != 0:
        print("ERROR: This script requires root privileges for packet capture.")
        print("Please run with: sudo python3 main.py")
        sys.exit(1)

def get_network_interface():
    """Find active network interface with automatic fallback"""
    interfaces = ["eth0", "wlan0", "tun0", "lo"]
    for interface in interfaces:
        if os.path.exists(f"/sys/class/net/{interface}"):
            print(f"[+] Found active interface: {interface}")
            return interface
    print("[!] Warning: No known interfaces found, defaulting to eth0")
    return "eth0"

def print_banner():
    print("\n" + "="*60)
    print("||" + " "*56 + "||")
    print("||    Real-Time Intrusion Detection System (Nmap Detector)    ||")
    print("||" + " "*56 + "||")
    print("="*60)
    print(f"|| Started at: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*60 + "\n")

def main():
    check_root()
    print_banner()
    
    # Configure Scapy for better performance
    conf.verb = 0  # Disable Scapy's default verbose output
    
    interface = get_network_interface()
    print(f"[*] Using network interface: {interface}")
    print("[*] Initializing components...")
    
    # Initialize components with verbose debugging
    packet_capture = PacketCapture(debug=True)
    traffic_analyzer = TrafficAnalyzer()
    detection_engine = DetectionEngine()
    alert_system = AlertSystem()

    # Start packet capture
    print("[*] Starting packet capture...")
    packet_capture.start_capture(interface=interface)

    try:
        print("\n[+] IDS now running. Testing Nmap detection capabilities...")
        print("[!] Try these scans from your Windows machine:")
        print("    - nmap -sS <kali-ip>  # Stealth scan")
        print("    - nmap -sX <kali-ip>  # Xmas scan")
        print("    - nmap -sN <kali-ip>  # Null scan")
        print("\n[*] Monitoring network traffic...\n")
        
        last_activity_time = time.time()
        packet_count = 0
        alert_count = 0
        
        while True:
            if not packet_capture.packet_queue.empty():
                packet = packet_capture.packet_queue.get()
                packet_count += 1
                last_activity_time = time.time()
                
                # Display basic packet info
                if IP in packet and TCP in packet:
                    print(f"[Pkt #{packet_count}] {packet[IP].src}:{packet[TCP].sport} -> {packet[IP].dst}:{packet[TCP].dport} [{packet[TCP].flags}]", end="\r")
                
                features = traffic_analyzer.analyze_packet(packet)
                
                if features:
                    threats = detection_engine.detect_threats(features)
                    for threat in threats:
                        alert_count += 1
                        packet_info = {
                            'source_ip': packet[IP].src,
                            'destination_ip': packet[IP].dst,
                            'src_port': packet[TCP].sport,
                            'dst_port': packet[TCP].dport,
                            'flags': str(packet[TCP].flags)
                        }
                        alert_system.generate_alert(threat, packet_info)
                        
                        # Enhanced Nmap detection alerts
                        if 'nmap' in threat['rule']:
                            print("\n" + "!"*60)
                            print(f"[!!!] NMAP SCAN DETECTED! (Alert #{alert_count})")
                            print(f"    Scan Type: {threat['rule'].upper().replace('_',' ')}")
                            print(f"    From: {packet_info['source_ip']}")
                            print(f"    Flags: {packet_info['flags']}")
                            print(f"    Target Port: {packet_info['dst_port']}")
                            print("!"*60)
                        else:
                            print(f"\n[!] SECURITY ALERT #{alert_count}")
                            print(f"    Type: {threat['type'].upper()}")
                            print(f"    Rule: {threat['rule']}")
                            print(f"    From: {packet_info['source_ip']}:{packet_info['src_port']}")
                            print(f"    To: {packet_info['destination_ip']}:{packet_info['dst_port']}")
                            print(f"    Confidence: {threat.get('confidence', 0.0)*100:.1f}%")
            
            # Show heartbeat every 15 seconds if no activity
            if time.time() - last_activity_time > 15:
                print(f"\n[*] Status: Monitoring... (Captured {packet_count} packets, {alert_count} alerts so far)")
                last_activity_time = time.time()

    except KeyboardInterrupt:
        print("\n[*] Stopping IDS...")
        packet_capture.stop()
        print(f"[*] Statistics:")
        print(f"    Total packets processed: {packet_count}")
        print(f"    Total alerts generated: {alert_count}")
        print("[+] IDS shutdown complete")

if __name__ == "__main__":
    main()