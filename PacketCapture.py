from scapy.all import sniff, IP, TCP
import threading
import queue

class PacketCapture:
    def __init__(self, debug=False):
        self.packet_queue = queue.Queue()
        self.stop_capture = threading.Event()
        self.debug = debug
        self.packet_count = 0

    def packet_callback(self, packet):
        if IP in packet and TCP in packet:  # Only queue IP/TCP packets
            self.packet_queue.put(packet)
            self.packet_count += 1
            if self.debug and self.packet_count % 10 == 0:
                print(f"Captured {self.packet_count} packets")

    def start_capture(self, interface="eth0"):
        def capture_thread():
            if self.debug:
                print(f"Starting capture on {interface}")
            sniff(iface=interface,
                  prn=self.packet_callback,
                  store=0,
                  stop_filter=lambda _: self.stop_capture.is_set())

        self.capture_thread = threading.Thread(target=capture_thread)
        self.capture_thread.start()

    def stop(self):
        self.stop_capture.set()
        self.capture_thread.join()