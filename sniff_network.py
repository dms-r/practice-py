from scapy.all import sniff, get_if_list, IP, TCP, UDP
from collections import defaultdict
import time
import sys

# Konfigurasi Awal
SUSPICIOUS_PORTS = [4444, 5555, 6666, 1337, 31337]
PACKET_LIMIT = 100
packet_count = 0
ip_counter = defaultdict(int)
suspicious_activity = []

def pilih_interface():
    interfaces = get_if_list()
    print("=== Daftar Interface Tersedia ===")
    for i, iface in enumerate(interfaces):
        print(f"{i + 1}. {iface}")

    while True:
        try:
            pilihan = int(input("\nPilih nomor interface yang akan digunakan: ")) - 1
            if 0 <= pilihan < len(interfaces):
                return interfaces[pilihan]
            else:
                print("Pilihan tidak valid. Coba lagi.")
        except ValueError:
            print("Masukkan angka yang valid.")

def process_packet(packet):
    global packet_count
    packet_count += 1

    if IP in packet:
        ip_src = packet[IP].src
        ip_counter[ip_src] += 1

        if TCP in packet:
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            if dport in SUSPICIOUS_PORTS or sport in SUSPICIOUS_PORTS:
                suspicious_activity.append((ip_src, dport))
                print(f"[!] Koneksi mencurigakan dari {ip_src} ke port {dport}")

        elif UDP in packet:
            dport = packet[UDP].dport
            if dport in SUSPICIOUS_PORTS:
                suspicious_activity.append((ip_src, dport))
                print(f"[!] UDP mencurigakan dari {ip_src} ke port {dport}")

    if packet_count >= PACKET_LIMIT:
        print_summary()
        sys.exit()

def print_summary():
    print("\n=== Ringkasan Aktivitas ===")
    print("Total paket yang diproses:", packet_count)
    print("Top IP pengirim:")
    for ip, count in sorted(ip_counter.items(), key=lambda x: x[1], reverse=True)[:5]:
        print(f"{ip} - {count} paket")

    if suspicious_activity:
        print("\nAktivitas mencurigakan yang terdeteksi:")
        for ip, port in suspicious_activity:
            print(f"{ip} -> Port {port}")
    else:
        print("\nTidak ada aktivitas mencurigakan yang terdeteksi.")

if __name__ == "__main__":
    interface = pilih_interface()
    print(f"\n[*] Memulai pemantauan pada interface: {interface}")
    sniff(iface=interface, prn=process_packet, store=False)
