import socket
from concurrent.futures import ThreadPoolExecutor

def scan_port(ip, port):
    """Memindai port tertentu pada IP target."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)  # waktu tunggu per port
        sock.connect((ip, port))
        return port
    except:
        return None
    finally:
        sock.close()

def main():
    target_ip = input("Masukkan IP target: ").strip()
    port_range = input("Masukkan range port (misal 1-1000): ").strip()

    start_port, end_port = map(int, port_range.split('-'))
    print(f"\nMemindai {target_ip} dari port {start_port} hingga {end_port}...\n")

    open_ports = []
    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = [executor.submit(scan_port, target_ip, port) for port in range(start_port, end_port + 1)]
        for future in futures:
            result = future.result()
            if result:
                open_ports.append(result)

    if open_ports:
        print(f"\nPort terbuka di {target_ip}: {open_ports}")
    else:
        print(f"\nTidak ditemukan port terbuka di {target_ip}.")

if __name__ == "__main__":
    main()
