from scapy.all import sniff, get_if_list, IP
from collections import defaultdict
from colorama import Fore, Style
import time

# Show available interfaces
print("🖥️  Available Network Interfaces:")
interfaces = get_if_list()
for i, iface in enumerate(interfaces):
    print(f"{i+1}. {iface}")

# Choose interface
choice = int(input("\nEnter the number of the interface to sniff: ")) - 1
iface = interfaces[choice]
print(f"\n🚀 Sniffing on: {iface}\n")

packet_count = defaultdict(int)
start_time = time.time()
LOG_FILE = "packet_log.txt"

def log_to_file(data):
    with open(LOG_FILE, "a") as f:
        f.write(data + "\n")

def packet_callback(packet):
    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        packet_count[src] += 1

        info = f"{src} -> {dst}"
        print(Fore.GREEN + "[+] " + info + Style.RESET_ALL)
        log_to_file(info)

        # Detect suspicious activity (too many packets quickly)
        if packet_count[src] > 20 and (time.time() - start_time) < 10:
            print(Fore.RED + f"[!] Suspicious activity from {src}" + Style.RESET_ALL)

# Start sniffing
sniff(prn=packet_callback, iface=iface, store=False)
