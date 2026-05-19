#!/usr/bin/env python3
"""
alert_arpspoof.py - Detector de ARP Spoofing mediante Scapy
Monitoriza respuestas ARP y alerta cuando una IP cambia de MAC (posible MITM)
"""

from scapy.all import sniff, ARP
from datetime import datetime

# Tabla ARP legítima: {IP: MAC}
arp_table = {}

def alert_arpspoof(packet):
    if packet.haslayer(ARP) and packet[ARP].op == 2:  # op=2 es ARP reply
        ip_src  = packet[ARP].psrc
        mac_src = packet[ARP].hwsrc

        if ip_src in arp_table:
            if arp_table[ip_src] != mac_src:
                ts = datetime.now().strftime("%H:%M:%S")
                print(f"\n[!] [{ts}] ARP SPOOFING DETECTADO")
                print(f"    IP     : {ip_src}")
                print(f"    MAC OK : {arp_table[ip_src]}")
                print(f"    MAC NEW: {mac_src}  <-- SOSPECHOSA")
                print(f"    Posible ataque MITM en curso\n")
        else:
            arp_table[ip_src] = mac_src
            print(f"[*] MAC registrada -> {ip_src} = {mac_src}")

print("[*] Iniciando monitorización ARP... (Ctrl+C para detener)")
sniff(filter="arp", iface="br-e031e5a89389", prn=alert_arpspoof, store=0)
