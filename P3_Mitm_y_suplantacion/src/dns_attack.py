#!/usr/bin/env python3
"""
dns_attack.py - Generador de tráfico DNS sospechoso (simula ataque Kaminsky)
Envía ráfagas de consultas a subdominios aleatorios para activar el IDS
"""

from scapy.all import IP, UDP, DNS, DNSQR, send
import random
import string
import time

DNS_SERVER = "172.20.0.20"   # dnsserver
DOMAIN     = "example.com"
COUNT      = 30               # número de consultas a enviar
DELAY      = 0.1              # segundos entre consultas

def random_subdomain(length=8):
    return ''.join(random.choices(string.ascii_lowercase, k=length))

print(f"[*] Iniciando ataque DNS Snooping simulado -> {DNS_SERVER}")
print(f"[*] Enviando {COUNT} consultas a subdominios aleatorios de {DOMAIN}\n")

for i in range(COUNT):
    sub = random_subdomain()
    qname = f"{sub}.{DOMAIN}"
    pkt = IP(dst=DNS_SERVER) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=qname))
    send(pkt, verbose=0)
    print(f"[{i+1:02d}] Consulta: {qname}")
    time.sleep(DELAY)

print("\n[*] Ataque simulado completado.")
