from scapy.all import IP, TCP, UDP, ICMP, sr1, sr, srp, Ether, conf # Importamos sr y srp
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def craft_discovery_pkts(metodos, objetivos, conteo=None, puerto_base=80):
    if isinstance(metodos, str): metodos = [metodos]
    lista_ips = [objetivos] if isinstance(objetivos, str) else objetivos
    conteo = conteo or {m: 1 for m in metodos}
    pool_paquetes = []

    for direccion_ip in lista_ips:
        encabezado_ip = IP(dst=direccion_ip)
        for modo in metodos:
            iteraciones = conteo.get(modo, 1)
            for _ in range(iteraciones):
                id_modo = modo.upper()
                if id_modo == "TCP_ACK":
                    pqt = encabezado_ip / TCP(dport=puerto_base, flags="A")
                elif id_modo == "UDP":
                    pqt = encabezado_ip / UDP(dport=puerto_base)
                elif id_modo == "ICMP_TS":
                    pqt = encabezado_ip / ICMP(type=13)
                else:
                    continue
                pool_paquetes.append(pqt)
    return pool_paquetes

def ejecutar_reconocimiento():
    # Usamos 127.0.0.1 para que las capturas de Wireshark salgan 
    nodos_objetivo = ["127.0.0.1"]
    tecnicas = ["TCP_ACK", "UDP", "ICMP_TS"]
    
    print(f"[*] Modo de diagnóstico local activado sobre interfaz 'lo'")
    trafico_generado = craft_discovery_pkts(tecnicas, nodos_objetivo)
    
    # Usamos sr() porque enviamos en Capa 3 (IP) sobre la interfaz loopback
    respondidos, _ = sr(trafico_generado, timeout=2, verbose=1, iface="lo")

    if respondidos:
        for _, res in respondidos:
            print(f"[+] Nodo identificado como ACTIVO: {res.src}")
    else:
        print("[-] No se recibieron respuestas. Revisa Wireshark en interfaz 'lo'.")

if __name__ == "__main__":
    ejecutar_reconocimiento()