#set document(title: "Práctica 3: MITM y Suplantación", author: "Sergio García")
#set page(
  paper: "a4",
  margin: (top: 2.5cm, bottom: 2.5cm, left: 3cm, right: 2.5cm),
  numbering: "1",
)
#set text(font: "New Computer Modern", size: 11pt, lang: "es")
#set heading(numbering: "1.")
#set par(justify: true, leading: 0.72em, spacing: 1.2em)
#show heading.where(level: 1): it => {
  v(1.2em)
  it
  v(0.6em)
}
#show heading.where(level: 2): it => {
  v(0.8em)
  it
  v(0.4em)
}

// Portada
#align(center)[
  #v(2cm)
  #text(size: 14pt, weight: "bold")[Universidad Europea de Madrid]
  #v(0.3cm)
  #text(size: 12pt)[Grado en Ingeniería Informática]
  #v(0.3cm)
  #text(size: 11pt)[Técnicas de Hacking — Curso 2025/2026]
  #v(2cm)
  #line(length: 100%)
  #v(0.5cm)
  #text(size: 18pt, weight: "bold")[Práctica 3: MITM y Suplantación]
  #v(0.3cm)
  #text(size: 13pt)[Detección de ARP Spoofing y DNS Snooping mediante análisis pasivo de tráfico]
  #v(0.5cm)
  #line(length: 100%)
  #v(2cm)
  #grid(
    columns: (1fr, 1fr),
    align: left,
    gutter: 0.5cm,
    [*Autor:*], [Sergio García],
    [*Profesor:*], [Alfredo Robledano Abasolo],
    [*Fecha:*], [Mayo 2026],
  )
]

#pagebreak()

// Resumen
= Resumen

Este trabajo aborda el diseño e implementación de un sistema ligero de detección de intrusos orientado a dos amenazas de red bien diferenciadas: el envenenamiento de tablas ARP mediante la técnica conocida como ARP Spoofing, y la enumeración masiva de subdominios DNS relacionada con el ataque de Kaminsky y el DNS Snooping. Ambas técnicas son empleadas habitualmente como fases de reconocimiento o posicionamiento previas a ataques más graves, como la interceptación silenciosa de comunicaciones o el envenenamiento de la caché de un resolvedor DNS.

Para reproducir los escenarios de ataque de forma segura y aislada se han empleado entornos de red virtualizados mediante Docker Compose, lo que ha permitido definir topologías realistas con múltiples nodos sin necesidad de infraestructura física adicional. La herramienta bettercap se ha utilizado para ejecutar el ataque ARP, mientras que el tráfico DNS malicioso se ha generado mediante un script propio construido con la librería Scapy.

Los sistemas de detección desarrollados, también basados en Scapy, han funcionado correctamente en ambos escenarios: la función `alert_arpspoof` detectó el cambio de dirección MAC asociado al envenenamiento ARP, y la función `alert_dnssnooping` identificó la ráfaga de consultas DNS sospechosas al superar el umbral configurado. Los resultados demuestran que es posible construir detectores funcionales con herramientas de código abierto y un nivel de complejidad técnica accesible.

#pagebreak()

// Índice de contenidos
#outline(title: "Índice", depth: 2, indent: 1.5em)

#pagebreak()

// Índice de figuras
#outline(
  title: "Índice de figuras",
  target: figure.where(kind: image),
)

#pagebreak()

// Introducción
= Introducción

La seguridad en redes locales es uno de los vectores de ataque más frecuentemente subestimados. Mientras que la mayor parte de los esfuerzos defensivos se concentran en las capas superiores del modelo OSI, los ataques que operan en la capa de enlace y en la capa de aplicación DNS pueden pasar completamente desapercibidos si no existe una monitorización activa del tráfico de red.

El protocolo ARP (Address Resolution Protocol) fue diseñado en los años 80 sin mecanismos de autenticación @rfc826. Su funcionamiento es sencillo: cuando un nodo necesita conocer la dirección MAC asociada a una IP, emite una solicitud ARP en broadcast y el nodo correspondiente responde con su MAC. El problema es que cualquier nodo de la red puede enviar una respuesta ARP sin que nadie lo haya solicitado, y los sistemas operativos actualizan su caché sin verificar la legitimidad de esa respuesta. Esta carencia es la base del ARP Spoofing @bettercap.

El ARP Spoofing permite a un atacante asociar su propia dirección MAC con la IP de otro nodo legítimo, normalmente el gateway de la red. A partir de ese momento, el tráfico destinado al gateway pasa primero por el atacante, que puede leerlo, modificarlo o descartarlo antes de reenviarlo. Este escenario se denomina ataque Man-In-The-Middle (MITM) y constituye una amenaza grave para la confidencialidad e integridad de las comunicaciones en redes locales.

Por otro lado, el sistema de nombres de dominio (DNS) también presenta vulnerabilidades conocidas. El ataque de Kaminsky @kaminsky, presentado públicamente en 2008, demostró cómo era posible envenenar la caché de un resolvedor DNS recursivo mediante una inyección masiva de respuestas falsificadas. La mecánica del ataque se apoya en la resolución de subdominios inexistentes: el atacante fuerza al resolvedor a hacer consultas recursivas y, mientras espera la respuesta del servidor autoritativo, intenta adivinar el identificador de transacción para inyectar una respuesta falsa antes que la legítima.

Relacionada con esta técnica, la denominada DNS Snooping @dns_snooping aprovecha el análisis de la caché de un resolvedor para deducir qué dominios han sido consultados recientemente desde la red interna, lo que permite cartografiar la infraestructura o los hábitos de navegación de los usuarios.

El objetivo de esta práctica es implementar dos firmas de detección basadas en análisis pasivo de tráfico para identificar ambos tipos de ataque en tiempo real, sin interferir con el tráfico legítimo de la red.

= Fundamentos teóricos

== ARP Spoofing y ataques MITM

El protocolo ARP opera en la capa 2 del modelo OSI y es fundamental para el funcionamiento de cualquier red Ethernet. Cuando un equipo quiere comunicarse con una IP de su misma subred, consulta primero su tabla ARP local. Si no encuentra una entrada para esa IP, emite un paquete ARP Request en broadcast preguntando "¿quién tiene la IP X?". El equipo con esa IP responde con un ARP Reply indicando su dirección MAC, y el solicitante almacena esa asociación en su caché ARP durante un tiempo determinado.

La vulnerabilidad surge porque los sistemas operativos aceptan ARP Replies no solicitadas (denominadas _gratuitous ARP_). Un atacante puede enviar continuamente respuestas ARP falsas indicando que su MAC corresponde a la IP del router, logrando que la víctima actualice su caché y empiece a enviarle el tráfico. Si simultáneamente hace lo mismo con el router (asociando su MAC a la IP de la víctima), se sitúa como intermediario entre ambos, configurando un ataque MITM completo.

La detección de este tipo de ataque se basa en monitorizar las respuestas ARP y detectar cuándo una IP conocida aparece asociada a una dirección MAC diferente a la que tenía registrada, lo que indica que alguien está intentando sobreescribir la caché de forma ilegítima.

== Ataque de Kaminsky y DNS Snooping

El DNS es un sistema distribuido y jerárquico que traduce nombres de dominio en direcciones IP. Cuando un cliente consulta un nombre, su resolvedor local pregunta de forma recursiva a los servidores autoritativos hasta obtener la respuesta. Para reducir la carga de consultas repetidas, los resolvedores almacenan las respuestas en caché durante el tiempo indicado por el campo TTL.

El ataque de Kaminsky @kaminsky explota este mecanismo de caché. El atacante genera una gran cantidad de consultas a subdominios aleatorios e inexistentes de un dominio objetivo (por ejemplo, `abcxyz.example.com`). Cada vez que el resolvedor hace la consulta recursiva correspondiente, el atacante intenta inyectar una respuesta DNS falsificada que incluya un registro NS malicioso para el dominio raíz. Si lo consigue antes de que llegue la respuesta legítima, envenena la caché del resolvedor para ese dominio.

La firma de detección implementada en esta práctica se basa en el análisis por volumen (_threshold_): una ráfaga de consultas DNS procedentes de un mismo origen hacia subdominios aleatorios en una ventana de tiempo corta es estadísticamente anómala y puede indicar la ejecución de este tipo de ataque.

= Desarrollo

== Escenario de red para ARP Spoofing

=== Diseño de la topología

El entorno de pruebas para la parte de ARP se ha definido mediante Docker Compose @docker con cuatro contenedores distribuidos en dos redes virtuales aisladas:

- *Red LAN* (192.168.10.0/24): red interna que simula la red local de una organización. Contiene el nodo víctima (192.168.10.10), el nodo atacante con bettercap (192.168.10.99) y el router (192.168.10.2).
- *Red WAN* (10.0.0.0/24): red externa que simula Internet o una DMZ. Contiene el router y el servidor web Nginx (10.0.0.10).

El router tiene una interfaz en cada red y actúa como pasarela con IP forwarding habilitado, replicando el comportamiento de un gateway real en una red corporativa. El servidor web representa un destino legítimo al que la víctima accedería normalmente.

El nodo atacante utiliza la imagen oficial de Kali Linux y dispone de capacidades de red elevadas (`NET_ADMIN` y `NET_RAW` en Docker) para poder manipular y enviar paquetes a nivel de enlace, lo cual es necesario para que bettercap pueda operar correctamente.

#figure(
  image("images/cap02_docker_arp_running.png", width: 90%),
  caption: [Entorno Docker ARP levantado con los cuatro contenedores activos: attacker, router, victim y webserver.],
)

=== Herramienta de ataque: bettercap

Para simular el envenenamiento ARP se ha utilizado bettercap @bettercap, una herramienta de auditoría de red de código abierto ampliamente utilizada en pruebas de penetración. Entre sus módulos destaca `arp.spoof`, que automatiza el envío continuo de respuestas ARP falsificadas hacia los objetivos configurados. La versión empleada en esta práctica es la 2.41.5.

#figure(
  image("images/cap01_bettercap_instalado.png", width: 80%),
  caption: [Verificación de la instalación de bettercap v2.41.5 en el contenedor atacante.],
)

El ataque se lanzó desde el interior del contenedor atacante especificando la víctima como objetivo y el router como gateway a suplantar:

```bash
bettercap -iface eth0 -eval \
  "set arp.spoof.targets 192.168.10.10; \
   set arp.spoof.gateway 192.168.10.2; \
   arp.spoof on; net.probe on"
```

El módulo `net.probe` se activa para que bettercap descubra los nodos activos en la red antes de iniciar el spoofing. Una vez identificada la víctima, el módulo `arp.spoof` empieza a enviar respuestas ARP falsificadas de forma periódica para mantener envenenadas las cachés ARP tanto de la víctima como del router.

#figure(
  image("images/cap03_bettercap_ataque.png", width: 90%),
  caption: [bettercap en ejecución: el módulo arp.spoof detecta el endpoint víctima 192.168.10.10 e inicia el envenenamiento ARP.],
)

=== Función de detección: alert_arpspoof

La función de detección `alert_arpspoof` se ha implementado en Python utilizando la librería Scapy @scapy. El script escucha el tráfico ARP en la interfaz bridge de la red LAN (`br-e031e5a89389`) y mantiene una tabla interna de asociaciones IP-MAC observadas. Cada vez que llega un paquete ARP de tipo Reply (código de operación 2), se extrae la IP y la MAC del campo origen y se comprueba si ya existe una entrada para esa IP en la tabla:

- Si no existe, se registra la asociación como legítima.
- Si existe y la MAC es diferente a la registrada, se genera una alerta indicando la IP afectada, la MAC original y la nueva MAC sospechosa.

La lógica central de la firma es la siguiente:

```python
def alert_arpspoof(packet):
    if packet.haslayer(ARP) and packet[ARP].op == 2:
        ip_src  = packet[ARP].psrc
        mac_src = packet[ARP].hwsrc
        if ip_src in arp_table:
            if arp_table[ip_src] != mac_src:
                print(f"[!] ARP SPOOFING DETECTADO")
                print(f"    IP     : {ip_src}")
                print(f"    MAC OK : {arp_table[ip_src]}")
                print(f"    MAC NEW: {mac_src}  <-- SOSPECHOSA")
        else:
            arp_table[ip_src] = mac_src
```

Este patrón de detección se fundamenta en que el ARP Spoofing requiere enviar respuestas ARP no solicitadas (_gratuitous ARP_) de forma continua para mantener la caché de la víctima envenenada. Cada uno de esos paquetes es una oportunidad para que el detector identifique la anomalía.

== Escenario de red para DNS Snooping

=== Diseño de la topología

Para la parte de DNS se ha definido un entorno independiente con dos nodos en la red `dnsnet` (172.20.0.0/24):

- *dnsserver* (172.20.0.10): servidor DNS basado en BIND9 @bind9, configurado con recursividad habilitada y reenvío de consultas a 8.8.8.8. Actúa como resolvedor recursivo, el objetivo típico de los ataques de Kaminsky.
- *resolver* (172.20.0.20): nodo cliente Alpine Linux que simula las peticiones DNS de un usuario o sistema interno.

La separación entre servidor DNS y resolver en nodos distintos permite reproducir de forma más fiel un escenario real, donde el resolvedor es un servidor de la organización que recibe las consultas de los clientes internos y las resuelve de forma recursiva.

#figure(
  image("images/cap05_docker_dns_running.png", width: 90%),
  caption: [Entorno Docker DNS con dnsserver (BIND9) y resolver (Alpine) activos en la red 172.20.0.0/24.],
)

=== Función de detección: alert_dnssnooping

La función `alert_dnssnooping` implementa un mecanismo de detección basado en umbral de volumen (_threshold_). El script escucha el tráfico UDP en el puerto 53 de la interfaz bridge de la red DNS (`br-dafe511130b7`) y contabiliza las consultas DNS de tipo Query (bit QR=0) originadas desde cada dirección IP en una ventana temporal deslizante de 5 segundos. Si una misma IP supera las 10 consultas en ese intervalo, se considera tráfico anómalo y se genera una alerta.

La ventana deslizante se implementa manteniendo una lista de timestamps por IP y descartando los que queden fuera del intervalo en cada nueva consulta:

```python
query_count[ip_src] = [t for t in query_count[ip_src]
                       if now - t < WINDOW]
query_count[ip_src].append(now)

if len(query_count[ip_src]) >= THRESHOLD:
    print(f"[!] DNS SNOOPING DETECTADO desde {ip_src}")
    print(f"    Consultas en {WINDOW}s: {len(query_count[ip_src])}")
```

El uso de una ventana deslizante en lugar de un contador fijo permite detectar ráfagas que comiencen en cualquier momento, sin depender de intervalos predefinidos que podrían dejar pasar un ataque que se inicie justo entre dos ventanas consecutivas.

=== Script generador de tráfico

Para validar el funcionamiento del detector se ha implementado el script `dns_attack.py`, que simula el comportamiento de un atacante ejecutando la fase de enumeración del ataque de Kaminsky. El script genera 30 paquetes UDP dirigidos al puerto 53 del servidor DNS, cada uno con un nombre de subdominio aleatorio de ocho caracteres sobre el dominio `example.com`. Los subdominios se generan de forma completamente aleatoria para simular la búsqueda de nombres inexistentes que forzaría consultas recursivas al servidor autoritativo:

```python
def random_subdomain(length=8):
    return ''.join(random.choices(string.ascii_lowercase, k=length))

for i in range(COUNT):
    sub = random_subdomain()
    qname = f"{sub}.{DOMAIN}"
    pkt = IP(dst=DNS_SERVER) / UDP(dport=53) / DNS(
            rd=1, qd=DNSQR(qname=qname))
    send(pkt, verbose=0)
```

El intervalo entre consultas se fija en 0.1 segundos, lo que garantiza que se supere el umbral de 10 consultas en 5 segundos y se active la alerta del detector.

= Resultados

Los dos sistemas de detección han operado correctamente durante las pruebas, generando alertas en tiempo real sin falsos negativos en los escenarios evaluados. A continuación se detallan los resultados obtenidos para cada parte.

== Detección de ARP Spoofing

En el momento en que bettercap comenzó a emitir respuestas ARP falsificadas, el detector `alert_arpspoof` identificó de inmediato la anomalía. El sistema registró primero las asociaciones legítimas observadas durante el arranque del entorno y, al recibir una respuesta ARP que asociaba la IP del router (192.168.10.1) a una dirección MAC diferente, generó la alerta correspondiente.

#figure(
  image("images/cap04_arpspoof_detectado.png", width: 90%),
  caption: [Salida de alert_arpspoof: detección del cambio de MAC en la IP 192.168.10.1 provocado por bettercap.],
)

El análisis del paquete capturado revela el patrón característico del ataque: la MAC legítima del router (`02:42:c0:a8:0a:63`) fue sustituida por la MAC del contenedor atacante (`02:42:51:b6:f9:2b`). A partir de ese momento, todo el tráfico de la víctima destinado al router habría pasado por el atacante.

#figure(
  table(
    columns: (auto, auto, auto, auto),
    align: (left, left, left, center),
    table.header([*IP*], [*MAC legítima*], [*MAC sospechosa*], [*Resultado*]),
    [192.168.10.1 (router)], [02:42:c0:a8:0a:63], [02:42:51:b6:f9:2b], [ARP Spoofing ✓],
    [192.168.10.10 (víctima)], [02:42:c0:a8:0a:0a], [—], [Sin anomalías],
    [192.168.10.99 (atacante)], [02:42:c0:a8:0a:63], [—], [Sin anomalías],
  ),
  caption: [Resumen de asociaciones ARP observadas y anomalías detectadas durante el ataque.]
)

== Detección de DNS Snooping

El script `dns_attack.py` completó el envío de las 30 consultas en aproximadamente 3 segundos, superando holgadamente el umbral de 10 consultas en 5 segundos.

#figure(
  image("images/cap06_dns_attack_completado.png", width: 85%),
  caption: [Script dns_attack.py completando el envío de 30 consultas DNS a subdominios aleatorios de example.com.],
)

El detector `alert_dnssnooping` identificó la ráfaga en tiempo real y generó la alerta al alcanzar el umbral, mostrando la IP origen, el número de consultas detectadas en la ventana temporal y el último subdominio consultado.

#figure(
  image("images/cap07_dns_snooping_detectado.png", width: 90%),
  caption: [Alerta generada por alert_dnssnooping al superar el umbral de 10 consultas en 5 segundos desde 172.20.0.1.],
)

Durante las pruebas se observó que el propio servidor DNS (`172.20.0.10`) también generó alertas, ya que al procesar y reenviar las consultas recibidas producía a su vez un volumen de tráfico DNS elevado. Esto pone de manifiesto que el umbral debe calibrarse teniendo en cuenta el comportamiento normal del servidor en la red objetivo.

#figure(
  table(
    columns: (auto, auto, auto, auto),
    align: (left, center, center, center),
    table.header([*IP origen*], [*Consultas en 5s*], [*Umbral*], [*Resultado*]),
    [172.20.0.1 (script ataque)], [10], [10], [DNS Snooping ✓],
    [172.20.0.10 (dnsserver)],    [10], [10], [DNS Snooping ✓],
    [172.20.0.20 (resolver)],     [< 10], [10], [Sin anomalías],
  ),
  caption: [Resumen de alertas DNS generadas durante la simulación del ataque de Kaminsky.]
)

= Conclusiones

Esta práctica ha permitido comprobar que la detección temprana de ataques de ARP Spoofing y DNS Snooping es técnicamente accesible mediante herramientas de código abierto y un análisis pasivo del tráfico de red. No es necesario disponer de soluciones comerciales costosas para implementar un nivel básico de visibilidad sobre estas amenazas.

En el caso del ARP Spoofing, la firma implementada demostró ser efectiva y de baja latencia: la alerta se generó prácticamente en tiempo real, con el primer paquete ARP falsificado. La principal limitación del enfoque adoptado es que la legitimidad de la primera asociación IP-MAC observada se asume sin verificación. En un entorno de producción, esta debilidad podría mitigarse mediante una lista blanca estática de asociaciones conocidas o mediante la integración con un inventario de activos de red.

En cuanto al DNS Snooping, el mecanismo de umbral ha resultado eficaz para detectar la ráfaga de consultas generada por el script de ataque. Sin embargo, la observación de que el propio servidor DNS también disparó alertas es un recordatorio de que cualquier sistema de detección basado en umbrales fijos requiere un proceso de calibración previo. Una mejora natural sería complementar el análisis de volumen con la inspección de los nombres de subdominio consultados, buscando patrones de aleatoriedad estadística característicos de la generación automatizada de subdominios.

La virtualización mediante Docker se ha revelado como una aproximación muy adecuada para este tipo de prácticas: permite definir topologías de red complejas en minutos, garantiza el aislamiento del tráfico generado y facilita la reproducción del entorno en cualquier máquina con Docker instalado. El uso de `docker-compose` para describir la topología como código también aporta valor desde el punto de vista de la documentación y la reproducibilidad.

Como línea de trabajo futuro, sería interesante integrar ambos detectores en un sistema de correlación de eventos que pudiese detectar ataques combinados, donde el ARP Spoofing se use como paso previo para interceptar y manipular el tráfico DNS de la víctima, forzando la resolución de dominios maliciosos.

= Bibliografía

#bibliography("bibliography.bib", style: "ieee")
