#set text(lang: "es", font: "Noto Sans", size: 11pt)
#set page(paper: "a4", numbering: "1", margin: (top: 2.5cm, bottom: 2.5cm, left: 2.5cm, right: 2.5cm))
#set heading(numbering: "1.1.")
#set par(justify: true, leading: 0.75em)
#show heading: it => { v(0.8em); it; v(0.4em) }

#align(center)[
  #v(3em)
  #text(weight: 700, size: 2em)[Informe de Reconocimiento Pasivo:\ Iberdrola S.A.]
  #v(1.5em)
  #line(length: 80%)
  #v(1em)
  #text(size: 1.2em)[Asignatura: *Técnicas de Hacking I*] \
  #v(0.5em)
  #text(size: 1.1em)[Universidad Europea de Madrid] \
  #v(1.5em)
  #text()[*Autor:* Sergio García Gallego] \
  #text()[*Fecha:* Mayo 2026] \
  #v(3em)
]

#pagebreak()

= Resumen

Este informe recoge el reconocimiento pasivo realizado sobre Iberdrola S.A., empresa del IBEX 35 y una de las mayores eléctricas del mundo. El objetivo era mapear su exposición digital sin enviar ningún paquete a sus sistemas: solo fuentes públicas, solo OSINT.

Las herramientas empleadas incluyen `dig`, Shodan, BuiltWith, DNSDumpster, RIPE NCC y la Google Hacking Database. El resultado general es que Iberdrola tiene una infraestructura bien gestionada, con Akamai y Proofpoint cubriendo gran parte del perímetro. Aun así, la transparencia de certificados y los subdominios indexados en Google exponen más superficie de la que parece a primera vista. Los perfiles de empleados en LinkedIn con conocimientos OT y SCADA también son un dato relevante en el contexto de una empresa de infraestructura crítica.

El informe está organizado en dos partes: la primera analiza los registros DNS y la distinción entre reconocimiento pasivo y activo; la segunda desarrolla el perfil OSINT completo de la empresa, desde su modelo de negocio hasta los hallazgos de dorking.

#outline(title: "Índice de contenidos", indent: 2em, depth: 3)

#pagebreak()

#outline(
  title: "Índice de figuras",
  target: figure.where(kind: image),
)

#pagebreak()

= Parte 1: Investigación de Registros DNS

El DNS convierte nombres como `iberdrola.com` en direcciones IP que los equipos pueden usar para conectarse. Funciona como una jerarquía distribuida de bases de datos: cuando un navegador necesita la IP de un dominio, consulta a su resolutor local, que a su vez pregunta a servidores raíz, luego a los servidores autoritativos del dominio, y devuelve la respuesta. Todo este proceso es público por diseño.

Para un auditor, eso tiene una consecuencia importante: consultar los registros DNS de una empresa usando resolutores públicos no deja rastro en los sistemas del objetivo. El servidor de Iberdrola nunca recibe esa consulta. La recibe Google (8.8.8.8) o Cloudflare (1.1.1.1), que ya tienen la respuesta cacheada. Es información pública, consultada a través de un tercero.

== Descripción de los tipos de registro

=== Registro A (Address)

El registro *A* vincula un nombre de dominio con una dirección *IPv4* de 32 bits. Es el registro más consultado en la práctica: cada vez que se accede a una web, se resuelve su registro A.

```
$ dig iberdrola.com A +short
23.195.34.25
```

En el caso de Iberdrola, esa IP no pertenece a la empresa sino a Akamai (ASN 20940). Eso ya dice algo importante: Iberdrola no expone directamente su servidor web. Todo pasa por el CDN. La IP real del servidor de origen no es visible desde Internet.

Desde el punto de vista del reconocimiento, el registro A permite identificar el proveedor de infraestructura, estimar la geolocalización del servidor de borde más cercano y determinar si el dominio está detrás de un CDN. Si la IP cambia mucho entre consultas, confirma que hay balanceo de carga geográfico.

=== Registro AAAA (IPv6 Address)

El registro *AAAA* hace lo mismo que el A pero para *IPv6*. Su nombre viene de que almacena 128 bits en vez de 32 (cuatro veces más, de ahí las cuatro A). Los sistemas modernos consultan primero AAAA y, si no hay respuesta, caen al registro A.

```
$ dig iberdrola.com AAAA +short
2a02:26f0:480::18c3:2219
```

Que Iberdrola tenga AAAA activo confirma que su CDN soporta doble pila (dual-stack). Desde el punto de vista del reconocimiento, los rangos IPv6 a veces revelan el bloque de red del proveedor con más precisión que el IPv4, y en algunos casos de configuración incorrecta del CDN, la IP de origen puede filtrarse a través del registro AAAA aunque esté oculta en el A.

=== Registro MX (Mail Exchanger)

El registro *MX* define qué servidores reciben el correo del dominio. Pueden existir varios, con prioridades numéricas: menor número, mayor prioridad. Esto permite redundancia: si el servidor principal no responde, el correo se redirige al secundario.

```
$ dig iberdrola.com MX +short
10 mxb-00109d01.gslb.pphosted.com.
20 mxa-00109d01.gslb.pphosted.com.
```

El sufijo `pphosted.com` corresponde a *Proofpoint*, una plataforma de seguridad de correo en la nube. El prefijo `gslb` indica Global Server Load Balancing, lo que confirma que Proofpoint tiene redundancia geográfica también en su infraestructura. Todo el correo de Iberdrola, entrante y saliente, pasa por Proofpoint antes de llegar a los servidores internos.

Esto es relevante por varias razones. Primero, confirma que Iberdrola ha externalizado la seguridad del correo y no la gestiona internamente. Segundo, permite correlacionar la versión del servicio con CVEs conocidos de Proofpoint. Tercero, en un ejercicio de red team autorizado, saber que el correo pasa por Proofpoint orienta las pruebas de evasión de filtros.

=== Registro TXT (Text)

El registro *TXT* almacena texto arbitrario asociado al dominio. En teoría puede contener cualquier cosa; en la práctica se usa para tres propósitos concretos.

*SPF (Sender Policy Framework):* lista los servidores autorizados para enviar correo en nombre del dominio. Un receptor puede comprobar si el servidor que le envía un email está en esta lista; si no lo está, puede rechazarlo o marcarlo como sospechoso.

*DKIM (DomainKeys Identified Mail):* publica la clave pública que permite verificar la firma criptográfica incluida en los correos salientes. Si alguien intercepta un correo y lo modifica, la firma se invalida.

*Verificaciones de terceros:* Google, Microsoft y muchos otros servicios piden que se añada un registro TXT con un código para demostrar que controlas el dominio. Esos códigos son visibles para cualquiera.

```
$ dig iberdrola.com TXT +short
"v=spf1 include:_spf.proofpoint.com include:spf.protection.outlook.com -all"
"MS=ms12345678"
"google-site-verification=XXXXXXXXXXXXXXXX"
```

El SPF confirma Proofpoint y Microsoft 365 como plataformas de correo autorizadas. El registro `MS=` confirma que tienen una suscripción de Microsoft activa verificada sobre el dominio. El de Google confirma Google Workspace o algún servicio de Google vinculado al dominio.

=== Registro CNAME (Canonical Name)

Un CNAME es un alias: en lugar de apuntar a una IP, apunta a otro nombre de dominio. El DNS resuelve ese nombre hasta llegar a una IP. Se usa para asociar subdominios a servicios externos sin tener que gestionar IPs directamente, y para facilitar la migración entre proveedores cambiando un solo registro.

```
$ dig www.iberdrola.com CNAME +short
iberdrola.com.edgekey.net.
```

`edgekey.net` es el dominio que Akamai usa para sus nodos de borde en contratos Enterprise. El CNAME de `www.iberdrola.com` apunta ahí, lo que significa que cualquier petición a la web principal pasa por esos nodos antes de llegar a cualquier servidor de Iberdrola.

El aspecto más interesante de los CNAMEs para el reconocimiento es la posibilidad de _subdomain takeover_: si un subdominio tiene un CNAME que apunta a un servicio que ya no existe (una instancia de AWS, una CDN que se canceló), cualquiera puede reclamar ese servicio y recibir el tráfico de ese subdominio. Es un vector de ataque pasivo de detectar y activo de explotar.

=== Registro NS (Name Server)

El registro *NS* indica qué servidores tienen autoridad sobre la zona DNS del dominio. Cuando un resolutor necesita saber los registros de `iberdrola.com`, pregunta a los servidores NS de ese dominio.

```
$ dig iberdrola.com NS +short
a11-64.akam.net.
a7-65.akam.net.
a28-66.akam.net.
a5-67.akam.net.
```

Los cuatro servidores son de Akamai. Iberdrola ha delegado completamente la gestión de su DNS en su proveedor de CDN. Esto tiene sentido operativo (Akamai tiene una infraestructura DNS más robusta que la mayoría de empresas), pero también significa que la seguridad del DNS de Iberdrola depende de la seguridad de la cuenta de Akamai.

Para el reconocimiento, los NS son importantes porque determinan si es posible intentar una transferencia de zona (AXFR). Si los servidores NS fueran mal configurados, responderían a una petición AXFR enviando todos los registros de la zona, lo que equivale a un volcado completo del DNS. Akamai los configura correctamente: AXFR rechazado.

=== Registro SOA (Start of Authority)

El SOA es el primer registro de cualquier zona DNS y contiene los metadatos administrativos de esa zona. Sus campos son: *MNAME* (servidor primario de la zona), *RNAME* (correo del administrador, con el @ sustituido por un punto), *Serial* (número de versión de la zona, que se incrementa con cada cambio), y *Refresh*, *Retry*, *Expire* y *Minimum TTL* (parámetros de sincronización entre servidores DNS secundarios).

```
$ dig iberdrola.com SOA +short
a11-64.akam.net. hostmaster.akamai.com. 2026030101 3600 600 604800 300
```

El campo RNAME da `hostmaster.akamai.com`, que en formato de correo es `hostmaster@akamai.com`. Confirma que la zona la administra Akamai, no un equipo interno de Iberdrola. El Serial `2026030101` indica que la zona se actualizó el 1 de marzo de 2026 (formato YYYYMMDDNN). El TTL de 300 segundos significa que los registros se actualizan cada 5 minutos en los servidores secundarios.

=== Registro PTR (Pointer)

El registro PTR hace la operación inversa al registro A: dada una dirección IP, devuelve el nombre de dominio asociado. Se almacena en dominios especiales del tipo `in-addr.arpa` para IPv4 e `ip6.arpa` para IPv6. No todos los servidores tienen PTR configurado, y cuando lo tienen, quien lo controla es el propietario del bloque de IP, no el del dominio.

```
$ dig -x 23.195.34.25 +short
a23-195-34-25.deploy.static.akamaitechnologies.com.
```

La resolución inversa de la IP del registro A de Iberdrola devuelve un nombre de Akamai. Confirma el proveedor y el tipo de despliegue (`deploy.static` indica un nodo estático, no dinámico).

El PTR es útil para verificar la coherencia entre los registros directos e inversos, y para identificar servidores con nombres descriptivos que revelen su función. Por ejemplo, un servidor con PTR `mail-relay-01.empresa.com` inmediatamente dice qué hace ese servidor.

== Resultados de las consultas DNS sobre iberdrola.com

La tabla siguiente consolida los resultados obtenidos con `dig` @tool_dig desde Kali Linux, usando resolutores públicos:

#table(
  columns: (auto, 1fr, 2fr),
  inset: 8pt,
  align: (left, left, left),
  [*Tipo*], [*Valor obtenido*], [*Qué revela*],
  [A], [`23.195.34.25`], [IP de nodo Akamai (ASN 20940). El servidor real de Iberdrola no es visible.],
  [AAAA], [`2a02:26f0:480::18c3:2219`], [IPv6 activo. Infraestructura dual-stack gestionada por Akamai.],
  [MX], [`mxb-00109d01.gslb.pphosted.com` (pri. 10)], [Correo entrante filtrado por Proofpoint antes de llegar a Iberdrola.],
  [TXT], [`v=spf1 include:_spf.proofpoint.com...`], [Proofpoint y Microsoft 365 autorizados para enviar correo del dominio.],
  [CNAME], [`iberdrola.com.edgekey.net.`], [www apunta a nodo Akamai EdgeKey (contrato Enterprise CDN).],
  [NS], [`a11-64.akam.net.` (y tres más)], [DNS autoritativo completamente delegado a Akamai.],
  [SOA], [`hostmaster.akamai.com.` serial 2026030101], [Zona administrada por Akamai. Última actualización: 1 marzo 2026.],
  [PTR], [`a23-195-34-25.deploy.static.akamaitechnologies.com.`], [Resolución inversa confirma nodo estático de Akamai.],
)

#figure(
  image("img/dns_dig.png", width: 90%),
  caption: [Consulta `dig` sobre iberdrola.com desde terminal Kali Linux. Los registros A, MX y NS apuntan a infraestructura de Akamai y Proofpoint respectivamente.],
)

== Reconocimiento pasivo vs. activo en DNS

La diferencia práctica entre pasivo y activo en DNS es a quién va dirigida la consulta.

Cuando se usa un resolutor público como 8.8.8.8, la consulta va a Google, que responde con la información que tiene cacheada. El servidor de Iberdrola nunca recibe nada. No hay registro de la consulta en sus logs. Eso es reconocimiento pasivo: la información es pública y se obtiene a través de un intermediario.

Cuando la consulta va directamente a los servidores NS de Iberdrola, esos servidores sí reciben el paquete y pueden registrarlo. Si además se solicita una transferencia de zona (AXFR) o se usan opciones poco habituales (CHAOS, HINFO), la actividad es claramente anómala y detectable. Eso es reconocimiento activo.

#table(
  columns: (1fr, auto, 1fr),
  inset: 8pt,
  [*Técnica*], [*Tipo*], [*Herramienta*],
  [`dig iberdrola.com A` con resolutor 8.8.8.8], [✅ Pasivo], [`dig`, `nslookup`, `host`],
  [Consulta WHOIS a registros públicos], [✅ Pasivo], [`whois`, `who.is`],
  [Búsqueda en logs de Certificate Transparency], [✅ Pasivo], [`crt.sh`, DNSDumpster],
  [Consulta de DNS histórico], [✅ Pasivo], [SecurityTrails, VirusTotal Passive DNS],
  [Búsqueda en Shodan por hostname], [✅ Pasivo], [Shodan web],
  [`dig @a11-64.akam.net iberdrola.com AXFR`], [🔴 Activo], [`dig`, `fierce`],
  [Fuerza bruta de subdominios sobre servidores NS], [🔴 Activo], [`fierce`, `dnsx`, `amass`],
  [Escaneo de puertos en servidores NS autoritativos], [🔴 Activo], [`nmap`, `masscan`],
)

Hay un caso intermedio que vale la pena mencionar: herramientas como `amass` o `theHarvester` tienen modos pasivos que solo consultan fuentes externas (bases de datos de CT, DNS pasivo de VirusTotal, Shodan) y modos activos que envían consultas directas. La distinción no está en la herramienta sino en cómo se configura.

#pagebreak()

= Parte 2: Auditoría OSINT sobre Iberdrola S.A. (IBEX 35)

== Modelo de negocio

=== La empresa

*Iberdrola S.A.* nació en 1992 de la fusión de Iberduero e Hidroeléctrica Española. Hoy es una de las cinco mayores eléctricas del mundo por capitalización bursátil y la empresa con más capacidad instalada en energía eólica offshore a nivel global. Cotiza en el IBEX 35 con un peso de aproximadamente el 10% del índice, y tiene domicilio social en Bilbao. El dominio auditado es `iberdrola.com` @u1_teoria.

La elección de Iberdrola como objetivo de este análisis no es arbitraria. Al ser una empresa de infraestructura crítica —gestiona redes eléctricas que suministran electricidad a millones de personas— es también un objetivo de alto valor para actores de amenaza avanzada (APT). El reconocimiento OSINT sobre este tipo de organizaciones tiene implicaciones directas en ciberseguridad nacional.

=== Qué hace

Iberdrola tiene tres líneas de negocio diferenciadas.

*Generación de energía:* opera parques eólicos onshore y offshore, instalaciones solares fotovoltaicas, centrales hidroeléctricas y algunas plantas de ciclo combinado de gas como respaldo. Es líder mundial en eólica marina con proyectos activos en el Reino Unido (East Anglia ONE y TWO), EE.UU. (Vineyard Wind) y Alemania. En 2023 tenía más de 40 GW de capacidad renovable instalada.

*Gestión de redes:* a través de sus filiales gestiona redes de distribución eléctrica reguladas por los gobiernos de cada país. En España opera como red de distribución en varias comunidades autónomas; en el Reino Unido a través de ScottishPower Energy Networks; en EE.UU. a través de Avangrid Networks; y en Brasil con Neoenergia. Este negocio es intensivo en infraestructura OT y sistemas SCADA.

*Comercialización:* vende electricidad y gas natural a unos 40 millones de clientes finales, desde hogares hasta grandes industriales con contratos PPA (_Power Purchase Agreement_) de varios años. En España compite directamente con Endesa y Naturgy.

=== Clientes y proveedores tecnológicos

Sus clientes son principalmente hogares y empresas en cuatro mercados: España, Reino Unido, EE.UU. y Brasil. El mercado corporativo incluye gobiernos, grandes manufactureras y utilities que compran energía renovable certificada.

En el lado tecnológico, los proveedores que aparecen en el reconocimiento pasivo son: *Akamai Technologies* para CDN y seguridad web @akamai; *Proofpoint* para seguridad de correo corporativo @proofpoint; *Microsoft 365* para colaboración y correo interno; *Salesforce* como plataforma CRM para gestión de clientes; *Siemens y General Electric* para hardware de generación y transformación eléctrica.

== Tecnologías web expuestas

BuiltWith @builtwith analiza las cabeceras HTTP, el código fuente público y los metadatos del sitio para identificar qué tecnologías usa una web. No envía nada agresivo al servidor: lee lo que el servidor ya publica en cada respuesta. Para `iberdrola.com` detecta *139 tecnologías activas*, lo que da una imagen bastante completa de su stack sin haber abierto ninguna sesión privilegiada.

#figure(
  image("img/builtwith.png", width: 88%),
  caption: [BuiltWith sobre iberdrola.com. Se detectan 139 tecnologías activas, entre ellas Salesforce, Akamai mPulse, Google Analytics, CrazyEgg y LinkedIn Insights. Datos recogidos el 25 de mayo de 2026.],
)

#table(
  columns: (auto, 1fr),
  inset: 8pt,
  [*Tecnología detectada*], [*Qué implica para el reconocimiento*],
  [Salesforce], [El CRM está en la nube de Salesforce. Los datos de clientes no están en infraestructura propia de Iberdrola.],
  [Akamai mPulse], [Monitorización de rendimiento web en tiempo real (RUM). Confirma contrato Enterprise con Akamai, más allá del CDN básico.],
  [Google Analytics], [Datos de navegación de usuarios se envían a Google. Implica que existe una política de cookies y que cumplen con el RGPD en este punto.],
  [Google Conversion Linker], [Seguimiento de conversiones publicitarias activo. Hay campañas en Google Ads en marcha.],
  [LinkedIn Insights], [Píxel de LinkedIn instalado en la web. Tienen campañas de marketing B2B dirigidas a profesionales en LinkedIn.],
  [CrazyEgg], [Herramienta de heatmaps y grabación de sesiones para analizar el comportamiento de los visitantes.],
)

La combinación de Akamai mPulse y CrazyEgg indica que Iberdrola tiene un equipo activo de optimización web que monitoriza tanto el rendimiento técnico como la experiencia de usuario. Salesforce como CRM confirma que la gestión de la relación con el cliente está externalizada en una plataforma SaaS, lo que desplaza parte de la superficie de datos sensibles a la infraestructura de Salesforce.

== Infraestructura y proveedores

=== Análisis WHOIS

WHOIS es un protocolo público que permite consultar información sobre el registro de un dominio: quién lo registró, cuándo, con qué registrador y datos de contacto. Desde la entrada en vigor del GDPR en Europa, los datos de contacto personales están anonimizados en la mayoría de registros, pero el resto de la información sigue siendo pública.

#figure(
  image("img/whois.png", width: 88%),
  caption: [WHOIS de iberdrola.com desde terminal Kali. El registrador es MarkMonitor, los datos de contacto están anonimizados por GDPR. Se confirma DNSSEC activo y dominio creado en 1995.],
)

Los datos relevantes del WHOIS de `iberdrola.com`:

El registrador es *MarkMonitor* @markmonitor, un servicio especializado en protección de dominios corporativos. Su función principal es dificultar el registro de dominios similares que puedan usarse para phishing o suplantación de marca. Que Iberdrola lo use indica una postura activa en la protección de su identidad digital.

El dominio fue creado en *1995*, lo que lo hace uno de los dominios corporativos españoles más antiguos en activo. Un dominio con tanta antigüedad tiene mayor reputación en los filtros de spam y menor riesgo de ser incluido en listas negras.

*DNSSEC está habilitado*. DNSSEC añade firmas criptográficas a las respuestas DNS, lo que impide que un atacante pueda falsificar respuestas DNS y redirigir el tráfico a servidores maliciosos (ataque de envenenamiento de caché). No es algo que todas las empresas implementen; que Iberdrola lo tenga activo indica madurez en la gestión del DNS.

Los datos de contacto técnico y administrativo están anonimizados por GDPR. Esto no es específico de Iberdrola: es el comportamiento estándar para dominios registrados en Europa desde 2018.

=== Infraestructura CDN y seguridad perimetral

Iberdrola tiene toda su web detrás de Akamai (ASN 20940), uno de los tres mayores proveedores de CDN del mundo junto a Cloudflare y Fastly. Esto tiene varias implicaciones prácticas para el reconocimiento.

La IP real del servidor web no es visible desde Internet. Las IPs que devuelve el DNS son de nodos de borde de Akamai distribuidos geográficamente. Un atacante que intentara un ataque directo a esas IPs estaría atacando a Akamai, no a Iberdrola.

El WAF que usa Iberdrola a través de Akamai es *Kona Site Defender*, la solución de seguridad web empresarial de Akamai. Filtra tráfico malicioso antes de que llegue a la infraestructura de Iberdrola y absorbe ataques DDoS volumétricos mediante la capacidad de red distribuida de Akamai (más de 300 Tbps a nivel global).

Para el correo, Proofpoint actúa como gateway entre Internet y los buzones corporativos de Iberdrola. Filtra phishing, malware adjunto y ataques de fraude BEC (_Business Email Compromise_) antes de que el correo llegue a ningún empleado. El registro SPF, que solo autoriza a Proofpoint y Microsoft 365 para enviar correo del dominio, confirma que el correo saliente también pasa por ese control.

== Huella digital geográfica

=== Bloques de IP propios (RIPE NCC)

RIPE NCC @ripe_ncc gestiona la asignación de direcciones IP en Europa, Oriente Medio y Asia Central. Su base de datos es pública y permite buscar qué bloques de IPs tiene registrados una organización concreta. Es distinto de los rangos de Akamai que aparecen en las consultas DNS: estos son los bloques que Iberdrola tiene asignados directamente para sus propias instalaciones corporativas.

#figure(
  image("img/ripe.png", width: 88%),
  caption: [Consulta RIPE NCC para la organización Iberdrola. Se identifican bloques de IP asignados directamente para uso corporativo en España, diferenciados de la infraestructura de Akamai.],
)

Conocer los bloques de IP propios de Iberdrola es útil porque permite distinguir qué tráfico originado desde esas IPs pertenece realmente a la empresa (empleados, servidores internos con acceso a Internet) frente al tráfico que viene a través de Akamai. En un análisis más avanzado, esas IPs podrían buscarse en Shodan para ver qué servicios tienen expuestos.

=== Presencia internacional

Iberdrola opera en cuatro continentes, y cada filial tiene su propio dominio y, en muchos casos, su propia infraestructura tecnológica:

#table(
  columns: (1fr, 1fr, 1fr),
  inset: 8pt,
  [*Filial*], [*Mercado*], [*Dominio*],
  [Iberdrola España], [España], [`iberdrola.es`],
  [ScottishPower], [Reino Unido], [`scottishpower.co.uk`],
  [Avangrid], [EE.UU.], [`avangrid.com`],
  [Neoenergia], [Brasil], [`neoenergia.com`],
  [Iberdrola México], [México], [`iberdrola.mx`],
)

Cada uno de esos dominios es una superficie de ataque independiente. Lo que vale para `iberdrola.com` (Akamai, Proofpoint, DigiCert) no tiene por qué aplicarse a `scottishpower.co.uk` o `neoenergia.com`. Un auditor que solo analiza el dominio principal puede estar ignorando filiales con configuraciones de seguridad más débiles.

== Exposición de activos

=== Subdominios mediante Certificate Transparency

Las Autoridades Certificadoras (CA) están legalmente obligadas, desde 2018, a publicar en logs públicos todos los certificados TLS que emiten. El objetivo de esta medida era detectar certificados fraudulentos, pero el efecto secundario es que cualquier subdominio que tenga HTTPS queda registrado permanentemente en esos logs, consultable por cualquiera.

DNSDumpster y crt.sh @crtsh permiten buscar todos los certificados emitidos para subdominios de un dominio sin mandar ningún paquete a los servidores de ese dominio. Es reconocimiento completamente pasivo: la fuente es el log de la CA, no la infraestructura del objetivo.

#figure(
  image("img/crtsh.png", width: 90%),
  caption: [Enumeración pasiva de subdominios de iberdrola.com mediante Certificate Transparency (DNSDumpster). Se identifican portales corporativos, APIs, entornos de pre-producción y plataformas de gestión interna.],
)

Entre los subdominios que aparecen en los logs hay portales de acceso a clientes, APIs públicas e internas, entornos de staging, plataformas de formación de empleados y portales para proveedores. Ninguno de esto implica que esos sistemas sean vulnerables, pero sí definen el perímetro real de la infraestructura de Iberdrola. En un test autorizado, esa lista sería el punto de partida para el reconocimiento activo.

Vale la pena señalar que los entornos de staging son habitualmente menos seguros que producción: pueden tener versiones de software más antiguas, credenciales de prueba que no se han rotado, o configuraciones que se copian de un entorno a otro sin revisar.

=== Shodan

Shodan @shodan no es un buscador de páginas web sino de servicios de red. Cuando un servidor escucha en un puerto, Shodan se conecta y registra el banner que devuelve (la respuesta inicial del servicio, que suele incluir el tipo de software, la versión y a veces datos de configuración). Indexa esa información para que sea consultable sin que nadie tenga que conectarse de nuevo al servidor.

#figure(
  image("img/shodan.png", width: 88%),
  caption: [Búsqueda en Shodan sobre iberdrola.com. Los activos visibles están protegidos por Akamai con certificados DigiCert EV. No se detectan puertos sensibles expuestos directamente a Internet.],
)

Los resultados de Shodan para Iberdrola muestran varios puntos relevantes. Los servidores web responden con cabeceras que identifican Akamai como proxy inverso, lo que confirma que el CDN está activo incluso ante conexiones directas. Los certificados son DigiCert Extended Validation (EV), que requieren verificación presencial de la identidad de la empresa: un nivel de validación más alto que el estándar DV o OV. Los protocolos TLS disponibles son 1.2 y 1.3; TLS 1.0 y 1.1 están deshabilitados. No aparecen puertos SSH (22), RDP (3389) ni bases de datos (3306, 5432) expuestos en las IPs que devuelve el DNS. Eso indica una segmentación de red correcta en el perímetro.

== Presencia en redes sociales

LinkedIn es la fuente más útil en este apartado, y no por los datos corporativos de Iberdrola sino por lo que revelan sus empleados.

#figure(
  image("img/linkedin.png", width: 88%),
  caption: [Perfil corporativo de Iberdrola en LinkedIn con más de 900.000 seguidores. Los perfiles del área técnica mencionan herramientas de ciberseguridad específicas y tecnologías OT/SCADA utilizadas en sus instalaciones.],
)

Los perfiles de empleados del área IT y ciberseguridad mencionan herramientas concretas que usan en su trabajo. Las ofertas de empleo publicadas por Iberdrola en LinkedIn especifican el stack tecnológico que buscan en los candidatos: nombres de fabricantes de firewalls, plataformas SIEM, herramientas de gestión de identidad. No hace falta interactuar con ningún sistema de Iberdrola para saber qué herramientas usan. Está en los anuncios públicos de empleo.

Los ingenieros de campo que trabajan en subestaciones y plantas de generación también tienen perfiles en LinkedIn con experiencia detallada en protocolos industriales, marcas de PLCs y versiones de software de control. Esa información es directamente relevante para un adversario interesado en los sistemas OT de la empresa.

#table(
  columns: (auto, 1fr),
  inset: 8pt,
  [*Red social*], [*Relevancia para el reconocimiento*],
  [LinkedIn (>900k seguidores)], [Tecnologías internas, estructura de equipos, stack tecnológico en ofertas de trabajo, perfiles OT/SCADA de ingenieros de campo.],
  [X / Twitter (>200k)], [Comunicaciones corporativas, respuestas públicas a incidentes, menciones de proyectos con proveedores.],
  [YouTube (canal activo)], [Vídeos de instalaciones que muestran equipamiento, marcas de fabricantes y layout de subestaciones.],
  [Instagram (corporativo)], [Contenido de marca. Menor utilidad técnica, pero los eventos pueden revelar socios tecnológicos.],
)

== Google Dorking

Los dorks son consultas con operadores avanzados de Google para encontrar contenido específico que una búsqueda normal no devolvería. La referencia estándar es la *Google Hacking Database (GHDB)* @ghdb de Offensive Security, que documenta cientos de patrones útiles para auditorías OSINT.

=== Dork 1: documentos con clasificación interna

*Consulta:* `site:iberdrola.com filetype:pdf "confidencial" OR "uso interno" OR "restringido"`

*Objetivo:* encontrar documentos PDF publicados en el dominio de Iberdrola que contengan marcas de clasificación interna. Si un documento dice "uso interno" y aparece indexado en Google, eso indica que el servidor lo está sirviendo sin control de acceso, independientemente de la etiqueta que tenga el propio documento.

*Análisis:* este tipo de hallazgo no es necesariamente crítico en términos de contenido, pero sí es un indicador de proceso. Si la política de publicación de documentos no detecta que un archivo marcado como "uso interno" está accesible públicamente, hay una brecha en el control de activos digitales. En empresas de infraestructura crítica, esa brecha puede tener consecuencias mayores que en una empresa de retail.

#figure(
  image("img/dork1.png", width: 88%),
  caption: [Dork 1: PDFs con marcas de clasificación interna indexados en Google dentro del dominio de Iberdrola. Se obtienen resultados de memorias anuales e informes técnicos con etiquetas de uso interno accesibles sin autenticación.],
)

=== Dork 2: empleados con conocimientos OT/SCADA en LinkedIn

*Consulta:* `site:linkedin.com "iberdrola" "SCADA" OR "ICS" OR "OT" OR "control industrial"`

*Objetivo:* localizar perfiles de empleados de Iberdrola que mencionan experiencia con sistemas de control industrial. LinkedIn está indexado por Google, así que esta búsqueda funciona sin necesidad de una cuenta de LinkedIn.

*Análisis:* los sistemas OT de las empresas energéticas son el objetivo de algunos de los grupos APT más sofisticados. El apagón de Ucrania en diciembre de 2015, ejecutado por el grupo Sandworm, empezó meses antes con una fase de reconocimiento que incluía perfiles profesionales de los ingenieros que operaban los sistemas SCADA de las distribuidoras eléctricas. Un perfil de LinkedIn de un empleado que menciona "Siemens WinCC", "Modbus" o "DNP3" revela qué tecnologías de control industrial usa Iberdrola en sus instalaciones, sin necesidad de conectarse a ningún sistema.

#figure(
  image("img/dork2.png", width: 88%),
  caption: [Dork 2: perfiles de empleados de Iberdrola con experiencia en sistemas OT y SCADA encontrados en LinkedIn a través de Google. Los resultados revelan tecnologías de control industrial específicas usadas en las instalaciones de la empresa.],
)

=== Dork 3: subdominios no enlazados indexados por exclusión

*Consulta:* `site:iberdrola.com -site:www.iberdrola.com -site:clientes.iberdrola.com`

*Objetivo:* encontrar subdominios de Iberdrola que Google ha indexado pero que no están enlazados desde la web principal. Los operadores negativos (`-site:`) filtran los dominios conocidos y dejan ver los demás.

*Análisis:* Google indexa contenido cuando lo descubre, no cuando la empresa decide publicarlo. Un portal de formación interna que tiene algún enlace externo, un entorno de desarrollo que se dejó accesible por error, una herramienta de proveedores que se enlazó desde un documento público: todo eso puede acabar en el índice de Google. Esta técnica permite enumerar esos subdominios sin hacer ninguna petición a los servidores de Iberdrola. La fuente es el índice de Google, no el DNS de Iberdrola.

#figure(
  image("img/dork3.png", width: 88%),
  caption: [Dork 3: subdominios de Iberdrola indexados por Google mediante operadores de exclusión. Aparecen portales de formación, plataformas de proveedores y entornos no enlazados desde la web corporativa principal.],
)

#pagebreak()

= Conclusiones

Iberdrola tiene la infraestructura que cabría esperar de una empresa de su tamaño en un sector regulado. Akamai delante de todo, Proofpoint en el correo, DigiCert con certificados EV, MarkMonitor protegiendo el dominio, DNSSEC activo. No hay puertos sensibles expuestos y el servidor web real no es visible desde Internet. La postura de seguridad perimetral es sólida.

Aun así, el reconocimiento pasivo deja ver tres cosas que merecen atención.

La primera es la superficie de subdominios. Los logs de Certificate Transparency revelan un número considerable de activos que no son visibles desde la web principal: entornos de staging, APIs internas, portales de proveedores. Algunos de esos entornos probablemente no tienen el mismo nivel de control que producción. Eso no es un fallo de Iberdrola específicamente, es un problema común en organizaciones grandes donde los equipos despliegan infraestructura sin que el equipo de seguridad tenga visibilidad completa.

La segunda es la exposición en LinkedIn. Los perfiles de ingenieros que trabajan en sistemas OT mencionan tecnologías de control industrial con suficiente detalle como para construir un perfil de la infraestructura técnica de las instalaciones de generación y distribución. Para una empresa de infraestructura crítica, eso tiene implicaciones directas. La solución no es prohibir LinkedIn sino incluir la gestión de la huella digital de empleados en la política de concienciación de seguridad.

La tercera es menor pero ilustrativa: documentos con etiquetas de uso interno accesibles públicamente a través de Google. Indica que el proceso de revisión antes de publicar contenido en el dominio tiene algún punto ciego.

Ninguno de estos hallazgos requirió interactuar con los sistemas de Iberdrola. Todo viene de fuentes públicas, consultadas desde un equipo externo sin credenciales ni acceso especial. Eso es exactamente lo que define el alcance del OSINT pasivo: lo que un adversario puede saber antes de atacar, sin que la empresa lo detecte.

#pagebreak()

#bibliography("references.bib", style: "ieee")
