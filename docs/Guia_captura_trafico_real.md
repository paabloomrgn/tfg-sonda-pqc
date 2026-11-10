# Guía: capturar tráfico real y pasarlo por la sonda

Dos capturas que se complementan:

| Captura | Cliente | Para qué sirve |
|---|---|---|
| A. WSL + curl | OpenSSL 3.5 (lo controlamos nosotros) | Sabemos exactamente qué manda el cliente: manda clave X25519MLKEM768, así que el veredicto del **servidor** es definitivo (o la elige, o la rechaza). |
| B. Windows + Chrome | Navegador real | Tráfico como el de cualquier usuario de la red: es lo que verá la sonda desplegada. |

En WSL2 (modo NAT), `tcpdump` dentro de Ubuntu **solo ve el tráfico de WSL**, no el de Windows. Por eso la captura de Chrome se hace con Wireshark en Windows.

> **Privacidad.** Una captura real contiene las IP y los dominios visitados. No subas `trazas/reales/` a GitHub (ya está en `.gitignore`). Usa un perfil de Chrome sin tus cuentas.

---

## 0. Compilar y comprobar la sonda

```bash
cd ~/tfg && git pull
cd sonda && gcc -Wall -Wextra -std=gnu11 -O2 -o sonda sonda.c -lpcap
python3 ../herramientas/gen_trazas.py ../trazas 3000      # regenera también casos_ipv6.pcap
./sonda -f ../trazas/casos_clasificacion.pcap -t           # texto legible
./sonda -f ../trazas/casos_ipv6.pcap | jq -c '{server_name, pq_status, server_status}'
```

Debe salir, en los dos ficheros y en este orden: `soporta_pq`, `indeterminado`, `fuerza_pq`, `inseguro`, `indeterminado`, `inseguro`.

Opciones nuevas:

| Opción | Qué hace |
|---|---|
| (por defecto) | NDJSON por la salida estándar; mensajes y resumen por stderr |
| `-o fich.ndjson` | escribe el JSON en un fichero |
| `-t` | texto legible, como antes |
| `-i any` | captura en todas las interfaces (enlace Linux SLL2, ya soportado) |

---

## A. Captura con curl en WSL

**1. Comprobar que el cliente ofrece PQ** (terminal de WSL):

```bash
openssl version                                       # debe ser 3.5.x
openssl s_client -connect google.com:443 -brief </dev/null 2>&1 | grep -i group
curl -V | head -1                                     # debe decir OpenSSL/3.5.x
ip -br addr                                           # nombre de la interfaz (normalmente eth0)
```

La línea del grupo debe mostrar `X25519MLKEM768`.

**2. Capturar** (terminal 1):

```bash
mkdir -p ~/tfg/trazas/reales
sudo tcpdump -i eth0 -s 0 -w ~/tfg/trazas/reales/curl_$(date +%Y%m%d).pcap 'tcp port 443'
```

**3. Generar tráfico** (terminal 2):

```bash
for d in google.com cloudflare.com wikipedia.org github.com microsoft.com apple.com \
         amazon.es uam.es ucm.es upm.es caixabank.es bbva.es santander.es \
         elpais.com rtve.es boe.es agenciatributaria.gob.es renfe.com; do
  curl -s -o /dev/null -m 15 -w "%{http_code}  $d\n" "https://$d"
done
```

Después, Ctrl+C en la terminal 1.

**4. Pasar la captura por la sonda:**

```bash
cd ~/tfg/sonda
F=../trazas/reales/curl_$(date +%Y%m%d).pcap
./sonda -f $F -t | less                                   # leerlo
./sonda -f $F -o ../medidas/curl_$(date +%Y%m%d).ndjson   # guardarlo en JSON
```

**Qué esperar:**

- **Cliente:** `potencialmente_inseguro` en todas las conexiones, porque OpenSSL 3.5 manda clave X25519MLKEM768 y también x25519.
- **Servidor:** `soporta_pq` o `inseguro (clave_pq_rechazada)`. Nunca debería salir `indeterminado`, porque siempre tuvo la clave PQ a mano.

**Alternativa en vivo, sin fichero intermedio:**

```bash
sudo ./sonda -i eth0 -o ../medidas/vivo.ndjson
```

Lanza el bucle de curl en otra terminal y para la sonda con Ctrl+C.

---

## B. Captura con Chrome en Windows

**1.** Instala Wireshark para Windows (con Npcap) y crea en Chrome un perfil nuevo sin cuentas.

Lista de webs usada (10/11/2026), siempre en este orden: google.com, youtube.com, cloudflare.com, wikipedia.org, github.com, microsoft.com, apple.com, amazon.es, uam.es, ucm.es, upm.es, bbva.es, santander.es, elpais.com, rtve.es, boe.es, renfe.com, instagram.com, netflix.com. Esperar a que cargue cada una y unos 5 s más; no hace falta tocar Wireshark entre webs.

Antes de empezar, cerrar Edge y las aplicaciones que no se necesiten: todo su tráfico HTTPS también se captura.

**2. Primera pasada, con QUIC activado (el comportamiento normal).**
- Comprobar en `chrome://net-internals/#quic` que *QUIC Enabled* es `true`.
- En Wireshark, *Captura → Opciones*: interfaz Wi-Fi (o Ethernet) y filtro de captura **exactamente** `tcp port 443 or udp port 443` (la caja se pone verde). Sin la parte `udp`, QUIC no se guarda.
- Comprobación en directo: con youtube.com abierto, escribir `quic` en el filtro de visualización; deben salir paquetes.
- Visitar la lista, parar y guardar como `chrome_quic_on.pcapng` en `C:\Users\<usuario>\tfg_capturas\`.

**3. Segunda pasada, sin QUIC.**
- Abre `chrome://flags`, busca *Experimental QUIC protocol*, ponlo en *Disabled* y pulsa *Relaunch*.
- Comprobar en `chrome://net-internals/#quic` que *QUIC Enabled* es `false`. (`chrome.exe --disable-quic` no sirve si Chrome sigue abierto en segundo plano.)
- Repite la captura con el mismo filtro y guárdala como `chrome_quic_off.pcapng`.
- **Al terminar, volver a poner el flag en *Default***: se mantiene aunque se reinicie Chrome.

El filtro usado queda grabado en el pcapng (Wireshark: *Estadísticas → Propiedades del fichero de captura*). Conviene revisarlo antes de dar una captura por buena.

**4. Copiar a WSL y analizar:**

```bash
cp /mnt/c/Users/<usuario>/tfg_capturas/*.pcapng ~/tfg/trazas/reales/
cd ~/tfg/sonda
./sonda -f ../trazas/reales/chrome_quic_off.pcapng -o ../medidas/chrome_quic_off_$(date +%Y%m%d).ndjson
./sonda -f ../trazas/reales/chrome_quic_on.pcapng  -o ../medidas/chrome_quic_on.ndjson
```

**5. Medir cuánto se pierde por QUIC.**
- En Wireshark, con `chrome_quic_on.pcapng`, abre *Estadísticas → Conversaciones* y compara los bytes y conexiones de UDP 443 con los de TCP 443.
- Es el dato para la pregunta de si QUIC entra en el alcance.

**Qué esperar:**
- Chrome manda GREASE, X25519MLKEM768 y x25519, así que el cliente sale `potencialmente_inseguro`.
- Habrá conexiones IPv6 si tu red tiene IPv6: ahora la sonda las analiza.
- Con QUIC activado, Google, YouTube y gran parte de Cloudflare apenas aparecerán por TCP.

---

## Consultas útiles sobre el JSON

```bash
J=../medidas/curl_20261106.ndjson

# Conexiones por estado (comparable con TLScensus)
jq -r 'select(.type=="connection") | .pq_status' $J | sort | uniq -c

# Grupo elegido por cada servidor
jq -r 'select(.type=="connection") | [.server_name, .version, .group] | @tsv' $J | sort -u

# Ficha de cada servidor (estado acumulado)
jq -r 'select(.type=="server") | [.server_status, .server_ip, (.server_names|join(","))] | @tsv' $J | sort

# Servidores que rechazan la clave PQ
jq -c 'select(.type=="connection" and .server_reason=="clave_pq_rechazada") | {server_name, group, key_share_groups}' $J
```

## Contraste con Wireshark

Para comprobar una conexión concreta:
- Filtro `tls.handshake.type == 2` (ServerHello).
- Despliega *Extension: key_share* y compara el grupo con el campo `group` del JSON.
- Para el cliente, usa `tls.handshake.type == 1` y mira `supported_groups` y `key_share`.
