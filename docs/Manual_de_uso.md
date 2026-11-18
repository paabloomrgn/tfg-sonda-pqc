# Manual de uso de la sonda

Sonda pasiva de detección de elementos de red inseguros frente a la computación cuántica.
TFG de Pablo Marugán Bastante (GITST, EPS-UAM). Tutor: Jorge E. López de Vergara.

La sonda lee tráfico de red (de un fichero de captura o de una interfaz en vivo), reconstruye el inicio de cada conexión TLS y dice, para cada conexión, cada cliente y cada servidor, si usan intercambio de claves postcuántico (ML-KEM o híbrido).

---

## 1. Instalación

Necesita Linux (o WSL en Windows), un compilador de C y libpcap.

```bash
sudo apt install -y build-essential libpcap-dev jq
cd sonda
gcc -Wall -Wextra -std=gnu11 -O2 -o sonda sonda.c -lpcap
```

`jq` no es necesario para la sonda; sirve para consultar su salida JSON.

La sonda lee al arrancar la tabla de algoritmos `grupos_pqc.csv`. Por defecto la busca en la carpeta desde la que se ejecuta (`sonda/`). Si se ejecuta desde otra carpeta, hay que indicarla con `-g`.

---

## 2. Uso rápido

```bash
./sonda -f captura.pcap                       # analizar un fichero; salida JSON
./sonda -f captura.pcap -t                    # lo mismo, en texto legible
./sonda -f captura.pcap -o resultado.ndjson   # guardar el JSON en un fichero
./sonda -f captura.pcap -p tls                # todos los puertos de TLS implícito
sudo ./sonda -i eth0 -o vivo.ndjson           # en vivo (Ctrl+C para parar)
```

---

## 3. Opciones

| Opción | Qué hace | Por defecto |
|---|---|---|
| `-f fichero` | Lee un fichero de captura (`.pcap` o `.pcapng`) | — |
| `-i interfaz` | Captura en vivo de una interfaz (`eth0`, `wlan0`…; `any` = todas). Necesita `sudo` | — |
| `-p puertos` | Puertos TCP a analizar (ver tabla siguiente) | `443` |
| `-g fichero` | Tabla de algoritmos | `grupos_pqc.csv` |
| `-o fichero` | Escribe la salida en un fichero en lugar de en pantalla | pantalla |
| `-t` | Salida en texto legible en lugar de JSON | JSON |
| `-v` | Una línea por cada segmento TCP analizado (depuración) | — |
| `-h` | Muestra la ayuda | — |

Hay que usar `-f` o `-i`, no los dos.

### Puertos (`-p`)

| Valor | Puertos analizados |
|---|---|
| (sin `-p`) | Solo el 443 (HTTPS) |
| `-p 993` | Uno concreto |
| `-p 443,993,8000-8100` | Una lista de puertos y rangos |
| `-p tls` | Los 18 puertos de TLS implícito (tabla de abajo) |
| `-p all` | Todos. Solo se analizan las conexiones cuyo primer mensaje es un registro TLS (`0x16 0x03`); el resto se descarta |

Se pueden combinar: `-p tls,8080`.

| Puerto | Servicio | Puerto | Servicio | Puerto | Servicio |
|---|---|---|---|---|---|
| 443 | https | 990 | ftps | 5223 | xmpp-tls |
| 465 | smtps | 992 | telnets | 5671 | amqps |
| 563 | nntps | 993 | imaps | 6697 | ircs |
| 636 | ldaps | 994 | ircs | 8443 | https-alt |
| 853 | dns-over-tls | 995 | pop3s | 8883 | mqtts |
| 989 | ftps-data | 5061 | sip-tls | 9093 | kafka-tls |

**No se cubren todavía los puertos con STARTTLS** (25, 587, 143, 110, 389, 21): en ellos la conexión empieza en texto plano y pasa a TLS más tarde.

---

## 4. Qué capturas acepta

- **Formatos:** pcap y pcapng (tcpdump, Wireshark, tshark).
- **Tipos de enlace:** Ethernet (con o sin VLAN 802.1Q/QinQ), Linux «cooked» SLL y SLL2 (`tcpdump -i any`), loopback (Linux, BSD, Windows) y RAW.
- **Red:** IPv4 e IPv6 (con cabeceras de extensión).
- **Capturas hechas en el propio equipo con Windows (Npcap):** se corrige la longitud IP a 0 que provoca el *TCP Segmentation Offload*.
- **Requisito:** la captura debe guardar los paquetes enteros (`tcpdump -s 0`). Si se recortan, se pierde el `key_share`.

Para capturar:

```bash
sudo tcpdump -i eth0 -s 0 -w captura.pcap 'tcp port 443'
```

En Wireshark, con el filtro de captura `tcp port 443 or udp port 443` (la parte UDP solo sirve para medir QUIC, que la sonda no analiza). Ver [`Guia_captura_trafico_real.md`](Guia_captura_trafico_real.md).

---

## 5. Salida

- **Salida estándar** (pantalla o `-o`): el JSON, o el texto si se usa `-t`.
- **Salida de errores**: los mensajes de arranque y el resumen final.

Así, `./sonda -f x.pcap | jq …` funciona sin que el resumen se mezcle con el JSON. Para no ver el resumen: `2>/dev/null`.

### 5.1. JSON: una línea por conexión (`"type":"connection"`)

Los campos marcados con ★ tienen el mismo nombre y significado que en TLScensus.

| Campo | Contenido |
|---|---|
| `first_seen`, `last_seen` ★ | Primer y último paquete de la conexión (UTC) |
| `transport`, `ip_version` | `tcp`; 4 o 6 |
| `client_ip`, `client_port`, `server_ip`, `server_port` ★ | Extremos de la conexión |
| `service` | Nombre del servicio según el puerto (`https`, `imaps`…) o `null` |
| `server_name` ★ | Nombre del servidor que pide el cliente (SNI) |
| `version_offered` | Versión máxima que ofrece el cliente |
| `version` ★ | Versión negociada (`TLS 1.3`, `TLS 1.2`…) o `null` si no hubo ServerHello |
| `group` ★, `group_id`, `group_class` | Grupo de intercambio de claves negociado, su identificador y su clase |
| `group_source` | De dónde se sacó: `key_share` (TLS 1.3) o `server_key_exchange` (TLS 1.2) |
| `supported_groups` ★ | Grupos que el cliente **sabe** usar |
| `key_share_groups` ★ | Grupos para los que el cliente **manda** clave |
| `key_shares` | Lo mismo con la longitud de cada clave y si es la esperada (`length_ok`) |
| `server_key_share_length`, `…_ok` | Longitud de la clave del servidor y si es la esperada |
| `pq_status` ★ | Estado al estilo de TLScensus (ver 6.4) |
| `hrr`, `hrr_group` | Si hubo HelloRetryRequest y qué grupo pidió el servidor |
| `key_share_groups_retry` | Grupos del segundo ClientHello, tras el HRR |
| `server_alert` | Alert del servidor en lugar de ServerHello: `level`, `code`, `description` |
| `server_close` | Cierre del servidor en lugar de ServerHello: `fin` o `rst` |
| `connection_status` | Veredicto de la conexión (6.1) |
| `client_status`, `client_reason` | Veredicto del cliente y su motivo (6.2) |
| `server_status`, `server_reason` | Veredicto del servidor en esta conexión y su motivo (6.3) |

Los grupos GREASE (valores de relleno que mandan los navegadores) se omiten en las listas.

### 5.2. JSON: una línea por servidor (`"type":"server"`)

Se escriben al terminar, con lo acumulado de todas las conexiones a cada servidor (IP:puerto).

| Campo | Contenido |
|---|---|
| `server_ip`, `server_port`, `ip_version` | Servidor |
| `server_names` | Nombres (SNI) con los que se le ha pedido (hasta 8) |
| `connections` | Número de conexiones vistas |
| `groups_selected` | Grupos que ha elegido y cuántas veces |
| `reasons` | Cuántas conexiones por cada motivo (`server_reason`) |
| `server_status`, `server_status_detail` | Veredicto acumulado (6.5) y su explicación |

### 5.3. Texto (`-t`)

Un bloque por conexión con lo que el cliente sabe y manda, lo que el servidor elige o responde, y los tres veredictos. Al final, la lista de servidores con su estado acumulado. Sirve para leer a mano; para procesar, mejor el JSON.

---

## 6. Cómo leer los veredictos

### 6.1. Conexión (`connection_status`)

| Valor | Significado |
|---|---|
| `segura` | Se negoció un grupo PQ o híbrido |
| `insegura` | Se negoció un grupo clásico (o TLS ≤ 1.2) |
| `rechazada` | El servidor respondió con un Alert o cerró la conexión en lugar de mandar ServerHello |
| `incompleta` | El servidor mandó un HelloRetryRequest y el cliente no siguió |
| `sin_respuesta` | No se vio respuesta del servidor |

### 6.2. Cliente (`client_status`)

| Valor | Motivo | Significado |
|---|---|---|
| `inseguro` | `no_ofrece_pq` | No ofrece ningún grupo PQ |
| `potencialmente_inseguro` | `pq_y_clasico` | Ofrece PQ, pero también clásico (Chrome, curl…) |
| `seguro` | `solo_pq` | Solo ofrece grupos PQ |

### 6.3. Servidor en una conexión (`server_status`)

| Valor | Motivo | Significado |
|---|---|---|
| `fuerza_pq` | `hrr_pide_pq` | Pidió PQ con un HelloRetryRequest |
| `soporta_pq` | `eligio_pq` | Eligió PQ |
| `inseguro` | `clave_pq_rechazada` | Tenía la clave PQ del cliente y eligió clásico |
| `inseguro` | `version_sin_pq` | El cliente ofrecía TLS 1.3 y eligió una versión sin PQ |
| `inseguro` | `rechaza_solo_pq` / `cierra_solo_pq` | El cliente solo ofrecía PQ y respondió con un Alert o cerró |
| `indeterminado` | `pq_solo_anunciado` | El cliente anunció PQ sin mandar la clave y el servidor no la pidió |
| `indeterminado` | `cliente_sin_pq` | El cliente no ofrecía PQ: el servidor no tuvo opción |
| `indeterminado` | `alerta` / `cierre` | Alert o cierre ante un cliente que también ofrecía clásico (puede ser por otra causa) |
| `indeterminado` | `sin_respuesta` | No se vio respuesta |

### 6.4. Estado al estilo de TLScensus (`pq_status`)

`post_quantum` (se negoció PQ) · `offered_not_selected` (el cliente mandó clave PQ y no se eligió) · `advertised_only` (el cliente solo lo anunció) · `classical` (el cliente no ofreció PQ) · `unknown` (no hubo ServerHello).

### 6.5. Servidor acumulado (líneas `"type":"server"`)

| Valor | Cuándo |
|---|---|
| `inseguro` | Alguna vez eligió clásico teniendo la opción PQ, o rechaza a los clientes que solo ofrecen PQ |
| `potencialmente_inseguro` | Elige PQ, pero también acepta clásico de clientes que no le dan la clave PQ |
| `seguro` | Solo se le ha visto negociar PQ (aunque rechace algún grupo PQ concreto) |
| `indeterminado` | Ningún cliente le dio la opción PQ, o no se vio su respuesta |

---

## 7. Consultas útiles con `jq`

```bash
J=resultado.ndjson

# Conexiones por estado
jq -r 'select(.type=="connection") | .connection_status' $J | sort | uniq -c

# Qué grupo elige cada servidor
jq -r 'select(.type=="connection") | [.server_name, .version, .group] | @tsv' $J | sort -u

# Ficha de cada servidor
jq -r 'select(.type=="server") | [.server_status, .server_ip, (.server_names|join(","))] | @tsv' $J | sort

# Servidores que rechazan la clave PQ
jq -c 'select(.type=="connection" and .server_reason=="clave_pq_rechazada") | {server_name, group}' $J

# Rechazos con su Alert o cierre
jq -r 'select(.connection_status=="rechazada") | [.server_name, (.server_alert.description // .server_close)] | @tsv' $J
```

---

## 8. Tabla de algoritmos (`grupos_pqc.csv`)

Una línea por grupo. Para añadir un algoritmo nuevo basta con añadir una línea; no hay que recompilar.

```
id_hex,id_dec,nombre,clase,long_cliente,long_servidor,fuente
0x11EC,4588,X25519MLKEM768,hibrido,1216,1120,IANA / RFC 10024
0xFE33,65075,hqc1,experimental,0,0,oqs-provider (no IANA)
```

| Columna | Contenido |
|---|---|
| `id_hex` | Identificador del grupo (NamedGroup), en hexadecimal |
| `id_dec` | El mismo en decimal (informativo) |
| `nombre` | Nombre que aparece en la salida |
| `clase` | `clasico`, `pq`, `hibrido`, `hibrido_obsoleto` o `experimental`. Todas menos `clasico` cuentan como postcuánticas |
| `long_cliente`, `long_servidor` | Bytes esperados de la clave de cada lado (0 = no se comprueba) |
| `fuente` | De dónde sale el identificador (informativo) |

Las líneas que empiezan por `#` son comentarios. Hoy contiene 90 grupos: el registro IANA completo, los Kyber obsoletos y los de Open Quantum Safe (FrodoKEM, BIKE, HQC…).

---

## 9. Resumen final

Al terminar (o al pulsar Ctrl+C en vivo), la sonda escribe por la salida de errores un resumen con:

- **Paquetes:** total, VLAN, truncados, IPv4/IPv6, fragmentos, longitud IP a 0 (TSO), TCP/UDP.
- **TCP de los puertos analizados:** segmentos, con datos, que empiezan un registro TLS.
- **Reensamblado:** flujos, cerrados por FIN/RST, desordenados, retransmisiones, registros TLS completos.
- **Clasificación:** conexiones, clientes y servidores por estado, y cuántas respuestas fueron Alert o cierre.

Si «TCP malformados» o «truncados» no son 0, conviene revisar la captura (snaplen corto, paquetes cortados).

---

## 10. Limitaciones

- **QUIC (HTTP/3):** va sobre UDP y no se analiza. En navegación con Chrome puede ser un 20 % de los handshakes, casi todos con PQ.
- **STARTTLS:** no se sigue el diálogo en claro (puertos 25, 587, 143, 110…).
- **Conexiones reutilizadas:** si el cliente no abre una conexión nueva, no hay handshake que ver.
- **Servidor que no responde:** no se puede clasificar (`sin_respuesta`).
- **Mensajes de handshake repartidos en varios registros TLS:** no se reconstruyen (un ClientHello o ServerHello repartido así es muy raro).
- **Fragmentos IP:** se descartan.

---

## 11. Problemas frecuentes

| Síntoma | Causa y solución |
|---|---|
| `No se pudo leer la tabla de grupos` | Se ejecuta fuera de `sonda/`: añadir `-g ruta/grupos_pqc.csv` |
| `Tipo de enlace … no soportado` | La captura es de un tipo de enlace distinto de los de la sección 4 |
| 0 conexiones con una captura de otro puerto | Falta `-p` con ese puerto, o `-p all` |
| Muchas menos conexiones que ClientHello en Wireshark | Captura recortada (usar `-s 0`) o versión antigua de la sonda sin la corrección de TSO |
| Error de permisos con `-i` | Ejecutar con `sudo` |
