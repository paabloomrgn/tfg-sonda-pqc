# Sonda pasiva de detección de elementos de red inseguros frente a la computación cuántica

TFG de Pablo Marugán Bastante — Grado en Ingeniería de Tecnologías y Servicios de Telecomunicación (GITST), EPS-UAM.
Tutor: Jorge E. López de Vergara.

Sonda en C con libpcap. Captura tráfico, reensambla los handshakes TLS y lee `supported_groups` y `key_share`. Con eso clasifica cada conexión, cada cliente y cada servidor según usen o no algoritmos de intercambio de claves postcuánticos (ML-KEM e híbridos).

## Estructura

| Carpeta | Contenido |
|---|---|
| `sonda/` | `sonda.c` (la sonda) y `grupos_pqc.csv` (tabla de algoritmos, editable sin recompilar) |
| `herramientas/` | `gen_trazas.py` (trazas de prueba con veredicto conocido), `validar_scapy.py` (segunda implementación para validar), `sonda_tls.py` (sondeo activo de un servidor) |
| `trazas/` | Trazas de prueba. Las capturas reales van en `trazas/reales/` y no se suben |
| `medidas/` | Resultados: salidas NDJSON de la sonda y sondeos activos, con la fecha en el nombre |
| `docs/` | Un PDF breve por tarea (índice abajo) y la guía de captura |
| `zeek/` | Comparación con Zeek sobre la traza de prueba |
| `referencia/` | Código de partida (analizador Modbus con libpcap) |

## Compilar y usar

```bash
sudo apt install -y libpcap-dev jq
cd sonda
gcc -Wall -Wextra -std=gnu11 -O2 -o sonda sonda.c -lpcap

./sonda -f ../trazas/casos_clasificacion.pcap -t          # texto legible
./sonda -f traza.pcap -o ../medidas/salida.ndjson         # NDJSON a fichero
sudo ./sonda -i eth0                                      # en vivo
```

| Opción | Uso |
|---|---|
| `-f` / `-i` | Fichero pcap/pcapng o interfaz (`any` = todas) |
| `-p` | Puerto TCP (443 por defecto) |
| `-g` | Tabla de grupos (`grupos_pqc.csv` por defecto) |
| `-o` | Fichero de salida |
| `-t` | Texto en lugar de JSON |
| `-v` | Una línea por segmento TCP |

**Salida:**
- Una línea JSON por conexión (`"type":"connection"`), con los campos de TLScensus más `connection_status`, `client_status` y `server_status` y sus motivos.
- Al final, una línea por servidor (`"type":"server"`) con el estado acumulado de todas sus conexiones.
- El resumen va por stderr.

**Comprobación rápida:** `casos_clasificacion.pcap` tiene 7 casos y debe dar `soporta_pq`, `indeterminado`, `fuerza_pq`, `inseguro`, `indeterminado`, `inseguro`, `inseguro`.

`casos_rechazo.pcap` (el servidor no responde con un ServerHello) tiene 6 casos y debe dar `inseguro` ×3, `indeterminado` ×3; las 5 primeras conexiones salen `rechazada` y la última `sin_respuesta`.

## Documentación por tareas

| Fecha | Documento | Tema |
|---|---|---|
| **Tutoría 1** | | |
| 13/10/2026 | `Repaso_IP_TCP_TLS.pdf` | Repaso de IP, TCP y TLS 1.3 |
| 13/10/2026 | `Patente_Resumen.pdf` | Resumen de la patente del grupo |
| 13/10/2026 | `TFG_Celia_Base_Sonda.pdf` | Código de partida |
| 13/10/2026 | `Prueba_TFG_Roberto.pdf` | Prueba de la sonda activa de Roberto |
| 13/10/2026 | `Campana_Medidas_PQC.pdf` | Primeras medidas activas |
| 13/10/2026 | `Analisis_Zeek.pdf` | Zeek frente a la sonda |
| 13/10/2026 | `Analizadores_TLS_Existentes.pdf` | Analizadores TLS existentes |
| **Tutoría 2** | | |
| 03/11/2026 | `Identificadores_PQC.pdf` | Identificadores de grupos PQ e híbridos |
| 04/11/2026 | `Analisis_key_share.pdf` | Lectura de `key_share` y clasificación |
| 04/11/2026 | `libpcap_vs_Scapy.pdf` | libpcap frente a Scapy |
| 04/11/2026 | `TLScensus_Comparativa.pdf` | Comparación con TLScensus |
| 04/11/2026 | `Estado_Arte_PQ_TLS.pdf` | Estado del arte |
| 04/11/2026 | `libpcap_en_la_sonda.pdf` | Uso de libpcap en la sonda |
| **Tutoría 3** | | |
| 09/11/2026 | `Salida_JSON_y_trafico_real.pdf` | Salida JSON, IPv6 y captura real con curl |
| 10/11/2026 | `Trafico_real_Chrome_y_QUIC.pdf` | Captura real con Chrome y efecto de QUIC |
| 11/11/2026 | `Alertas_y_cierres.pdf` | Alert y cierres tras el ClientHello; contraste pasivo/activo |
| — | `Guia_captura_trafico_real.md` | Cómo capturar tráfico real |
