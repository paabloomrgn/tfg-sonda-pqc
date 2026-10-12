# Comparación con Zeek

Zeek 8.0.10 (zeek-lts) instalado desde el repositorio oficial del proyecto,
rama xUbuntu_26.04. Ejecutado sobre la traza de prueba cargando el script
de política que amplía ssl.log:

    zeek -r ../trazas/clienthello_pqc.pcap policy/protocols/ssl/ssl-log-ext

## Resultado sobre la traza de prueba

    version                  TLSv13
    curve                    x25519
    client_curves            4588,29,23
    client_key_share_groups  4588,29
    server_key_share_group   29
    ssl_client_exts          0,10,13,43,21,51

Coincide exactamente con el ClientHello construido por sonda_tls.py y con
la disección de Wireshark. La traza queda validada por tres implementaciones
independientes.

## Lo que Zeek ya hace

- Reensamblado TCP completo: reporta 1 conexión donde la sonda ve 6 paquetes.
- Parseo de ClientHello y ServerHello.
- Campo `curve`: el grupo elegido por el servidor, traducido a nombre.
- Con ssl-log-ext: `client_curves` (supported_groups),
  `client_key_share_groups` y `server_key_share_group`.
- Tabla de constantes con los grupos híbridos (verificado con grep):
      [4587] SecP256r1MLKEM768
      [4588] X25519MLKEM768
      [4589] SecP384r1MLKEM1024
      [25497] [25498] Kyber draft, obsoletos
      [512] [513] [514] ML-KEM puros

## Lo que NO hace, y es la aportación de este TFG

- No emite veredicto. La línea de ssl.log describe el handshake pero no
  clasifica el equipo como seguro, inseguro o indeterminado.
- No modela el problema del HelloRetryRequest: 45 % de falsos negativos
  medidos el 12/10/2026 sobre 20 dominios.
- No construye el inventario de la patente (reivindicación 10) ni mantiene
  estado persistente por servidor entre conexiones.
- Los campos extendidos salen como números, no como nombres: incluso con
  Zeek hace falta la base de datos de identificadores (reivindicación 8).
- Le faltan los codepoints privados 0xFE30 y 0xFE31 (verificado: el grep
  no devuelve nada).
- Sus constantes citan el Internet-Draft, no la RFC 10024 de agosto de 2026.

## Papel de Zeek en el TFG

1. Verdad de referencia para validar la sonda campo a campo.
2. Línea base de rendimiento sobre la misma traza.
3. Referencia de diseño del reensamblado y del analizador TLS.
