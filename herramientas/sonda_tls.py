#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sonda_tls.py — herramienta de apoyo para el TFG de sonda pasiva PQC.

Hace tres cosas:

  1) disecciona   Construye un ClientHello y lo imprime byte a byte, anotado.
                  Es el mapa que necesitas para escribir el parser en C.

  2) sondea       Lanza tres variantes de ClientHello contra un servidor real
                  y parsea el ServerHello / HelloRetryRequest.

  3) pcap         Guarda el intercambio en un .pcap con cabeceras Ethernet/IP/TCP
                  sinteticas, para usarlo como vector de prueba de la sonda en C.

Solo biblioteca estandar. Python 3.8+.

    python3 sonda_tls.py disecciona
    python3 sonda_tls.py sondea  www.uam.es
    python3 sonda_tls.py pcap    www.uam.es  salida.pcap
"""

import os
import socket
import struct
import secrets
import sys
import time

# ----------------------------------------------------------------------------
# Registro IANA "TLS Supported Groups"  (los relevantes)
# ----------------------------------------------------------------------------
GROUPS = {
    0x0017: "secp256r1",
    0x0018: "secp384r1",
    0x0019: "secp521r1",
    0x001D: "x25519",
    0x001E: "x448",
    0x11EB: "SecP256r1MLKEM768",
    0x11EC: "X25519MLKEM768",
    0x11ED: "SecP384r1MLKEM1024",
    0x6399: "X25519Kyber768Draft00",
    0x639A: "SecP256r1Kyber768Draft00",
    0xFE30: "X25519Kyber512Draft00",
    0xFE31: "X25519Kyber768Draft00",
}

# Esta es la tabla que la reivindicacion 8 de la patente llama "base de datos
# de identificadores". En la sonda en C debe cargarse de un fichero externo,
# no estar compilada.
PQC = {0x11EB, 0x11EC, 0x11ED, 0x6399, 0x639A, 0xFE30, 0xFE31}

# Longitud del campo key_exchange, en bytes (RFC 10024, secciones 4.1 y 4.2)
#                 cliente  servidor
SHARE_LEN = {
    0x001D:        (32,     32),
    0x0017:        (65,     65),
    0x0018:        (97,     97),
    0x11EC:        (1216,   1120),
    0x11EB:        (1249,   1153),
    0x11ED:        (1665,   1665),
}

# ServerHello.random que marca un HelloRetryRequest (RFC 8446 / 9846, 4.1.3)
HRR_RANDOM = bytes.fromhex(
    "CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C")

EXT_NAMES = {
    0: "server_name", 10: "supported_groups", 13: "signature_algorithms",
    43: "supported_versions", 51: "key_share",
}

X25519, P256, MLKEM768 = 0x001D, 0x0017, 0x11EC


def gname(gid):
    return GROUPS.get(gid, "desconocido")


# ----------------------------------------------------------------------------
# Clave de encapsulacion ML-KEM-768 sintacticamente valida
# ----------------------------------------------------------------------------
# No sirve para cifrar (no tenemos la privada), pero supera el
# "encapsulation key check" de FIPS 203 7.2, que es lo unico que mira el
# servidor antes de contestar. Suficiente para provocar un ServerHello real.
Q = 3329


def _byte_encode_12(coeffs):
    out = bytearray()
    for i in range(0, 256, 2):
        a0, a1 = coeffs[i], coeffs[i + 1]
        out.append(a0 & 0xFF)
        out.append(((a0 >> 8) & 0x0F) | ((a1 & 0x0F) << 4))
        out.append((a1 >> 4) & 0xFF)
    return bytes(out)


def mlkem768_ek():
    ek = b"".join(_byte_encode_12([secrets.randbelow(Q) for _ in range(256)])
                  for _ in range(3))
    ek += os.urandom(32)                 # rho
    assert len(ek) == 1184
    return ek


def share_x25519mlkem768():
    """RFC 10024 4.1: ML-KEM primero, X25519 despues (orden invertido)."""
    return mlkem768_ek() + os.urandom(32)          # 1184 + 32 = 1216


# ----------------------------------------------------------------------------
# Construccion del ClientHello
# ----------------------------------------------------------------------------
def _ext(etype, body):
    return struct.pack("!HH", etype, len(body)) + body


def build_client_hello(sni, groups, shares, trace=None, pad_to=0):
    """
    shares: lista de (group_id, key_exchange)
    trace:  si es una lista, se le anexan tuplas (offset, longitud, etiqueta)
    """
    parts = []

    def add(label, data):
        parts.append((label, data))
        return data

    body = b""
    body += add("legacy_version = 0x0303 (TLS 1.2 por compatibilidad)",
                struct.pack("!H", 0x0303))
    body += add("random (32 B)", os.urandom(32))
    sid = os.urandom(32)
    body += add("legacy_session_id (1+32 B, modo compatibilidad)",
                struct.pack("!B", len(sid)) + sid)
    suites = struct.pack("!HHH", 0x1301, 0x1302, 0x1303)
    body += add("cipher_suites (2+6 B): AES128-GCM, AES256-GCM, CHACHA20",
                struct.pack("!H", len(suites)) + suites)
    body += add("legacy_compression_methods", b"\x01\x00")

    e = b""
    host = sni.encode()
    sn = struct.pack("!BH", 0, len(host)) + host
    e += add("ext 0  server_name", _ext(0, struct.pack("!H", len(sn)) + sn))

    g = b"".join(struct.pack("!H", x) for x in groups)
    e += add("ext 10 supported_groups  <-- CAPACIDAD DECLARADA DEL CLIENTE",
             _ext(10, struct.pack("!H", len(g)) + g))

    sa = b"".join(struct.pack("!H", x) for x in
                  (0x0403, 0x0804, 0x0401, 0x0503, 0x0805,
                   0x0501, 0x0806, 0x0601))
    e += add("ext 13 signature_algorithms (obligatoria)",
             _ext(13, struct.pack("!H", len(sa)) + sa))

    sv = struct.pack("!H", 0x0304)
    e += add("ext 43 supported_versions = TLS 1.3",
             _ext(43, struct.pack("!B", len(sv)) + sv))

    ks = b""
    for gid, kx in shares:
        ks += struct.pack("!HH", gid, len(kx)) + kx
    ks_ext = _ext(51, struct.pack("!H", len(ks)) + ks)

    # ext 21 padding (RFC 7685). Los navegadores reales envian muchas mas
    # extensiones que este CH minimo. La colocamos ANTES de key_share, que es
    # el caso que de verdad duele: empuja el key_share al segundo segmento TCP.
    if pad_to:
        actual = 5 + 4 + len(body) + 2 + len(e) + len(ks_ext)
        falta = pad_to - actual - 4
        if falta > 0:
            e += add(f"ext 21 padding ({falta} B) — simula el resto de "
                     f"extensiones de un navegador",
                     _ext(21, b"\x00" * falta))

    e += add("ext 51 key_share  <-- APUESTA DEL CLIENTE (claves efimeras)",
             ks_ext)

    body += add("extensions (2 B de longitud + " + str(len(e)) + " B)",
                struct.pack("!H", len(e)) + e)

    hs = struct.pack("!B", 1) + struct.pack("!I", len(body))[1:] + body
    rec = struct.pack("!BHH", 0x16, 0x0301, len(hs)) + hs

    if trace is not None:
        trace.append(("TLSPlaintext: type=0x16 handshake, version, length", 5))
        trace.append(("Handshake: msg_type=0x01 client_hello, length(3B)", 4))
        emitida = False
        for label, data in parts:
            if label.startswith("extensions ("):
                continue                      # ya se emitio antes del primer ext
            if label.startswith("ext ") and not emitida:
                trace.append(("extensions: longitud total del bloque (2 B)", 2))
                emitida = True
            trace.append((label, len(data)))
    return rec


# ----------------------------------------------------------------------------
# Parseo de la respuesta
# ----------------------------------------------------------------------------
def read_record(sock):
    hdr = b""
    while len(hdr) < 5:
        c = sock.recv(5 - len(hdr))
        if not c:
            return None, None
        hdr += c
    ctype, _ver, ln = struct.unpack("!BHH", hdr)
    data = b""
    while len(data) < ln:
        c = sock.recv(ln - len(data))
        if not c:
            break
        data += c
    return ctype, hdr + data


def parse_server_hello(hs):
    """
    hs = cuerpo del handshake, sin el byte de tipo ni los 3 de longitud.

    Comprueba los limites en CADA lectura. No es paranoia: www.sabadell.com
    (12/10/2026) devuelve un ServerHello que termina justo tras el metodo de
    compresion, sin bloque de extensiones. En TLS 1.2 ese campo es opcional;
    en TLS 1.3 es obligatorio. Un parser que lo de por hecho lee fuera del
    buffer — en C, una vulnerabilidad.
    """
    n = len(hs)
    out = {"legacy_version": 0, "is_hrr": False, "cipher": 0, "exts": {},
           "truncado": False}

    if n < 2:
        out["truncado"] = True
        return out
    o = 0
    out["legacy_version"] = struct.unpack_from("!H", hs, o)[0]; o += 2

    if o + 32 > n:
        out["truncado"] = True
        return out
    random = hs[o:o + 32]; o += 32
    out["is_hrr"] = (random == HRR_RANDOM)

    if o + 1 > n:
        out["truncado"] = True
        return out
    sidlen = hs[o]; o += 1
    if o + sidlen > n:
        out["truncado"] = True
        return out
    o += sidlen

    if o + 2 > n:
        out["truncado"] = True
        return out
    out["cipher"] = struct.unpack_from("!H", hs, o)[0]; o += 2

    if o + 1 > n:                      # metodo de compresion
        out["truncado"] = True
        return out
    o += 1

    # A partir de aqui el bloque de extensiones puede NO existir.
    if o + 2 > n:
        return out                     # ServerHello sin extensiones: legitimo
    extlen = struct.unpack_from("!H", hs, o)[0]; o += 2
    end = min(o + extlen, n)

    while o + 4 <= end:
        et, el = struct.unpack_from("!HH", hs, o); o += 4
        if o + el > end:               # extension que se sale del bloque
            out["truncado"] = True
            break
        out["exts"][et] = hs[o:o + el]; o += el
    return out


def interpret(sh, ofrecio_pqc_en_sg=False, mando_key_share_pqc=False):
    """
    Devuelve (texto, group_id o None, veredicto).

    El veredicto NO depende solo de lo que eligio el servidor, sino tambien
    de QUE TENIA DISPONIBLE al elegir. Si el cliente no le mando la clave
    postcuantica, un grupo clasico no permite concluir nada: el servidor
    puede soportar PQC y estar evitando el HelloRetryRequest (medido en
    www.bbva.es, 12/10/2026).
    """
    ks = sh["exts"].get(51)
    if ks is None:
        return "ServerHello sin key_share", None, "INDETERMINADO"

    if sh["is_hrr"]:
        gid = struct.unpack("!H", ks[:2])[0]
        v = "SEGURO" if gid in PQC else "INSEGURO"
        return (f"HelloRetryRequest: el servidor EXIGE {gname(gid)} "
                f"(0x{gid:04X})"), gid, v

    gid, kl = struct.unpack_from("!HH", ks, 0)
    exp = SHARE_LEN.get(gid, (None, None))[1]
    ok = "  [longitud conforme a RFC 10024]" if exp == kl else ""
    txt = (f"ServerHello: grupo elegido {gname(gid)} (0x{gid:04X}), "
           f"key_exchange = {kl} B{ok}")

    if gid in PQC:
        return txt, gid, "SEGURO"
    if mando_key_share_pqc:
        # Tenia la clave PQC en la mano, sin coste de RTT, y la rechazo.
        return txt, gid, "INSEGURO"
    if ofrecio_pqc_en_sg:
        return txt, gid, "INDETERMINADO (pudo evitar el HelloRetryRequest)"
    return txt, gid, "NO INFORMATIVO (el cliente no ofrecio PQC)"


# ----------------------------------------------------------------------------
# Modo 1: diseccion anotada
# ----------------------------------------------------------------------------
def modo_disecciona():
    for titulo, groups, shares in (
        ("CLIENTE CLASICO", [X25519, P256], [(X25519, os.urandom(32))]),
        ("CLIENTE POSTCUANTICO", [MLKEM768, X25519, P256],
         [(MLKEM768, share_x25519mlkem768()), (X25519, os.urandom(32))]),
    ):
        trace = []
        ch = build_client_hello("www.uam.es", groups, shares, trace)
        print("=" * 78)
        print(f"  {titulo}   —   ClientHello de {len(ch)} bytes")
        print("=" * 78)
        off = 0
        for label, ln in trace:
            trozo = ch[off:off + ln]
            hx = trozo[:16].hex(" ")
            if ln > 16:
                hx += " ..."
            print(f"  {off:>5}  +{ln:<5}  {hx:<52}")
            print(f"         {label}")
            off += ln
        if off < len(ch):
            print(f"  {off:>5}  +{len(ch)-off:<5}  (resto)")
        mss = 1460
        print()
        print(f"  >> ClientHello = {len(ch)} B   (MSS tipico = {mss} B)")
        if len(ch) > mss:
            print("     SE REPARTE EN VARIOS SEGMENTOS TCP. La sonda necesita")
            print("     reensamblado o perdera el key_share.")
        else:
            print("     Este CH minimo aun cabe en un segmento, pero le faltan")
            print("     extensiones que cualquier navegador real envia (ALPN,")
            print("     session_ticket, status_request, GREASE, ECH, padding).")
            print("     Con ellas se supera el MSS y el key_share acaba en el")
            print("     segundo segmento: de ahi la necesidad de reensamblado.")
        print()


# ----------------------------------------------------------------------------
# Modo 2: sondeo
# ----------------------------------------------------------------------------
CASOS = [
    ("A", "PQC en supported_groups, key_share solo clasico",
     [MLKEM768, X25519, P256], lambda: [(X25519, os.urandom(32))]),
    ("B", "cliente puramente clasico",
     [X25519, P256], lambda: [(X25519, os.urandom(32))]),
    ("C", "PQC en supported_groups Y key_share postcuantico",
     [MLKEM768, X25519, P256],
     lambda: [(MLKEM768, share_x25519mlkem768()), (X25519, os.urandom(32))]),
]


def _una(host, groups, shares):
    ch = build_client_hello(host, groups, shares)
    s = socket.create_connection((host, 443), timeout=10)
    try:
        s.sendall(ch)
        ctype, raw = read_record(s)
    finally:
        s.close()
    return ch, ctype, raw


# Suites de TLS 1.2, necesarias para la sonda de respaldo
SUITES_TLS12 = (0xC02F, 0xC030, 0xC02B, 0xC02C, 0xCCA8, 0xCCA9)


def comprobar_version(host):
    """
    Sonda de respaldo: ofrece TLS 1.2 Y 1.3 y mira que version elige el
    servidor. Sirve para distinguir 'no soporta TLS 1.3' de 'esta caido'.

    Un servidor sin TLS 1.3 NO PUEDE hacer intercambio de claves
    postcuantico: los grupos hibridos de la RFC 10024 solo estan definidos
    para TLS 1.3. Es una imposibilidad estructural.
    """
    body = b""
    body += struct.pack("!H", 0x0303)
    body += os.urandom(32)
    sid = os.urandom(32)
    body += struct.pack("!B", len(sid)) + sid

    suites = b"".join(struct.pack("!H", c)
                      for c in (0x1301, 0x1302, 0x1303) + SUITES_TLS12)
    body += struct.pack("!H", len(suites)) + suites
    body += b"\x01\x00"

    e = b""
    hn = host.encode()
    sn = struct.pack("!BH", 0, len(hn)) + hn
    e += _ext(0, struct.pack("!H", len(sn)) + sn)

    g = b"".join(struct.pack("!H", x) for x in (MLKEM768, X25519, P256, 0x0018))
    e += _ext(10, struct.pack("!H", len(g)) + g)

    sa = b"".join(struct.pack("!H", x) for x in
                  (0x0403, 0x0804, 0x0401, 0x0503, 0x0805,
                   0x0501, 0x0806, 0x0601))
    e += _ext(13, struct.pack("!H", len(sa)) + sa)

    # ec_point_formats: uncompressed. Algunos servidores TLS 1.2 la exigen.
    e += _ext(11, b"\x01\x00")

    # Esta vez ofrecemos LAS DOS versiones
    sv = struct.pack("!HH", 0x0304, 0x0303)
    e += _ext(43, struct.pack("!B", len(sv)) + sv)

    kx = os.urandom(32)
    ks = struct.pack("!HH", X25519, len(kx)) + kx
    e += _ext(51, struct.pack("!H", len(ks)) + ks)

    body += struct.pack("!H", len(e)) + e
    hs = struct.pack("!B", 1) + struct.pack("!I", len(body))[1:] + body
    ch = struct.pack("!BHH", 0x16, 0x0301, len(hs)) + hs

    s = socket.create_connection((host, 443), timeout=10)
    try:
        s.sendall(ch)
        ctype, raw = read_record(s)
    finally:
        s.close()

    if ctype == 0x15:
        return None, f"ALERT desc={raw[6]}"
    if ctype != 0x16:
        return None, f"registro inesperado {ctype}"

    data = raw[5:]
    hlen = int.from_bytes(data[1:4], "big")
    sh = parse_server_hello(data[4:4 + hlen])

    # En TLS 1.3 la version real va en supported_versions (43).
    # Si esa extension NO esta, lo negociado es TLS 1.2 o anterior.
    sv_ext = sh["exts"].get(43)
    if sv_ext:
        ver = struct.unpack("!H", sv_ext[:2])[0]
    else:
        ver = sh["legacy_version"]

    nombre = {0x0304: "TLS 1.3", 0x0303: "TLS 1.2",
              0x0302: "TLS 1.1", 0x0301: "TLS 1.0"}.get(ver, f"0x{ver:04X}")
    return ver, nombre


def modo_sondea(host):
    print("=" * 78)
    print(f"  {host}")
    print("=" * 78)

    # Paso previo: ¿habla TLS 1.3 siquiera? Sin TLS 1.3 no hay PQC posible.
    try:
        ver, nombre = comprobar_version(host)
    except Exception as exc:
        print(f"  No se pudo conectar: {type(exc).__name__}: {exc}\n")
        return

    if ver is None:
        print(f"  El servidor rechaza la conexion ({nombre})\n")
        return
    if ver != 0x0304:
        print(f"  Version negociada: {nombre}")
        print(f"  -> INSEGURO: sin TLS 1.3 no existe intercambio de claves")
        print(f"     postcuantico. Los grupos hibridos de la RFC 10024 solo")
        print(f"     estan definidos para TLS 1.3.\n")
        return
    print(f"  Version negociada: {nombre}\n")

    for cid, desc, groups, mkshares in CASOS:
        shares_usados = mkshares()
        try:
            ch, ctype, raw = _una(host, groups, shares_usados)
        except Exception as exc:
            print(f"  {cid}  {desc}")
            print(f"     ERROR: {type(exc).__name__}: {exc}\n")
            continue

        frag = "se fragmenta" if len(ch) > 1460 else "1 segmento"
        print(f"  {cid}  {desc}")
        print(f"     ClientHello = {len(ch)} B ({frag})")

        if ctype == 0x15:
            print(f"     ALERT  nivel={raw[5]} descripcion={raw[6]}\n")
            continue
        if ctype != 0x16:
            print(f"     respuesta inesperada, tipo de registro {ctype}\n")
            continue

        data = raw[5:]
        hlen = int.from_bytes(data[1:4], "big")
        sh = parse_server_hello(data[4:4 + hlen])

        sg_pqc = any(g in PQC for g in groups)
        ks_pqc = any(g in PQC for g, _ in shares_usados)
        txt, gid, veredicto = interpret(sh, sg_pqc, ks_pqc)
        print(f"     {txt}")
        print(f"     -> {veredicto}\n")

    print("  Como leer esto:")
    print("   · C elige PQC            -> servidor SEGURO, sin ambiguedad.")
    print("   · A clasico pero C PQC   -> el servidor soporta PQC pero evita el")
    print("                               HelloRetryRequest. A es INDETERMINADO.")
    print("                               (medido en www.bbva.es, 12/10/2026)")
    print("   · A y C clasicos         -> rechaza PQC teniendolo disponible: INSEGURO.")
    print("   · HelloRetryRequest      -> exige ese grupo: soporte confirmado.")


# ----------------------------------------------------------------------------
# Modo 3: volcado a pcap
# ----------------------------------------------------------------------------
def _cksum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def _tcp_packet(src_ip, dst_ip, sport, dport, seq, ack, flags, payload):
    ip_src = socket.inet_aton(src_ip)
    ip_dst = socket.inet_aton(dst_ip)
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, ack,
                      5 << 4, flags, 64240, 0, 0) + payload
    pseudo = ip_src + ip_dst + struct.pack("!BBH", 0, 6, len(tcp))
    ck = _cksum(pseudo + tcp)
    tcp = tcp[:16] + struct.pack("!H", ck) + tcp[18:]

    total = 20 + len(tcp)
    ip = struct.pack("!BBHHHBBH", 0x45, 0, total, 0x1234, 0x4000, 64, 6, 0)
    ip = ip + ip_src + ip_dst
    ip = ip[:10] + struct.pack("!H", _cksum(ip)) + ip[12:]

    eth = (b"\x02\x00\x00\x00\x00\x02" + b"\x02\x00\x00\x00\x00\x01"
           + b"\x08\x00")
    return eth + ip + tcp


def modo_pcap(host, salida, pad_to=1750):
    """Guarda el ClientHello PQC y la respuesta en un .pcap de prueba."""
    groups = [MLKEM768, X25519, P256]
    shares = [(MLKEM768, share_x25519mlkem768()), (X25519, os.urandom(32))]
    ch = build_client_hello(host, groups, shares, pad_to=pad_to)
    s = socket.create_connection((host, 443), timeout=10)
    try:
        s.sendall(ch)
        ctype, raw = read_record(s)
    finally:
        s.close()
    dst_ip = socket.gethostbyname(host)
    src_ip = "10.0.0.2"
    sport, dport = 54321, 443

    paquetes = []
    # SYN / SYN-ACK / ACK, para que la traza tenga un flujo completo
    paquetes.append((_tcp_packet(src_ip, dst_ip, sport, dport, 1000, 0, 0x02, b"")))
    paquetes.append((_tcp_packet(dst_ip, src_ip, dport, sport, 5000, 1001, 0x12, b"")))
    paquetes.append((_tcp_packet(src_ip, dst_ip, sport, dport, 1001, 5001, 0x10, b"")))

    # El ClientHello, troceado en segmentos de MSS para reproducir el caso real
    mss = 1460
    seq = 1001
    for i in range(0, len(ch), mss):
        trozo = ch[i:i + mss]
        paquetes.append(_tcp_packet(src_ip, dst_ip, sport, dport,
                                    seq, 5001, 0x18, trozo))
        seq += len(trozo)

    if raw:
        paquetes.append(_tcp_packet(dst_ip, src_ip, dport, sport,
                                    5001, seq, 0x18, raw))

    with open(salida, "wb") as f:
        f.write(struct.pack("!IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        t = time.time()
        for n, p in enumerate(paquetes):
            ts = t + n * 0.001
            f.write(struct.pack("!IIII", int(ts), int(ts % 1 * 1e6),
                                len(p), len(p)))
            f.write(p)

    nseg = (len(ch) + mss - 1) // mss
    # Localiza la extension key_share por su cabecera: tipo 0x0033 seguido de
    # la longitud, y comprueba que detras venga el primer grupo anunciado.
    ks_off = -1
    for gid, _kx in shares:
        pat = struct.pack("!H", 0x0033)
        i = ch.find(pat)
        while i != -1:
            if ch[i + 6:i + 8] == struct.pack("!H", shares[0][0]):
                ks_off = i
                break
            i = ch.find(pat, i + 1)
        break
    ks_end = ks_off + 4 + struct.unpack_from("!H", ch, ks_off + 2)[0] \
        if ks_off >= 0 else -1

    print(f"Escrito {salida}: {len(paquetes)} paquetes.")
    print(f"  ClientHello : {len(ch)} B en {nseg} segmento(s) TCP de {mss} B")
    if ks_off >= 0:
        s_ini, s_fin = ks_off // mss + 1, (ks_end - 1) // mss + 1
        print(f"  key_share   : bytes {ks_off}..{ks_end} -> "
              f"segmento{'s' if s_fin > s_ini else ''} "
              f"{s_ini}{'-' + str(s_fin) if s_fin > s_ini else ''} de {nseg}")
        if s_fin > 1:
            print("  => Vector de prueba valido: leyendo solo el primer")
            print("     segmento NO se obtiene el key_share completo.")
        else:
            print("  => El key_share cabe en el primer segmento. Aun asi el")
            print("     registro TLS declara", len(ch) - 5, "B de cuerpo y no estan")
            print("     todos, asi que el parser debe esperar igualmente.")
    if nseg == 1:
        print("  => Todo cabe en un segmento; sube pad_to para forzar el corte.")


# ----------------------------------------------------------------------------
if __name__ == "__main__":
    modo = sys.argv[1] if len(sys.argv) > 1 else "disecciona"
    if modo == "disecciona":
        modo_disecciona()
    elif modo == "sondea":
        modo_sondea(sys.argv[2] if len(sys.argv) > 2 else "www.uam.es")
    elif modo == "pcap":
        modo_pcap(sys.argv[2] if len(sys.argv) > 2 else "www.uam.es",
                  sys.argv[3] if len(sys.argv) > 3 else "clienthello.pcap")
    else:
        print(__doc__)
