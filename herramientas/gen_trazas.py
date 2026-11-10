#!/usr/bin/env python3
"""
gen_trazas.py - Genera trazas pcap de prueba para la sonda con Scapy.

TFG - Pablo Marugan Bastante - GITST, EPS-UAM

Los mensajes TLS se construyen byte a byte segun la RFC 8446, con las
longitudes reales de cada clave (X25519MLKEM768: 1216 B el cliente y
1120 B el servidor). No se cifra nada: la sonda solo lee ClientHello,
HelloRetryRequest y ServerHello, que van en claro.

Uso:
    python3 gen_trazas.py [directorio_salida] [n_conexiones_rendimiento]

Genera:
    casos_clasificacion.pcap      un caso por cada situacion de clasificacion
    casos_ipv6.pcap               los mismos casos sobre IPv6, uno de ellos
                                  con una cabecera de extension (hop-by-hop)
    reensamblado_desordenado.pcap ClientHello en 3 segmentos, desordenado y
                                  con una retransmision
    rendimiento.pcap              muchas conexiones mezcladas, para medir
                                  la velocidad de la sonda frente a Scapy
"""
import os
import random
import struct
import sys

from scapy.all import IP, IPv6, IPv6ExtHdrHopByHop, TCP, Ether, Raw, conf, wrpcap

conf.verb = 0

# ---------------------------------------------------------------- grupos
GREASE = 0x3A3A
X25519, P256 = 0x001D, 0x0017
X25519MLKEM768 = 0x11EC
# longitud de la clave en el key_share (RFC 10024 y RFC 7748/8446)
LONG_CLIENTE = {X25519: 32, P256: 65, X25519MLKEM768: 1216, GREASE: 1}
LONG_SERVIDOR = {X25519: 32, P256: 65, X25519MLKEM768: 1120}

# random fijo que identifica un HelloRetryRequest (RFC 8446, 4.1.3)
HRR_RANDOM = bytes.fromhex(
    "CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C")


# ------------------------------------------------- utilidades de formato
def u8(v): return struct.pack("!B", v)
def u16(v): return struct.pack("!H", v)
def u24(v): return struct.pack("!I", v)[1:]
def vec8(b): return u8(len(b)) + b          # longitud de 1 byte + datos
def vec16(b): return u16(len(b)) + b        # longitud de 2 bytes + datos
def ext(tipo, cuerpo): return u16(tipo) + vec16(cuerpo)
def aleatorio(n): return bytes(random.getrandbits(8) for _ in range(n))


# ------------------------------------------------------- mensajes TLS
def client_hello(sni, grupos, claves, tls13=True):
    """grupos -> supported_groups (lo que sabe); claves -> key_share (lo que manda)"""
    e = ext(0x0000, vec16(u8(0) + vec16(sni.encode())))                 # server_name
    e += ext(0x000A, vec16(b"".join(u16(g) for g in grupos)))           # supported_groups
    e += ext(0x000D, vec16(u16(0x0403) + u16(0x0804)))                  # signature_algorithms
    if tls13:
        e += ext(0x002B, vec8(u16(0x0304) + u16(0x0303)))               # supported_versions
        ks = b"".join(u16(g) + vec16(aleatorio(LONG_CLIENTE[g])) for g in claves)
        e += ext(0x0033, vec16(ks))                                      # key_share
    cuerpo = (u16(0x0303) + aleatorio(32) + vec8(aleatorio(32))
              + vec16(u16(0x1301) + u16(0x1302) + u16(0xC02F)) + vec8(b"\x00") + vec16(e))
    return u8(1) + u24(len(cuerpo)) + cuerpo


def server_hello(grupo, hrr=False, tls13=True, suite=0x1301):
    e = b""
    if tls13:
        e += ext(0x002B, u16(0x0304))
        # en un HRR, key_share lleva solo el grupo pedido; en un SH, grupo + clave
        e += ext(0x0033, u16(grupo) if hrr else u16(grupo) + vec16(aleatorio(LONG_SERVIDOR[grupo])))
    cuerpo = (u16(0x0303) + (HRR_RANDOM if hrr else aleatorio(32)) + vec8(aleatorio(32))
              + u16(suite) + u8(0) + (vec16(e) if e else b""))
    return u8(2) + u24(len(cuerpo)) + cuerpo


def certificado_falso(n=900):
    cuerpo = u24(n + 3) + u24(n) + aleatorio(n)
    return u8(11) + u24(len(cuerpo)) + cuerpo


def server_key_exchange(grupo):
    cuerpo = u8(3) + u16(grupo) + vec8(aleatorio(LONG_SERVIDOR[grupo])) + u16(0x0403) + vec16(aleatorio(72))
    return u8(12) + u24(len(cuerpo)) + cuerpo


def server_hello_done():
    return u8(14) + u24(0)


def registro(tipo, datos, version=0x0303):
    return u8(tipo) + u16(version) + vec16(datos)


# ------------------------------------------------------- conexion TCP
class Conexion:
    def __init__(self, ip_cliente, ip_servidor, puerto_cliente, puerto_servidor=443, mss=1460,
                 hop_by_hop=False):
        self.c, self.s = ip_cliente, ip_servidor
        self.ipv6 = ":" in ip_cliente
        self.hbh = hop_by_hop          # anadir una cabecera de extension IPv6
        self.pc, self.ps, self.mss = puerto_cliente, puerto_servidor, mss
        self.seq_c, self.seq_s = random.getrandbits(32), random.getrandbits(32)
        self.paquetes = []

    def _pkt(self, del_cliente, flags, seq, ack, datos=b""):
        src, dst = (self.c, self.s) if del_cliente else (self.s, self.c)
        if self.ipv6:
            ip = IPv6(src=src, dst=dst)
            if self.hbh:
                ip = ip / IPv6ExtHdrHopByHop()
        else:
            ip = IP(src=src, dst=dst)
        tcp = (TCP(sport=self.pc, dport=self.ps, flags=flags, seq=seq, ack=ack) if del_cliente
               else TCP(sport=self.ps, dport=self.pc, flags=flags, seq=seq, ack=ack))
        p = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / ip / tcp
        return p / Raw(datos) if datos else p

    def handshake_tcp(self):
        self.paquetes += [self._pkt(True, "S", self.seq_c, 0),
                          self._pkt(False, "SA", self.seq_s, self.seq_c + 1)]
        self.seq_c += 1
        self.seq_s += 1
        self.paquetes.append(self._pkt(True, "A", self.seq_c, self.seq_s))

    def segmentos(self, del_cliente, datos):
        """Parte los datos en segmentos de como mucho mss bytes (sin anadirlos)"""
        seq = self.seq_c if del_cliente else self.seq_s
        ack = self.seq_s if del_cliente else self.seq_c
        trozos = [self._pkt(del_cliente, "PA", seq + i, ack, datos[i:i + self.mss])
                  for i in range(0, len(datos), self.mss)]
        if del_cliente:
            self.seq_c += len(datos)
        else:
            self.seq_s += len(datos)
        return trozos

    def enviar(self, del_cliente, datos):
        self.paquetes += self.segmentos(del_cliente, datos)

    def cerrar(self):
        self.paquetes += [self._pkt(True, "FA", self.seq_c, self.seq_s),
                          self._pkt(False, "FA", self.seq_s, self.seq_c + 1)]


# ------------------------------------------------------------ casos
def caso(n, sni, grupos, claves, elegido, hrr=False, servidor_tls12=False, mss=1460,
         ipv6=False, hop_by_hop=False):
    """Una conexion completa. n distingue IP y puerto del cliente."""
    if ipv6:   # 2001:db8::/32 es el prefijo reservado para documentacion
        cli, srv = f"2001:db8:c::{n:x}", f"2001:db8:5::{n % 200 + 1:x}"
    else:
        cli, srv = f"10.0.{n >> 8 & 255}.{n & 255}", f"198.51.100.{n % 200 + 1}"
    con = Conexion(cli, srv, 40000 + n % 20000, mss=mss, hop_by_hop=hop_by_hop)
    con.handshake_tcp()
    con.enviar(True, registro(0x16, client_hello(sni, grupos, claves), version=0x0301))
    if hrr:   # el servidor pide un grupo (X25519MLKEM768 si hrr=True); el cliente
              # repite el ClientHello con la clave de ese grupo
        pedido = X25519MLKEM768 if hrr is True else hrr
        con.enviar(False, registro(0x16, server_hello(pedido, hrr=True)) + registro(0x14, b"\x01"))
        con.enviar(True, registro(0x14, b"\x01")
                   + registro(0x16, client_hello(sni, grupos, [pedido])))
    if servidor_tls12:
        con.enviar(False, registro(0x16, server_hello(0, tls13=False, suite=0xC02F)
                                   + certificado_falso() + server_key_exchange(P256) + server_hello_done()))
    else:
        con.enviar(False, registro(0x16, server_hello(elegido)) + registro(0x14, b"\x01")
                   + registro(0x17, aleatorio(300)))
    con.cerrar()
    return con.paquetes


CASOS = [
    # SNI                      sabe                              manda                  elige
    ("1-pq-elegido.es",       [GREASE, X25519MLKEM768, X25519, P256], [GREASE, X25519MLKEM768, X25519], X25519MLKEM768, {}),
    ("2-cliente-clasico.es",  [X25519, P256],                     [X25519],              X25519, {}),
    ("3-hrr-fuerza-pq.es",    [X25519MLKEM768, X25519, P256],     [X25519],              X25519MLKEM768, {"hrr": True}),
    ("4-rechaza-clave-pq.es", [X25519MLKEM768, X25519, P256],     [X25519MLKEM768, X25519], X25519, {}),
    ("5-no-fuerza-pq.es",     [X25519MLKEM768, X25519, P256],     [X25519],              X25519, {}),
    ("6-servidor-tls12.es",   [X25519MLKEM768, X25519, P256],     [X25519MLKEM768, X25519], X25519, {"servidor_tls12": True}),
    # Visto en trafico real (Microsoft): el cliente manda clave PQ y el
    # servidor pide un grupo clasico con HelloRetryRequest
    ("7-hrr-pide-clasico.es", [X25519MLKEM768, X25519, P256],     [X25519MLKEM768, X25519], P256, {"hrr": P256}),
]


def poner_tiempos(paquetes, t0=1793750400.0, paso=0.0002):
    """Marca de tiempo creciente en el ORDEN en que quedan los paquetes,
    como en una captura real (Scapy pone la hora de creacion)."""
    for i, p in enumerate(paquetes):
        p.time = t0 + i * paso
    return paquetes


def traza_casos():
    pk = []
    for i, (sni, sabe, manda, elige, op) in enumerate(CASOS, start=1):
        pk += caso(i, sni, sabe, manda, elige, **op)
    return poner_tiempos(pk)


def traza_casos_ipv6():
    """Los mismos casos sobre IPv6. El caso 1 lleva ademas una cabecera
    hop-by-hop, para comprobar que la sonda salta las extensiones."""
    pk = []
    for i, (sni, sabe, manda, elige, op) in enumerate(CASOS, start=1):
        pk += caso(i, sni, sabe, manda, elige, ipv6=True, hop_by_hop=(i == 1), **op)
    return poner_tiempos(pk)


def traza_desordenada():
    con = Conexion("10.0.0.2", "104.16.123.96", 51515, mss=600)
    con.handshake_tcp()
    ch = registro(0x16, client_hello("pq.ejemplo.es", [GREASE, X25519MLKEM768, X25519, P256],
                                     [GREASE, X25519MLKEM768, X25519]), version=0x0301)
    s = con.segmentos(True, ch)                      # 3 segmentos de 600, 600 y 212 B
    con.paquetes += [s[0], s[0].copy(), s[2], s[1]]  # 1, 1 repetido, 3, 2
    con.enviar(False, registro(0x16, server_hello(X25519MLKEM768)) + registro(0x14, b"\x01"))
    con.cerrar()
    return poner_tiempos(con.paquetes)


def traza_rendimiento(n):
    pk = []
    for i in range(n):
        sni, sabe, manda, elige, op = CASOS[i % len(CASOS)]
        pk += caso(100 + i, sni, sabe, manda, elige, **op)
    return poner_tiempos(pk, paso=0.00005)


def main():
    salida = sys.argv[1] if len(sys.argv) > 1 else "."
    n_rend = int(sys.argv[2]) if len(sys.argv) > 2 else 3000
    os.makedirs(salida, exist_ok=True)
    random.seed(2026)   # mismas trazas en cada ejecucion

    for nombre, pk in [("casos_clasificacion.pcap", traza_casos()),
                       ("casos_ipv6.pcap", traza_casos_ipv6()),
                       ("reensamblado_desordenado.pcap", traza_desordenada()),
                       ("rendimiento.pcap", traza_rendimiento(n_rend))]:
        ruta = os.path.join(salida, nombre)
        wrpcap(ruta, pk)
        print(f"{ruta}: {len(pk)} paquetes")


if __name__ == "__main__":
    main()
