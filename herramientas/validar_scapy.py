#!/usr/bin/env python3
"""
validar_scapy.py - Segunda implementacion, independiente de la sonda en C,
para validar lo que extrae de cada handshake TLS.

TFG - Pablo Marugan Bastante - GITST, EPS-UAM

Lee la traza con Scapy (reensamblado TCPSession + disector TLS) y saca, por
conexion, lo mismo que la sonda: grupos que el cliente sabe, claves que
manda, HelloRetryRequest y grupo elegido por el servidor. Con --sonda
ejecuta tambien la sonda y compara conexion a conexion.

Uso:
    python3 validar_scapy.py traza.pcap
    python3 validar_scapy.py traza.pcap --sonda ../sonda/sonda --grupos ../sonda/grupos_pqc.csv
"""
import argparse
import os
import re
import subprocess
import sys
import time

from scapy.all import Raw, conf, load_layer, sniff
from scapy.layers.inet import IP, TCP
from scapy.sessions import TCPSession

conf.verb = 0
load_layer("tls")
from scapy.layers.tls.handshake import TLSClientHello, TLSServerHello   # noqa: E402
from scapy.layers.tls.record import TLS                                  # noqa: E402

HRR_RANDOM = bytes.fromhex(
    "CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C")


def cargar_nombres(ruta):
    """Nombres de grupo desde grupos_pqc.csv, para escribirlos igual que la sonda."""
    nombres = {}
    with open(ruta) as f:
        for linea in f:
            if linea.startswith("#") or linea.startswith("id_hex"):
                continue
            c = linea.strip().split(",")
            if len(c) >= 3:
                nombres[int(c[0], 16)] = c[2]
    return nombres


def es_grease(g):
    return (g & 0x0F0F) == 0x0A0A and (g >> 8) == (g & 0xFF)


def ext_de(hello, nombre_clase):
    for e in (hello.ext or []):
        if type(e).__name__ == nombre_clase:
            return e
    return None


def leer_hrr_a_mano(datos):
    """Scapy no interpreta el HelloRetryRequest sin estado de sesion: lo deja
    como Raw. Se lee aqui el grupo pedido recorriendo las extensiones."""
    if len(datos) < 38 or datos[0] != 2 or datos[6:38] != HRR_RANDOM:
        return None
    p = 38
    p += 1 + datos[p]            # session_id
    p += 3                       # cipher_suite + compression
    fin = p + 2 + int.from_bytes(datos[p:p + 2], "big")
    p += 2
    while p + 4 <= min(fin, len(datos)):
        tipo = int.from_bytes(datos[p:p + 2], "big")
        n = int.from_bytes(datos[p + 2:p + 4], "big")
        if tipo == 51 and n >= 2:
            return int.from_bytes(datos[p + 4:p + 6], "big")
        p += 4 + n
    return None


def analizar(traza):
    """Devuelve {(ip_cliente, puerto_cliente): info} con lo extraido por Scapy."""
    conexiones = {}
    paquetes = sniff(offline=traza, session=TCPSession)
    for pkt in paquetes:
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt.haslayer(TLS)):
            continue
        ip, tcp = pkt[IP], pkt[TCP]

        if pkt.haslayer(TLSClientHello):
            clave = (ip.src, tcp.sport)
            ch = pkt[TLSClientHello]
            sg = ext_de(ch, "TLS_Ext_SupportedGroups")
            ks = ext_de(ch, "TLS_Ext_KeyShare_CH")
            sni = ext_de(ch, "TLS_Ext_ServerName")
            info = conexiones.setdefault(clave, {"ch": []})
            info["ch"].append({
                "sni": sni.servernames[0].servername.decode() if sni and sni.servernames else "-",
                "sabe": [g for g in (sg.groups if sg else []) if not es_grease(g)],
                "manda": [(e.group, e.kxlen) for e in (ks.client_shares if ks else [])
                          if not es_grease(e.group)],
            })
            continue

        clave = (ip.dst, tcp.dport)          # mensajes del servidor
        info = conexiones.setdefault(clave, {"ch": []})
        if pkt.haslayer(TLSServerHello):
            sh = pkt[TLSServerHello]
            sv = ext_de(sh, "TLS_Ext_SupportedVersion_SH")
            ks = ext_de(sh, "TLS_Ext_KeyShare_SH")
            if sh.random_bytes == HRR_RANDOM if hasattr(sh, "random_bytes") else False:
                continue
            info["version"] = sv.version if sv else sh.version
            if ks and ks.server_share:
                info["elige"] = (ks.server_share.group, ks.server_share.kxlen)
        else:
            # buscar un HelloRetryRequest que Scapy haya dejado como Raw
            capa = pkt[TLS]
            while capa is not None and isinstance(capa, TLS):
                for m in (capa.msg or []):
                    if isinstance(m, Raw):
                        g = leer_hrr_a_mano(bytes(m.load))
                        if g is not None:
                            info["hrr"] = g
                capa = capa.payload if isinstance(capa.payload, TLS) else None
    return conexiones


def resumen_scapy(info, nombres):
    nom = lambda g: nombres.get(g, f"0x{g:04X}")
    ch = info["ch"][0]
    r = {"sni": ch["sni"],
         "sabe": ", ".join(nom(g) for g in ch["sabe"]),
         "manda": ", ".join(f"{nom(g)} {n} B" for g, n in ch["manda"]),
         "hrr": nom(info["hrr"]) if "hrr" in info else "-",
         "manda2": ", ".join(f"{nom(g)} {n} B" for g, n in info["ch"][1]["manda"]) if len(info["ch"]) > 1 else "-"}
    v = info.get("version")
    if v == 0x0304 and "elige" in info:
        g, n = info["elige"]
        r["elige"] = f"TLS 1.3, {nom(g)} {n} B"
    elif v == 0x0303:
        r["elige"] = "TLS 1.2"
    else:
        r["elige"] = "-"
    return r


def resumen_sonda(sonda, traza, grupos):
    """Ejecuta la sonda y extrae los mismos campos de su salida."""
    salida = subprocess.run([sonda, "-f", traza, "-g", grupos], capture_output=True, text=True).stdout
    conexiones, actual = {}, None
    quitar = lambda t: re.sub(r" \((hibrido|clasico|PQ|hibrido obsoleto|experimental|desconocido|ok|ESPERADO \d+)\)", "", t).strip()
    for linea in salida.splitlines():
        m = re.match(r"\s+Conexion (\S+):(\d+) -> \S+\s+SNI=(\S+)", linea)
        if m:
            actual = {"sni": m.group(3), "hrr": "-", "manda2": "-", "elige": "-"}
            conexiones[(m.group(1), int(m.group(2)))] = actual
            continue
        if actual is None or ":" not in linea:
            continue
        campo, _, valor = linea.strip().partition(":")
        valor = quitar(valor)
        if campo == "Cliente sabe":          actual["sabe"] = valor
        elif campo == "Cliente manda":       actual["manda"] = valor
        elif campo == "Servidor pide (HRR)": actual["hrr"] = valor
        elif campo == "Cliente manda (2o)":  actual["manda2"] = valor
        elif campo == "Servidor elige":      actual["elige"] = valor
    return conexiones


def main():
    ap = argparse.ArgumentParser(description="Valida la sonda con Scapy")
    ap.add_argument("traza")
    ap.add_argument("--grupos", default="../sonda/grupos_pqc.csv")
    ap.add_argument("--sonda", help="ruta al ejecutable de la sonda, para comparar")
    a = ap.parse_args()

    nombres = cargar_nombres(a.grupos)
    t0 = time.perf_counter()
    scapy_con = analizar(a.traza)
    t_scapy = time.perf_counter() - t0
    resumen = {k: resumen_scapy(v, nombres) for k, v in scapy_con.items() if v["ch"]}

    if not a.sonda:
        for (ip, puerto), r in resumen.items():
            print(f"\n  Conexion {ip}:{puerto}   SNI={r['sni']}")
            for campo in ("sabe", "manda", "hrr", "manda2", "elige"):
                print(f"    {campo:8s} {r[campo]}")
        print(f"\nScapy: {len(resumen)} conexiones en {t_scapy:.2f} s")
        return

    t0 = time.perf_counter()
    sonda_con = resumen_sonda(a.sonda, a.traza, a.grupos)
    t_sonda = time.perf_counter() - t0

    iguales = 0
    for clave in sorted(set(resumen) | set(sonda_con)):
        s, c = resumen.get(clave), sonda_con.get(clave)
        if not s or not c:
            print(f"  DIFERENCIA {clave}: solo la ve {'la sonda' if c else 'Scapy'}")
            continue
        distintos = [k for k in ("sni", "sabe", "manda", "hrr", "manda2", "elige") if s.get(k) != c.get(k)]
        if distintos:
            print(f"  DIFERENCIA {clave[0]}:{clave[1]} SNI={s['sni']}")
            for k in distintos:
                print(f"      {k}:  Scapy='{s.get(k)}'  sonda='{c.get(k)}'")
        else:
            iguales += 1
    total = len(set(resumen) | set(sonda_con))
    print(f"\nConexiones iguales: {iguales} de {total}")
    print(f"Tiempo  sonda (C/libpcap): {t_sonda:.3f} s    Scapy: {t_scapy:.2f} s"
          f"    -> Scapy {t_scapy / max(t_sonda, 1e-6):.0f} veces mas lento")


if __name__ == "__main__":
    main()
