#!/usr/bin/env python3
"""Compara la salida de la sonda activa de Roberto (sonda.py) con la de la
sonda pasiva (NDJSON) sobre la captura de esa misma ejecucion.

La sonda de Roberto hace, por cada dominio, una conexion por grupo PQ
(X25519MLKEM768 y SecP256r1MLKEM768), ofreciendo SOLO ese grupo, y escribe:
    [3/40] www.amazon.es | SecP256r1MLKEM768 -> Supported

La sonda pasiva ve esas mismas conexiones. Para cada una:
    Supported      <=> connection_status "segura" con el grupo ofrecido
    Not supported  <=> rechazada (Alert / cierre), insegura o incompleta
    Error/Timeout  <=> la sonda no ve la conexion o la ve "sin_respuesta"

Uso:
    python3 comparar_roberto.py roberto_activa.txt sonda_pasiva.ndjson [-o discrepancias.csv]
"""
import argparse
import collections
import csv
import json
import re
import sys

LINEA = re.compile(r"^\[\d+/\d+\]\s+(\S+)\s+\|\s+(\S+)\s+->\s+(.+?)\s*$")


def leer_roberto(fichero):
    """{(dominio, grupo): veredicto} con veredicto Supported / Not supported / otro texto."""
    res = {}
    with open(fichero, encoding="utf-8", errors="replace") as f:
        for linea in f:
            m = LINEA.match(linea.strip())
            if m:
                dominio, grupo, veredicto = m.groups()
                res[(dominio.lower(), grupo)] = veredicto
    return res


def leer_sonda(fichero):
    """{(dominio, grupo ofrecido): [conexiones]} a partir de las lineas connection."""
    res = collections.defaultdict(list)
    with open(fichero, encoding="utf-8") as f:
        for linea in f:
            try:
                j = json.loads(linea)
            except json.JSONDecodeError:
                continue
            if j.get("type") != "connection" or not j.get("server_name"):
                continue
            # Roberto ofrece un unico grupo: es el del key_share
            for g in j.get("key_share_groups") or j.get("supported_groups") or []:
                res[(j["server_name"].lower(), g)].append(j)
    return res


def veredicto_pasivo(conexiones, grupo):
    """Supported / Not supported / Sin respuesta, y un detalle de por que."""
    if not conexiones:
        return "No vista", ""
    # Si hubo reintentos, basta con que una conexion negocie el grupo
    for c in conexiones:
        if c.get("connection_status") == "segura" and c.get("group") == grupo:
            return "Supported", "negocia " + grupo
    c = conexiones[-1]
    estado = c.get("connection_status")
    if estado == "sin_respuesta":
        return "Sin respuesta", "el servidor no contesta al ClientHello"
    if c.get("server_alert"):
        return "Not supported", "Alert " + str(c["server_alert"].get("description"))
    if c.get("server_close"):
        return "Not supported", "cierre " + str(c["server_close"])
    if c.get("hrr"):
        return "Not supported", "HelloRetryRequest a " + str(c.get("group"))
    if c.get("group"):
        return "Not supported", "elige " + str(c.get("group"))
    return "Not supported", str(estado)


def normalizar_roberto(v):
    v = v.strip()
    if v.lower().startswith("supported"):
        return "Supported"
    if v.lower().startswith("not supported"):
        return "Not supported"
    return "Error"          # Error, Timeout, excepciones...


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("activa")
    ap.add_argument("pasiva")
    ap.add_argument("-o", "--discrepancias", help="CSV con las pruebas en las que no coinciden")
    a = ap.parse_args()

    rob = leer_roberto(a.activa)
    son = leer_sonda(a.pasiva)
    if not rob:
        sys.exit("No hay lineas de resultado en " + a.activa)

    tabla = collections.Counter()
    detalles = collections.Counter()
    discrepancias = []
    for (dom, grupo), v in sorted(rob.items()):
        r = normalizar_roberto(v)
        p, det = veredicto_pasivo(son.get((dom, grupo), []), grupo)
        tabla[(r, p)] += 1
        if r == "Not supported" and p == "Not supported":
            detalles[det.split(" ")[0] + " " + det.split(" ")[1] if " " in det else det] += 1
        coincide = (r == p) or (r == "Error" and p in ("Sin respuesta", "No vista"))
        if not coincide:
            discrepancias.append({"dominio": dom, "grupo": grupo, "roberto": v,
                                  "sonda": p, "detalle": det})

    total = sum(tabla.values())
    coinciden = total - len(discrepancias)
    dominios = {d for d, _ in rob}
    print(f"Dominios: {len(dominios)}   pruebas (dominio x grupo): {total}")
    print(f"Coinciden: {coinciden}/{total} ({100 * coinciden / total:.1f} %)\n")

    filas = ["Supported", "Not supported", "Error"]
    cols = ["Supported", "Not supported", "Sin respuesta", "No vista"]
    print(f"{'Roberto \\ sonda':<16}" + "".join(f"{c:>15}" for c in cols))
    for f in filas:
        print(f"{f:<16}" + "".join(f"{tabla[(f, c)]:>15}" for c in cols))

    if detalles:
        print("\nPor que falla cada 'Not supported' (segun la sonda pasiva):")
        for d, n in detalles.most_common():
            print(f"  {n:>5}  {d}")

    # Resumen por dominio: que grupos PQ acepta cada servidor
    acepta = collections.defaultdict(set)
    for (dom, grupo), v in rob.items():
        if normalizar_roberto(v) == "Supported":
            acepta[dom].add(grupo)
    con_pq = sum(1 for d in dominios if acepta[d])
    print(f"\nDominios con algun grupo PQ (segun Roberto): {con_pq}/{len(dominios)} "
          f"({100 * con_pq / len(dominios):.1f} %)")

    if discrepancias:
        print(f"\nDiscrepancias ({len(discrepancias)}):")
        for d in discrepancias[:30]:
            print(f"  {d['dominio']:<35} {d['grupo']:<20} Roberto: {d['roberto']:<15} sonda: {d['sonda']} ({d['detalle']})")
        if len(discrepancias) > 30:
            print(f"  ... y {len(discrepancias) - 30} mas")
    if a.discrepancias:
        with open(a.discrepancias, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=["dominio", "grupo", "roberto", "sonda", "detalle"])
            w.writeheader()
            w.writerows(discrepancias)
        print(f"\nDiscrepancias guardadas en {a.discrepancias}")


if __name__ == "__main__":
    main()
