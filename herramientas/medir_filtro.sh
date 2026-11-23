#!/usr/bin/env bash
# Compara el filtro de puertos BPF con el filtro en el codigo de la sonda.
#
#   herramientas/medir_filtro.sh TRAZA.pcap NOMBRE [REPETICIONES] [MODOS_PUERTO]
#
# 1. Fichero (-f): mide tiempo y CPU de cada combinacion filtro x puertos.
# 2. En vivo (-i): crea un par de interfaces virtuales (veth0 <-> veth1),
#    inyecta la traza con tcpreplay a la maxima velocidad por veth0 y la
#    sonda escucha en veth1. Mide CPU de la sonda, paquetes que le llegan y
#    paquetes que el nucleo descarta porque la sonda no da abasto.
#    Necesita sudo, iproute2 y tcpreplay (sudo apt install tcpreplay).
#    Si no se quiere esta parte: VIVO=0 herramientas/medir_filtro.sh ...
#
# Resultado: medidas/NOMBRE_filtro.csv (una fila por ejecucion)
set -uo pipefail

TRAZA=${1:?Falta la traza}
NOMBRE=${2:?Falta el nombre}
REP=${3:-5}
MODOS=${4:-"443 tls all"}
VIVO=${VIVO:-1}
RAIZ=$(cd "$(dirname "$0")/.." && pwd)
SONDA="$RAIZ/sonda/sonda"
CSV="$RAIZ/medidas/${NOMBRE}_filtro.csv"
cd "$RAIZ/sonda"

[ -x "$SONDA" ] || { echo "Compila antes la sonda (cd sonda && gcc ... -o sonda sonda.c -lpcap)"; exit 1; }
echo "modo,filtro,puertos,rep,paquetes_sonda,tiempo_s,cpu_s,recibidos,descartados,enviados" > "$CSV"

campo() { sed -n "s/.*$1=\([^ ]*\).*/\1/p" <<< "$2"; }
fila() {   # modo filtro puertos rep "linea RENDIMIENTO" enviados
    local l=$5
    echo "$1,$2,$3,$4,$(campo paquetes "$l"),$(campo tiempo_s "$l"),$(campo cpu_s "$l"),$(campo recibidos "$l"),$(campo descartados "$l"),$6" >> "$CSV"
}

echo "== 1. Fichero: $TRAZA ($(du -h "$TRAZA" | cut -f1))"
cat "$TRAZA" > /dev/null          # que la traza este en la cache de disco
for p in $MODOS; do
    for f in codigo bpf; do
        for r in $(seq "$REP"); do
            l=$("$SONDA" -f "$TRAZA" -p "$p" -F "$f" -o /dev/null 2>&1 | grep RENDIMIENTO)
            fila fichero "$f" "$p" "$r" "$l" ""
            echo "   -p $p -F $f  rep $r: $(campo tiempo_s "$l") s, $(campo paquetes "$l") paquetes en la sonda"
        done
    done
done

if [ "$VIVO" = 1 ]; then
    echo "== 2. En vivo: tcpreplay por veth0, sonda en veth1"
    sudo ip link add veth0 type veth peer name veth1 2>/dev/null
    # MTU grande: las capturas de Windows traen segmentos TSO de hasta 64 KB
    sudo ip link set veth0 mtu 65535; sudo ip link set veth1 mtu 65535
    sudo ip link set veth0 up; sudo ip link set veth1 up
    sudo sysctl -qw net.ipv6.conf.veth1.disable_ipv6=1 net.ipv6.conf.veth0.disable_ipv6=1
    for p in $MODOS; do
        for f in codigo bpf; do
            for r in $(seq "$REP"); do
                sudo "$SONDA" -i veth1 -p "$p" -F "$f" -o /dev/null 2> /tmp/sonda_vivo.log &
                sleep 1
                env=$(sudo tcpreplay -i veth0 --topspeed "$TRAZA" 2>&1 | sed -n 's/.*Successful packets: *\([0-9]*\).*/\1/p')
                sleep 2
                sudo pkill -INT -f "sonda -i veth1"; wait
                l=$(grep RENDIMIENTO /tmp/sonda_vivo.log)
                fila vivo "$f" "$p" "$r" "$l" "$env"
                echo "   -p $p -F $f  rep $r: CPU $(campo cpu_s "$l") s, enviados $env, a la sonda $(campo paquetes "$l"), descartados $(campo descartados "$l")"
            done
        done
    done
    sudo ip link del veth0
fi

echo
python3 - "$CSV" <<'EOF'
import csv, sys, statistics as st, collections
g = collections.defaultdict(list)
for r in csv.DictReader(open(sys.argv[1])):
    g[(r["modo"], r["puertos"], r["filtro"])].append(r)
print(f"{'modo':<8}{'puertos':<8}{'filtro':<8}{'paq. sonda':>12}{'tiempo (s)':>12}{'CPU (s)':>10}{'descart.':>10}")
for (m, p, f), rs in sorted(g.items()):
    med = lambda k: st.median(float(x[k] or 0) for x in rs)
    print(f"{m:<8}{p:<8}{f:<8}{med('paquetes_sonda'):>12.0f}{med('tiempo_s'):>12.3f}{med('cpu_s'):>10.3f}{med('descartados'):>10.0f}")
print("(medianas de", len(rs), "repeticiones)")
EOF
echo "CSV: $CSV"
