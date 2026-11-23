#!/usr/bin/env bash
# Bateria a escala: lanza la sonda activa de Roberto (sonda.py) sobre una
# lista de dominios mientras tcpdump captura, pasa la captura por la sonda
# pasiva y compara las dos salidas.
#
# Uso (desde ~/tfg):
#   herramientas/bateria_dominios.sh LISTA.txt NOMBRE [DIR_ROBERTO] [LOTE]
#     LISTA.txt    un dominio por linea
#     NOMBRE       prefijo de los ficheros de salida (p. ej. tranco1000_20261123)
#     DIR_ROBERTO  carpeta con sonda.py (por defecto ~/tfg/referencia/sonda_tfg)
#     LOTE         dominios por llamada a sonda.py (por defecto 100)
#
# Genera:
#   trazas/reales/NOMBRE.pcap           captura (no se sube a GitHub)
#   medidas/NOMBRE_activa.txt           salida de la sonda de Roberto
#   medidas/NOMBRE_pasiva.ndjson        salida de la sonda pasiva
#   medidas/NOMBRE_comparacion.txt      tabla de coincidencias
#   medidas/NOMBRE_discrepancias.csv    pruebas en las que no coinciden
set -euo pipefail

LISTA=${1:?Falta la lista de dominios}
NOMBRE=${2:?Falta el nombre de la medida}
DIR_ROBERTO=${3:-$HOME/tfg/referencia/sonda_tfg}
LOTE=${4:-100}
RAIZ=$(cd "$(dirname "$0")/.." && pwd)
IFAZ=${IFAZ:-eth0}

PCAP="$RAIZ/trazas/reales/$NOMBRE.pcap"
ACTIVA="$RAIZ/medidas/${NOMBRE}_activa.txt"
PASIVA="$RAIZ/medidas/${NOMBRE}_pasiva.ndjson"
mkdir -p "$RAIZ/trazas/reales" "$RAIZ/medidas"

[ -f "$DIR_ROBERTO/sonda.py" ] || { echo "No encuentro $DIR_ROBERTO/sonda.py"; exit 1; }
mapfile -t DOMINIOS < <(grep -v '^\s*#' "$LISTA" | tr -d '\r' | awk 'NF {print $1}')
N=${#DOMINIOS[@]}
echo "Dominios: $N   lotes de $LOTE   interfaz $IFAZ"

# 1. Captura. Snaplen completo: el key_share PQ ocupa ~1,2 KB.
sudo -v
sudo tcpdump -i "$IFAZ" -s 0 -U -w "$PCAP" 'tcp port 443' 2>"$RAIZ/medidas/${NOMBRE}_tcpdump.log" &
TCPDUMP=$!
trap 'sudo kill -INT $TCPDUMP 2>/dev/null || true' EXIT
sleep 2

# 2. Sonda de Roberto por lotes (si un lote falla, sigue con el siguiente)
: > "$ACTIVA"
INICIO=$(date +%s)
for ((i = 0; i < N; i += LOTE)); do
    echo "--- Lote $((i / LOTE + 1)): dominios $((i + 1))-$((i + LOTE < N ? i + LOTE : N)) de $N ($(( $(date +%s) - INICIO )) s)"
    ( cd "$DIR_ROBERTO" && python3 sonda.py --host "${DOMINIOS[@]:i:LOTE}" -v --reduced -t 30 ) \
        >> "$ACTIVA" 2>&1 || echo "    (el lote termino con error; sigo)"
done
echo "Sondeo activo terminado en $(( $(date +%s) - INICIO )) s"

# 3. Parar la captura
sleep 3
sudo kill -INT $TCPDUMP; wait $TCPDUMP 2>/dev/null || true
trap - EXIT
sudo chown "$USER" "$PCAP"
ls -lh "$PCAP"

# 4. Sonda pasiva y comparacion
( cd "$RAIZ/sonda" && ./sonda -f "$PCAP" -o "$PASIVA" 2>"$RAIZ/medidas/${NOMBRE}_pasiva_resumen.txt" )
python3 "$RAIZ/herramientas/comparar_roberto.py" "$ACTIVA" "$PASIVA" \
    -o "$RAIZ/medidas/${NOMBRE}_discrepancias.csv" | tee "$RAIZ/medidas/${NOMBRE}_comparacion.txt"
