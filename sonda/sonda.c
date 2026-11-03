/* ===========================================================================
 * sonda.c — Sonda pasiva de deteccion de elementos de red inseguros
 *           desde el punto de vista postcuantico.
 *
 * TFG — Pablo Marugan Bastante — GITST, EPS-UAM
 * Tutor: Jorge E. Lopez de Vergara
 *
 * BLOQUE 1: captura y diseccion hasta la capa IP.
 * BLOQUE 2: diseccion de la cabecera TCP y filtro por puerto.
 * BLOQUE 3: tabla de flujos y reensamblado TCP del primer registro TLS
 *           de cada sentido (ClientHello / ServerHello).
 *
 * Compilar:  gcc -Wall -Wextra -std=gnu11 -o sonda sonda.c -lpcap
 * Ejecutar:  ./sonda -f traza.pcap [-p 443] [-v]
 *            sudo ./sonda -i eth0
 * ===========================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>
#include <getopt.h>
#include <inttypes.h>

#include <pcap.h>
#include <arpa/inet.h>      /* ntohs, ntohl, inet_ntop */

/* --- constantes -------------------------------------------------------- */
#define ETH_HLEN        14      /* cabecera Ethernet: siempre 14 bytes      */
#define VLAN_HLEN        4      /* cada etiqueta 802.1Q anade 4 bytes       */
#define MAX_VLAN         2      /* admitimos QinQ (doble etiqueta)          */

#define ETHERTYPE_IPV4  0x0800
#define ETHERTYPE_ARP   0x0806
#define ETHERTYPE_VLAN  0x8100  /* 802.1Q                                   */
#define ETHERTYPE_QINQ  0x88A8  /* 802.1ad                                  */
#define ETHERTYPE_IPV6  0x86DD

#define IPPROTO_TCP_     6
#define IPPROTO_UDP_    17

#define IP_OFFMASK  0x1FFF      /* 13 bits bajos del campo flags+offset     */

#define TCP_HLEN_MIN    20      /* cabecera TCP sin opciones                */

/* Flags TCP (byte 13 de la cabecera) */
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PSH  0x08
#define TH_ACK  0x10

#define TLS_HANDSHAKE   22      /* tipo de registro TLS: handshake (0x16)   */
#define TLS_REC_HLEN     5      /* cabecera de registro: tipo+version+long  */
#define TLS_REC_MAX  (16384 + TLS_REC_HLEN)  /* registro TLS mas grande     */

#define N_CUBETAS     4096      /* tamano de la tabla hash de flujos        */

/* --- cabeceras ---------------------------------------------------------
 * Usamos structs empaquetados para mapearlos directamente sobre el buffer.
 * __attribute__((packed)) impide que el compilador inserte relleno.
 */
struct eth_hdr {
    uint8_t  dst[6];
    uint8_t  src[6];
    uint16_t type;
} __attribute__((packed));

struct vlan_hdr {
    uint16_t tci;           /* prioridad (3b) + DEI (1b) + VLAN ID (12b)    */
    uint16_t type;          /* el EtherType verdadero                        */
} __attribute__((packed));

struct ip_hdr {
    uint8_t  vhl;           /* version (4b alto) + IHL (4b bajo)            */
    uint8_t  tos;
    uint16_t len;           /* longitud total, cabecera incluida            */
    uint16_t id;
    uint16_t off;           /* flags (3b) + offset de fragmento (13b)       */
    uint8_t  ttl;
    uint8_t  proto;
    uint16_t sum;
    uint8_t  src[4];
    uint8_t  dst[4];
} __attribute__((packed));

#define IP_V(h)   (((h)->vhl) >> 4)
#define IP_HL(h)  ((((h)->vhl) & 0x0F) * 4)   /* en bytes, no en palabras   */

/* Cabecera TCP (RFC 9293). Igual que en IP, la longitud de la cabecera va
 * en palabras de 32 bits: el "data offset" son los 4 bits altos del byte 12.
 * Puede haber opciones (MSS, timestamps, SACK...), asi que NUNCA asumir 20. */
struct tcp_hdr {
    uint16_t sport;
    uint16_t dport;
    uint32_t seq;           /* numero de secuencia del primer byte de datos  */
    uint32_t ack;
    uint8_t  off;           /* data offset (4b alto) + reservado (4b bajo)   */
    uint8_t  flags;         /* CWR ECE URG ACK PSH RST SYN FIN               */
    uint16_t win;
    uint16_t sum;
    uint16_t urp;
} __attribute__((packed));

#define TCP_HL(h) ((((h)->off) >> 4) * 4)       /* en bytes                  */

/* --- flujos (BLOQUE 3) ---------------------------------------------------
 * Un flujo es una conexion TCP: el mismo par (IP:puerto, IP:puerto) en los
 * dos sentidos. Para que los paquetes de ida y de vuelta caigan en el mismo
 * flujo, la clave se guarda en orden canonico: el extremo "menor" primero.
 *
 * Cada sentido tiene su propio buffer de reensamblado. Solo guardamos el
 * PRIMER registro TLS de cada sentido: en el cliente es el ClientHello y en
 * el servidor el ServerHello, que es todo lo que necesitamos.
 */
struct sentido {
    int       tiene_isn;    /* sabemos donde empieza el flujo de datos      */
    uint32_t  isn;          /* seq del primer byte de datos (ISN + 1)        */
    uint8_t  *buf;          /* bytes recibidos, colocados por posicion       */
    uint8_t  *mapa;         /* 1 bit por byte: 1 = ya recibido               */
    uint32_t  contiguos;    /* bytes seguidos disponibles desde el 0         */
    uint32_t  necesarios;   /* longitud del registro TLS (0 = aun no se sabe) */
    int       segmentos;    /* segmentos con datos que han aportado algo    */
    int       completo;     /* el registro ya esta entero                   */
    int       descartado;   /* no empieza por TLS: no nos interesa          */
};

struct flujo {
    uint32_t ip_a, ip_b;    /* orden canonico: (ip_a,puerto_a) <= (ip_b,puerto_b) */
    uint16_t puerto_a, puerto_b;
    struct sentido dir[2];  /* 0: a -> b    1: b -> a                       */
    struct flujo *sig;      /* siguiente en la misma cubeta                 */
};

static struct flujo *tabla[N_CUBETAS];

/* --- estado global ------------------------------------------------------ */
static pcap_t *descr = NULL;

static struct {
    uint64_t total;
    uint64_t truncados;
    uint64_t con_vlan;
    uint64_t no_ip;
    uint64_t ipv6;
    uint64_t arp;
    uint64_t ipv4;
    uint64_t fragmentos;
    uint64_t tcp;
    uint64_t udp;
    uint64_t otros_proto;
    uint64_t tcp_malformados;
    uint64_t tcp_puerto;        /* segmentos del puerto analizado            */
    uint64_t tcp_con_datos;     /*   ... que llevan datos                    */
    uint64_t tcp_tls_hs;        /*   ... que empiezan por un registro TLS    */
    uint64_t bytes_datos;
    uint64_t flujos;
    uint64_t desordenados;      /* llegan antes que un hueco anterior        */
    uint64_t retransmisiones;   /* no aportan ningun byte nuevo              */
    uint64_t registros_completos;
    uint64_t sin_memoria;
} est;

static int verbose = 0;
static uint16_t puerto = 443;   /* puerto TCP a analizar (-p)              */

/* --- utilidades --------------------------------------------------------- */
static void ip_str(const uint8_t a[4], char *out, size_t n)
{
    snprintf(out, n, "%u.%u.%u.%u", a[0], a[1], a[2], a[3]);
}

/* Flags TCP como texto, al estilo de Wireshark: "SYN,ACK" */
static void flags_str(uint8_t f, char *out, size_t n)
{
    out[0] = '\0';
    const struct { uint8_t bit; const char *nom; } t[] = {
        {TH_SYN, "SYN"}, {TH_FIN, "FIN"}, {TH_RST, "RST"},
        {TH_PSH, "PSH"}, {TH_ACK, "ACK"}
    };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        if (f & t[i].bit) {
            if (out[0]) strncat(out, ",", n - strlen(out) - 1);
            strncat(out, t[i].nom, n - strlen(out) - 1);
        }
    }
}

/* ======================= BLOQUE 3: flujos ============================ */

static uint32_t hash_flujo(uint32_t a, uint32_t b, uint16_t pa, uint16_t pb)
{
    uint32_t h = a * 2654435761u ^ b * 2246822519u ^ ((uint32_t)pa << 16 | pb);
    h ^= h >> 15;
    return h % N_CUBETAS;
}

/* Busca el flujo del paquete (o lo crea) y devuelve en *d su sentido. */
static struct flujo *buscar_flujo(uint32_t src, uint16_t sport,
                                  uint32_t dst, uint16_t dport, int *d)
{
    uint32_t a = src, b = dst;
    uint16_t pa = sport, pb = dport;
    *d = 0;
    if (src > dst || (src == dst && sport > dport)) {   /* orden canonico */
        a = dst; b = src; pa = dport; pb = sport; *d = 1;
    }
    uint32_t h = hash_flujo(a, b, pa, pb);
    for (struct flujo *f = tabla[h]; f; f = f->sig)
        if (f->ip_a == a && f->ip_b == b && f->puerto_a == pa && f->puerto_b == pb)
            return f;

    struct flujo *f = calloc(1, sizeof *f);
    if (!f) { est.sin_memoria++; return NULL; }
    f->ip_a = a; f->ip_b = b; f->puerto_a = pa; f->puerto_b = pb;
    f->sig = tabla[h];
    tabla[h] = f;
    est.flujos++;
    return f;
}

static void liberar_sentido(struct sentido *s)
{
    free(s->buf);  s->buf  = NULL;
    free(s->mapa); s->mapa = NULL;
}

static void liberar_flujos(void)
{
    for (int i = 0; i < N_CUBETAS; i++) {
        struct flujo *f = tabla[i];
        while (f) {
            struct flujo *sig = f->sig;
            liberar_sentido(&f->dir[0]);
            liberar_sentido(&f->dir[1]);
            free(f);
            f = sig;
        }
        tabla[i] = NULL;
    }
}

/* Coloca un segmento en el buffer de su sentido.
 * La posicion de cada byte dentro del flujo es  seq - isn  (aritmetica de
 * 32 bits sin signo, asi que funciona aunque el numero de secuencia de la
 * vuelta). Esto resuelve a la vez los segmentos desordenados (se colocan en
 * su sitio aunque falte el anterior) y las retransmisiones (se escriben
 * encima de bytes que ya estaban, sin cambiar nada).                       */
static void insertar_segmento(struct sentido *s, uint32_t seq,
                              const u_char *datos, uint32_t len)
{
    if (!s->buf) {
        s->buf  = malloc(TLS_REC_MAX);
        s->mapa = calloc(TLS_REC_MAX / 8 + 1, 1);
        if (!s->buf || !s->mapa) { liberar_sentido(s); est.sin_memoria++; return; }
    }

    uint32_t pos = seq - s->isn;
    if (pos >= TLS_REC_MAX) return;              /* mas alla de lo que guardamos */
    if (len > TLS_REC_MAX - pos) len = TLS_REC_MAX - pos;

    int nuevos = 0;
    for (uint32_t i = pos; i < pos + len; i++) {
        if (!(s->mapa[i / 8] & (1u << (i % 8)))) {
            s->mapa[i / 8] |= (uint8_t)(1u << (i % 8));
            nuevos++;
        }
    }
    if (nuevos == 0) { est.retransmisiones++; return; }  /* nada nuevo */
    if (pos > s->contiguos) est.desordenados++;          /* deja un hueco detras */
    memcpy(s->buf + pos, datos, len);
    s->segmentos++;

    /* Avanzar el limite de bytes contiguos (puede saltar varios segmentos
     * de golpe cuando llega el que tapaba un hueco).                       */
    while (s->contiguos < TLS_REC_MAX &&
           (s->mapa[s->contiguos / 8] & (1u << (s->contiguos % 8))))
        s->contiguos++;
}

/* Comprueba si ya tenemos el primer registro TLS entero.
 * Devuelve 1 justo cuando se completa.                                     */
static int registro_completo(struct sentido *s)
{
    if (s->completo || s->descartado) return 0;

    if (s->necesarios == 0 && s->contiguos >= TLS_REC_HLEN) {
        if (s->buf[0] != TLS_HANDSHAKE || s->buf[1] != 0x03) {
            s->descartado = 1;                   /* no es TLS: lo ignoramos */
            liberar_sentido(s);
            return 0;
        }
        s->necesarios = TLS_REC_HLEN + ((uint32_t)s->buf[3] << 8 | s->buf[4]);
    }
    if (s->necesarios && s->contiguos >= s->necesarios) {
        s->completo = 1;
        return 1;
    }
    return 0;
}

static void manejar_senal(int s)
{
    (void)s;
    if (descr) pcap_breakloop(descr);
}

/* --- callback de pcap ---------------------------------------------------
 * Se invoca una vez por paquete capturado.
 *   hdr->caplen : bytes realmente capturados (puede ser < len si hay snaplen)
 *   hdr->len    : bytes que habia en el cable
 * SIEMPRE hay que comprobar caplen antes de leer: si la traza se capturo con
 * un snaplen corto, leer mas alla es un desbordamiento.
 */
static void analizar_paquete(u_char *user,
                             const struct pcap_pkthdr *hdr,
                             const u_char *pkt)
{
    (void)user;
    est.total++;

    size_t off = 0;                 /* desplazamiento acumulado             */
    const uint32_t caplen = hdr->caplen;

    /* ---------------- Ethernet ---------------- */
    if (caplen < ETH_HLEN) { est.truncados++; return; }

    const struct eth_hdr *eth = (const struct eth_hdr *)(pkt);
    uint16_t type = ntohs(eth->type);
    off = ETH_HLEN;

    /* ---------------- etiquetas VLAN ----------------
     * Pueden venir encadenadas (QinQ). Avanzamos mientras haya.
     */
    int nvlan = 0;
    while ((type == ETHERTYPE_VLAN || type == ETHERTYPE_QINQ)
           && nvlan < MAX_VLAN) {
        if (caplen < off + VLAN_HLEN) { est.truncados++; return; }
        const struct vlan_hdr *v = (const struct vlan_hdr *)(pkt + off);
        if (verbose) {
            printf("      VLAN id=%u\n", ntohs(v->tci) & 0x0FFF);
        }
        type = ntohs(v->type);
        off += VLAN_HLEN;
        nvlan++;
    }
    if (nvlan) est.con_vlan++;

    /* ---------------- que hay encima ---------------- */
    if (type == ETHERTYPE_ARP)  { est.arp++;  est.no_ip++; return; }
    if (type == ETHERTYPE_IPV6) { est.ipv6++; est.no_ip++; return; }
    if (type != ETHERTYPE_IPV4) { est.no_ip++; return; }

    /* ---------------- IPv4 ---------------- */
    if (caplen < off + (int)sizeof(struct ip_hdr)) { est.truncados++; return; }

    const struct ip_hdr *ip = (const struct ip_hdr *)(pkt + off);

    if (IP_V(ip) != 4) { est.no_ip++; return; }

    int ip_hl = IP_HL(ip);                  /* NO asumir 20: puede haber opciones */
    if (ip_hl < 20) { est.truncados++; return; }
    if (caplen < off + (uint32_t)ip_hl) { est.truncados++; return; }

    uint16_t ip_len = ntohs(ip->len);       /* longitud total segun IP      */
    uint16_t frag   = ntohs(ip->off) & IP_OFFMASK;

    est.ipv4++;

    /* Un fragmento intermedio no lleva cabecera TCP: no se puede analizar.
     * De momento lo contamos y lo descartamos.                            */
    if (frag != 0) { est.fragmentos++; return; }

    /* Longitud del payload segun IP, no segun lo que nos dio pcap.
     * Ethernet rellena las tramas cortas hasta 60 B; fiarse de caplen
     * haria procesar relleno como si fueran datos.                        */
    int payload_len = ip_len - ip_hl;
    if (payload_len < 0) { est.truncados++; return; }

    switch (ip->proto) {
        case IPPROTO_TCP_: est.tcp++; break;
        case IPPROTO_UDP_: est.udp++; return;
        default:           est.otros_proto++; return;
    }

    /* ================= BLOQUE 2: TCP ================= */
    off += ip_hl;                                   /* off apunta a TCP     */

    if (payload_len < TCP_HLEN_MIN || caplen < off + TCP_HLEN_MIN) {
        est.tcp_malformados++; return;
    }
    const struct tcp_hdr *tcp = (const struct tcp_hdr *)(pkt + off);

    int tcp_hl = TCP_HL(tcp);                       /* NO asumir 20         */
    if (tcp_hl < TCP_HLEN_MIN || tcp_hl > payload_len) {
        est.tcp_malformados++; return;
    }

    uint16_t sport = ntohs(tcp->sport);
    uint16_t dport = ntohs(tcp->dport);

    /* Filtro de puerto: nos vale en cualquiera de los dos sentidos */
    if (sport != puerto && dport != puerto) return;
    est.tcp_puerto++;

    /* Datos de aplicacion: lo que queda tras la cabecera TCP, medido con
     * la longitud de IP (no con caplen, por el relleno de Ethernet).     */
    uint32_t datos_len = (uint32_t)(payload_len - tcp_hl);
    const u_char *datos = pkt + off + tcp_hl;

    /* Si el snaplen corto la captura, faltan datos: no se pueden analizar */
    if (caplen < off + (uint32_t)tcp_hl + datos_len) {
        est.truncados++; return;
    }

    if (datos_len > 0) {
        est.tcp_con_datos++;
        est.bytes_datos += datos_len;
        /* Un registro TLS de handshake empieza por 0x16 0x03 */
        if (datos_len >= 5 && datos[0] == TLS_HANDSHAKE && datos[1] == 0x03)
            est.tcp_tls_hs++;
    }

    if (verbose) {
        char s[16], d[16], fl[32];
        ip_str(ip->src, s, sizeof s);
        ip_str(ip->dst, d, sizeof d);
        flags_str(tcp->flags, fl, sizeof fl);
        printf("  #%-4" PRIu64 " %s:%u -> %s:%u  [%s]  seq=%u ack=%u  "
               "tcp_hl=%d  len=%u",
               est.total, s, sport, d, dport, fl,
               ntohl(tcp->seq), ntohl(tcp->ack), tcp_hl, datos_len);
        if (datos_len >= 5 && datos[0] == TLS_HANDSHAKE && datos[1] == 0x03)
            printf("  <- empieza registro TLS handshake (%u bytes)",
                   (unsigned)((datos[3] << 8) | datos[4]) + 5);
        printf("\n");
    }

    /* ================= BLOQUE 3: flujo y reensamblado ================= */
    uint32_t src, dst;
    memcpy(&src, ip->src, 4);  src = ntohl(src);
    memcpy(&dst, ip->dst, 4);  dst = ntohl(dst);

    int d;
    struct flujo *f = buscar_flujo(src, sport, dst, dport, &d);
    if (!f) return;
    struct sentido *s = &f->dir[d];
    uint32_t seq = ntohl(tcp->seq);

    /* El SYN fija el punto de partida: el primer byte de datos es ISN+1 */
    if (tcp->flags & TH_SYN) {
        s->isn = seq + 1;
        s->tiene_isn = 1;
    }

    if (datos_len == 0 || s->completo || s->descartado) return;

    /* Si la captura empezo con la conexion ya abierta no hemos visto el SYN.
     * Solo lo aceptamos si este segmento empieza un registro TLS.          */
    if (!s->tiene_isn) {
        if (datos_len >= TLS_REC_HLEN && datos[0] == TLS_HANDSHAKE && datos[1] == 0x03) {
            s->isn = seq;
            s->tiene_isn = 1;
        } else {
            s->descartado = 1;
            return;
        }
    }

    insertar_segmento(s, seq, datos, datos_len);

    if (registro_completo(s)) {
        est.registros_completos++;
        char a[16], b[16];
        ip_str(ip->src, a, sizeof a);
        ip_str(ip->dst, b, sizeof b);
        uint8_t tipo = s->buf[TLS_REC_HLEN];          /* 1er byte del mensaje */
        const char *nombre = tipo == 1 ? "ClientHello"
                           : tipo == 2 ? "ServerHello" : "otro mensaje";
        printf("  >> %s:%u -> %s:%u  %s completo: %u bytes en %d segmento(s)\n",
               a, sport, b, dport, nombre, s->necesarios, s->segmentos);

        /* BLOQUE 4: aqui se leera el mensaje: s->buf, s->necesarios bytes */

        liberar_sentido(s);              /* ya no hace falta guardar mas */
    }
}

/* --- resumen ------------------------------------------------------------ */
static void imprimir_resumen(void)
{
    printf("\n--- Resumen -------------------------------------------\n");
    printf("  Paquetes procesados .......... %" PRIu64 "\n", est.total);
    printf("    con etiqueta VLAN .......... %" PRIu64 "\n", est.con_vlan);
    printf("    truncados / malformados .... %" PRIu64 "\n", est.truncados);
    printf("    no IPv4 .................... %" PRIu64
           "   (ARP: %" PRIu64 ", IPv6: %" PRIu64 ")\n",
           est.no_ip, est.arp, est.ipv6);
    printf("    IPv4 ....................... %" PRIu64 "\n", est.ipv4);
    printf("      fragmentos descartados ... %" PRIu64 "\n", est.fragmentos);
    printf("      TCP ...................... %" PRIu64 "\n", est.tcp);
    printf("      UDP ...................... %" PRIu64 "\n", est.udp);
    printf("      otros protocolos ......... %" PRIu64 "\n", est.otros_proto);
    printf("  TCP puerto %u\n", puerto);
    printf("    segmentos .................. %" PRIu64 "\n", est.tcp_puerto);
    printf("      con datos ................ %" PRIu64 "  (%" PRIu64 " bytes)\n",
           est.tcp_con_datos, est.bytes_datos);
    printf("      inicio de registro TLS ... %" PRIu64 "\n", est.tcp_tls_hs);
    printf("    TCP malformados ............ %" PRIu64 "\n", est.tcp_malformados);
    printf("  Reensamblado\n");
    printf("    flujos ..................... %" PRIu64 "\n", est.flujos);
    printf("    segmentos desordenados ..... %" PRIu64 "\n", est.desordenados);
    printf("    retransmisiones ............ %" PRIu64 "\n", est.retransmisiones);
    printf("    registros TLS completos .... %" PRIu64 "\n", est.registros_completos);
    if (est.sin_memoria)
        printf("    SIN MEMORIA ................ %" PRIu64 "\n", est.sin_memoria);
    printf("-------------------------------------------------------\n");
}

/* --- main --------------------------------------------------------------- */
static void uso(const char *prog)
{
    fprintf(stderr,
            "Uso: %s (-f traza.pcap | -i interfaz) [-p puerto] [-v]\n"
            "  -f  leer de un fichero pcap\n"
            "  -i  capturar de una interfaz (requiere privilegios)\n"
            "  -p  puerto TCP a analizar (por defecto 443)\n"
            "  -v  imprimir una linea por segmento TCP del puerto\n", prog);
}

int main(int argc, char **argv)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    const char *fichero = NULL, *interfaz = NULL;
    int opt;

    while ((opt = getopt(argc, argv, "f:i:p:vh")) != -1) {
        switch (opt) {
            case 'f': fichero  = optarg; break;
            case 'i': interfaz = optarg; break;
            case 'p': {
                long v = strtol(optarg, NULL, 10);
                if (v < 1 || v > 65535) { fprintf(stderr, "Puerto no valido\n"); return 1; }
                puerto = (uint16_t)v;
                break;
            }
            case 'v': verbose = 1; break;
            default:  uso(argv[0]); return 1;
        }
    }
    if ((fichero && interfaz) || (!fichero && !interfaz)) {
        uso(argv[0]);
        return 1;
    }

    signal(SIGINT, manejar_senal);

    if (fichero) {
        descr = pcap_open_offline(fichero, errbuf);
        if (!descr) {
            fprintf(stderr, "Error abriendo %s: %s\n", fichero, errbuf);
            return 1;
        }
        printf("Leyendo %s\n\n", fichero);
    } else {
        /* snaplen 65535: queremos el paquete entero. Un snaplen corto
         * cortaria justo el key_share, que es lo que nos interesa.        */
        descr = pcap_open_live(interfaz, 65535, 1 /*promiscuo*/, 100, errbuf);
        if (!descr) {
            fprintf(stderr, "Error abriendo %s: %s\n", interfaz, errbuf);
            return 1;
        }
        printf("Capturando en %s (Ctrl+C para parar)\n\n", interfaz);
    }

    /* Comprobacion imprescindible: este codigo asume cabecera Ethernet.
     * Una captura de loopback o de un tunel usa otro tipo de enlace y
     * los offsets serian distintos.                                      */
    int dlt = pcap_datalink(descr);
    if (dlt != DLT_EN10MB) {
        fprintf(stderr, "Aviso: tipo de enlace %s, no Ethernet. "
                        "Los offsets no seran validos.\n",
                pcap_datalink_val_to_name(dlt));
    }

    if (pcap_loop(descr, -1, analizar_paquete, NULL) == PCAP_ERROR) {
        fprintf(stderr, "Error en pcap_loop: %s\n", pcap_geterr(descr));
    }

    imprimir_resumen();
    liberar_flujos();
    pcap_close(descr);
    return 0;
}
