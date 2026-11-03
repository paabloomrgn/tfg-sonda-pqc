/* ===========================================================================
 * sonda.c — Sonda pasiva de deteccion de elementos de red inseguros
 *           desde el punto de vista postcuantico.
 *
 * TFG — Pablo Marugan Bastante — GITST, EPS-UAM
 * Tutor: Jorge E. Lopez de Vergara
 *
 * BLOQUE 1: captura y diseccion hasta la capa IP.
 * BLOQUE 2: diseccion de la cabecera TCP y filtro por puerto.
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

    /* BLOQUE 3: aqui entrara la tabla de flujos y el reensamblado TCP */
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
    pcap_close(descr);
    return 0;
}
