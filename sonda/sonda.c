/* ===========================================================================
 * sonda.c — Sonda pasiva de deteccion de elementos de red inseguros
 *           desde el punto de vista postcuantico.
 *
 * TFG — Pablo Marugan Bastante — GITST, EPS-UAM
 * Tutor: Jorge E. Lopez de Vergara
 *
 * BLOQUE 1: captura y diseccion hasta la capa IP.
 *
 * Compilar:  gcc -Wall -Wextra -std=gnu11 -o sonda sonda.c -lpcap
 * Ejecutar:  ./sonda -f traza.pcap
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
} est;

static int verbose = 0;

/* --- utilidades --------------------------------------------------------- */
static void ip_str(const uint8_t a[4], char *out, size_t n)
{
    snprintf(out, n, "%u.%u.%u.%u", a[0], a[1], a[2], a[3]);
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
        case IPPROTO_UDP_: est.udp++; break;
        default:           est.otros_proto++; break;
    }

    if (verbose) {
        char s[16], d[16];
        ip_str(ip->src, s, sizeof s);
        ip_str(ip->dst, d, sizeof d);
        const char *p = ip->proto == IPPROTO_TCP_ ? "TCP"
                      : ip->proto == IPPROTO_UDP_ ? "UDP" : "otro";
        printf("  #%-6" PRIu64 "  %-15s -> %-15s  %-4s  "
               "ip_hl=%d  total=%u  payload=%d  ttl=%u\n",
               est.total, s, d, p, ip_hl, ip_len, payload_len, ip->ttl);
    }

    /* BLOQUE 2: aqui entrara la diseccion TCP, con
     *   const u_char *tcp = pkt + off + ip_hl;
     */
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
    printf("-------------------------------------------------------\n");
}

/* --- main --------------------------------------------------------------- */
static void uso(const char *prog)
{
    fprintf(stderr,
            "Uso: %s (-f traza.pcap | -i interfaz) [-v]\n"
            "  -f  leer de un fichero pcap\n"
            "  -i  capturar de una interfaz (requiere privilegios)\n"
            "  -v  imprimir una linea por paquete\n", prog);
}

int main(int argc, char **argv)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    const char *fichero = NULL, *interfaz = NULL;
    int opt;

    while ((opt = getopt(argc, argv, "f:i:vh")) != -1) {
        switch (opt) {
            case 'f': fichero  = optarg; break;
            case 'i': interfaz = optarg; break;
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
