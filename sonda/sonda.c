/* ===========================================================================
 * sonda.c — Sonda pasiva de deteccion de elementos de red inseguros
 *           desde el punto de vista postcuantico.
 *
 * TFG — Pablo Marugan Bastante — GITST, EPS-UAM
 * Tutor: Jorge E. Lopez de Vergara
 *
 * BLOQUE 1: captura y diseccion hasta la capa IP (Ethernet, VLAN, Linux
 *           SLL/SLL2, loopback y RAW; IPv4 e IPv6).
 * BLOQUE 2: diseccion de la cabecera TCP y filtro por puerto.
 * BLOQUE 3: tabla de flujos y reensamblado TCP de los registros TLS
 *           del inicio de cada sentido.
 * BLOQUE 4: lectura de ClientHello / HelloRetryRequest / ServerHello
 *           (supported_groups y key_share), y en TLS 1.2 del
 *           ServerKeyExchange; clasificacion de la conexion, el cliente y
 *           el servidor segun la tabla grupos_pqc.csv.
 * BLOQUE 5: salida NDJSON (una linea por conexion, al estilo de TLScensus)
 *           y estado acumulado por servidor.
 *
 * Compilar:  gcc -Wall -Wextra -std=gnu11 -o sonda sonda.c -lpcap
 * Ejecutar:  ./sonda -f traza.pcap [-p 443] [-g grupos_pqc.csv] [-o salida.ndjson]
 *            ./sonda -f traza.pcap -t          (texto legible en lugar de JSON)
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
#include <time.h>
#include <sys/time.h>
#include <sys/socket.h>     /* AF_INET, AF_INET6                           */

#include <pcap.h>
#include <arpa/inet.h>      /* ntohs, ntohl, inet_ntop */

/* Tipos de enlace que puede no definir una libpcap antigua */
#ifndef DLT_LINUX_SLL2
#define DLT_LINUX_SLL2  276
#endif
#ifndef DLT_IPV4
#define DLT_IPV4        228
#endif
#ifndef DLT_IPV6
#define DLT_IPV6        229
#endif

/* --- constantes -------------------------------------------------------- */
#define ETH_HLEN        14      /* cabecera Ethernet: siempre 14 bytes      */
#define SLL_HLEN        16      /* Linux "cooked" v1 (captura con -i any)   */
#define SLL2_HLEN       20      /* Linux "cooked" v2 (libpcap >= 1.10)      */
#define NULL_HLEN        4      /* loopback BSD/Windows: familia (4 bytes)  */
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
#define IP_MF       0x2000      /* flag "more fragments"                    */
#define IP6_HLEN        40      /* cabecera IPv6 fija                       */

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

#define STREAM_MAX  (2 * TLS_REC_MAX)    /* bytes guardados por sentido: caben
                                          dos registros (por el HelloRetryRequest) */
#define N_CUBETAS     4096      /* tamano de la tabla hash de flujos        */

/* Tipos de registro y de mensaje TLS */
#define TLS_CCS          20     /* ChangeCipherSpec                         */
#define TLS_HS_CLIENT_HELLO        1
#define TLS_HS_SERVER_HELLO        2
#define TLS_HS_SERVER_KEY_EXCHANGE 12   /* solo TLS <= 1.2                  */
#define TLS_HS_SERVER_HELLO_DONE   14   /* solo TLS <= 1.2                  */
#define TLS_HS_HLEN      4      /* cabecera de mensaje: tipo (1) + long (3) */

/* Extensiones que nos interesan */
#define EXT_SUPPORTED_GROUPS    10
#define EXT_SUPPORTED_VERSIONS  43
#define EXT_KEY_SHARE           51

#define MAX_GRUPOS      64      /* grupos por ClientHello que guardamos     */
#define MAX_TABLA      512      /* filas maximas de grupos_pqc.csv          */

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

/* Cabecera IPv6 (RFC 8200). Es de tamano fijo (40 B); lo variable va en
 * las cabeceras de extension, encadenadas por el campo "next header".     */
struct ip6_hdr_ {
    uint32_t vtc_flow;      /* version (4b) + clase de trafico + etiqueta   */
    uint16_t plen;          /* longitud de lo que va DETRAS de estos 40 B   */
    uint8_t  nxt;           /* siguiente cabecera (6 = TCP, 17 = UDP...)    */
    uint8_t  hlim;
    uint8_t  src[16];
    uint8_t  dst[16];
} __attribute__((packed));

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
 * Las direcciones se guardan siempre en 16 bytes: una IPv4 ocupa los 4
 * primeros y el resto queda a cero (la version va aparte en la clave).
 *
 * Cada sentido tiene su propio buffer de reensamblado. Solo guardamos los
 * primeros registros TLS de cada sentido: en el cliente el ClientHello y en
 * el servidor el ServerHello (y en TLS 1.2 hasta el ServerKeyExchange).
 */
struct sentido {
    int       tiene_isn;    /* sabemos donde empieza el flujo de datos      */
    uint32_t  isn;          /* seq del primer byte de datos (ISN + 1)        */
    uint8_t  *buf;          /* bytes recibidos, colocados por posicion       */
    uint8_t  *mapa;         /* 1 bit por byte: 1 = ya recibido               */
    uint32_t  contiguos;    /* bytes seguidos disponibles desde el 0         */
    uint32_t  inicio;       /* donde empieza el siguiente registro por leer */
    int       segmentos;    /* segmentos con datos que han aportado algo    */
    int       fin;          /* no hay nada mas que leer en este sentido     */
};

/* --- lo que se extrae de cada mensaje (BLOQUE 4) ------------------------ */
struct client_hello {
    int      ofrece_tls13;              /* supported_versions contiene 1.3  */
    char     sni[256];
    uint16_t grupos[MAX_GRUPOS];        /* supported_groups: lo que SABE    */
    int      n_grupos;
    uint16_t ks_grupo[MAX_GRUPOS];      /* key_share: para que MANDA clave  */
    uint16_t ks_long[MAX_GRUPOS];
    int      n_ks;
};

struct server_hello {
    uint16_t version;                   /* version negociada                */
    uint16_t suite;                     /* cipher suite elegida             */
    int      es_hrr;                    /* HelloRetryRequest                */
    uint16_t grupo;                     /* grupo elegido (o pedido, si HRR) */
    uint16_t long_clave;                /* 0 en un HRR: no lleva clave      */
};

/* Que hemos sabido del intercambio de claves en TLS 1.2 */
enum ske { SKE_NADA = 0, SKE_CURVA, SKE_DHE, SKE_SIN };  /* SIN: no hubo SKE (RSA) */

struct flujo {
    uint8_t  ipv;                       /* 4 o 6                            */
    uint8_t  ip_a[16], ip_b[16];        /* orden canonico: (ip_a,puerto_a) <= (ip_b,puerto_b) */
    uint16_t puerto_a, puerto_b;
    struct sentido dir[2];  /* 0: a -> b    1: b -> a                       */
    struct flujo *sig;      /* siguiente en la misma cubeta                 */
    struct timeval t_primero, t_ultimo; /* primer y ultimo paquete visto    */
    int      fin_visto[2];  /* FIN de cada sentido                          */

    int      dir_cliente;   /* sentido del cliente, -1 si aun no se sabe    */
    struct client_hello ch[2];   /* el 2o solo si hubo HelloRetryRequest     */
    int      n_ch;
    struct server_hello hrr, sh;
    int      hay_hrr, hay_sh;
    int      esperando_ske; /* TLS 1.2: vimos el ServerHello, falta el SKE  */
    enum ske tipo_ske;
    uint16_t grupo_tls12;   /* curva del ServerKeyExchange                  */
    int      terminado;     /* ya clasificado: ignorar el resto del flujo  */
};

/* --- tabla de grupos (cargada de grupos_pqc.csv) ------------------------ */
enum clase {
    C_DESCONOCIDO = 0, C_CLASICO, C_PQ, C_HIBRIDO, C_HIBRIDO_OBSOLETO,
    C_EXPERIMENTAL, C_GREASE
};

struct grupo {
    uint16_t   id;
    char       nombre[96];
    enum clase clase;
    uint16_t   long_cliente, long_servidor;
};

static struct grupo grupos[MAX_TABLA];
static int n_grupos_tabla = 0;

/* --- servidores (BLOQUE 5) ----------------------------------------------
 * Por que un servidor elige lo que elige solo se ve juntando conexiones:
 * una sola conexion clasica no dice nada si el cliente no le ofrecio PQ.
 * Por eso cada conexion suma en la ficha de su servidor (IP + puerto) el
 * motivo por el que se clasifico; al final se decide con todas a la vez. */
enum motivo_srv {
    M_SIN_RESPUESTA = 0,    /* no se vio el ServerHello                      */
    M_HRR_PQ,               /* pidio la clave PQ con HelloRetryRequest       */
    M_ELIGIO_PQ,            /* eligio PQ / hibrido directamente              */
    M_VERSION_SIN_PQ,       /* cliente ofrecia TLS 1.3, servidor eligio <=1.2 */
    M_CLAVE_PQ_RECHAZADA,   /* tenia la clave PQ del cliente y eligio clasico */
    M_PQ_SOLO_ANUNCIADO,    /* cliente solo anuncio PQ; servidor no lo pidio */
    M_CLIENTE_SIN_PQ,       /* el cliente no ofrecia PQ                      */
    N_MOTIVOS
};

static const char *MOTIVO_CODIGO[N_MOTIVOS] = {
    "sin_respuesta", "hrr_pide_pq", "eligio_pq", "version_sin_pq",
    "clave_pq_rechazada", "pq_solo_anunciado", "cliente_sin_pq"
};
static const char *MOTIVO_TEXTO[N_MOTIVOS] = {
    "no se vio el ServerHello",
    "lo pidio con HelloRetryRequest",
    "eligio PQ",
    "el cliente ofrecia TLS 1.3 y eligio una version sin PQ",
    "tenia la clave PQ del cliente y eligio clasico",
    "el cliente solo anuncio PQ y el servidor no lo pidio con HRR",
    "el cliente no ofrecia PQ"
};

#define MAX_NOMBRES_SRV  8      /* SNI distintos que guardamos por servidor  */
#define MAX_GRUPOS_SRV   8      /* grupos elegidos distintos por servidor    */

struct servidor {
    uint8_t  ipv, ip[16];
    uint16_t puerto;
    char     nombres[MAX_NOMBRES_SRV][256];
    int      n_nombres;
    uint16_t grupo[MAX_GRUPOS_SRV];     /* grupos que se le ha visto elegir  */
    uint32_t veces[MAX_GRUPOS_SRV];
    int      n_grupos;
    uint32_t conexiones;
    uint32_t motivo[N_MOTIVOS];         /* cuantas conexiones por cada motivo */
    struct timeval t_primero, t_ultimo;
    struct servidor *sig;
};

static struct servidor *tabla_srv[N_CUBETAS];

/* --- veredicto de una conexion ------------------------------------------ */
struct veredicto {
    const char *conexion;       /* segura | insegura | sin_respuesta         */
    const char *cliente;        /* inseguro | potencialmente_inseguro | seguro */
    const char *cliente_motivo; /* no_ofrece_pq | pq_y_clasico | solo_pq     */
    const char *servidor;       /* inseguro | indeterminado | soporta_pq | fuerza_pq */
    enum motivo_srv motivo;
    const char *pq_status;      /* el estado de TLScensus, para comparar     */
    int         hay_grupo;      /* se sabe que grupo se negocio              */
    uint16_t    grupo;
    const char *fuente_grupo;   /* key_share | server_key_exchange           */
};

static void informe(struct flujo *f);   /* definida en el BLOQUE 4 */

static struct flujo *tabla[N_CUBETAS];

/* --- estado global ------------------------------------------------------ */
static pcap_t *descr = NULL;
static int enlace = DLT_EN10MB;         /* tipo de enlace de la captura     */
static struct timeval t_paquete;        /* marca de tiempo del paquete actual */

static struct {
    uint64_t total;
    uint64_t truncados;
    uint64_t con_vlan;
    uint64_t no_ip;
    uint64_t arp;
    uint64_t ipv4;
    uint64_t ipv6;
    uint64_t fragmentos;
    uint64_t tso;               /* longitud IP a 0 por segmentation offload */
    uint64_t tcp;
    uint64_t udp;
    uint64_t otros_proto;
    uint64_t tcp_malformados;
    uint64_t tcp_puerto;        /* segmentos del puerto analizado            */
    uint64_t tcp_con_datos;     /*   ... que llevan datos                    */
    uint64_t tcp_tls_hs;        /*   ... que empiezan por un registro TLS    */
    uint64_t bytes_datos;
    uint64_t flujos;
    uint64_t flujos_cerrados;   /* liberados al ver FIN en los dos sentidos o RST */
    uint64_t desordenados;      /* llegan antes que un hueco anterior        */
    uint64_t retransmisiones;   /* no aportan ningun byte nuevo              */
    uint64_t registros_completos;
    uint64_t sin_memoria;
    /* BLOQUE 4 */
    uint64_t tls_malformados;
    uint64_t hs_partidos;       /* mensaje de handshake repartido en varios registros */
    uint64_t long_incorrecta;   /* key_share con longitud distinta de la esperada */
    uint64_t conexiones;
    uint64_t con_segura, con_insegura, con_sin_respuesta;
    uint64_t cli_inseguro, cli_potencial, cli_seguro;
    uint64_t srv_inseguro, srv_indeterminado, srv_soporta_pq, srv_fuerza_pq;
    /* BLOQUE 5 */
    uint64_t servidores;
} est;

static int verbose = 0;
static int modo_texto = 0;      /* -t: texto legible en lugar de JSON      */
static uint16_t puerto = 443;   /* puerto TCP a analizar (-p)              */
static const char *fichero_grupos = "grupos_pqc.csv";   /* -g              */
static FILE *salida;            /* JSON o texto (stdout o -o fichero)      */
static FILE *info;              /* mensajes y resumen: stderr con JSON     */

/* --- utilidades --------------------------------------------------------- */
static uint16_t leer_be16(const u_char *p) { return (uint16_t)(p[0] << 8 | p[1]); }

/* Direccion IPv4 o IPv6 como texto (inet_ntop ya abrevia la IPv6 con ::) */
static void ip_str(int ipv, const uint8_t *a, char *out, size_t n)
{
    inet_ntop(ipv == 6 ? AF_INET6 : AF_INET, a, out, (socklen_t)n);
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

/* Hash FNV-1a sobre unos bytes (sirve para flujos y para servidores) */
static uint32_t fnv(uint32_t h, const void *datos, size_t n)
{
    const uint8_t *p = datos;
    for (size_t i = 0; i < n; i++) { h ^= p[i]; h *= 16777619u; }
    return h;
}

/* ======================= BLOQUE 3: flujos ============================ */

static uint32_t hash_flujo(uint8_t ipv, const uint8_t *a, const uint8_t *b,
                           uint16_t pa, uint16_t pb)
{
    uint32_t h = fnv(2166136261u, &ipv, 1);
    h = fnv(h, a, 16);
    h = fnv(h, b, 16);
    h = fnv(h, &pa, 2);
    h = fnv(h, &pb, 2);
    return h % N_CUBETAS;
}

/* Busca el flujo del paquete y devuelve en *d su sentido. Si no existe y
 * crear != 0 lo crea; si no, devuelve NULL (asi un ACK suelto despues de
 * cerrar la conexion no vuelve a crear un flujo vacio).                    */
static struct flujo *buscar_flujo(uint8_t ipv, const uint8_t *src, uint16_t sport,
                                  const uint8_t *dst, uint16_t dport, int *d, int crear)
{
    const uint8_t *a = src, *b = dst;
    uint16_t pa = sport, pb = dport;
    *d = 0;
    int cmp = memcmp(src, dst, 16);
    if (cmp > 0 || (cmp == 0 && sport > dport)) {       /* orden canonico */
        a = dst; b = src; pa = dport; pb = sport; *d = 1;
    }
    uint32_t h = hash_flujo(ipv, a, b, pa, pb);
    for (struct flujo *f = tabla[h]; f; f = f->sig)
        if (f->ipv == ipv && f->puerto_a == pa && f->puerto_b == pb &&
            !memcmp(f->ip_a, a, 16) && !memcmp(f->ip_b, b, 16))
            return f;
    if (!crear) return NULL;

    struct flujo *f = calloc(1, sizeof *f);
    if (!f) { est.sin_memoria++; return NULL; }
    f->ipv = ipv;
    memcpy(f->ip_a, a, 16); memcpy(f->ip_b, b, 16);
    f->puerto_a = pa; f->puerto_b = pb;
    f->dir_cliente = -1;
    f->t_primero = f->t_ultimo = t_paquete;
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

/* Cierra un flujo: informa de lo pendiente, lo saca de la tabla y libera.
 * Sin esto la tabla crece sin limite en una captura en vivo.             */
static void cerrar_flujo(struct flujo *f)
{
    if (!f->terminado) informe(f);     /* ClientHello sin respuesta, o TLS 1.2 sin SKE */
    uint32_t h = hash_flujo(f->ipv, f->ip_a, f->ip_b, f->puerto_a, f->puerto_b);
    for (struct flujo **pp = &tabla[h]; *pp; pp = &(*pp)->sig)
        if (*pp == f) { *pp = f->sig; break; }
    liberar_sentido(&f->dir[0]);
    liberar_sentido(&f->dir[1]);
    free(f);
}

static void liberar_flujos(void)
{
    for (int i = 0; i < N_CUBETAS; i++)
        while (tabla[i]) cerrar_flujo(tabla[i]);
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
        s->buf  = malloc(STREAM_MAX);
        s->mapa = calloc(STREAM_MAX / 8 + 1, 1);
        if (!s->buf || !s->mapa) { liberar_sentido(s); est.sin_memoria++; return; }
    }

    uint32_t pos = seq - s->isn;
    if (pos >= STREAM_MAX) return;               /* mas alla de lo que guardamos */
    if (len > STREAM_MAX - pos) len = STREAM_MAX - pos;

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
    while (s->contiguos < STREAM_MAX &&
           (s->mapa[s->contiguos / 8] & (1u << (s->contiguos % 8))))
        s->contiguos++;
}

/* Mira si el registro TLS que empieza en s->inicio ya esta entero.
 *   1: completo (deja en *rec y *len donde esta y cuanto mide)
 *   0: faltan bytes
 *  -1: lo que hay ahi no es un registro TLS                               */
static int siguiente_registro(struct sentido *s, const uint8_t **rec, uint32_t *len)
{
    if (s->fin || !s->buf) return 0;
    if (s->contiguos < s->inicio + TLS_REC_HLEN) return 0;

    const uint8_t *r = s->buf + s->inicio;
    if (r[0] < TLS_CCS || r[0] > 23 || r[1] != 0x03) return -1;   /* tipos 20..23 */

    uint32_t n = TLS_REC_HLEN + ((uint32_t)r[3] << 8 | r[4]);
    if (s->contiguos < s->inicio + n) return 0;
    *rec = r;
    *len = n;
    return 1;
}

/* ======================= BLOQUE 4: tabla de grupos ===================== */

static enum clase clase_de_texto(const char *t)
{
    if (!strcmp(t, "clasico"))          return C_CLASICO;
    if (!strcmp(t, "pq"))               return C_PQ;
    if (!strcmp(t, "hibrido"))          return C_HIBRIDO;
    if (!strcmp(t, "hibrido_obsoleto")) return C_HIBRIDO_OBSOLETO;
    if (!strcmp(t, "experimental"))     return C_EXPERIMENTAL;
    return C_DESCONOCIDO;
}

static const char *texto_de_clase(enum clase c)
{
    switch (c) {
        case C_CLASICO:          return "clasico";
        case C_PQ:               return "pq";
        case C_HIBRIDO:          return "hibrido";
        case C_HIBRIDO_OBSOLETO: return "hibrido_obsoleto";
        case C_EXPERIMENTAL:     return "experimental";
        case C_GREASE:           return "grease";
        default:                 return "desconocido";
    }
}

/* Lee grupos_pqc.csv. Formato de cada linea (las que empiezan por # y la
 * cabecera se saltan):
 *   id_hex,id_dec,nombre,clase,long_cliente,long_servidor,fuente          */
static int cargar_grupos(const char *ruta)
{
    FILE *fp = fopen(ruta, "r");
    if (!fp) return -1;

    char linea[512];
    while (fgets(linea, sizeof linea, fp) && n_grupos_tabla < MAX_TABLA) {
        if (linea[0] == '#' || strncmp(linea, "id_hex", 6) == 0) continue;

        char *campo[7] = {0};
        int n = 0;
        char *p = linea;
        while (n < 7) {                       /* partir por comas a mano   */
            campo[n++] = p;
            char *coma = strchr(p, ',');
            if (!coma) break;
            *coma = '\0';
            p = coma + 1;
        }
        if (n < 6) continue;                  /* linea incompleta: ignorar */

        struct grupo *g = &grupos[n_grupos_tabla];
        g->id = (uint16_t)strtol(campo[0], NULL, 16);
        snprintf(g->nombre, sizeof g->nombre, "%s", campo[2]);
        g->clase = clase_de_texto(campo[3]);
        g->long_cliente  = (uint16_t)atoi(campo[4]);
        g->long_servidor = (uint16_t)atoi(campo[5]);
        if (g->clase == C_DESCONOCIDO)
            fprintf(stderr, "Aviso: clase '%s' no valida para %s\n", campo[3], campo[0]);
        n_grupos_tabla++;
    }
    fclose(fp);
    return n_grupos_tabla;
}

/* GREASE (RFC 8701): 0x0A0A, 0x1A1A ... 0xFAFA. Se detecta por el patron. */
static int es_grease(uint16_t id)
{
    return (id & 0x0F0F) == 0x0A0A && (id >> 8) == (id & 0xFF);
}

static const struct grupo *buscar_grupo(uint16_t id)
{
    for (int i = 0; i < n_grupos_tabla; i++)
        if (grupos[i].id == id) return &grupos[i];
    return NULL;
}

static enum clase clase_grupo(uint16_t id)
{
    if (es_grease(id)) return C_GREASE;
    const struct grupo *g = buscar_grupo(id);
    return g ? g->clase : C_DESCONOCIDO;
}

/* "Postcuantico" a efectos de seguridad: PQ puro o cualquier hibrido. */
static int es_pq(uint16_t id)
{
    enum clase c = clase_grupo(id);
    return c == C_PQ || c == C_HIBRIDO || c == C_HIBRIDO_OBSOLETO || c == C_EXPERIMENTAL;
}

static const char *nombre_grupo(uint16_t id, char *tmp, size_t n)
{
    const struct grupo *g = buscar_grupo(id);
    if (g) return g->nombre;
    snprintf(tmp, n, es_grease(id) ? "GREASE(0x%04X)" : "0x%04X", id);
    return tmp;
}

/* ======================= BLOQUE 4: lectura de TLS ====================== */

/* Lector con control de limites. Los datos vienen de la red: un campo de
 * longitud falso no puede hacernos leer fuera del buffer. Cualquier
 * lectura que se salga pone err = 1 y a partir de ahi todo devuelve 0.    */
struct lector { const uint8_t *p; uint32_t len, pos; int err; };

static int hay(struct lector *l, uint32_t n)
{
    if (l->err || l->len - l->pos < n) { l->err = 1; return 0; }
    return 1;
}
static uint8_t  leer8 (struct lector *l) { return hay(l, 1) ? l->p[l->pos++] : 0; }
static uint16_t leer16(struct lector *l)
{
    if (!hay(l, 2)) return 0;
    uint16_t v = (uint16_t)(l->p[l->pos] << 8 | l->p[l->pos + 1]);
    l->pos += 2;
    return v;
}
static void saltar(struct lector *l, uint32_t n) { if (hay(l, n)) l->pos += n; }
/* Sub-lector de n bytes: para recorrer una extension sin salirse de ella */
static struct lector sub(struct lector *l, uint32_t n)
{
    struct lector s = { NULL, 0, 0, 1 };
    if (!hay(l, n)) return s;
    s.p = l->p + l->pos; s.len = n; s.err = 0;
    l->pos += n;
    return s;
}

/* random de un HelloRetryRequest: SHA-256("HelloRetryRequest"), RFC 8446 4.1.3 */
static const uint8_t HRR_RANDOM[32] = {
    0xCF,0x21,0xAD,0x74,0xE5,0x9A,0x61,0x11,0xBE,0x1D,0x8C,0x02,0x1E,0x65,0xB8,0x91,
    0xC2,0xA2,0x11,0x16,0x7A,0xBB,0x8C,0x5E,0x07,0x9E,0x09,0xE2,0xC8,0xA8,0x33,0x9C
};

/* ClientHello (RFC 8446 4.1.2):
 *   version(2) random(32) session_id(1+n) cipher_suites(2+n)
 *   compression(1+n) extensions(2+n)                                      */
static int leer_client_hello(const uint8_t *p, uint32_t len, struct client_hello *ch)
{
    struct lector l = { p, len, 0, 0 };
    memset(ch, 0, sizeof *ch);

    saltar(&l, 2);                 /* legacy_version: siempre 0x0303      */
    saltar(&l, 32);                /* random                              */
    saltar(&l, leer8(&l));         /* session_id                          */
    saltar(&l, leer16(&l));        /* cipher_suites                       */
    saltar(&l, leer8(&l));         /* compression_methods                 */
    if (l.err) return -1;
    if (l.pos == l.len) return 0;  /* sin extensiones: TLS muy antiguo    */

    struct lector exts = sub(&l, leer16(&l));
    while (!exts.err && exts.pos < exts.len) {
        uint16_t tipo = leer16(&exts);
        struct lector e = sub(&exts, leer16(&exts));
        if (exts.err) break;

        if (tipo == 0) {                                   /* server_name */
            struct lector lista = sub(&e, leer16(&e));
            if (leer8(&lista) == 0) {                      /* host_name   */
                uint16_t n = leer16(&lista);
                if (hay(&lista, n) && n < sizeof ch->sni) {
                    memcpy(ch->sni, lista.p + lista.pos, n);
                    ch->sni[n] = '\0';
                }
            }
        } else if (tipo == EXT_SUPPORTED_GROUPS) {
            struct lector lista = sub(&e, leer16(&e));
            while (!lista.err && lista.pos + 2 <= lista.len && ch->n_grupos < MAX_GRUPOS)
                ch->grupos[ch->n_grupos++] = leer16(&lista);
        } else if (tipo == EXT_KEY_SHARE) {
            /* lista de KeyShareEntry { grupo(2), long(2), clave(long) }   */
            struct lector lista = sub(&e, leer16(&e));
            while (!lista.err && lista.pos < lista.len && ch->n_ks < MAX_GRUPOS) {
                uint16_t g = leer16(&lista);
                uint16_t n = leer16(&lista);
                saltar(&lista, n);
                if (lista.err) break;
                ch->ks_grupo[ch->n_ks] = g;
                ch->ks_long[ch->n_ks]  = n;
                ch->n_ks++;
            }
        } else if (tipo == EXT_SUPPORTED_VERSIONS) {
            struct lector lista = sub(&e, leer8(&e));
            while (!lista.err && lista.pos + 2 <= lista.len)
                if (leer16(&lista) == 0x0304) ch->ofrece_tls13 = 1;
        }
    }
    return exts.err ? -1 : 0;
}

/* ServerHello / HelloRetryRequest (mismo formato):
 *   version(2) random(32) session_id(1+n) cipher_suite(2) compression(1)
 *   extensions(2+n)
 * En un HRR, key_share lleva solo el grupo pedido (2 bytes); en un
 * ServerHello lleva una KeyShareEntry {grupo, long, clave}.               */
static int leer_server_hello(const uint8_t *p, uint32_t len, struct server_hello *sh)
{
    struct lector l = { p, len, 0, 0 };
    memset(sh, 0, sizeof *sh);

    sh->version = leer16(&l);
    if (!hay(&l, 32)) return -1;
    sh->es_hrr = memcmp(l.p + l.pos, HRR_RANDOM, 32) == 0;
    saltar(&l, 32);
    saltar(&l, leer8(&l));         /* session_id                          */
    sh->suite = leer16(&l);
    saltar(&l, 1);                 /* compression                         */
    if (l.err) return -1;
    if (l.pos == l.len) return 0;  /* sin extensiones: TLS <= 1.2         */

    struct lector exts = sub(&l, leer16(&l));
    while (!exts.err && exts.pos < exts.len) {
        uint16_t tipo = leer16(&exts);
        struct lector e = sub(&exts, leer16(&exts));
        if (exts.err) break;

        if (tipo == EXT_SUPPORTED_VERSIONS) {
            sh->version = leer16(&e);       /* la version de verdad (1.3) */
        } else if (tipo == EXT_KEY_SHARE) {
            sh->grupo = leer16(&e);
            if (!sh->es_hrr) sh->long_clave = leer16(&e);
        }
    }
    return exts.err ? -1 : 0;
}

/* Suites de TLS 1.2 con intercambio ECDHE (las que llevan una curva con
 * nombre en el ServerKeyExchange). El resto con SKE son DHE de campo finito. */
static int suite_ecdhe(uint16_t s)
{
    return (s >= 0xC006 && s <= 0xC00A) ||     /* ECDHE_ECDSA (TLS 1.0)    */
           (s >= 0xC010 && s <= 0xC014) ||     /* ECDHE_RSA   (TLS 1.0)    */
           (s >= 0xC023 && s <= 0xC024) || (s >= 0xC027 && s <= 0xC028) ||
           (s >= 0xC02B && s <= 0xC02C) || (s >= 0xC02F && s <= 0xC030) ||
           (s >= 0xC035 && s <= 0xC03B) ||     /* ECDHE_PSK                */
           (s >= 0xC048 && s <= 0xC049) || (s >= 0xC04C && s <= 0xC04D) ||
           (s >= 0xC05C && s <= 0xC05D) || (s >= 0xC060 && s <= 0xC061) ||
           (s >= 0xC072 && s <= 0xC073) || (s >= 0xC076 && s <= 0xC077) ||
           (s >= 0xC086 && s <= 0xC087) || (s >= 0xC08A && s <= 0xC08B) ||
           (s >= 0xC0AC && s <= 0xC0AF) ||     /* ECDHE_ECDSA con CCM      */
           s == 0xCCA8 || s == 0xCCA9 || s == 0xCCAC;   /* ChaCha20        */
}

/* ServerKeyExchange de TLS 1.2 con ECDHE (RFC 8422 5.4):
 *   curve_type(1) = 3 (named_curve) + NamedCurve(2) + punto + firma
 * Es el mismo NamedGroup que en supported_groups, asi que sirve la tabla. */
static void leer_server_key_exchange(struct flujo *f, const uint8_t *p, uint32_t len)
{
    if (suite_ecdhe(f->sh.suite) && len >= 3 && p[0] == 3) {
        f->tipo_ske = SKE_CURVA;
        f->grupo_tls12 = (uint16_t)(p[1] << 8 | p[2]);
    } else {
        f->tipo_ske = SKE_DHE;        /* DH de campo finito: sin NamedGroup */
    }
}

/* ======================= BLOQUE 4: clasificacion ======================= */

static int ch_manda_clave_pq(const struct client_hello *ch);

/* Lo SABE hacer si lo anuncia en supported_groups o si manda clave PQ
 * (un cliente que manda la clave sabe hacerlo aunque no lo anuncie).     */
static int ch_tiene_pq(const struct client_hello *ch)
{
    for (int i = 0; i < ch->n_grupos; i++) if (es_pq(ch->grupos[i])) return 1;
    return ch_manda_clave_pq(ch);
}
static int ch_tiene_clasico(const struct client_hello *ch)
{
    for (int i = 0; i < ch->n_grupos; i++)
        if (clase_grupo(ch->grupos[i]) == C_CLASICO) return 1;
    return 0;
}
static int ch_manda_clave_pq(const struct client_hello *ch)    /* lo MANDA */
{
    for (int i = 0; i < ch->n_ks; i++) if (es_pq(ch->ks_grupo[i])) return 1;
    return 0;
}

static const char *texto_version(uint16_t v)
{
    switch (v) {
        case 0x0304: return "TLS 1.3";
        case 0x0303: return "TLS 1.2";
        case 0x0302: return "TLS 1.1";
        case 0x0301: return "TLS 1.0";
        case 0x0300: return "SSL 3.0";
        default:     return "?";
    }
}

/* Aplica la tabla acordada en la tutoria 2:
 *   conexion: segura si se negocio un grupo PQ o hibrido
 *   cliente : segun lo que SABE hacer (supported_groups)
 *   servidor: segun lo que eligio y lo que el cliente le dio a elegir    */
static struct veredicto clasificar(const struct flujo *f)
{
    struct veredicto v = {0};
    const struct client_hello *ch  = &f->ch[0];           /* el primero   */
    const struct client_hello *chu = &f->ch[f->n_ch - 1]; /* el ultimo    */
    int tls13 = f->hay_sh && f->sh.version == 0x0304;

    /* ---- grupo negociado ---- */
    if (tls13 && f->sh.grupo) {
        v.hay_grupo = 1; v.grupo = f->sh.grupo; v.fuente_grupo = "key_share";
    } else if (f->hay_sh && f->tipo_ske == SKE_CURVA) {
        v.hay_grupo = 1; v.grupo = f->grupo_tls12; v.fuente_grupo = "server_key_exchange";
    }
    int pq_negociado = tls13 && es_pq(f->sh.grupo);

    /* ---- conexion ---- */
    if (!f->hay_sh)        v.conexion = "sin_respuesta";
    else if (pq_negociado) v.conexion = "segura";
    else                   v.conexion = "insegura";

    /* ---- cliente: por lo que SABE hacer ---- */
    if (!ch_tiene_pq(ch))          { v.cliente = "inseguro";                v.cliente_motivo = "no_ofrece_pq"; }
    else if (ch_tiene_clasico(ch)) { v.cliente = "potencialmente_inseguro"; v.cliente_motivo = "pq_y_clasico"; }
    else                           { v.cliente = "seguro";                  v.cliente_motivo = "solo_pq"; }

    /* ---- servidor: por lo que eligio y lo que tenia disponible ---- */
    if (!f->hay_sh)                          { v.servidor = "indeterminado"; v.motivo = M_SIN_RESPUESTA; }
    else if (pq_negociado && f->hay_hrr)     { v.servidor = "fuerza_pq";     v.motivo = M_HRR_PQ; }
    else if (pq_negociado)                   { v.servidor = "soporta_pq";    v.motivo = M_ELIGIO_PQ; }
    else if (!tls13 && ch->ofrece_tls13)     { v.servidor = "inseguro";      v.motivo = M_VERSION_SIN_PQ; }
    /* Mira los dos ClientHello: si el primero ya llevaba clave PQ y el
     * servidor pidio un grupo clasico con HRR, la rechazo igualmente.    */
    else if (ch_manda_clave_pq(ch) || ch_manda_clave_pq(chu))
                                             { v.servidor = "inseguro";      v.motivo = M_CLAVE_PQ_RECHAZADA; }
    else if (ch_tiene_pq(ch))                { v.servidor = "indeterminado"; v.motivo = M_PQ_SOLO_ANUNCIADO; }
    else                                     { v.servidor = "indeterminado"; v.motivo = M_CLIENTE_SIN_PQ; }

    /* ---- estado de TLScensus, para poder comparar linea a linea ---- */
    if (!f->hay_sh)                v.pq_status = "unknown";
    else if (pq_negociado)         v.pq_status = "post_quantum";
    else if (ch_manda_clave_pq(ch)) v.pq_status = "offered_not_selected";
    else if (ch_tiene_pq(ch))      v.pq_status = "advertised_only";
    else                           v.pq_status = "classical";
    return v;
}

/* ======================= BLOQUE 5: salida JSON ========================= */

/* Cadena JSON. El SNI viene de la red: hay que escapar comillas, barras y
 * cualquier byte de control o no ASCII, o una linea mal formada romperia
 * el procesado posterior (jq, Python...).                                 */
static void j_str(const char *s)
{
    fputc('"', salida);
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        if (*p == '"' || *p == '\\') fprintf(salida, "\\%c", *p);
        else if (*p < 0x20 || *p >= 0x7F) fprintf(salida, "\\u%04x", *p);
        else fputc(*p, salida);
    }
    fputc('"', salida);
}

/* Marca de tiempo ISO 8601 en UTC, con microsegundos: 2026-11-04T00:00:00.000800Z */
static void j_tiempo(struct timeval tv)
{
    struct tm tm;
    time_t t = tv.tv_sec;
    gmtime_r(&t, &tm);
    char b[32];
    strftime(b, sizeof b, "%Y-%m-%dT%H:%M:%S", &tm);
    fprintf(salida, "\"%s.%06ldZ\"", b, (long)tv.tv_usec);
}

static void j_ip(int ipv, const uint8_t *a)
{
    char b[INET6_ADDRSTRLEN];
    ip_str(ipv, a, b, sizeof b);
    fprintf(salida, "\"%s\"", b);
}

/* Lista de nombres de grupo (sin GREASE, como TLScensus) */
static void j_grupos(const uint16_t *g, int n)
{
    char tmp[24];
    int primero = 1;
    fputc('[', salida);
    for (int i = 0; i < n; i++) {
        if (es_grease(g[i])) continue;
        if (!primero) fputc(',', salida);
        j_str(nombre_grupo(g[i], tmp, sizeof tmp));
        primero = 0;
    }
    fputc(']', salida);
}

/* key_share del cliente con longitudes: [{"group":..,"length":..,"length_ok":..}] */
static void j_key_shares(const struct client_hello *ch)
{
    char tmp[24];
    int primero = 1;
    fputc('[', salida);
    for (int i = 0; i < ch->n_ks; i++) {
        if (es_grease(ch->ks_grupo[i])) continue;
        const struct grupo *g = buscar_grupo(ch->ks_grupo[i]);
        if (!primero) fputc(',', salida);
        fprintf(salida, "{\"group\":");
        j_str(nombre_grupo(ch->ks_grupo[i], tmp, sizeof tmp));
        fprintf(salida, ",\"class\":\"%s\",\"length\":%u,\"length_ok\":%s}",
                texto_de_clase(clase_grupo(ch->ks_grupo[i])), ch->ks_long[i],
                (g && g->long_cliente) ? (g->long_cliente == ch->ks_long[i] ? "true" : "false") : "null");
        primero = 0;
    }
    fputc(']', salida);
}

static void j_conexion(const struct flujo *f, const struct veredicto *v,
                       const uint8_t *ipc, uint16_t pc, const uint8_t *ips, uint16_t ps)
{
    const struct client_hello *ch = &f->ch[0];
    char tmp[24];

    /* Campos con el mismo nombre y significado que en TLScensus */
    fprintf(salida, "{\"type\":\"connection\",\"first_seen\":");
    j_tiempo(f->t_primero);
    fprintf(salida, ",\"last_seen\":");
    j_tiempo(f->t_ultimo);
    fprintf(salida, ",\"transport\":\"tcp\",\"ip_version\":%u,\"client_ip\":", f->ipv);
    j_ip(f->ipv, ipc);
    fprintf(salida, ",\"client_port\":%u,\"server_ip\":", pc);
    j_ip(f->ipv, ips);
    fprintf(salida, ",\"server_port\":%u,\"server_name\":", ps);
    if (ch->sni[0]) j_str(ch->sni); else fprintf(salida, "null");
    fprintf(salida, ",\"version_offered\":\"%s\"", ch->ofrece_tls13 ? "TLS 1.3" : "TLS 1.2");
    if (f->hay_sh) fprintf(salida, ",\"version\":\"%s\"", texto_version(f->sh.version));
    else           fprintf(salida, ",\"version\":null");
    if (v->hay_grupo) {
        fprintf(salida, ",\"group\":");
        j_str(nombre_grupo(v->grupo, tmp, sizeof tmp));
        fprintf(salida, ",\"group_id\":\"0x%04X\",\"group_class\":\"%s\",\"group_source\":\"%s\"",
                v->grupo, texto_de_clase(clase_grupo(v->grupo)), v->fuente_grupo);
    } else {
        fprintf(salida, ",\"group\":null");
    }
    fprintf(salida, ",\"key_share_groups\":");
    j_grupos(ch->ks_grupo, ch->n_ks);
    fprintf(salida, ",\"supported_groups\":");
    j_grupos(ch->grupos, ch->n_grupos);
    fprintf(salida, ",\"pq_status\":\"%s\"", v->pq_status);

    /* Campos propios del TFG */
    fprintf(salida, ",\"key_shares\":");
    j_key_shares(ch);
    if (f->hay_sh && f->sh.version == 0x0304 && f->sh.grupo) {
        const struct grupo *g = buscar_grupo(f->sh.grupo);
        fprintf(salida, ",\"server_key_share_length\":%u,\"server_key_share_length_ok\":%s",
                f->sh.long_clave,
                (g && g->long_servidor) ? (g->long_servidor == f->sh.long_clave ? "true" : "false") : "null");
    }
    fprintf(salida, ",\"hrr\":%s", f->hay_hrr ? "true" : "false");
    if (f->hay_hrr) {
        fprintf(salida, ",\"hrr_group\":");
        j_str(nombre_grupo(f->hrr.grupo, tmp, sizeof tmp));
        if (f->n_ch > 1) {
            fprintf(salida, ",\"key_share_groups_retry\":");
            j_grupos(f->ch[1].ks_grupo, f->ch[1].n_ks);
        }
    }
    fprintf(salida, ",\"connection_status\":\"%s\",\"client_status\":\"%s\",\"client_reason\":\"%s\""
                    ",\"server_status\":\"%s\",\"server_reason\":\"%s\"}\n",
            v->conexion, v->cliente, v->cliente_motivo, v->servidor, MOTIVO_CODIGO[v->motivo]);
}

/* ======================= BLOQUE 4: informe en texto ==================== */

static void imprimir_grupos(const char *titulo, const uint16_t *g, int n)
{
    char tmp[24];
    fprintf(salida, "    %-22s", titulo);
    int primero = 1;
    for (int i = 0; i < n; i++) {
        if (es_grease(g[i])) continue;                 /* no aporta nada  */
        fprintf(salida, "%s%s (%s)", primero ? "" : ", ",
                nombre_grupo(g[i], tmp, sizeof tmp), texto_de_clase(clase_grupo(g[i])));
        primero = 0;
    }
    fprintf(salida, "%s\n", primero ? "(ninguno)" : "");
}

static void imprimir_key_share(const char *titulo, const struct client_hello *ch)
{
    char tmp[24];
    fprintf(salida, "    %-22s", titulo);
    int primero = 1;
    for (int i = 0; i < ch->n_ks; i++) {
        if (es_grease(ch->ks_grupo[i])) continue;
        const struct grupo *g = buscar_grupo(ch->ks_grupo[i]);
        fprintf(salida, "%s%s %u B", primero ? "" : ", ",
                nombre_grupo(ch->ks_grupo[i], tmp, sizeof tmp), ch->ks_long[i]);
        if (g && g->long_cliente)
            fprintf(salida, g->long_cliente == ch->ks_long[i] ? " (ok)" : " (ESPERADO %u)", g->long_cliente);
        primero = 0;
    }
    fprintf(salida, "%s\n", primero ? "(ninguna)" : "");
}

static void texto_conexion(const struct flujo *f, const struct veredicto *v,
                           const uint8_t *ipc, uint16_t pc, const uint8_t *ips, uint16_t ps)
{
    char sc[INET6_ADDRSTRLEN], ss[INET6_ADDRSTRLEN], tmp[24];
    ip_str(f->ipv, ipc, sc, sizeof sc);
    ip_str(f->ipv, ips, ss, sizeof ss);
    const struct client_hello *ch = &f->ch[0];

    if (f->ipv == 6) fprintf(salida, "\n  Conexion [%s]:%u -> [%s]:%u   SNI=%s\n", sc, pc, ss, ps, ch->sni[0] ? ch->sni : "-");
    else             fprintf(salida, "\n  Conexion %s:%u -> %s:%u   SNI=%s\n", sc, pc, ss, ps, ch->sni[0] ? ch->sni : "-");
    imprimir_grupos("Cliente sabe:", ch->grupos, ch->n_grupos);
    imprimir_key_share("Cliente manda:", ch);
    if (f->hay_hrr) {
        fprintf(salida, "    %-22s%s\n", "Servidor pide (HRR):", nombre_grupo(f->hrr.grupo, tmp, sizeof tmp));
        if (f->n_ch > 1) imprimir_key_share("Cliente manda (2o):", &f->ch[1]);
    }
    if (f->hay_sh) {
        fprintf(salida, "    %-22s%s", "Servidor elige:", texto_version(f->sh.version));
        if (v->hay_grupo) {
            fprintf(salida, ", %s (%s)", nombre_grupo(v->grupo, tmp, sizeof tmp),
                    texto_de_clase(clase_grupo(v->grupo)));
            if (f->sh.version == 0x0304) {
                const struct grupo *g = buscar_grupo(v->grupo);
                fprintf(salida, " %u B", f->sh.long_clave);
                if (g && g->long_servidor)
                    fprintf(salida, g->long_servidor == f->sh.long_clave ? " (ok)" : " (ESPERADO %u)", g->long_servidor);
            } else {
                fprintf(salida, " [ServerKeyExchange]");
            }
        } else if (f->tipo_ske == SKE_DHE) {
            fprintf(salida, ", DHE de campo finito");
        } else if (f->tipo_ske == SKE_SIN) {
            fprintf(salida, ", sin ServerKeyExchange (intercambio RSA)");
        }
        fprintf(salida, "\n");
    }
    fprintf(salida, "    => CONEXION: %s\n", v->conexion);
    fprintf(salida, "    => CLIENTE:  %s (%s)\n", v->cliente, v->cliente_motivo);
    fprintf(salida, "    => SERVIDOR: %s (%s)\n", v->servidor, MOTIVO_TEXTO[v->motivo]);
}

/* ======================= BLOQUE 5: estado por servidor ================= */

static struct servidor *buscar_servidor(uint8_t ipv, const uint8_t *ip, uint16_t p)
{
    uint32_t h = fnv(fnv(fnv(2166136261u, &ipv, 1), ip, 16), &p, 2) % N_CUBETAS;
    for (struct servidor *s = tabla_srv[h]; s; s = s->sig)
        if (s->ipv == ipv && s->puerto == p && !memcmp(s->ip, ip, 16)) return s;

    struct servidor *s = calloc(1, sizeof *s);
    if (!s) { est.sin_memoria++; return NULL; }
    s->ipv = ipv; memcpy(s->ip, ip, 16); s->puerto = p;
    s->t_primero = t_paquete;
    s->sig = tabla_srv[h];
    tabla_srv[h] = s;
    est.servidores++;
    return s;
}

static void acumular_servidor(const struct flujo *f, const struct veredicto *v,
                              const uint8_t *ips, uint16_t ps)
{
    struct servidor *s = buscar_servidor(f->ipv, ips, ps);
    if (!s) return;
    s->conexiones++;
    s->motivo[v->motivo]++;
    s->t_ultimo = f->t_ultimo;

    const char *sni = f->ch[0].sni;
    if (sni[0]) {
        int i;
        for (i = 0; i < s->n_nombres; i++) if (!strcmp(s->nombres[i], sni)) break;
        if (i == s->n_nombres && s->n_nombres < MAX_NOMBRES_SRV)
            snprintf(s->nombres[s->n_nombres++], sizeof s->nombres[0], "%s", sni);
    }
    if (v->hay_grupo) {
        int i;
        for (i = 0; i < s->n_grupos; i++) if (s->grupo[i] == v->grupo) break;
        if (i == s->n_grupos && s->n_grupos < MAX_GRUPOS_SRV) { s->grupo[i] = v->grupo; s->n_grupos++; }
        if (i < s->n_grupos) s->veces[i]++;
    }
}

/* Decision sobre el servidor con todas sus conexiones (tabla de la tutoria 2):
 *   inseguro                : alguna vez tuvo PQ a mano y eligio clasico (o
 *                             una version sin PQ)
 *   potencialmente_inseguro : se le ha visto elegir PQ y tambien aceptar
 *                             clasico de clientes que no le dieron la clave
 *   seguro                  : solo se le ha visto negociar PQ
 *   indeterminado           : nunca se le ofrecio PQ de forma que pudiera
 *                             elegirlo, o no se vio su respuesta           */
static const char *estado_servidor(const struct servidor *s, const char **motivo)
{
    uint32_t pq       = s->motivo[M_ELIGIO_PQ] + s->motivo[M_HRR_PQ];
    uint32_t rechazo  = s->motivo[M_CLAVE_PQ_RECHAZADA] + s->motivo[M_VERSION_SIN_PQ];
    uint32_t clasico  = s->motivo[M_PQ_SOLO_ANUNCIADO] + s->motivo[M_CLIENTE_SIN_PQ];

    if (rechazo) { *motivo = "ha elegido clasico teniendo la opcion PQ"; return "inseguro"; }
    if (pq && clasico) { *motivo = "elige PQ, pero tambien acepta clasico"; return "potencialmente_inseguro"; }
    if (pq) { *motivo = "solo se le ha visto negociar PQ"; return "seguro"; }
    if (clasico) { *motivo = "ningun cliente le ha dado la clave PQ"; return "indeterminado"; }
    *motivo = "no se ha visto ninguna respuesta"; return "indeterminado";
}

static void emitir_servidores(void)
{
    char tmp[24], ip[INET6_ADDRSTRLEN];
    if (modo_texto) fprintf(salida, "\n--- Servidores ----------------------------------------\n");

    for (int h = 0; h < N_CUBETAS; h++) {
        for (struct servidor *s = tabla_srv[h]; s; s = s->sig) {
            const char *motivo, *estado = estado_servidor(s, &motivo);
            if (modo_texto) {
                ip_str(s->ipv, s->ip, ip, sizeof ip);
                fprintf(salida, "  %s%s%s:%u  %s  (%" PRIu32 " conexiones: %s)\n",
                        s->ipv == 6 ? "[" : "", ip, s->ipv == 6 ? "]" : "", s->puerto,
                        s->n_nombres ? s->nombres[0] : "-", s->conexiones, motivo);
                fprintf(salida, "    => %s\n", estado);
                continue;
            }
            fprintf(salida, "{\"type\":\"server\",\"first_seen\":");
            j_tiempo(s->t_primero);
            fprintf(salida, ",\"last_seen\":");
            j_tiempo(s->t_ultimo);
            fprintf(salida, ",\"ip_version\":%u,\"server_ip\":", s->ipv);
            j_ip(s->ipv, s->ip);
            fprintf(salida, ",\"server_port\":%u,\"server_names\":[", s->puerto);
            for (int i = 0; i < s->n_nombres; i++) {
                if (i) fputc(',', salida);
                j_str(s->nombres[i]);
            }
            fprintf(salida, "],\"connections\":%" PRIu32 ",\"groups_selected\":{", s->conexiones);
            for (int i = 0; i < s->n_grupos; i++) {
                if (i) fputc(',', salida);
                j_str(nombre_grupo(s->grupo[i], tmp, sizeof tmp));
                fprintf(salida, ":%" PRIu32, s->veces[i]);
            }
            fprintf(salida, "},\"reasons\":{");
            int primero = 1;
            for (int m = 0; m < N_MOTIVOS; m++) {
                if (!s->motivo[m]) continue;
                fprintf(salida, "%s\"%s\":%" PRIu32, primero ? "" : ",", MOTIVO_CODIGO[m], s->motivo[m]);
                primero = 0;
            }
            fprintf(salida, "},\"server_status\":\"%s\",\"server_status_detail\":", estado);
            j_str(motivo);
            fprintf(salida, "}\n");
        }
    }
}

static void liberar_servidores(void)
{
    for (int h = 0; h < N_CUBETAS; h++) {
        struct servidor *s = tabla_srv[h];
        while (s) { struct servidor *sig = s->sig; free(s); s = sig; }
        tabla_srv[h] = NULL;
    }
}

/* ======================= informe de una conexion ======================= */

static void informe(struct flujo *f)
{
    if (f->n_ch == 0) return;                  /* no vimos el ClientHello */
    est.conexiones++;

    int dc = f->dir_cliente;
    const uint8_t *ipc = dc == 0 ? f->ip_a : f->ip_b, *ips = dc == 0 ? f->ip_b : f->ip_a;
    uint16_t pc = dc == 0 ? f->puerto_a : f->puerto_b,
             ps = dc == 0 ? f->puerto_b : f->puerto_a;

    /* TLS 1.2 que termina sin ServerKeyExchange: intercambio RSA */
    if (f->hay_sh && f->sh.version != 0x0304 && f->tipo_ske == SKE_NADA && !f->esperando_ske)
        f->tipo_ske = SKE_SIN;

    struct veredicto v = clasificar(f);

    /* Avisos de longitud (implementacion rara o trafico manipulado) */
    for (int i = 0; i < f->ch[0].n_ks; i++) {
        const struct grupo *g = buscar_grupo(f->ch[0].ks_grupo[i]);
        if (g && g->long_cliente && g->long_cliente != f->ch[0].ks_long[i]) est.long_incorrecta++;
    }

    if (!strcmp(v.conexion, "segura")) est.con_segura++;
    else if (!strcmp(v.conexion, "insegura")) est.con_insegura++;
    else est.con_sin_respuesta++;
    if (!strcmp(v.cliente, "inseguro")) est.cli_inseguro++;
    else if (!strcmp(v.cliente, "seguro")) est.cli_seguro++;
    else est.cli_potencial++;
    if (!strcmp(v.servidor, "inseguro")) est.srv_inseguro++;
    else if (!strcmp(v.servidor, "fuerza_pq")) est.srv_fuerza_pq++;
    else if (!strcmp(v.servidor, "soporta_pq")) est.srv_soporta_pq++;
    else est.srv_indeterminado++;

    if (modo_texto) texto_conexion(f, &v, ipc, pc, ips, ps);
    else            j_conexion(f, &v, ipc, pc, ips, ps);
    acumular_servidor(f, &v, ips, ps);
}

static void terminar(struct flujo *f)
{
    informe(f);
    f->terminado = 1;
}

/* No se puede seguir leyendo un sentido. Si el servidor estaba a mitad de
 * un handshake TLS 1.2, se informa con lo que haya.                       */
static void parar_sentido(struct flujo *f, int d)
{
    f->dir[d].fin = 1;
    if (f->esperando_ske && d != f->dir_cliente) {
        f->esperando_ske = 0;
        terminar(f);
    }
}

/* Un mensaje de handshake completo (cuerpo sin la cabecera de 4 bytes) */
static void procesar_mensaje(struct flujo *f, int d, uint8_t tipo,
                             const uint8_t *cuerpo, uint32_t mlen)
{
    if (tipo == TLS_HS_CLIENT_HELLO) {
        if (f->dir_cliente < 0) f->dir_cliente = d;
        if (d != f->dir_cliente) { parar_sentido(f, d); return; }
        if (f->n_ch < 2) {
            if (leer_client_hello(cuerpo, mlen, &f->ch[f->n_ch]) == 0) f->n_ch++;
            else { est.tls_malformados++; parar_sentido(f, d); }
        }
        return;
    }
    if (d == f->dir_cliente) { parar_sentido(f, d); return; }  /* otro mensaje del cliente */

    if (tipo == TLS_HS_SERVER_HELLO && !f->hay_sh) {
        struct server_hello sh;
        if (leer_server_hello(cuerpo, mlen, &sh) != 0) { est.tls_malformados++; parar_sentido(f, d); return; }
        if (sh.es_hrr) {
            f->hrr = sh; f->hay_hrr = 1;   /* el cliente mandara otro ClientHello */
        } else {
            f->sh = sh; f->hay_sh = 1;
            if (sh.version == 0x0304) terminar(f);     /* ya lo tenemos todo */
            else f->esperando_ske = 1;     /* TLS <= 1.2: el grupo va despues */
        }
    } else if (f->esperando_ske && tipo == TLS_HS_SERVER_KEY_EXCHANGE) {
        leer_server_key_exchange(f, cuerpo, mlen);
        f->esperando_ske = 0;
        terminar(f);
    } else if (f->esperando_ske && tipo == TLS_HS_SERVER_HELLO_DONE) {
        f->tipo_ske = SKE_SIN;             /* no hubo SKE: intercambio RSA */
        f->esperando_ske = 0;
        terminar(f);
    } else if (!f->esperando_ske) {
        parar_sentido(f, d);               /* otro mensaje: ya no nos interesa */
    }
    /* esperando_ske y otro mensaje (Certificate...): seguir leyendo */
}

/* Procesa un registro TLS completo de un sentido. Un registro puede llevar
 * varios mensajes de handshake seguidos (en TLS 1.2 es habitual
 * ServerHello + Certificate + ServerKeyExchange + ServerHelloDone).       */
static void procesar_registro(struct flujo *f, int d, const uint8_t *r, uint32_t n)
{
    if (r[0] == TLS_CCS) return;               /* ChangeCipherSpec: saltar */
    if (r[0] != TLS_HANDSHAKE) { parar_sentido(f, d); return; }   /* cifrado o alerta */

    uint32_t pos = TLS_REC_HLEN;
    while (pos < n && !f->terminado && !f->dir[d].fin) {
        /* Cabecera del mensaje de handshake: tipo (1) + longitud (3) */
        if (n - pos < TLS_HS_HLEN) { est.hs_partidos++; parar_sentido(f, d); return; }
        const uint8_t *m = r + pos;
        uint32_t mlen = (uint32_t)m[1] << 16 | (uint32_t)m[2] << 8 | m[3];
        /* El mensaje sigue en el registro siguiente (p. ej. un certificado
         * de mas de 16 KB). No lo reconstruimos: no nos hace falta.       */
        if (mlen > n - pos - TLS_HS_HLEN) { est.hs_partidos++; parar_sentido(f, d); return; }
        procesar_mensaje(f, d, m[0], m + TLS_HS_HLEN, mlen);
        pos += TLS_HS_HLEN + mlen;
    }
}


static void manejar_senal(int s)
{
    (void)s;
    if (descr) pcap_breakloop(descr);
}

/* ======================= BLOQUE 1: capa de enlace ======================
 * Devuelve en *off donde empieza la capa de red y en *tipo su EtherType.
 * Cada tipo de enlace pone una cabecera distinta delante de IP:
 *   Ethernet  : 14 B, EtherType en los bytes 12-13
 *   Linux SLL : 16 B, protocolo en los bytes 14-15  (tcpdump -i any)
 *   Linux SLL2: 20 B, protocolo en los bytes 0-1    (tcpdump -i any, libpcap >= 1.10)
 *   NULL/LOOP : 4 B con la familia de direcciones   (loopback de Windows/BSD)
 *   RAW       : sin cabecera, empieza directamente IP
 * En NULL/LOOP/RAW no hay EtherType: se deduce de la version de IP.
 * Devuelve -1 si el paquete es demasiado corto.                          */
static int capa_enlace(const u_char *pkt, uint32_t caplen, size_t *off, uint16_t *tipo)
{
    size_t o;
    switch (enlace) {
        case DLT_EN10MB:
            if (caplen < ETH_HLEN) return -1;
            *tipo = ntohs(((const struct eth_hdr *)pkt)->type);
            *off = ETH_HLEN;
            return 0;
        case DLT_LINUX_SLL:
            if (caplen < SLL_HLEN) return -1;
            *tipo = leer_be16(pkt + 14);
            *off = SLL_HLEN;
            return 0;
        case DLT_LINUX_SLL2:
            if (caplen < SLL2_HLEN) return -1;
            *tipo = leer_be16(pkt);
            *off = SLL2_HLEN;
            return 0;
        case DLT_NULL:
        case DLT_LOOP:
            o = NULL_HLEN;
            break;
        default:                     /* DLT_RAW, DLT_IPV4, DLT_IPV6       */
            o = 0;
            break;
    }
    if (caplen < o + 1) return -1;
    uint8_t version = pkt[o] >> 4;
    *tipo = version == 4 ? ETHERTYPE_IPV4 : version == 6 ? ETHERTYPE_IPV6 : 0;
    *off = o;
    return 0;
}

static int enlace_soportado(int dlt)
{
    return dlt == DLT_EN10MB || dlt == DLT_LINUX_SLL || dlt == DLT_LINUX_SLL2 ||
           dlt == DLT_NULL || dlt == DLT_LOOP || dlt == DLT_RAW ||
           dlt == DLT_IPV4 || dlt == DLT_IPV6;
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
    t_paquete = hdr->ts;

    size_t off = 0;                 /* desplazamiento acumulado             */
    const uint32_t caplen = hdr->caplen;
    uint16_t type;

    /* ---------------- enlace ---------------- */
    if (capa_enlace(pkt, caplen, &off, &type) < 0) { est.truncados++; return; }

    /* ---------------- etiquetas VLAN ----------------
     * Pueden venir encadenadas (QinQ). Avanzamos mientras haya.
     */
    int nvlan = 0;
    while ((type == ETHERTYPE_VLAN || type == ETHERTYPE_QINQ)
           && nvlan < MAX_VLAN) {
        if (caplen < off + VLAN_HLEN) { est.truncados++; return; }
        const struct vlan_hdr *v = (const struct vlan_hdr *)(pkt + off);
        if (verbose) {
            fprintf(info, "      VLAN id=%u\n", ntohs(v->tci) & 0x0FFF);
        }
        type = ntohs(v->type);
        off += VLAN_HLEN;
        nvlan++;
    }
    if (nvlan) est.con_vlan++;

    /* ---------------- capa de red ----------------
     * Al salir de aqui: ipv, src, dst (16 B, IPv4 en los 4 primeros),
     * proto (protocolo de transporte), off apuntando a la cabecera de
     * transporte y payload_len con lo que mide segun la cabecera IP.    */
    uint8_t ipv, proto;
    uint8_t src[16] = {0}, dst[16] = {0};
    int payload_len;

    if (type == ETHERTYPE_ARP) { est.arp++; est.no_ip++; return; }

    if (type == ETHERTYPE_IPV4) {
        if (caplen < off + (int)sizeof(struct ip_hdr)) { est.truncados++; return; }
        const struct ip_hdr *ip = (const struct ip_hdr *)(pkt + off);
        if (IP_V(ip) != 4) { est.no_ip++; return; }

        int ip_hl = IP_HL(ip);                  /* NO asumir 20: puede haber opciones */
        if (ip_hl < 20) { est.truncados++; return; }
        if (caplen < off + (uint32_t)ip_hl) { est.truncados++; return; }

        uint32_t ip_len = ntohs(ip->len);       /* longitud total segun IP      */
        uint16_t frag   = ntohs(ip->off);
        est.ipv4++;

        /* TCP Segmentation Offload (TSO/LSO): al capturar en el propio
         * equipo que envia (Npcap en Windows, o Linux con TSO), el sistema
         * entrega a la tarjeta un "super-segmento" de hasta 64 KB con la
         * longitud IP a 0, y es la tarjeta quien lo trocea y la rellena.
         * La captura se hace antes, asi que el campo llega a 0. En ese caso
         * la unica longitud fiable es la capturada.                        */
        if (ip_len == 0) {
            ip_len = caplen - (uint32_t)off;
            est.tso++;
        }

        /* Un fragmento no se puede analizar sin reensamblado IP (el
         * primero si lleva TCP, pero cortado). Se cuentan y se descartan. */
        if ((frag & IP_OFFMASK) != 0 || (frag & IP_MF)) { est.fragmentos++; return; }

        /* Longitud del payload segun IP, no segun lo que nos dio pcap.
         * Ethernet rellena las tramas cortas hasta 60 B; fiarse de caplen
         * haria procesar relleno como si fueran datos.                    */
        payload_len = (int)ip_len - ip_hl;
        if (payload_len < 0) { est.truncados++; return; }

        ipv = 4; proto = ip->proto;
        memcpy(src, ip->src, 4);
        memcpy(dst, ip->dst, 4);
        off += ip_hl;
    } else if (type == ETHERTYPE_IPV6) {
        if (caplen < off + IP6_HLEN) { est.truncados++; return; }
        const struct ip6_hdr_ *ip6 = (const struct ip6_hdr_ *)(pkt + off);
        if ((pkt[off] >> 4) != 6) { est.no_ip++; return; }
        est.ipv6++;

        uint32_t resto = ntohs(ip6->plen);      /* bytes tras los 40 fijos  */
        /* Igual que en IPv4: con TSO la longitud llega a 0 (o seria un
         * jumbograma, que en la practica no se usa). Se toma la capturada. */
        if (resto == 0 && caplen > off + IP6_HLEN) {
            resto = caplen - (uint32_t)off - IP6_HLEN;
            est.tso++;
        }
        uint8_t nxt = ip6->nxt;
        memcpy(src, ip6->src, 16);
        memcpy(dst, ip6->dst, 16);
        off += IP6_HLEN;

        /* Cabeceras de extension: se saltan hasta llegar al transporte.
         * Casi siempre no hay ninguna, pero si las hay estan aqui.
         *   0 hop-by-hop, 43 routing, 60 destination: long = (byte1+1)*8
         *   51 AH: long = (byte1+2)*4
         *   44 fragment: 8 B fijos                                          */
        for (int k = 0; k < 8; k++) {
            if (nxt == 0 || nxt == 43 || nxt == 60 || nxt == 51) {
                if (resto < 2 || caplen < off + 2) { est.truncados++; return; }
                uint32_t hl = nxt == 51 ? (pkt[off + 1] + 2u) * 4 : (pkt[off + 1] + 1u) * 8;
                if (hl > resto || caplen < off + hl) { est.truncados++; return; }
                nxt = pkt[off];
                off += hl; resto -= hl;
            } else if (nxt == 44) {
                if (resto < 8 || caplen < off + 8) { est.truncados++; return; }
                uint16_t fo = leer_be16(pkt + off + 2);
                /* offset != 0 o "more fragments": fragmento de verdad.
                 * Si no, es un fragmento "atomico" y se puede seguir.     */
                if ((fo & 0xFFF8) != 0 || (fo & 1)) { est.fragmentos++; return; }
                nxt = pkt[off];
                off += 8; resto -= 8;
            } else {
                break;
            }
        }
        ipv = 6; proto = nxt;
        payload_len = (int)resto;
    } else {
        est.no_ip++;
        return;
    }

    switch (proto) {
        case IPPROTO_TCP_: est.tcp++; break;
        case IPPROTO_UDP_: est.udp++; return;
        default:           est.otros_proto++; return;
    }

    /* ================= BLOQUE 2: TCP ================= */
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
        char s[INET6_ADDRSTRLEN], d[INET6_ADDRSTRLEN], fl[32];
        ip_str(ipv, src, s, sizeof s);
        ip_str(ipv, dst, d, sizeof d);
        flags_str(tcp->flags, fl, sizeof fl);
        fprintf(info, "  #%-4" PRIu64 " %s:%u -> %s:%u  [%s]  seq=%u ack=%u  "
                "tcp_hl=%d  len=%u",
                est.total, s, sport, d, dport, fl,
                ntohl(tcp->seq), ntohl(tcp->ack), tcp_hl, datos_len);
        if (datos_len >= 5 && datos[0] == TLS_HANDSHAKE && datos[1] == 0x03)
            fprintf(info, "  <- empieza registro TLS handshake (%u bytes)",
                    (unsigned)((datos[3] << 8) | datos[4]) + 5);
        fprintf(info, "\n");
    }

    /* ================= BLOQUE 3: flujo y reensamblado ================= */
    int syn = tcp->flags & TH_SYN, ack = tcp->flags & TH_ACK;
    int d;
    struct flujo *f = buscar_flujo(ipv, src, sport, dst, dport, &d, syn || datos_len > 0);
    if (!f) return;

    /* SYN nuevo sobre un flujo que ya tenia TLS: el cliente ha reutilizado
     * el mismo puerto origen para otra conexion. Se cierra la anterior.   */
    if (syn && !ack && (f->terminado || f->n_ch > 0)) {
        cerrar_flujo(f);
        est.flujos_cerrados++;
        f = buscar_flujo(ipv, src, sport, dst, dport, &d, 1);
        if (!f) return;
    }
    f->t_ultimo = t_paquete;
    struct sentido *s = &f->dir[d];
    uint32_t seq = ntohl(tcp->seq);

    /* El SYN fija el punto de partida: el primer byte de datos es ISN+1 */
    if (syn) {
        s->isn = seq + 1;
        s->tiene_isn = 1;
    }

    if (datos_len > 0 && !f->terminado && !s->fin) {
        /* Si la captura empezo con la conexion ya abierta no hemos visto el SYN.
         * Solo lo aceptamos si este segmento empieza un registro TLS.          */
        if (!s->tiene_isn) {
            if (datos_len >= TLS_REC_HLEN && datos[0] == TLS_HANDSHAKE && datos[1] == 0x03) {
                s->isn = seq;
                s->tiene_isn = 1;
            } else {
                parar_sentido(f, d);
            }
        }

        if (!s->fin) {
            insertar_segmento(s, seq, datos, datos_len);

            /* Leer todos los registros que ya esten completos en este sentido.
             * Normalmente es uno (el ClientHello o el ServerHello); tras un
             * HelloRetryRequest el cliente manda otro ClientHello detras.    */
            const uint8_t *rec;
            uint32_t rlen;
            int r;
            while (!f->terminado && !s->fin && (r = siguiente_registro(s, &rec, &rlen)) != 0) {
                if (r < 0) { parar_sentido(f, d); break; }   /* no es TLS: ignorar */
                est.registros_completos++;
                if (verbose) {
                    char a[INET6_ADDRSTRLEN], b[INET6_ADDRSTRLEN];
                    ip_str(ipv, src, a, sizeof a);
                    ip_str(ipv, dst, b, sizeof b);
                    fprintf(info, "  >> %s:%u -> %s:%u  registro TLS tipo %u completo: %u bytes\n",
                            a, sport, b, dport, rec[0], rlen);
                }
                procesar_registro(f, d, rec, rlen);       /* BLOQUE 4             */
                s->inicio += rlen;
            }
        }

        /* Ya clasificada, o sin nada mas que leer: liberar memoria */
        if (f->terminado) { liberar_sentido(&f->dir[0]); liberar_sentido(&f->dir[1]); }
        else if (s->fin)  liberar_sentido(s);
    }

    /* Fin de la conexion: FIN en los dos sentidos o RST. Se informa de lo
     * pendiente y se libera el flujo entero.                              */
    if (tcp->flags & TH_FIN) f->fin_visto[d] = 1;
    if ((tcp->flags & TH_RST) || (f->fin_visto[0] && f->fin_visto[1])) {
        cerrar_flujo(f);
        est.flujos_cerrados++;
    }
}

/* --- resumen ------------------------------------------------------------ */
static void imprimir_resumen(void)
{
    FILE *o = info;
    fprintf(o, "\n--- Resumen -------------------------------------------\n");
    fprintf(o, "  Paquetes procesados .......... %" PRIu64 "\n", est.total);
    fprintf(o, "    con etiqueta VLAN .......... %" PRIu64 "\n", est.con_vlan);
    fprintf(o, "    truncados / malformados .... %" PRIu64 "\n", est.truncados);
    fprintf(o, "    no IP ...................... %" PRIu64 "   (ARP: %" PRIu64 ")\n",
            est.no_ip, est.arp);
    fprintf(o, "    IPv4 ....................... %" PRIu64 "\n", est.ipv4);
    fprintf(o, "    IPv6 ....................... %" PRIu64 "\n", est.ipv6);
    fprintf(o, "      fragmentos descartados ... %" PRIu64 "\n", est.fragmentos);
    if (est.tso)
        fprintf(o, "      longitud IP a 0 (TSO) .... %" PRIu64 "\n", est.tso);
    fprintf(o, "      TCP ...................... %" PRIu64 "\n", est.tcp);
    fprintf(o, "      UDP ...................... %" PRIu64 "\n", est.udp);
    fprintf(o, "      otros protocolos ......... %" PRIu64 "\n", est.otros_proto);
    fprintf(o, "  TCP puerto %u\n", puerto);
    fprintf(o, "    segmentos .................. %" PRIu64 "\n", est.tcp_puerto);
    fprintf(o, "      con datos ................ %" PRIu64 "  (%" PRIu64 " bytes)\n",
            est.tcp_con_datos, est.bytes_datos);
    fprintf(o, "      inicio de registro TLS ... %" PRIu64 "\n", est.tcp_tls_hs);
    fprintf(o, "    TCP malformados ............ %" PRIu64 "\n", est.tcp_malformados);
    fprintf(o, "  Reensamblado\n");
    fprintf(o, "    flujos ..................... %" PRIu64 "  (cerrados por FIN/RST: %" PRIu64 ")\n",
            est.flujos, est.flujos_cerrados);
    fprintf(o, "    segmentos desordenados ..... %" PRIu64 "\n", est.desordenados);
    fprintf(o, "    retransmisiones ............ %" PRIu64 "\n", est.retransmisiones);
    fprintf(o, "    registros TLS completos .... %" PRIu64 "\n", est.registros_completos);
    if (est.sin_memoria)
        fprintf(o, "    SIN MEMORIA ................ %" PRIu64 "\n", est.sin_memoria);
    fprintf(o, "  Clasificacion (%" PRIu64 " conexiones TLS, %" PRIu64 " servidores)\n",
            est.conexiones, est.servidores);
    fprintf(o, "    conexiones   segura %" PRIu64 " | insegura %" PRIu64 " | sin respuesta %" PRIu64 "\n",
            est.con_segura, est.con_insegura, est.con_sin_respuesta);
    fprintf(o, "    clientes     inseguro %" PRIu64 " | potencialmente inseguro %" PRIu64 " | seguro %" PRIu64 "\n",
            est.cli_inseguro, est.cli_potencial, est.cli_seguro);
    fprintf(o, "    servidores   inseguro %" PRIu64 " | indeterminado %" PRIu64
            " | soporta PQ %" PRIu64 " | fuerza PQ %" PRIu64 "  (por conexion)\n",
            est.srv_inseguro, est.srv_indeterminado, est.srv_soporta_pq, est.srv_fuerza_pq);
    if (est.tls_malformados)
        fprintf(o, "    mensajes TLS malformados ... %" PRIu64 "\n", est.tls_malformados);
    if (est.hs_partidos)
        fprintf(o, "    mensajes en varios registros %" PRIu64 "\n", est.hs_partidos);
    if (est.long_incorrecta)
        fprintf(o, "    key_share de long. rara .... %" PRIu64 "\n", est.long_incorrecta);
    fprintf(o, "-------------------------------------------------------\n");
}

/* --- main --------------------------------------------------------------- */
static void uso(const char *prog)
{
    fprintf(stderr,
            "Uso: %s (-f traza.pcap | -i interfaz) [-p puerto] [-g grupos.csv]\n"
            "          [-o salida.ndjson] [-t] [-v]\n"
            "  -f  leer de un fichero pcap o pcapng\n"
            "  -i  capturar de una interfaz (requiere privilegios; 'any' = todas)\n"
            "  -p  puerto TCP a analizar (por defecto 443)\n"
            "  -g  tabla de grupos (por defecto grupos_pqc.csv)\n"
            "  -o  escribir la salida en un fichero (por defecto, la pantalla)\n"
            "  -t  salida en texto legible en lugar de JSON\n"
            "  -v  imprimir una linea por segmento TCP del puerto (por stderr)\n"
            "\n"
            "Salida JSON: una linea por conexion (\"type\":\"connection\") y, al\n"
            "terminar, una por servidor (\"type\":\"server\"). Resumen por stderr.\n", prog);
}

int main(int argc, char **argv)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    const char *fichero = NULL, *interfaz = NULL, *fichero_salida = NULL;
    int opt;

    while ((opt = getopt(argc, argv, "f:i:p:g:o:tvh")) != -1) {
        switch (opt) {
            case 'f': fichero  = optarg; break;
            case 'g': fichero_grupos = optarg; break;
            case 'i': interfaz = optarg; break;
            case 'o': fichero_salida = optarg; break;
            case 't': modo_texto = 1; break;
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

    /* La salida (JSON o texto) va a la pantalla o a -o. Con JSON en
     * pantalla, los mensajes y el resumen van por stderr para que la
     * salida estandar sea NDJSON puro y se pueda pasar a jq con una tuberia. */
    salida = stdout;
    if (fichero_salida) {
        salida = fopen(fichero_salida, "w");
        if (!salida) { perror(fichero_salida); return 1; }
    }
    info = (modo_texto && !fichero_salida) ? stdout : stderr;

    if (cargar_grupos(fichero_grupos) <= 0) {
        fprintf(stderr, "No se pudo leer la tabla de grupos %s (usa -g ruta)\n", fichero_grupos);
        return 1;
    }
    fprintf(info, "Tabla de grupos: %d grupos de %s\n", n_grupos_tabla, fichero_grupos);

    signal(SIGINT, manejar_senal);

    if (fichero) {
        descr = pcap_open_offline(fichero, errbuf);
        if (!descr) {
            fprintf(stderr, "Error abriendo %s: %s\n", fichero, errbuf);
            return 1;
        }
        fprintf(info, "Leyendo %s\n", fichero);
    } else {
        /* snaplen 65535: queremos el paquete entero. Un snaplen corto
         * cortaria justo el key_share, que es lo que nos interesa.        */
        descr = pcap_open_live(interfaz, 65535, 1 /*promiscuo*/, 100, errbuf);
        if (!descr) {
            fprintf(stderr, "Error abriendo %s: %s\n", interfaz, errbuf);
            return 1;
        }
        fprintf(info, "Capturando en %s (Ctrl+C para parar)\n", interfaz);
        /* En vivo, que cada conexion salga en cuanto se clasifica */
        setvbuf(salida, NULL, _IOLBF, 0);

        /* Filtro BPF en el nucleo: solo llegan a la sonda los segmentos
         * del puerto, en lugar de todo el trafico de la interfaz.         */
        char filtro[96];
        struct bpf_program bpf;
        snprintf(filtro, sizeof filtro, "tcp port %u or (vlan and tcp port %u)", puerto, puerto);
        if (pcap_compile(descr, &bpf, filtro, 1, PCAP_NETMASK_UNKNOWN) == 0) {
            if (pcap_setfilter(descr, &bpf) != 0)
                fprintf(stderr, "Aviso: no se pudo aplicar el filtro: %s\n", pcap_geterr(descr));
            pcap_freecode(&bpf);
        }
    }

    /* Cada tipo de enlace pone una cabecera distinta delante de IP
     * (ver capa_enlace). Si no es ninguno de los conocidos, no se sabe
     * donde empieza IP y no se puede analizar nada.                      */
    enlace = pcap_datalink(descr);
    fprintf(info, "Tipo de enlace: %s\n", pcap_datalink_val_to_name(enlace));
    if (!enlace_soportado(enlace)) {
        fprintf(stderr, "Tipo de enlace %s no soportado\n", pcap_datalink_val_to_name(enlace));
        pcap_close(descr);
        return 1;
    }

    if (pcap_loop(descr, -1, analizar_paquete, NULL) == PCAP_ERROR) {
        fprintf(stderr, "Error en pcap_loop: %s\n", pcap_geterr(descr));
    }

    liberar_flujos();          /* antes del resumen: informa de lo pendiente */
    emitir_servidores();
    imprimir_resumen();
    liberar_servidores();
    pcap_close(descr);
    if (salida != stdout) fclose(salida);
    return 0;
}
