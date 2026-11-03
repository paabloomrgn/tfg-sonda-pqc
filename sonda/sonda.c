/* ===========================================================================
 * sonda.c — Sonda pasiva de deteccion de elementos de red inseguros
 *           desde el punto de vista postcuantico.
 *
 * TFG — Pablo Marugan Bastante — GITST, EPS-UAM
 * Tutor: Jorge E. Lopez de Vergara
 *
 * BLOQUE 1: captura y diseccion hasta la capa IP.
 * BLOQUE 2: diseccion de la cabecera TCP y filtro por puerto.
 * BLOQUE 3: tabla de flujos y reensamblado TCP de los registros TLS
 *           del inicio de cada sentido.
 * BLOQUE 4: lectura de ClientHello / HelloRetryRequest / ServerHello
 *           (supported_groups y key_share) y clasificacion de la conexion,
 *           el cliente y el servidor segun la tabla grupos_pqc.csv.
 *
 * Compilar:  gcc -Wall -Wextra -std=gnu11 -o sonda sonda.c -lpcap
 * Ejecutar:  ./sonda -f traza.pcap [-p 443] [-g grupos_pqc.csv] [-v]
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

#define STREAM_MAX  (2 * TLS_REC_MAX)    /* bytes guardados por sentido: caben
                                          dos registros (por el HelloRetryRequest) */
#define N_CUBETAS     4096      /* tamano de la tabla hash de flujos        */

/* Tipos de registro y de mensaje TLS */
#define TLS_CCS          20     /* ChangeCipherSpec                         */
#define TLS_HS_CLIENT_HELLO  1
#define TLS_HS_SERVER_HELLO  2
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
    int      es_hrr;                    /* HelloRetryRequest                */
    uint16_t grupo;                     /* grupo elegido (o pedido, si HRR) */
    uint16_t long_clave;                /* 0 en un HRR: no lleva clave      */
};

struct flujo {
    uint32_t ip_a, ip_b;    /* orden canonico: (ip_a,puerto_a) <= (ip_b,puerto_b) */
    uint16_t puerto_a, puerto_b;
    struct sentido dir[2];  /* 0: a -> b    1: b -> a                       */
    struct flujo *sig;      /* siguiente en la misma cubeta                 */

    int      dir_cliente;   /* sentido del cliente, -1 si aun no se sabe    */
    struct client_hello ch[2];   /* el 2o solo si hubo HelloRetryRequest     */
    int      n_ch;
    struct server_hello hrr, sh;
    int      hay_hrr, hay_sh;
    int      terminado;     /* ya clasificado: ignorar el resto del flujo  */
};

/* --- tabla de grupos (cargada de grupos_pqc.csv) ------------------------ */
enum clase {
    C_DESCONOCIDO = 0, C_CLASICO, C_PQ, C_HIBRIDO, C_HIBRIDO_OBSOLETO,
    C_EXPERIMENTAL, C_GREASE
};

struct grupo {
    uint16_t   id;
    char       nombre[64];
    enum clase clase;
    uint16_t   long_cliente, long_servidor;
};

static struct grupo grupos[MAX_TABLA];
static int n_grupos_tabla = 0;

static void informe(struct flujo *f);   /* definida en el BLOQUE 4 */

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
    /* BLOQUE 4 */
    uint64_t tls_malformados;
    uint64_t conexiones;
    uint64_t con_segura, con_insegura, con_sin_respuesta;
    uint64_t cli_inseguro, cli_potencial, cli_seguro;
    uint64_t srv_inseguro, srv_indeterminado, srv_soporta_pq, srv_fuerza_pq;
} est;

static int verbose = 0;
static uint16_t puerto = 443;   /* puerto TCP a analizar (-p)              */
static const char *fichero_grupos = "grupos_pqc.csv";   /* -g              */

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
    f->dir_cliente = -1;
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
            if (!f->terminado) informe(f);   /* ClientHello sin respuesta */
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
        case C_PQ:               return "PQ";
        case C_HIBRIDO:          return "hibrido";
        case C_HIBRIDO_OBSOLETO: return "hibrido obsoleto";
        case C_EXPERIMENTAL:     return "experimental";
        case C_GREASE:           return "GREASE";
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
    saltar(&l, 2 + 1);             /* cipher_suite + compression          */
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
        default:     return "?";
    }
}

static void imprimir_grupos(const char *titulo, const uint16_t *g, int n)
{
    char tmp[24];
    printf("    %-22s", titulo);
    int primero = 1;
    for (int i = 0; i < n; i++) {
        if (es_grease(g[i])) continue;                 /* no aporta nada  */
        printf("%s%s (%s)", primero ? "" : ", ",
               nombre_grupo(g[i], tmp, sizeof tmp), texto_de_clase(clase_grupo(g[i])));
        primero = 0;
    }
    printf("%s\n", primero ? "(ninguno)" : "");
}

static void imprimir_key_share(const char *titulo, const struct client_hello *ch)
{
    char tmp[24];
    printf("    %-22s", titulo);
    int primero = 1;
    for (int i = 0; i < ch->n_ks; i++) {
        if (es_grease(ch->ks_grupo[i])) continue;
        const struct grupo *g = buscar_grupo(ch->ks_grupo[i]);
        printf("%s%s %u B", primero ? "" : ", ",
               nombre_grupo(ch->ks_grupo[i], tmp, sizeof tmp), ch->ks_long[i]);
        if (g && g->long_cliente)
            printf(g->long_cliente == ch->ks_long[i] ? " (ok)" : " (ESPERADO %u)", g->long_cliente);
        primero = 0;
    }
    printf("%s\n", primero ? "(ninguna)" : "");
}

/* Informe de una conexion. Aplica la tabla acordada para la tutoria:
 *   conexion: segura si se negocio un grupo PQ o hibrido
 *   cliente : segun lo que SABE hacer (supported_groups)
 *   servidor: segun lo que eligio y lo que el cliente le dio a elegir    */
static void informe(struct flujo *f)
{
    if (f->n_ch == 0) return;                  /* no vimos el ClientHello */
    est.conexiones++;

    int dc = f->dir_cliente;
    uint32_t ipc = dc == 0 ? f->ip_a : f->ip_b,  ips = dc == 0 ? f->ip_b : f->ip_a;
    uint16_t pc  = dc == 0 ? f->puerto_a : f->puerto_b,
             ps  = dc == 0 ? f->puerto_b : f->puerto_a;
    uint8_t a[4] = { (uint8_t)(ipc >> 24), (uint8_t)(ipc >> 16), (uint8_t)(ipc >> 8), (uint8_t)ipc };
    uint8_t b[4] = { (uint8_t)(ips >> 24), (uint8_t)(ips >> 16), (uint8_t)(ips >> 8), (uint8_t)ips };
    char sc[16], ss[16], tmp[24];
    ip_str(a, sc, sizeof sc);
    ip_str(b, ss, sizeof ss);

    const struct client_hello *ch  = &f->ch[0];           /* el primero   */
    const struct client_hello *chu = &f->ch[f->n_ch - 1]; /* el ultimo    */

    printf("\n  Conexion %s:%u -> %s:%u   SNI=%s\n", sc, pc, ss, ps,
           ch->sni[0] ? ch->sni : "-");
    imprimir_grupos("Cliente sabe:", ch->grupos, ch->n_grupos);
    imprimir_key_share("Cliente manda:", ch);
    if (f->hay_hrr) {
        printf("    %-22s%s\n", "Servidor pide (HRR):", nombre_grupo(f->hrr.grupo, tmp, sizeof tmp));
        if (f->n_ch > 1) imprimir_key_share("Cliente manda (2o):", chu);
    }

    /* ---- conexion ---- */
    const char *conexion;
    uint16_t elegido = f->hay_sh ? f->sh.grupo : 0;
    int tls13 = f->hay_sh && f->sh.version == 0x0304;
    if (!f->hay_sh) {
        conexion = "SIN RESPUESTA (no se vio el ServerHello)";
        est.con_sin_respuesta++;
    } else {
        printf("    %-22s%s", "Servidor elige:", texto_version(f->sh.version));
        if (tls13) {
            const struct grupo *g = buscar_grupo(elegido);
            printf(", %s (%s) %u B", nombre_grupo(elegido, tmp, sizeof tmp),
                   texto_de_clase(clase_grupo(elegido)), f->sh.long_clave);
            if (g && g->long_servidor)
                printf(g->long_servidor == f->sh.long_clave ? " (ok)" : " (ESPERADO %u)", g->long_servidor);
        }
        printf("\n");
        if (tls13 && es_pq(elegido)) { conexion = "SEGURA";   est.con_segura++; }
        else                         { conexion = "INSEGURA"; est.con_insegura++; }
    }

    /* ---- cliente: por lo que SABE hacer ---- */
    const char *cliente;
    if (!ch_tiene_pq(ch))           { cliente = "INSEGURO (no ofrece PQ)"; est.cli_inseguro++; }
    else if (ch_tiene_clasico(ch))  { cliente = "POTENCIALMENTE INSEGURO (PQ, pero tambien acepta clasico)"; est.cli_potencial++; }
    else                            { cliente = "SEGURO (solo PQ)"; est.cli_seguro++; }

    /* ---- servidor: por lo que eligio y lo que tenia disponible ---- */
    const char *servidor;
    if (!f->hay_sh) {
        servidor = "INDETERMINADO (sin respuesta)"; est.srv_indeterminado++;
    } else if (tls13 && es_pq(elegido)) {
        if (f->hay_hrr) { servidor = "FUERZA PQ (lo pidio con HelloRetryRequest)"; est.srv_fuerza_pq++; }
        else            { servidor = "SOPORTA PQ (eligio PQ)"; est.srv_soporta_pq++; }
    } else if (!tls13 && ch->ofrece_tls13) {
        servidor = "INSEGURO (el cliente ofrecia TLS 1.3 y eligio una version sin PQ)"; est.srv_inseguro++;
    } else if (ch_manda_clave_pq(chu)) {
        servidor = "INSEGURO (tenia la clave PQ del cliente y eligio clasico)"; est.srv_inseguro++;
    } else if (ch_tiene_pq(ch)) {
        servidor = "INDETERMINADO (el cliente solo anuncio PQ y el servidor no lo pidio con HRR)"; est.srv_indeterminado++;
    } else {
        servidor = "INDETERMINADO (el cliente no ofrecia PQ)"; est.srv_indeterminado++;
    }

    printf("    => CONEXION: %s\n", conexion);
    printf("    => CLIENTE:  %s\n", cliente);
    printf("    => SERVIDOR: %s\n", servidor);
}

/* Procesa un registro TLS completo de un sentido */
static void procesar_registro(struct flujo *f, int d, const uint8_t *r, uint32_t n)
{
    struct sentido *s = &f->dir[d];

    if (r[0] == TLS_CCS) return;               /* ChangeCipherSpec: saltar */
    if (r[0] != TLS_HANDSHAKE) { s->fin = 1; return; }   /* datos cifrados */
    if (n < TLS_REC_HLEN + TLS_HS_HLEN) { est.tls_malformados++; s->fin = 1; return; }

    /* Cabecera del mensaje de handshake: tipo (1) + longitud (3) */
    const uint8_t *m = r + TLS_REC_HLEN;
    uint32_t mlen = (uint32_t)m[1] << 16 | (uint32_t)m[2] << 8 | m[3];
    if (mlen > n - TLS_REC_HLEN - TLS_HS_HLEN) { est.tls_malformados++; s->fin = 1; return; }
    const uint8_t *cuerpo = m + TLS_HS_HLEN;

    if (m[0] == TLS_HS_CLIENT_HELLO) {
        if (f->dir_cliente < 0) f->dir_cliente = d;
        if (f->n_ch < 2) {
            if (leer_client_hello(cuerpo, mlen, &f->ch[f->n_ch]) == 0) f->n_ch++;
            else { est.tls_malformados++; s->fin = 1; }
        }
    } else if (m[0] == TLS_HS_SERVER_HELLO) {
        struct server_hello sh;
        if (leer_server_hello(cuerpo, mlen, &sh) != 0) { est.tls_malformados++; s->fin = 1; return; }
        if (sh.es_hrr) {
            f->hrr = sh; f->hay_hrr = 1;   /* el cliente mandara otro ClientHello */
        } else {
            f->sh = sh; f->hay_sh = 1;
            informe(f);                    /* ya lo tenemos todo          */
            f->terminado = 1;
        }
    } else {
        s->fin = 1;     /* otro mensaje (Certificate...): ya no nos interesa */
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

    if (datos_len == 0 || f->terminado || s->fin) return;

    /* Si la captura empezo con la conexion ya abierta no hemos visto el SYN.
     * Solo lo aceptamos si este segmento empieza un registro TLS.          */
    if (!s->tiene_isn) {
        if (datos_len >= TLS_REC_HLEN && datos[0] == TLS_HANDSHAKE && datos[1] == 0x03) {
            s->isn = seq;
            s->tiene_isn = 1;
        } else {
            s->fin = 1;
            return;
        }
    }

    insertar_segmento(s, seq, datos, datos_len);

    /* Leer todos los registros que ya esten completos en este sentido.
     * Normalmente es uno (el ClientHello o el ServerHello); tras un
     * HelloRetryRequest el cliente manda otro ClientHello detras.         */
    const uint8_t *rec;
    uint32_t rlen;
    int r;
    while (!f->terminado && !s->fin && (r = siguiente_registro(s, &rec, &rlen)) != 0) {
        if (r < 0) { s->fin = 1; break; }        /* no es TLS: ignorar      */
        est.registros_completos++;
        if (verbose) {
            char a[16], b[16];
            ip_str(ip->src, a, sizeof a);
            ip_str(ip->dst, b, sizeof b);
            printf("  >> %s:%u -> %s:%u  registro TLS tipo %u completo: %u bytes\n",
                   a, sport, b, dport, rec[0], rlen);
        }
        procesar_registro(f, d, rec, rlen);       /* BLOQUE 4             */
        s->inicio += rlen;
    }

    /* Ya clasificada, o sin nada mas que leer: liberar memoria */
    if (f->terminado) { liberar_sentido(&f->dir[0]); liberar_sentido(&f->dir[1]); }
    else if (s->fin)  liberar_sentido(s);
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
    printf("  Clasificacion (%" PRIu64 " conexiones TLS)\n", est.conexiones);
    printf("    conexiones   segura %" PRIu64 " | insegura %" PRIu64 " | sin respuesta %" PRIu64 "\n",
           est.con_segura, est.con_insegura, est.con_sin_respuesta);
    printf("    clientes     inseguro %" PRIu64 " | potencialmente inseguro %" PRIu64 " | seguro %" PRIu64 "\n",
           est.cli_inseguro, est.cli_potencial, est.cli_seguro);
    printf("    servidores   inseguro %" PRIu64 " | indeterminado %" PRIu64
           " | soporta PQ %" PRIu64 " | fuerza PQ %" PRIu64 "\n",
           est.srv_inseguro, est.srv_indeterminado, est.srv_soporta_pq, est.srv_fuerza_pq);
    if (est.tls_malformados)
        printf("    mensajes TLS malformados ... %" PRIu64 "\n", est.tls_malformados);
    printf("-------------------------------------------------------\n");
}

/* --- main --------------------------------------------------------------- */
static void uso(const char *prog)
{
    fprintf(stderr,
            "Uso: %s (-f traza.pcap | -i interfaz) [-p puerto] [-g grupos.csv] [-v]\n"
            "  -f  leer de un fichero pcap\n"
            "  -i  capturar de una interfaz (requiere privilegios)\n"
            "  -p  puerto TCP a analizar (por defecto 443)\n"
            "  -g  tabla de grupos (por defecto grupos_pqc.csv)\n"
            "  -v  imprimir una linea por segmento TCP del puerto\n", prog);
}

int main(int argc, char **argv)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    const char *fichero = NULL, *interfaz = NULL;
    int opt;

    while ((opt = getopt(argc, argv, "f:i:p:g:vh")) != -1) {
        switch (opt) {
            case 'f': fichero  = optarg; break;
            case 'g': fichero_grupos = optarg; break;
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

    if (cargar_grupos(fichero_grupos) <= 0) {
        fprintf(stderr, "No se pudo leer la tabla de grupos %s (usa -g ruta)\n", fichero_grupos);
        return 1;
    }
    printf("Tabla de grupos: %d grupos de %s\n", n_grupos_tabla, fichero_grupos);

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

    liberar_flujos();          /* antes del resumen: informa de lo pendiente */
    imprimir_resumen();
    pcap_close(descr);
    return 0;
}
