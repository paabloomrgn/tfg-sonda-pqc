/***************************************************************************
 analisisModbus.c
 Este código toma como punto de partida la practica de redes de comunicaciones,
 asignatura de ingeniería informática de la EPS, UAM.
 Autor: Celia Pascual Casado
 2019 EPS-UAM
***************************************************************************/

#include <stdio.h>
#include <stdlib.h>

#include <pcap.h>
#include <string.h>
#include <netinet/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <signal.h>
#include <time.h>
#include <sys/timeb.h>
#include <getopt.h>
#include <inttypes.h>

#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <math.h>
#include <stdbool.h>

#include <unistd.h>
#include <pthread.h>

#include <stdbool.h> 


/*Definicion de constantes *************************************************/
#define ETH_ALEN      6      /* Tamanio de la direccion ethernet           */
#define ETH_HLEN      14     /* Tamanio de la cabecera ethernet            */
#define ETH_TLEN      2      /* Tamanio del campo tipo ethernet            */
#define ETH_FRAME_MAX 1514   /* Tamanio maximo la trama ethernet (sin CRC) */
#define ETH_FRAME_MIN 60     /* Tamanio minimo la trama ethernet (sin CRC) */
#define ETH_DATA_MAX  (ETH_FRAME_MAX - ETH_HLEN) /* Tamano maximo y minimo de los datos de una trama ethernet*/
#define ETH_DATA_MIN  (ETH_FRAME_MIN - ETH_HLEN)
#define IP_ALEN 4			/* Tamanio de la direccion IP					*/
#define OK 0
#define ERROR 1
#define PACK_READ 1
#define PACK_ERR -1
#define BREAKLOOP -2
#define NO_FILTER 0
#define NO_LIMIT -1

#define ERROR 1
#define OK 0


pcap_t *descr=NULL, *descr2=NULL;


void handleSignal(int nsignal);

void analizar_paquete(u_char *user,const struct pcap_pkthdr *hdr, const uint8_t *pack);


/* Ethernet header */
struct sniff_ethernet {
	u_char ether_dhost[ETH_ALEN]; 		/* Destination host address */
	u_char ether_shost[ETH_ALEN]; 		/* Source host address */		
	u_short ether_type; 				/* IP? ARP? RARP? etc */
};

/* VLAN header */
struct sniff_virtualLan {
	uint16_t init;
	uint16_t Lan_type; 				/* IP? ARP? RARP? etc */
	uint16_t padding;
};

/* IP header */
struct sniff_ip {
	u_char ip_vhl; /* version << 4 | header length >> 2 */
	u_char ip_tos; /* type of service */
	u_short ip_len; /* total length */
	u_short ip_id; /* identification */
	u_short ip_off; /* fragment offset field */
	#define IP_RF 0x8000 /* reserved fragment flag */
	#define IP_DF 0x4000 /* dont fragment flag */
	#define IP_MF 0x2000 /* more fragments flag */
	#define IP_OFFMASK 0x1fff /* mask for fragmenting bits */
	u_char ip_ttl; /* time to live */
	u_char ip_p; /* protocol */
	u_short ip_sum; /* checksum */
	u_char ip_src[IP_ALEN];
	u_char ip_dst[IP_ALEN]; 	/* source and dest address */
};
#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip) (((ip)->ip_vhl) >> 4)


/* TCP header */
struct tcp_item {
	struct in_addr ip_src;
	struct in_addr ip_dst;	
	u_short port;
};

typedef u_int tcp_seq;


struct sniff_tcp {
	u_short th_sport; /* source port */
	u_short th_dport; /* destination port */
	tcp_seq th_seq; /* sequence number */
	tcp_seq th_ack; /* acknowledgement number */
	u_char th_offx2; /* data offset, rsvd */
	#define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
	u_char th_flags;
	#define TH_FIN 0x01
	#define TH_SYN 0x02
	#define TH_RST 0x04
	#define TH_PUSH 0x08
	#define TH_ACK 0x10
	#define TH_URG 0x20
	#define TH_ECE 0x40
	#define TH_CWR 0x80
	#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win; /* window */
	u_short th_sum; /* checksum */
	u_short th_urp; /* urgent pointer */
};

/* Modbus TCP header*/
#define SIZE_MODBUS_HEADER 8;
struct sniff_modbus {
	u_short transaction_id;
	u_short protocol_id;
	u_short len;
	u_char unit_id;
	u_char function_code;
};


/* other modbus field*/
u_char *mb_begin; // the beginning after modbus header
u_short mb_ref_num;
u_short mb_word_count;
u_char mb_byte_count;
u_char *mb_data;

pcap_dumper_t *pdumper=NULL;


int throughput = 0;

uint16_t tipo_ether, version_ihl;
uint32_t ip_src, ip_dst, ipsrc_arg = 0;
uint8_t syn_fin;


/*CONTADORES*/
uint64_t contador = 0;
long int no_ip_counter = 0;
long int tcp_counter = 0;
int udp_counter = 0;
long int modbus_counter = 0;
int func_code_1 = 0;
int func_code_2 = 0;
int func_code_3 = 0; 
int func_code_4 = 0; 
int func_code_5 = 0;
int func_code_6 = 0; 
int func_code_7 = 0; 
int func_code_15 = 0; 
int func_code_16 = 0;
int func_code_20 = 0; 
int func_code_21 = 0;
int func_code_24 = 0;
int func_code_43 = 0;   
int error_modbus = 0;
int error_respuesta_modbus = 0;
int reservado_modbus = 0;
int defined_modbus = 0;
long int query_counter = 0;
int response_counter = 0;
long int peticiones_escritura = 0;
long int peticiones_lectura = 0;
long int contador_syn = 0;
long int contador_fin = 0;



//******************************************** H A S H ********************************************//
typedef struct DataNode {
   	uint8_t ipsrc[IP_ALEN];
	u_char function_code;
	int counter;
	struct DataNode* next;
}DataNode;

DataNode *hash[1000000];
int hashSize = 10000;

int search(int key, uint8_t ipsrc[IP_ALEN], u_char function_code){
	DataNode *n;

	
	
	for(n=hash[key]; n != NULL; n=n->next){
		if(n->ipsrc[0]==ipsrc[0] && n->ipsrc[1]==ipsrc[1] && n->ipsrc[2]==ipsrc[2] && n->ipsrc[3]==ipsrc[3] && n->function_code==function_code){
			n->counter++;	
			return 1;
		}	
	}

	return -1;
}

void insert(int key,uint8_t ipsrc[IP_ALEN], u_char function_code, int counter){
	DataNode *new_node, *n1;

	new_node=(DataNode*)malloc(sizeof(DataNode));
	if(new_node == NULL){
		printf("Error reservando memoria\n");
	}
	int i;

	new_node->ipsrc[0]=ipsrc[0];
    for (i = 1; i < IP_ALEN; i++) {
		new_node->ipsrc[i]=ipsrc[i];
	}
	
	new_node->function_code=function_code;
  	new_node->counter=counter;
	new_node->next=NULL;
	
	key=key%hashSize;
	if(hash[key] == NULL){
		hash[key]=new_node;
	}
	
	else{
		for(n1=hash[key]; n1->next !=NULL; n1=n1->next);
		n1->next=new_node;
	}
}

void printlist(DataNode *n){
	int j;
	DataNode *n1;
	for(n1=n; n1!=NULL; n1=n1->next){
		
		printf(" %d", n1->ipsrc[0]);
		for (j = 1; j < IP_ALEN-1; j++) {
			printf(".%d",n1->ipsrc[j]);
		}
		printf(".%d",n1->ipsrc[3]);
		
		//formato
		if(n1->ipsrc[0]<100) {printf(" ");}
		if(n1->ipsrc[0]<10) {printf(" ");}

		if(n1->ipsrc[1]<100) {printf(" ");}
		if(n1->ipsrc[1]<10) {printf(" ");}

		if(n1->ipsrc[2]<100) {printf(" ");}
		if(n1->ipsrc[2]<10) {printf(" ");}

		if(n1->ipsrc[3]<100) {printf(" ");}
		if(n1->ipsrc[3]<10) {printf(" ");}
		
		printf("    %2d \t\t",n1->function_code);
		printf("   %d \t\t",n1->counter);

		printf("\n\n");
		free(n1);
	} 
}

void printHashtable(){
	int i;
	printf("\tIP  \tFunction Code\tCantidad\t        \n\n");
	for(i=0; i<hashSize; i++){
		printlist(hash[i]);
	}
}
//*************************************** E N D  H A S H ***************************************//





//**************************************** H A S H  I P ****************************************//
typedef struct IPnode {
   	uint8_t ipsrc[IP_ALEN];
	uint8_t ipdst[IP_ALEN];
	struct IPnode* next;
}IPnode;

IPnode *hashTable[1000000];
int hashTableSize = 10000;

void insert_IP(int key, uint8_t ipsrc[IP_ALEN], uint8_t ipdst[IP_ALEN]){
	IPnode *new_node, *n1;
	int i;

	new_node=(IPnode*)malloc(sizeof(IPnode));
	
	new_node->ipsrc[0]=ipsrc[0];
    for (i = 1; i < IP_ALEN; i++) {
		new_node->ipsrc[i]=ipsrc[i];
	}
	
	new_node->ipdst[0]=ipdst[0];
    for (i = 1; i < IP_ALEN; i++) {
		new_node->ipdst[i]=ipdst[i];
	}
	new_node->next=NULL;
	

	key=key%hashTableSize;
	if(hashTable[key] == NULL){
		hashTable[key]=new_node;
	}
	else{
		for(n1=hashTable[key]; n1->next !=NULL; n1=n1->next)
		n1->next=new_node;
	}
}

int num_maestros=0;

int search_IP(int key, uint8_t ipsrc[IP_ALEN]/*, uint8_t ipdst[IP_ALEN]*/){
	IPnode *n;
	for(n=hashTable[key]; n != NULL; n=n->next){
		if(n->ipsrc[0]==ipsrc[0] && n->ipsrc[1]==ipsrc[1] && n->ipsrc[2]==ipsrc[2] && n->ipsrc[3]==ipsrc[3]){
			return 1;
		}
	}
	num_maestros++;
	return -1;
}
//*********************************** E N D  H A S H  I P ***********************************//





//**************************** H A S H  T R A N S A C T I O N  I D ****************************//
typedef struct table_id {
	u_short id;
	int counter;
	struct table_id* next;
}table_id;

table_id *hashTable_id[1000000];
int hashTableSize_id = 100000;


int search_ID(int key, u_short id){
	table_id *n;
	
	for(n=hashTable_id[key]; n != NULL; n=n->next){
		
		if(n->id == id){
			n->counter++;
			
			return 1;
		}
	}
	return 0;
}
	
void insert_ID(int key, u_short id, int counter){	
	
		table_id * new_node,*n;
		new_node=(table_id*)malloc(sizeof(table_id));
		new_node->id = id;
		new_node->next=NULL;
		new_node->counter = counter;
		
		//Si la posición key de la tabla hashTable está vacía, insertamos el nodo
		key=key%hashTableSize_id;
		if(hashTable_id[key] == NULL){
			hashTable_id[key]=new_node;
			
		}
		else{
			for(n=hashTable_id[key]; n->next !=NULL; n=n->next)
				n->next=new_node;
		}		
}

void printlist2(table_id *n){
	table_id *n1;
	for(n1=n; n1!=NULL; n1=n1->next){
		if(n1->counter >2){
			printf("El transaction id %2d",n1->id);
			printf(" aparece %2d veces \n\n",n1->counter);
		}
	}
	free(n1); 
}

void printHash_id(){
	int i;
	for(i=0; i<hashTableSize_id; i++){
		printlist2(hashTable_id[i]);
	}
}	
//************************* E N D  H A S H  T R A N S A C T I O N  I D *************************//


//************************* P E T I C I O N E S  P O R  T I E M P O ***************************//
typedef struct peticion {
	uint8_t ipsrc[IP_ALEN];
	int num_pet;
	struct peticion* next;
	double media;
	double media_anterior;
	double desviacion;
	double desviacion_anterior;
}peticion;

peticion *hashTable_pet[1000000];
int hashTableSize_pet = 100000;


//Valores fijos
double alpha = 0.2;
double beta = 0.2;

//Valores a elegir para inicializar
double media = 0.2;
double desviacion = 0.1;


void smoothing (){
	
	peticion *n;
	int i = 0;


	for(i=0; i<hashTableSize_pet; i++){
		for (n=hashTable_pet[i]; n != NULL; n=n->next ){
			n->media_anterior = n->media;
			n->desviacion_anterior = n->desviacion;
			
			media = (alpha*(n->num_pet) + (1-alpha)*media);
			desviacion = (beta * abs(media - (n->num_pet)) + (1 - beta) * desviacion);
			
			//printf("smoothing llamado: ip = %d.%d.%d.%d\n",n->ipsrc[0],n->ipsrc[1],n->ipsrc[2],n->ipsrc[3]);
			//printf("media = %lf. desviacion = %lf. Contador =%d. Paquete %"PRIu64"\n",media, desviacion, n->num_pet,contador);
			n->media = media;
			n->desviacion = desviacion;
			n->num_pet =0;
			
			//printf("si %lf < %lf < %lf\n",(n->media_anterior-n->desviacion_anterior),n->media,(n->media_anterior+n->desviacion_anterior));
			if(n->media > (n->media_anterior+n->desviacion_anterior) ||n->media < (n->media_anterior-n->desviacion_anterior)){
				printf("ALERTA. Flujo de paquetes anormal para la IP ip = %d.%d.%d.%d. Paquete %"PRIu64"\n",n->ipsrc[0],n->ipsrc[1],n->ipsrc[2],n->ipsrc[3], contador);
			}
		
		}
	}
	
}

int searchNode_peticion(int key, uint8_t ipsrc[IP_ALEN]){
	peticion *n;
	for(n=hashTable_pet[key]; n != NULL; n=n->next){
		if(n->ipsrc[0]==ipsrc[0] && n->ipsrc[1]==ipsrc[1] && n->ipsrc[2]==ipsrc[2] && n->ipsrc[3]==ipsrc[3]){
			n->num_pet ++;
			return n->num_pet;
		}
	}
	return -1;
}

void insert_peticion(int key, uint8_t ipsrc[IP_ALEN], int num_pet){
	peticion *new_node, *n1;
	int i;

	new_node=(peticion*)malloc(sizeof(peticion));
	
	new_node->ipsrc[0]=ipsrc[0];
    for (i = 1; i < IP_ALEN; i++) {
		new_node->ipsrc[i]=ipsrc[i];
	}
	
	
	new_node->num_pet=num_pet;
	new_node->next=NULL;
	

	key=key%hashTableSize_pet;
	if(hashTable_pet[key] == NULL){
		hashTable_pet[key]=new_node;
	}
	else{
		for(n1=hashTable_pet[key]; n1->next !=NULL; n1=n1->next)
		n1->next=new_node;
	}
}

int contador_peticiones = 0;
int key_before=100000000;
int peticiones( double date_inicio, double date_fin, u_int puerto_dst_tcp,uint8_t ip_src[IP_ALEN]){
	
	int key;
	
	key = ip_src[0]+ip_src[1]+ip_src[2]+ip_src[3];
	
	if(puerto_dst_tcp == 502){
		contador_peticiones = searchNode_peticion(key,ip_src);
		if(contador_peticiones==-1){
			insert_peticion(key, ip_src, 1);
		}
	
		if(date_fin-date_inicio > 120){
			
			smoothing();
			contador_peticiones = 0;
			return 1;
		}
	}
	return 0;
}
//*********************** E N D  P E T I C I O N E S  P O R  T I E M P O ***********************//



void handleSignal(int nsignal){
	
	(void) nsignal;
	printf("Control C pulsado\n");
	if(descr)
		pcap_close(descr);
	exit(OK);
}


time_t fech, fech1;
const struct pcap_pkthdr *hdr;
double suma, t_primero,t_primero2 = 0,tiempo_actual = 0;



int main (int argc, char **argv) {
	
	char errbuf[PCAP_ERRBUF_SIZE];
	int long_index = 0, retorno = 0;
	char opt;
	char file_name[256];
	struct timeval time;
	
	clock_t start = clock();
	
	if (signal(SIGINT, handleSignal) == SIG_ERR) {
		printf("Error: Fallo al capturar la senal SIGINT.\n");
		exit(ERROR);
	}

	if (argc == 1) {
		printf("Ejecucion: %s <-f traza.pcap / -i eth0> \n", argv[0]);
		exit(ERROR);
	}

	static struct option options[] = {
		{"f", required_argument, 0, 'f'},
		{"i",required_argument, 0,'i'},
		{"h", no_argument, 0, '1'},
		{0, 0, 0, 0}
	};

	//Simple lectura por parametros por completar casos de error, ojo no cumple 100% los requisitos del enunciado!
	while ((opt = getopt_long_only(argc, argv, "f:i:1", options, &long_index)) != -1) {
		switch (opt) {
		case 'i' :
			if(descr || descr2) { // comprobamos que no se ha abierto ninguna otra interfaz o fichero
				printf("Ha seleccionado más de una fuente de datos\n");
				pcap_close(descr);
				pcap_close(descr2);
				exit(ERROR);
			}
			
			if ((descr = pcap_open_live(optarg,1514,0,100, errbuf)) == NULL){
				printf("Error: Interface: %s, %s %s %d.\n", optarg,errbuf,__FILE__,__LINE__);
				exit(ERROR);
			}
			
			//Para volcado de traza
			descr2=pcap_open_dead(DLT_EN10MB,1514);
			if (!descr2){
				printf("Error al abrir el dump.\n");
				pcap_close(descr);
				exit(ERROR);
			}
			gettimeofday(&time,NULL);
			sprintf(file_name,"captura.eth0.%lld.pcap",(long long)time.tv_sec);
			pdumper=pcap_dump_open(descr2,file_name);
			if(!pdumper){
				printf("Error al abrir el dumper: %s, %s %d.\n",pcap_geterr(descr2),__FILE__,__LINE__);
				pcap_close(descr);
				pcap_close(descr2);
				exit(ERROR);
			}
			break;

		case 'f' :
			if(descr) { // comprobamos que no se ha abierto ninguna otra interfaz o fichero
				printf("Ha seleccionado más de una fuente de datos\n");
				pcap_close(descr);
				exit(ERROR);
			}

			if ((descr = pcap_open_offline(optarg, errbuf)) == NULL) {
				printf("Error: pcap_open_offline(): File: %s, %s %s %d.\n", optarg, errbuf, __FILE__, __LINE__);
				exit(ERROR);
			}

			break;

		case '1' :
			printf("Ayuda. Ejecucion: %s <-f traza.pcap / -i eth0> : %d\n", argv[0], argc);
			exit(ERROR);
			break;

		case '?' :
		default:
			printf("Error. Ejecucion: %s <-f traza.pcap / -i eth0> : %d\n", argv[0], argc);
			exit(ERROR);
			break;
		}
	}

	if (!descr) {
		printf("No selecciono ningún origen de paquetes.\n");
		return ERROR;
	}

	printf("\n\n");
	

	retorno=pcap_loop(descr,NO_LIMIT,analizar_paquete,NULL);
	switch(retorno)	{
		case OK:
			printf("Traza leída\n\n");
			break;
		case PACK_ERR: 
			printf("Error leyendo paquetes\n");
			break;
		case BREAKLOOP: 
			printf("pcap_breakloop llamado\n");
			break;
	} 
	
	printf("Se procesaron %"PRIu64" paquetes, de los cuales hay:\n", contador);
	printf("\t%"PRIu64" paquetes IPv4.\n", (contador - no_ip_counter));
	printf("\t%ld paquetes TCP.\n", tcp_counter);
	//printf("\t%d paquetes UDP.\n", udp_counter);
	printf("\t%ld paquetes Modbus TCP, de los cuales:\n", modbus_counter);
	printf("\t\t %ld peticiones de lectura.\n", peticiones_lectura);
	printf("\t\t%ld peticiones de escritura.\n", peticiones_escritura);
	printf("\t\t%d paquetes con datos erroneos.\n", error_modbus);	 
	printf("\t\t%d respuestas con excepción.\n", error_respuesta_modbus);	 
	printf("\t\t%d paquetes con código de funcion no válido (reservado).\n", reservado_modbus);	 
	 
	
	printf("\tNumero de maestros en la red: %d\n\n", num_maestros);
	if(contador_syn >0) printf("\tFlag SYN activado en %ld paquetes\n\n", contador_syn);
	if(contador_fin >0) printf("\tFlag FIN activado en %ld paquetes\n\n", contador_fin);

	printHashtable();
	printHash_id();
	
	
	clock_t end = clock();
	double time_taken = (double)(end - start)/CLOCKS_PER_SEC;
	
	
	printf("El programa ha tardado %lf segundos en ejecutar.\n\n", time_taken); 
	printf("Se procesaron %lf pps\n\n", contador/time_taken); 

	throughput=throughput/time_taken;
	printf("El throughput es de %d Bytes/segundo.\n\n", throughput); 
	
	pcap_close(descr);

	return OK;
}
  

  
void analizar_paquete(u_char *user,const struct pcap_pkthdr *hdr, const uint8_t *pack){
	
	(void)user;
	
	//uint8_t ether_dhost[ETH_ALEN], ether_shost[ETH_ALEN];
	uint16_t type;
	uint8_t version, ip_ttl;
	int size_ip;
	int size_tcp;
	int ip_total_len;
	int ip_protocol;
	uint16_t aux16;
	uint16_t ip_offset;
	uint8_t ip_src[IP_ALEN], ip_dst[IP_ALEN];
	u_int puerto_src_tcp, puerto_dst_tcp, tcp_header_len;
	u_char th_flags;
	uint8_t syn=0, fin=0;
	int i = 0;
	int tam_lan = 0;
	int resto_paquete;
	int acum =0;
	u_short modbus_len;
	uint16_t transaction_id;
	
	
	
	int hash;
	int hashfind;
	int hash_id;
	int key_IP;
	int key;
	int key_id;
	u_short id;
	
	contador++;
	
	//printf("\n %"PRIu64". Nuevo paquete capturado el %s\n",contador, ctime((const time_t *) & (hdr->ts.tv_sec)));
	
	if (contador == 1){
		fech1 =hdr->ts.tv_sec;
		t_primero = hdr->ts.tv_sec + (hdr->ts.tv_usec)*0.000001;
		t_primero2 = t_primero -t_primero;
	}		
	fech =hdr->ts.tv_sec;
	suma = hdr->ts.tv_sec + (hdr->ts.tv_usec)*0.000001;
	tiempo_actual = suma- t_primero;

	

	
	const struct sniff_ethernet *ethernet; /* The ethernet header [1] */
	const struct sniff_ip *ip; /* The IP header */
	const struct sniff_tcp *tcp; /* The TCP header */
	const struct sniff_modbus *modbus;
	
	
	//***************************************** E T H E R N E T ********************************************//
	
	ethernet = (struct sniff_ethernet*)(pack);
	
	/*ether_dhost[0]=ethernet->ether_dhost[0];
	for (i = 1; i < ETH_ALEN; i++) {
		ether_dhost[i]=ethernet->ether_dhost[i];
	}
	
	ether_shost[0]=ethernet->ether_shost[0];
	for (i = 1; i < ETH_ALEN; i++) {
		ether_shost[i]=ethernet->ether_shost[i];
	}*/
	
	type=ethernet->ether_type;
	//printf("TIPO %04X\n",type);
	
	
	
	//********************************************** I P ************************************************//
	
	if(type == 8 || type == 129){
		
		if(type == 129){
			//printf("PAQUETE CON VLAN:\n");
			tam_lan = 4;
			
			const struct sniff_virtualLan *lan; /* The IP header */
			lan = (struct sniff_virtualLan*)(pack + ETH_HLEN);
		
			type=lan->Lan_type;
		}
		
		if(type == 8){
			//printf("Protocolo IP.\n");
			
			ip = (struct sniff_ip*)(pack + ETH_HLEN + tam_lan);
			
			version=(ip->ip_vhl>>4);
			if(version !=4){
				printf("El numero de versión no es el esperado (IPv4)\n");
				return;
			}
		
			size_ip = IP_HL(ip)*4;
			//printf("\tTamano cabecera IP %d.\n",size_ip);
			
			if (size_ip < 20) {
				printf("Tamaño de cabecera TCP no válido: %d Bytes\n", size_ip);
				return;
			}
			
			memcpy(&aux16,&ip->ip_len,sizeof(uint16_t));
			ip_total_len=ntohs(aux16);
			//printf("\tLongitud total IP: %d\n",ip_total_len);
			throughput = ip_total_len+ETH_HLEN+throughput+tam_lan;
		
			aux16 =0;
			
			//Offset
			memcpy(&aux16, &ip->ip_off, sizeof(uint16_t));
			aux16=ntohs(aux16);
			
			ip_offset=(aux16 & IP_OFFMASK);
			//printf("\taux16: %04X\n",aux16);
			//printf("\tOFFSET: %04X\n",ip_offset);
			
			if(ip_offset!=0){
				printf("Desplazamiento IP !=0\n");
				return;
			}
		
			//Tiempo de vida
			ip_ttl=ip->ip_ttl;
			if(ip_ttl<=1){
				printf("TTL igual o inferior a 1.%"PRIu64" \n", contador);
			}
			
			//Protocolo
			ip_protocol=ip->ip_p;
			
			//Dirección ip origen
			ip_src[0]=ip->ip_src[0];
			for (i = 1; i < IP_ALEN; i++) {
				ip_src[i]=ip->ip_src[i];
			}

			//Dirección ip destino
			ip_dst[0]=ip->ip_dst[0];
			for (i = 1; i < IP_ALEN; i++) {
				ip_dst[i]=ip->ip_dst[i];
			}
			
			
		}
	
		else {
			//printf("Paquete no IPv4\n");
			no_ip_counter ++;
			return;
		}
	
	
	//********************************************** T C P ************************************************//	
	
		if (ip_offset == 0 && ip_protocol == 6) {
			
			tcp_counter ++;						
			tcp = (const struct sniff_tcp*)(pack + ETH_HLEN + tam_lan +size_ip);
			//printf("\tPAQUETE TCP \n");
			size_tcp = TH_OFF(tcp)*4;
			if (size_tcp < 20) {
				printf("Tamaño de cabecera TCP no válido: %u bytes\n", size_tcp);
			return;
			}
			
			memcpy(&puerto_src_tcp,&tcp->th_sport,sizeof(uint16_t));
			puerto_src_tcp  =ntohs(puerto_src_tcp); 
			//printf("\tPuerto origen TCP: %d \n",puerto_src_tcp);
				
				
			memcpy(&puerto_dst_tcp,&tcp->th_dport,sizeof(uint16_t));
			puerto_dst_tcp=ntohs(puerto_dst_tcp); 
			//printf("\tPuerto destino TCP: %0d \n",puerto_dst_tcp);
				
				
			memcpy(&tcp_header_len,&tcp->th_offx2,sizeof(uint8_t));
			tcp_header_len =  (tcp->th_offx2 >> 4)*4;
			//printf("\tTamaño cabecera TCP: %d \n",tcp_header_len);
						
			
			memcpy(&th_flags,&tcp->th_flags,sizeof(uint8_t));
			fin = th_flags & TH_FIN;
			syn = (th_flags & TH_SYN)>>1;
			
			
			if(syn ==1){
				//printf("Flag SYN=1 en el paquete %"PRIu64"\n",contador);
				contador_syn ++;
			}
			if(fin ==1){
				//printf("Flag FIN=1 en el paquete %"PRIu64"\n",contador);
				contador_fin ++;
			}
			

			
			resto_paquete = ip_total_len - (size_ip + size_tcp);
			
			
			
	//********************************************** M O D B U S ************************************************//
			
			//modbus = (const struct sniff_modbus*)(pack + ETH_HLEN + tam_lan + size_ip + size_tcp + acum);
			
			if(resto_paquete> 0   &&(puerto_src_tcp == 502 || puerto_dst_tcp == 502) /*&& modbus->protocol_id == 0 && (ntohs(modbus->len) >= 2 || ntohs(modbus->len) <= 254)*/){
				
				
				if(puerto_dst_tcp == 502){
					query_counter++;
				}
				
				if(puerto_src_tcp == 502){
					response_counter++;
				}
				
				modbus_counter ++;
			
			if(peticiones (t_primero2,tiempo_actual,puerto_dst_tcp,ip_src)==1){
				t_primero2 = tiempo_actual;
			}
			
			
			//Comprobación de número de maestros
			if (puerto_dst_tcp==502){
				key_IP =ip_src[0]+ip_src[1]+ip_src[2]+ip_src[3];

				hashfind=search_IP(key_IP, ip_src/*, ip_dst*/);

				if(hashfind == -1){
					insert_IP(key_IP, ip_src, ip_dst);
				} 
			}
			

				do{
				
					modbus = (const struct sniff_modbus*)(pack + ETH_HLEN + tam_lan + size_ip + size_tcp + acum);
					if(modbus->protocol_id != 0 ){
						printf("Error en el id del protocolo modbus en el paquete %"PRIu64"\n",contador);
						error_modbus ++;
						return;
					}
					 
 
					modbus_len = ntohs(modbus->len);

					if(modbus_len < 2 || modbus_len > 254){
						printf("Error en la longitud del paquete modbus %"PRIu64"\n",contador);
						error_modbus ++;
						return;
					}
					
					if((modbus->function_code & 0x80) == 0x80){
						printf("El código de función %d del paquete %"PRIu64" indica error\n",modbus->function_code,contador);
						error_respuesta_modbus++;
						return;
					}
					
					/*else if(modbus->function_code >=128){ 
						printf("El código de función %d indica que ha habido un error en el paquete %"PRIu64"\n",modbus->function_code,contador);
						error_modbus ++;
						return;
					}*/
					
					if(modbus->function_code == 0){
						printf("Código de función no válido en el paquete %"PRIu64"\n", contador);
						error_modbus++;
						return;
					}
					if((modbus->function_code >= 65 && modbus->function_code <= 72) ||(modbus->function_code >= 100 && modbus->function_code <= 110)){ 
						printf("Código de función no estandar. Definido por el usuario en el paquete%"PRIu64"\n",contador);
						defined_modbus ++;
						//return;
					}
					if(modbus->function_code == 8  ||modbus->function_code == 9 ||modbus->function_code == 10||modbus->function_code == 13
					||modbus->function_code == 14 ||modbus->function_code == 41 ||modbus->function_code == 42 ||modbus->function_code == 90
					 ||modbus->function_code == 91|| modbus->function_code == 125||modbus->function_code == 126 ||modbus->function_code == 127){ 
						printf("Código de función reservado (no válido) %"PRIu64"\n",contador);
						reservado_modbus ++;
					//return;
					}
					
					
					
					if(puerto_dst_tcp == 502 && (modbus->function_code == 0x01 || modbus->function_code == 0x02 || modbus->function_code == 0x03
							|| modbus->function_code == 0x04 || modbus->function_code == 0x07 || modbus->function_code == 0x18 
							|| modbus->function_code == 0x14 || modbus->function_code == 0x2b)){
								peticiones_lectura++;
					
					}

					if(puerto_dst_tcp == 502 && (modbus->function_code == 0x10 || modbus->function_code == 0x0F || modbus->function_code == 0x05
							|| modbus->function_code == 0x06 || modbus->function_code == 0x15 )){
								peticiones_escritura++;
					}
					
					if(modbus->function_code == 0x01){//printf("Lectura de bits\n");
						func_code_1 ++;	
					}
					
					else if(modbus->function_code == 0x02){//printf("Lectura de entradas discretas\n");
						func_code_2 ++;	
					}
					
					else if(modbus->function_code == 0x03){//printf("Lectura de registros\n");						
						func_code_3 ++;	
					}
					
					else if(modbus->function_code == 0x04){//printf("Lectura de registros de entrada\n");						
						func_code_4 ++;	
					}
					
					else if(modbus->function_code == 0x05){//printf("Escritura de un bit\n");	
						func_code_5 ++;	
					}
					
					else if(modbus->function_code == 0x06){//printf("Escritura de un registro\n");	
						func_code_6 ++;	
					}
					
					else if(modbus->function_code == 0x07){//printf("Leer estado de Excepción\n");	
						func_code_7 ++;	
					}
					
					else if(modbus->function_code == 0x0F){//printf("Escritura de varios bits\n");	
						func_code_15 ++;	
					}
					
					else if(modbus->function_code == 0x10){//printf("Escritura de varios registros\n");		
						func_code_16 ++;	
					}
					
					else if(modbus->function_code == 0x15){//printf("Escritura de registro de archivo\n");		
						func_code_21 ++;	
					}
					
					else if(modbus->function_code == 0x18){//printf("Lectura cola FIFO\n");		
						func_code_24 ++;
					}
					
					else if(modbus->function_code == 0x14){//printf("Lectura de registro de archivo\n");		
						func_code_20 ++;
					}
					else if(modbus->function_code == 0x2b){//printf("Lectura identificacion del dispositivo\n");		
						func_code_43 ++;
					}
					
					
					//tabla hash
					key=ip_src[0]+ip_src[1]+ip_src[2]+ip_src[3]+modbus->function_code;
							
					
					hash=search(key, ip_src,modbus->function_code);
					
					if(hash == -1){
						insert(key, ip_src,modbus->function_code,1);
					}
					
					acum = acum + 6 + ntohs(modbus->len);
					
					resto_paquete = resto_paquete - (6+ntohs(modbus->len));
					
					
					memcpy(&transaction_id,&modbus->transaction_id,sizeof(uint16_t));
					transaction_id=ntohs(transaction_id);
					id = transaction_id;
					

					key_id = id;
					
					hash_id = search_ID(key_id, id);
					if(hash_id == 0)insert_ID(key_id,id,1);
					
					
					
					if(resto_paquete <0) resto_paquete = 0;
					if(resto_paquete == 0){
						//modbus_counter ++;
						return;	
					} 
						
				}while (resto_paquete!=0);
				//printf("Paquete analizado\n");
				
				
				
			} 
	}
		else {
			//printf("No es el protocolo TCP esperado\n\n");	
			
			if (ip_protocol == 17){
				//printf("Protocolo UDP\n\n");
				udp_counter ++;	
				//printf("CONTADOR UDP: %d\n", udp_counter);
			}
		}
	}

	else {
		//printf("Paquete no IPv4\n");
		no_ip_counter ++;	
	}

}
