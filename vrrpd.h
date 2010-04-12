#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sockio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if_arp.h>
#include <fcntl.h>
#include <signal.h>
#include <syslog.h>

#include "sysmac.h"

// Default path to configuration file -  set this by hand for now
#define CONF "/etc/vrrpd.conf"

#define AUTH_DATA_SIZE 2
#define AUTH_NONE 0
#define AUTH_SIMP 1
#define AUTH_ENCR 2

#define INIT_STAT 0
#define BKUP_STAT 1 
#define MSTR_STAT 2
#define SHUTDOWN_STAT 3

#define FALSE 0
#define TRUE 1



// Constants, limits and defaults dictated by the RFC
#define VRRP_VER 2
#define VRRP_PROTO 112
#define MAX_VRID 255
#define VRRP_TTL 255
#define MDI_FACTOR 3
#define VRRP_DEFAULT_PRIORITY 100
#define VRRP_DEFAULT_PREEMPT TRUE
#define VRRP_DEFAULT_ADVERINT 1

#define VRRP_ADDR_STR "224.0.0.18"
#define VRRP_STAT_LEN 16 // length of VRRP pkt not counting IPs
#define VRRP_PKTBUF_SIZE 2048
#define HADDR_LEN 6 // length of MAC address
#define AUTH_PWD_BUF 8

typedef unsigned char vrid_t;

typedef struct ip_hdr {
	uchar_t		vers_hlen;
	uchar_t		tos;
	ushort_t	pkt_len;
	ushort_t	pkt_id;
	ushort_t	flag_frag;
	uchar_t		ttl;
	uchar_t		proto;
	ushort_t	checksum;
	uint32_t	src_ip, dst_ip;
} ip_hdr_t;
	

typedef struct vrrp_packet {
	uchar_t		vers_type;
	uchar_t		vrid;
	uchar_t		priority;
	uchar_t		ip_count;
	uchar_t		auth_type;
	uchar_t		adver_int;
	uint16_t	checksum;
	uint32_t	dyndata[258];
	uchar_t		len;
	uint32_t *	auth_data_ptr;
	uint32_t	src_ip;
} vrrp_packet_t;

typedef struct _vrrp_instance {
	pthread_cond_t	vrrp_cond;
	pthread_mutex_t vrrp_mutex;
	unsigned char	status;
	timespec_t	adver_interval;
	timespec_t	master_down_interval;
	timespec_t	abs_timer;
	timespec_t	skew_time;
	uchar_t		preempt_mode;
	pthread_t *	if_tid;
	int *		socket;
	uchar_t *	haddr;
	vrrp_packet_t *	pkt;
	
} vrrp_instance;

struct vrid_node {
	vrrp_instance * vrrp_inst_ptr;
	struct vrid_node * next_node_ptr;
};
typedef struct vrid_node vrid_node_t;

// this data type will be passed to the i/f thread
typedef struct if_config {
	uchar_t 	auth_type;
	unsigned int 	auth_data[AUTH_DATA_SIZE];
	uint32_t 	src_ip;		// address of i/f
	vrid_node_t *	head_node;
	uchar_t *	haddr;
} if_config_t;

struct ifconf_node {
	if_config_t * if_conf_ptr;
	struct ifconf_node * next_node_ptr;
};
typedef struct ifconf_node ifconf_node_t;



// create data structures
if_config_t * create_if_config( unsigned char auth_type, unsigned int * auth_data, uint32_t ip);
//vrrp_instance * create_vrrp_instance(	if_config_t * conf,		unsigned char vrid,
vrrp_instance * create_vrrp_instance(		unsigned char vrid, unsigned char priority,
						timespec_t adver_interval, unsigned char preempt_mode,
						ushort_t ip_count, unsigned int * ip_list);

vrid_node_t * create_vrid_node( vrrp_instance * instance, vrid_node_t * previous_node);
ifconf_node_t * create_ifconf_node( if_config_t * ifconf, ifconf_node_t * previous_node);
vrrp_instance ** init_vrrp_table( vrid_node_t * cur_vrid_node );
uint16_t vrrp_checksum(vrrp_packet_t * pkt);
void ntoh_vrrp_pkt(vrrp_packet_t * pkt);

// threads
void * if_thread(void *arg);
void * adver_thread(void *arg);

void reload_config(void);

// network
void advertise_master(vrrp_packet_t * vrrp_pkt, int * sockptr);
void grat_arp(vrrp_instance * vrrp_inst);
int * init_mc_sock(uint32_t src_addr);
vrrp_packet_t * recv_pkt(int *);
void mc_connect(int * sock, uint32_t ip);
void db_prt_vrrp_pkt(vrrp_packet_t *);
int vrrp_authenticate(vrrp_packet_t * local, vrrp_packet_t * in);
int get_haddr(uint32_t ip, uchar_t * dst);
void arp_op(uint32_t ip, uchar_t * haddr, int op);

// time spec manipulation
void reduce_timespec(timespec_t * time_in);
void add_timespec(timespec_t * a, timespec_t * b);
void mult_timespec(timespec_t * time_in, int factor);
void freshen_timespec(timespec_t * ts);
#define YYSTYPE unsigned long
#define LOG_LEV0 0 // log errors only
#define LOG_LEV1 1 // moderate logging
#define LOG_LEV2 2 // debug
extern uint32_t p_src_ip;
extern vrid_node_t * p_cur_vrid_node;
extern vrid_node_t * p_prev_vrid_node;
extern vrid_node_t * p_head_node;
extern vrrp_instance * p_cur_vrrp_inst;
extern vrrp_instance * p_prev_vrrp_inst;
extern uchar_t p_adverint;
extern uchar_t p_preempt;
extern uchar_t p_ip_count;
extern uint32_t p_addresses[255];
extern timespec_t p_ai_ts;
extern char l_strbuf[AUTH_PWD_BUF];
extern uint32_t p_auth_data[AUTH_DATA_SIZE];
extern uchar_t p_auth_type;
extern if_config_t * p_cur_if_conf;
extern ifconf_node_t * p_cur_ifconf_node;
extern ifconf_node_t * p_prev_ifconf_node;
extern ifconf_node_t * p_head_ifconf_node;
extern int ifcount;
extern FILE * yyin;
extern int log_level;
