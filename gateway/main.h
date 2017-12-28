#define RX_RING_SIZE 128
#define TX_RING_SIZE 512

#define NUM_MBUFS 8191
#define NUM_MANAGER_MBUFS 1023 
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32
#define MAX_RX_QUEUE_PER_LCORE 16
#define NB_SOCKETS 8
#ifndef IPv4_BYTES
#define IPv4_BYTES_FMT "%" PRIu8 ".%" PRIu8 ".%" PRIu8 ".%" PRIu8
#define IPv4_BYTES(addr) \
		(uint8_t) (((addr) >> 24) & 0xFF),\
		(uint8_t) (((addr) >> 16) & 0xFF),\
		(uint8_t) (((addr) >> 8) & 0xFF),\
		(uint8_t) ((addr) & 0xFF)
#endif


/* Configuration about NF */
/* Hash parameters. */
#ifdef RTE_ARCH_64
/* default to 4 million hash entries (approx) */
#define HASH_ENTRIES		(1024*1024*4)
#else
/* 32-bit has less address-space for hugepage memory, limit to 1M entries */
#define HASH_ENTRIES		(1024*1024*1)
#endif

#define DIP_POOL_SIZE 5

#define EM_HASH_CRC

#ifdef EM_HASH_CRC
#include <rte_hash_crc.h>
#define DEFAULT_HASH_FUNC       rte_hash_crc
#else
#include <rte_jhash.h>
#define DEFAULT_HASH_FUNC       rte_jhash
#endif

/* Configuration about ECMP */
#define N_MACHINE_MAX 8
#define N_INTERFACE_MAX 48

struct nf_states{
    uint32_t ipserver; //Load Balancer

    uint32_t dip; //NAT
uint16_t dport;

    uint32_t bip; // Backup Machine IP

}__rte_cache_aligned;

struct ipv4_5tuple {
	uint32_t ip_dst;
	uint32_t ip_src;
	uint16_t port_dst;
	uint16_t port_src;
	uint8_t  proto;
} __rte_cache_aligned;

union ipv4_5tuple_host {
	struct {
		uint8_t  pad0;
		uint8_t  proto;
		uint16_t pad1;
		uint32_t ip_src;
		uint32_t ip_dst;
		uint16_t port_src;
		uint16_t port_dst;
	};
	xmm_t xmm;
};

struct port_param {
    struct rte_mempool* nf_mempool;
    struct rte_mempool* manager_mempool;
};

struct machine_IP_pair{
	uint8_t id;
	uint32_t ip;
};

extern struct port_param single_port_param;

extern struct rte_ring* nf_manager_ring;

extern int enabled_port_mask; 

extern uint32_t dip_pool[DIP_POOL_SIZE];

extern struct rte_hash *state_hash_table[NB_SOCKETS];

extern struct machine_IP_pair topo[N_MACHINE_MAX];
extern struct machine_IP_pair* this_machine;
extern struct rte_mbuf* probing_packet;
extern struct ether_addr interface_MAC;

void setStates(struct ipv4_5tuple *ip_5tuple, struct nf_states *state);
int getStates(struct ipv4_5tuple *ip_5tuple, struct nf_states ** state);
int port_init(uint8_t port, struct rte_mempool *mbuf_pool, struct rte_mempool *manager_mbuf_pool);
int parse_args(int argc, char **argv);
void setup_hash(const int socketid);
void check_all_ports_link_status(uint8_t port_num, uint32_t port_mask);

void build_probe_packet(uint32_t dip,uint32_t sip,uint16_t dport,uint32_t sport);
void backup_receive_probe_packet(struct rte_mbuf* mbuf);
void master_receive_probe_reply(struct rte_mbuf* mbuf,uint32_t* machine_ip ,uint32_t* sip, uint32_t* dip, uint16_t* sport, uint16_t* dport);
void ecmp_predict_init(struct rte_mempool * mbuf_pool);

int lcore_nf(__attribute__((unused)) void *arg);
int lcore_manager(__attribute__((unused)) void *arg);
int lcore_manager_slave(__attribute__((unused)) void *arg);

