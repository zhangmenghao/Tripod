#define RX_RING_SIZE 512
#define TX_RING_SIZE 512

#define NUM_MBUFS 8191
#define NUM_MANAGER_MBUFS 8191
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
#define N_MACHINE 4
#define N_MACHINE_MAX 8
#define N_INTERFACE_MAX 48

#define TIMER_RESOLUTION_CYCLES 2399987461ULL

/*
 * Configure debug output level
 * none debug output: nothing to do
 * debug output level 1: #define __DEBUG_LV1
 * debug output level 2: #define __DEBUG_LV1
 *                       #define __DEBUG_LV2
 */

//#define __DEBUG_LV1


struct nf_states{
    uint32_t ipserver; //Load Balancer

    uint32_t dip; //NAT
    uint16_t dport;

    uint32_t bip; // Backup Machine IP

};

struct nf_indexs{
    uint32_t backupip[2];
};

struct ipv4_5tuple {
    uint32_t ip_dst;
    uint32_t ip_src;
    uint16_t port_dst;
    uint16_t port_src;
    uint8_t  proto;
};

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
extern struct rte_ring* nf_pull_wait_ring;

extern int enabled_port_mask;

extern uint8_t debug_mode;

extern uint32_t dip_pool[DIP_POOL_SIZE];

extern struct rte_hash *state_hash_table[NB_SOCKETS];
extern struct rte_hash *index_hash_table[NB_SOCKETS];

extern struct machine_IP_pair topo[N_MACHINE_MAX];
extern struct machine_IP_pair* this_machine;
extern struct rte_mbuf* probing_packet;
extern struct ether_addr interface_MAC;
extern uint32_t broadcast_ip;
extern uint32_t this_machine_index;

extern uint32_t flow_counts;
extern uint32_t last_flow_counts;
extern uint32_t malicious_packet_counts;
/* Data nf received statistics */
extern unsigned long long nf_rx_bytes;
extern unsigned long long last_nf_rx_bytes;
extern unsigned long long nf_rx_pkts;
extern unsigned long long last_nf_rx_pkts;
/* Data nf transmitted statistics */
extern unsigned long long nf_tx_bytes;
extern unsigned long long last_nf_tx_bytes;
extern unsigned long long nf_tx_pkts;
extern unsigned long long last_nf_tx_pkts;
/* Data transmitted by manager statistics */
extern unsigned long long mg_nf_tx_bytes;
extern unsigned long long last_mg_nf_tx_bytes;
extern unsigned long long mg_nf_tx_pkts;
extern unsigned long long last_mg_nf_tx_pkts;
/* Control message transmitted by nf statistics */
extern unsigned long long nf_ctrl_tx_bytes;
extern unsigned long long last_nf_ctrl_tx_bytes;
extern unsigned long long nf_ctrl_tx_pkts;
extern unsigned long long last_nf_ctrl_tx_pkts;

void convert_ipv4_5tuple(struct ipv4_5tuple *key1, union ipv4_5tuple_host *key2);
void setStates(struct ipv4_5tuple *ip_5tuple, struct nf_states *state);
int getStates(struct ipv4_5tuple *ip_5tuple, struct nf_states ** state, void* callback_arg);
void setIndexs(struct ipv4_5tuple *ip_5tuple, struct nf_indexs *index);
int getIndexs(struct ipv4_5tuple *ip_5tuple, struct nf_indexs **index);
int pullState(uint16_t nf_id, uint8_t port, void* callback_arg, struct ipv4_5tuple* ip_5tuple,
              struct nf_indexs* target_indexs, struct nf_states** target_states);
int pullStateCallback(struct nf_states* state, void* callback_arg);
int port_init(uint8_t port, struct rte_mempool *mbuf_pool, struct rte_mempool *manager_mbuf_pool);
int parse_args(int argc, char **argv);
void setup_hash(const int socketid);
void check_all_ports_link_status(uint8_t port_num, uint32_t port_mask);

struct rte_mbuf* build_probe_packet(struct ipv4_5tuple* ip_5tuple);
struct rte_mbuf* backup_receive_probe_packet(struct rte_mbuf* mbuf);
void master_receive_probe_reply(struct rte_mbuf* mbuf, uint32_t* machine_ip1, uint32_t* machine_ip2, struct ipv4_5tuple** ip_5tuple);
void ecmp_predict_init(struct rte_mempool * mbuf_pool);

int lcore_nf(__attribute__((unused)) void *arg);
int lcore_manager(__attribute__((unused)) void *arg);
int lcore_manager_slave(__attribute__((unused)) void *arg);
int lcore_main_loop(__attribute__((unused)) void *arg);

