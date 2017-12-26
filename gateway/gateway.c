/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2015 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdint.h>
#include <inttypes.h>
#include <getopt.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_byteorder.h>
#include <rte_ip.h>
#include <rte_ether.h>
#include <rte_common.h>
#include <rte_arp.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_hash.h>

#include "ecmp_predict.h"

#define RX_RING_SIZE 128
#define TX_RING_SIZE 512

#define NUM_MBUFS 8191
#define NUM_MANAGER_MBUFS 1023 
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32
#define MAX_RX_QUEUE_PER_LCORE 16
#define NB_SOCKETS 8
/* Hash parameters. */
#ifdef RTE_ARCH_64
/* default to 4 million hash entries (approx) */
#define HASH_ENTRIES		(1024*1024*4)
#else
/* 32-bit has less address-space for hugepage memory, limit to 1M entries */
#define HASH_ENTRIES		(1024*1024*1)
#endif

#define DIP_POOL_SIZE 5

#ifndef IPv4_BYTES
#define IPv4_BYTES_FMT "%" PRIu8 ".%" PRIu8 ".%" PRIu8 ".%" PRIu8
#define IPv4_BYTES(addr) \
		(uint8_t) (((addr) >> 24) & 0xFF),\
		(uint8_t) (((addr) >> 16) & 0xFF),\
		(uint8_t) (((addr) >> 8) & 0xFF),\
		(uint8_t) ((addr) & 0xFF)
#endif

#define MACHINE_IP IPv4(172, 16, 0, 1)

#define EM_HASH_CRC

#ifdef EM_HASH_CRC
#include <rte_hash_crc.h>
#define DEFAULT_HASH_FUNC       rte_hash_crc
#else
#include <rte_jhash.h>
#define DEFAULT_HASH_FUNC       rte_jhash
#endif

static const struct rte_eth_conf port_conf_default = {
	.rxmode = {
        .max_rx_pkt_len = ETHER_MAX_LEN, //1518
        .mq_mode = ETH_MQ_RX_RSS,
    }, 
    .rx_adv_conf = {
        .rss_conf = {
            .rss_key = NULL,
            .rss_hf = ETH_RSS_IP | ETH_RSS_UDP | ETH_RSS_TCP | ETH_RSS_SCTP,
        }
    },
    .fdir_conf = {
        .mode = RTE_FDIR_MODE_PERFECT,
        .pballoc = RTE_FDIR_PBALLOC_64K,
        .status = RTE_FDIR_REPORT_STATUS,
        .mask = {
            .vlan_tci_mask = 0x0,
            .ipv4_mask = {
                // .src_ip = 0x0000FFFF,
                .dst_ip = 0x0000FFFF,
            },
            // .ipv6_mask = {
                // .src_ip = {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF},
                // .dst_ip = {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF},
            // },
            // .src_port_mask = 0xFFFF,
            // .dst_port_mask = 0xFFFF,
            // .mac_addr_byte_mask = 0xFF,
            // .tunnel_type_mask = 1,
            // .tunnel_id_mask = 0xFFFFFFFF,
        },
        .drop_queue = 127,
    },
};

static struct rte_eth_fdir_filter fdir_filter_state = {
    .soft_id = 1,
    .input = {
        .flow_type = RTE_ETH_FLOW_NONFRAG_IPV4_OTHER,
        .flow = {
            .ip4_flow = {
                // .dst_ip = 0x000010AC,
                .dst_ip = IPv4(0, 0, 16, 172),
            }
        }
    },
    .action = {
        .rx_queue = 1,
        .behavior = RTE_ETH_FDIR_ACCEPT,
        .report_status = RTE_ETH_FDIR_REPORT_ID,
    }
};

static struct rte_eth_fdir_filter fdir_filter_ecmp_tcp = {
    .soft_id = 2,
    .input = {
        .flow_type = RTE_ETH_FLOW_NONFRAG_IPV4_TCP,
        .flow = {
            .tcp4_flow = {
                .ip = {
                    // .src_ip = 0x0000000A, 
                    .dst_ip = IPv4(0, 0, 16, 172),
                },
                // .src_port = rte_cpu_to_be_16(1024),
                // .dst_port = rte_cpu_to_be_16(1024),
            }
        }
    },
    .action = {
        .rx_queue = 1,
        .behavior = RTE_ETH_FDIR_ACCEPT,
        .report_status = RTE_ETH_FDIR_REPORT_ID,
    }
};

static struct rte_eth_fdir_filter fdir_filter_ecmp_udp = {
    .soft_id = 3,
    .input = {
        .flow_type = RTE_ETH_FLOW_NONFRAG_IPV4_UDP,
        .flow = {
            .udp4_flow = {
                .ip = {
                    // .src_ip = 0x0000000A, 
                    .dst_ip = IPv4(0, 0, 16, 172),
                },
                // .src_port = rte_cpu_to_be_16(1024),
                // .dst_port = rte_cpu_to_be_16(1024),
            }
        }
    },
    .action = {
        .rx_queue = 1,
        .behavior = RTE_ETH_FDIR_ACCEPT,
        .report_status = RTE_ETH_FDIR_REPORT_ID,
    }
};

static struct rte_eth_fdir_filter fdir_filter_arp = {
    .soft_id = 4,
    .input = {
        .flow_type = RTE_ETH_FLOW_RAW,
        .flow = {
            .l2_flow = {
                .ether_type = 0x0608,
            }
        }
    },
    .action = {
        .rx_queue = 1,
        .behavior = RTE_ETH_FDIR_ACCEPT,
        .report_status = RTE_ETH_FDIR_REPORT_ID,
    }
};

static struct rte_eth_rss_reta_entry64 reta_conf[2];

static uint32_t manager_rx_queue_mask = 0x2;

static int enabled_port_mask = 0;

static struct rte_ring* nf_manager_ring;

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

struct ipv4_5tuple ip_5tuples[10000];
struct nf_states states[10000];

struct states_5tuple_pair {
    struct ipv4_5tuple l4_5tuple;
    struct nf_states states;
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
} single_port_param;

//share variables
struct rte_hash *state_hash_table[NB_SOCKETS];

//configurations
uint32_t dip_pool[DIP_POOL_SIZE]={
	IPv4(100,10,0,0),
	IPv4(100,10,0,1),
	IPv4(100,10,0,2),
	IPv4(100,10,0,3),
	IPv4(100,10,0,4),
};

static int counts = 0;

static void
convert_ipv4_5tuple(struct ipv4_5tuple *key1, union ipv4_5tuple_host *key2)
{
	key2->ip_dst = rte_cpu_to_be_32(key1->ip_dst);
	key2->ip_src = rte_cpu_to_be_32(key1->ip_src);
	key2->port_dst = rte_cpu_to_be_16(key1->port_dst);
	key2->port_src = rte_cpu_to_be_16(key1->port_src);
	key2->proto = key1->proto;
	key2->pad0 = 0;
	key2->pad1 = 0;
}


static void 
setStates(struct ipv4_5tuple *ip_5tuple, struct nf_states *state){
	union ipv4_5tuple_host newkey;
	convert_ipv4_5tuple(ip_5tuple, &newkey);
	int ret =  rte_hash_add_key_data(state_hash_table[0], &newkey, state);
	if (ret == 0)
	{
		printf("set success!\n");
	}
	else{
		printf("error found!\n");
		return;
	}
}

static int
getStates(struct ipv4_5tuple *ip_5tuple, struct nf_states ** state){
	union ipv4_5tuple_host newkey;
	convert_ipv4_5tuple(ip_5tuple, &newkey);
	int ret = rte_hash_lookup_data(state_hash_table[0], &newkey, (void **) state);
	if (ret == 0){
		printf("get success!\n");
	}
	if (ret == EINVAL){
		printf("parameter invalid\n");
	}
	if (ret == ENOENT){
		printf("key not found!\n");
	}
	return ret;
}

static inline int
rss_hash_set(uint32_t nb_nf_lcore, uint8_t port)
{
    unsigned int idx, i, j = 0;
	int retval;
    for (idx = 0; idx < 2; idx++) {
        reta_conf[idx].mask = ~0ULL;
        for (i = 0; i < RTE_RETA_GROUP_SIZE; i++, j++) {
            if (j == nb_nf_lcore)
                j = 0;
            reta_conf[idx].reta[i] = j;
        }
    }
    retval = rte_eth_dev_rss_reta_update(port, reta_conf, 128);
    return retval;
}

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */
static inline int
port_init(uint8_t port, struct rte_mempool *mbuf_pool, 
 		struct rte_mempool *manager_mbuf_pool)
{
	if ((enabled_port_mask & (1 << port)) == 0) {
		printf("Skipping disabled port %d\n", port);
		return 1;
	}

	struct rte_eth_conf port_conf = port_conf_default;
	const uint16_t rx_rings = 2, tx_rings = 1;
	uint16_t nb_rxd = RX_RING_SIZE;
	uint16_t nb_txd = TX_RING_SIZE;//64k
	int retval;
	uint16_t q;

	if (port >= rte_eth_dev_count())
		return -1;

	/* Configure the Ethernet device. */
	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
	if (retval != 0)
		return retval;

	/* Allocate and set up 2 RX queue per Ethernet port. */
	for (q = 0; q < rx_rings; q++) {
		if (((manager_rx_queue_mask >> q) & 1) == 1)
			retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
					rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		else
			retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
					rte_eth_dev_socket_id(port), NULL, manager_mbuf_pool);
		if (retval < 0)
			return retval;
		printf("Init queue %d for port %d\n", q, port);
	}

	/* Allocate and set up 1 TX queue per Ethernet port. */
	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, nb_txd,
				rte_eth_dev_socket_id(port), NULL);
		if (retval < 0)
			return retval;
	}

	/* Start the Ethernet port. */
	retval = rte_eth_dev_start(port);
	if (retval < 0)
		return retval;

    /* Set FlowDirector flow filter on port */
    retval = rte_eth_dev_filter_ctrl(port, RTE_ETH_FILTER_FDIR, 
                                       RTE_ETH_FILTER_ADD, &fdir_filter_state);
    if (retval < 0)
        return retval;
    // fdir_filter_ecmp.input.flow.tcp4_flow.src_port = rte_cpu_to_be_16(0),
    // fdir_filter_ecmp.input.flow.tcp4_flow.dst_port = rte_cpu_to_be_16(0),
    retval = rte_eth_dev_filter_ctrl(port, RTE_ETH_FILTER_FDIR, 
                                        RTE_ETH_FILTER_ADD, &fdir_filter_ecmp_tcp);
    if (retval < 0)
        return retval;
    retval = rte_eth_dev_filter_ctrl(port, RTE_ETH_FILTER_FDIR, 
                                        RTE_ETH_FILTER_ADD, &fdir_filter_ecmp_udp);
    if (retval < 0)
        return retval;
    retval = rte_eth_dev_filter_ctrl(port, RTE_ETH_FILTER_FDIR, 
  					 				 RTE_ETH_FILTER_ADD, &fdir_filter_arp);
    if (retval < 0)
        return retval;
    struct rte_eth_fdir_info fdir_info;
    retval = rte_eth_dev_filter_ctrl(port, RTE_ETH_FILTER_FDIR, 
  					 				 RTE_ETH_FILTER_INFO, &fdir_info);
    if (retval < 0)
        return retval;
    unsigned int j;
    for (j = 0; j < RTE_FLOW_MASK_ARRAY_SIZE; j++)
        printf("flow_types_mask[%d]: %08x\n", j, fdir_info.flow_types_mask[j]);

    /* Set hash array of RSS */
    retval = rss_hash_set(1, port);
	if (retval < 0)
		return retval;

	/* Display the port MAC address. */
	struct ether_addr addr;
	rte_eth_macaddr_get(port, &addr);
	printf("Port %u MAC: %02" PRIx8 ":%02" PRIx8 ":%02" PRIx8
			   ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 "\n",
			(unsigned)port,
			addr.addr_bytes[0], addr.addr_bytes[1],
			addr.addr_bytes[2], addr.addr_bytes[3],
			addr.addr_bytes[4], addr.addr_bytes[5]);

	/* Enable RX in promiscuous mode for the Ethernet device. */
	rte_eth_promiscuous_enable(port);

	return 0;
}

static void
print_ethaddr(const char *name, struct ether_addr *eth_addr)
{
	char buf[ETHER_ADDR_FMT_SIZE];
	ether_format_addr(buf, ETHER_ADDR_FMT_SIZE, eth_addr);
	printf("%s is %s\n", name, buf);
}

/* display usage */
static void
print_usage(const char *prgname)
{
	printf("%s [EAL options] -- -p PORTMASK [-q NQ]\n"
	       "  -p PORTMASK: hexadecimal bitmask of ports to configure\n",
	       prgname);
}

static int
parse_portmask(const char *portmask)
{
	char *end = NULL;
	unsigned long pm;

	/* parse hexadecimal string */
	pm = strtoul(portmask, &end, 16);
	if ((portmask[0] == '\0') || (end == NULL) || (*end != '\0'))
		return -1;

	if (pm == 0)
		return -1;

	return pm;
}

/* Parse the argument given in the command line of the application */
static int
parse_args(int argc, char **argv)
{
	int opt, ret;
	char **argvopt;
	int option_index;
	char *prgname = argv[0];
	static struct option lgopts[] = {
		{NULL, 0, 0, 0}
	};

	argvopt = argv;

	while ((opt = getopt_long(argc, argvopt, "p:",
				  lgopts, &option_index)) != EOF) {

		switch (opt) {
		/* portmask */
		case 'p':
			enabled_port_mask = parse_portmask(optarg);
			if (enabled_port_mask < 0) {
				printf("invalid portmask\n");
				print_usage(prgname);
				return -1;
			}
			break;

		/* long options */
		case 0:
			print_usage(prgname);
			return -1;

		default:
			print_usage(prgname);
			return -1;
		}
	}

	if (enabled_port_mask == 0) {
		printf("portmask not specified\n");
		print_usage(prgname);
		return -1;
	}

	if (optind >= 0)
		argv[optind-1] = prgname;

	ret = optind-1;
	optind = 1; /* reset getopt lib */
	return ret;
}

static void
check_all_ports_link_status(uint8_t port_num, uint32_t port_mask)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90 /* 9s (90 * 100ms) in total */
	uint8_t portid, count, all_ports_up, print_flag = 0;
	struct rte_eth_link link;

	printf("\nChecking link status");
	fflush(stdout);
	for (count = 0; count <= MAX_CHECK_TIME; count++) {
		all_ports_up = 1;
		for (portid = 0; portid < port_num; portid++) {
			if ((port_mask & (1 << portid)) == 0)
				continue;
			memset(&link, 0, sizeof(link));
			rte_eth_link_get_nowait(portid, &link);
			/* print link status if flag set */
			if (print_flag == 1) {
				if (link.link_status)
					printf("Port %d Link Up - speed %u "
						"Mbps - %s\n", (uint8_t)portid,
						(unsigned)link.link_speed,
				(link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
					("full-duplex") : ("half-duplex\n"));
				else
					printf("Port %d Link Down\n",
							(uint8_t)portid);
				continue;
			}
			/* clear all_ports_up flag if any link down */
			if (link.link_status == ETH_LINK_DOWN) {
				all_ports_up = 0;
				break;
			}
		}
		/* after finally printing all link status, get out */
		if (print_flag == 1)
			break;

		if (all_ports_up == 0) {
			printf(".");
			fflush(stdout);
			rte_delay_ms(CHECK_INTERVAL);
		}

		/* set the print_flag if all ports up or timeout */
		if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
			print_flag = 1;
			printf("\ndone\n");
		}
	}
}

static inline uint32_t
ipv4_hash_crc(const void *data, __rte_unused uint32_t data_len,
		uint32_t init_val)
{
	const union ipv4_5tuple_host *k;
	uint32_t t;
	const uint32_t *p;

	k = data;
	t = k->proto;
	p = (const uint32_t *)&k->port_src;

#ifdef EM_HASH_CRC
	//printf("em-hash-crc\n");
	init_val = rte_hash_crc_4byte(t, init_val);
	init_val = rte_hash_crc_4byte(k->ip_src, init_val);
	init_val = rte_hash_crc_4byte(k->ip_dst, init_val);
	init_val = rte_hash_crc_4byte(*p, init_val);
#else
	//printf("not em-hash-crc\n");
	init_val = rte_jhash_1word(t, init_val);
	init_val = rte_jhash_1word(k->ip_src, init_val);
	init_val = rte_jhash_1word(k->ip_dst, init_val);
	init_val = rte_jhash_1word(*p, init_val);
#endif

	//printf("init_val = %u\n", init_val);
	return init_val;
}

static void
setup_hash(const int socketid)
{
	struct rte_hash_parameters hash_params = {
		.name = NULL,
		.entries = HASH_ENTRIES,
		.key_len = sizeof(union ipv4_5tuple_host),
		.hash_func = ipv4_hash_crc,
		.hash_func_init_val = 0,
	};
	char s[64];
	snprintf(s, sizeof(s), "ipv4_hash_%d", socketid);
	hash_params.name = s;
	hash_params.socket_id = socketid;
	state_hash_table[socketid] =
		rte_hash_create(&hash_params);

	if (state_hash_table[socketid] == NULL)
		rte_exit(EXIT_FAILURE,
			"Unable to create the hash on socket %d\n",
			socketid);
	printf("setup hash_table %s\n", s);
}

/*
 * gateway network funtions.
 */
static int
lcore_nf(__attribute__((unused)) void *arg)
{
	const uint8_t nb_ports = rte_eth_dev_count();
	uint8_t port;
	int i;

	for (port = 0; port < nb_ports; port++)
		if (rte_eth_dev_socket_id(port) > 0 &&
				rte_eth_dev_socket_id(port) !=
						(int)rte_socket_id())
			printf("WARNING, port %u is on remote NUMA node to "
					"polling thread.\n\tPerformance will "
					"not be optimal.\n", port);

	printf("\nCore %u processing packets.\n",
			rte_lcore_id());

	/* Run until the application is quit or killed. */
	for (;;) {
		for (port = 0; port < nb_ports; port++) {
			if ((enabled_port_mask & (1 << port)) == 0) {
				//printf("Skipping %u\n", port);
				continue;
			}

			struct rte_mbuf *bufs[BURST_SIZE];
			const uint16_t nb_rx = rte_eth_rx_burst(port, 0,
					bufs, BURST_SIZE);

			if (unlikely(nb_rx == 0))
				continue;	
			
						
			for (i = 0; i < nb_rx; i ++){
				printf("packet comes from %u\n", port);

				struct ether_hdr *eth_hdr;
				eth_hdr = rte_pktmbuf_mtod(bufs[i], struct ether_hdr *);
				struct ether_addr eth_s_addr;
				eth_s_addr = eth_hdr->s_addr;
				struct ether_addr eth_d_addr;
				eth_d_addr = eth_hdr->d_addr;

				print_ethaddr("eth_s_addr", &eth_s_addr);
				print_ethaddr("eth_d_addr", &eth_d_addr);

				struct ipv4_5tuple ip_5tuple;
				struct ipv4_hdr *ip_hdr = (struct ipv4_hdr*)((char*)eth_hdr + sizeof(struct ether_hdr));

				ip_5tuple.ip_dst = rte_be_to_cpu_32(ip_hdr->dst_addr);
				ip_5tuple.ip_src = rte_be_to_cpu_32(ip_hdr->src_addr);
				ip_5tuple.proto = ip_hdr->next_proto_id;

				printf("ip_dst is "IPv4_BYTES_FMT " \n", IPv4_BYTES(ip_5tuple.ip_dst));
				printf("ip_src is "IPv4_BYTES_FMT " \n", IPv4_BYTES(ip_5tuple.ip_src));
				printf("next_proto_id is %u\n", ip_5tuple.proto);
				
				if (ip_5tuple.proto == 17){
					struct udp_hdr * upd_hdrs = (struct udp_hdr*)((char*)ip_hdr + sizeof(struct ipv4_hdr));
					ip_5tuple.port_src = rte_be_to_cpu_16(upd_hdrs->src_port);
					ip_5tuple.port_dst = rte_be_to_cpu_16(upd_hdrs->dst_port);
				}
				else if (ip_5tuple.proto == 6){
					struct tcp_hdr * tcp_hdrs = (struct tcp_hdr*)((char*)ip_hdr + sizeof(struct ipv4_hdr));
					ip_5tuple.port_src = rte_be_to_cpu_16(tcp_hdrs->src_port);
					ip_5tuple.port_dst = rte_be_to_cpu_16(tcp_hdrs->dst_port);
					printf("tcp_flags is %u\n", tcp_hdrs->tcp_flags);
					if (tcp_hdrs->tcp_flags == 2){
						states[counts].ipserver = dip_pool[counts % DIP_POOL_SIZE];
						setStates(&ip_5tuple, &states[counts]);
						ip_hdr->dst_addr = rte_cpu_to_be_32(states[counts].ipserver);
						printf("new_ip_dst is "IPv4_BYTES_FMT " \n", IPv4_BYTES(rte_be_to_cpu_32(ip_hdr->dst_addr)));
						//communicate with Manager
						ip_5tuples[counts] = ip_5tuple;
						printf("ip_5tuples.ip_dst, ip_src, next_proto_id, port_dst and port_src is "IPv4_BYTES_FMT " , "IPv4_BYTES_FMT " , %u, %u, and %u\n", 
							IPv4_BYTES(ip_5tuples[counts].ip_dst), IPv4_BYTES(ip_5tuples[counts].ip_src), ip_5tuples[counts].proto, 
							ip_5tuples[counts].port_dst, ip_5tuples[counts].port_src);
						if (rte_ring_enqueue(nf_manager_ring, &ip_5tuples[counts]) == 0) {
							printf("enqueue success!\n");
						}
						else{
							printf("enqueu failed!!!\n");
						}
						const uint16_t nb_tx = rte_eth_tx_burst(port, 0, &bufs[i], 1);
						rte_pktmbuf_free(bufs[i]);
						counts ++;
					}
					else{
						struct nf_states *state;
						int ret =  getStates(&ip_5tuple, &state);
						//printf("%x\n", state);
						//printf("the value of states is %u XXXXXXXXXXXXXXXXXXXXx\n", state->ipserver);
						if (ret == ENOENT){
							printf("if\n");
							//getIndex();
							//if else
						}
						else{
							printf("else!\n");
							ip_hdr->dst_addr = rte_cpu_to_be_32(state->ipserver);
							printf("new_ip_dst is "IPv4_BYTES_FMT " \n", IPv4_BYTES(rte_be_to_cpu_32(ip_hdr->dst_addr)));
							const uint16_t nb_tx = rte_eth_tx_burst(port, 0, &bufs[i], 1);
							rte_pktmbuf_free(bufs[i]);
						}
						
					}
					printf("port_src and port_dst is %u and %u\n", ip_5tuple.port_src, ip_5tuple.port_dst);
				}
				printf("\n");
			}

		}
	}
	return 0;
}

/*
 * gateway manager.
 */
static int
lcore_manager(__attribute__((unused)) void *arg)
{
	const uint8_t nb_ports = rte_eth_dev_count();
	uint8_t port;
	int i;
    struct ether_hdr* eth_h;
    struct ipv4_hdr* ip_h;
	// uint16_t eth_type;
	uint8_t ip_proto;
    u_char* payload;
    struct states_5tuple_pair* backup_pair;
    struct rte_mbuf* backup_packet;

	printf("\nCore %u manage states in gateway.\n",
			rte_lcore_id());

	/* Run until the application is quit or killed. */
	for (;;) {
		for (port = 0; port < nb_ports; port++) {
			if ((enabled_port_mask & (1 << port)) == 0) {
				//printf("Skipping %u\n", port);
				continue;
			}

			struct rte_mbuf *bufs[BURST_SIZE];
			const uint16_t nb_rx = rte_eth_rx_burst(port, 1,
					bufs, BURST_SIZE);

			if (unlikely(nb_rx == 0))
				continue;

 			if (rte_ring_dequeue(nf_manager_ring, (void**)&backup_pair) == 0) {
  			    // build_probe_packet();
			    rte_eth_tx_burst(port, 0, &probing_packet, 1);
  			}

			for (i = 0; i < nb_rx; i ++){
				printf("packet comes from port %u queue 1\n", port);
				eth_h = rte_pktmbuf_mtod(bufs[i], struct ether_hdr *);
				// eth_type = eth_h->ether_type;

 				// if (eth_type == rte_be_to_cpu_16(ETHER_TYPE_ARP)) {
  				//     /* ARP message to keep live with switch */
   				//     struct arp_hdr* arp_h;
   				//     struct ether_addr self_eth_addr;
   				//     uint32_t ip_addr;
  				//     arp_h = (struct arp_hdr*)
  				//     		((u_char*)eth_h + sizeof(struct ether_hdr));
  				//     rte_eth_macaddr_get(port, &self_eth_addr);
  				//     ether_addr_copy(&(eth_h->s_addr), &(eth_h->d_addr));
  				//     ether_addr_copy(&(eth_h->s_addr), &interface_MAC);
  				//     /* Set source MAC address with MAC of TX Port */
  				//     ether_addr_copy(&self_eth_addr, &(eth_h->s_addr));
  				//     arp_h->arp_op = rte_cpu_to_be_16(ARP_OP_REPLY);
  				//     ether_addr_copy(&(arp_h->arp_data.arp_sha)
   				//     			, &(arp_h->arp_data.arp_tha));
  				//     ether_addr_copy(&(eth_h->s_addr)
   				//     			, &(arp_h->arp_data.arp_sha));
  				//     /* Swap IP address in ARP payload */
  				//     ip_addr = arp_h->arp_data.arp_sip;
  				//     arp_h->arp_data.arp_sip = arp_h->arp_data.arp_tip;
  				//     arp_h->arp_data.arp_tip = ip_addr;
  				//     printf("This is ARP message\n");
  				// }
 				// else if (eth_type == rte_be_to_cpu_16(ETHER_TYPE_IPv4)) {
  				// }

				ip_h = (struct ipv4_hdr*)
  				  		((u_char*)eth_h + sizeof(struct ether_hdr));
				ip_proto = ip_h->next_proto_id;

 				if (ip_proto == 0x06 || ip_proto == 0x11) {
  				    /* Control message about ECMP */
  				    if ((ip_h->dst_addr & 0x00FF0000) == (0xFD << 16)) {
  				        /* Destination ip is 172.16.253.X */
  				        /* This is ECMP predict request message */
  				        backup_receive_probe_packet(bufs[i]);
  				        rte_eth_tx_burst(port, 0, &probing_packet, 1);
					// rte_pktmbuf_free(bufs[buf]);
  				        printf("This is ECMP predict request message\n");
   				    }
  				    else if ((ip_h->dst_addr & 0x00FF0000) == 0) {
  				        /* Destination ip is 172.16.0.X */
  				        /* This is ECMP predict reply message */
  				        // ecmp_receive_reply(bufs[i]);
   				        struct ether_addr self_eth_addr;
  				        uint32_t backup_no = master_receive_probe_reply(bufs[i]);
  				        printf("This is ECMP pedict reply message\n");
  				        backup_packet = rte_pktmbuf_alloc(single_port_param.manager_mempool);
  				        /* Allocate space */
  				        eth_h = (struct ether_hdr *)rte_pktmbuf_append(backup_packet, sizeof(struct ether_hdr));
  				        ip_h = (struct ipv4_hdr *)rte_pktmbuf_append(backup_packet, sizeof(struct ipv4_hdr));
  				        payload = (u_char*)rte_pktmbuf_append(backup_packet, sizeof(struct states_5tuple_pair));
  				        /* Set the packet */
  				        eth_h->ether_type =  rte_cpu_to_be_16(ETHER_TYPE_IPv4);
  				        ether_addr_copy(&interface_MAC, &(eth_h->d_addr));
  				        rte_eth_macaddr_get(port, &self_eth_addr);
  				        ether_addr_copy(&self_eth_addr, &(eth_h->s_addr));
  				        memset((char *)ip_h, 0, sizeof(struct ipv4_hdr));
  				        ip_h->src_addr=rte_cpu_to_be_32(MACHINE_IP);
  				        ip_h->dst_addr=rte_cpu_to_be_32(IPv4(172, 16, 0, 2));
  				        ip_h->version_ihl = (4 << 4) | 5;
  				        ip_h->total_length = rte_cpu_to_be_16(20 + sizeof(struct states_5tuple_pair));
  				        ip_h->packet_id= 0x36;/* NO USE */
  				        ip_h->time_to_live=4;
  				        ip_h->next_proto_id = 0x0;
  				        printf("Debug backup no %d\n", backup_no);
  				        ip_h->hdr_checksum = rte_ipv4_cksum(ip_h);
   				        backup_pair = (struct states_5tuple_pair*)payload;
   				        backup_pair->l4_5tuple.ip_src = IPv4(10, 0 , 0, 1);
   				        backup_pair->l4_5tuple.ip_dst = IPv4(10, 0 , 0, 2);
   				        backup_pair->l4_5tuple.port_src = 0x68;
   				        backup_pair->l4_5tuple.port_dst = 0x86;
   				        backup_pair->l4_5tuple.proto = 0x8;
   				        backup_pair->states.ipserver = IPv4(10, 0, 0, 3);
   				        backup_pair->states.dip = IPv4(10, 0, 0, 4);
   				        backup_pair->states.dport = 0x36;
   				        backup_pair->states.bip = IPv4(10, 0, 0, 5);
  				        rte_eth_tx_burst(port, 0, &backup_packet, 1);
   				    }
  				}
 				else if (ip_h->next_proto_id == 0) {
  				    /* Control message about state */
   				    if ((ip_h->dst_addr & 0xFF000000) == (255U << 24)) {
   				        /* Destination ip is 172.16.0.255 */
   				        /* This is flow broadcast message */
    			        printf("This is flow broadcast message\n");
   				    }
  				    else if ((ip_h->dst_addr & 0x00FF0000) == 0) {
  				        /* Destination ip is 172.16.0.X */
  				        /* This is state backup message */
  				        printf("This is state backup message\n");
   				        payload = (u_char*)ip_h + ((ip_h->version_ihl)&0x0F)*4;
   				        backup_pair = (struct states_5tuple_pair*)payload;
				        printf("ip_src is "IPv4_BYTES_FMT " \n", IPv4_BYTES(backup_pair->l4_5tuple.ip_src));
				        printf("ip_dst is "IPv4_BYTES_FMT " \n", IPv4_BYTES(backup_pair->l4_5tuple.ip_dst));
				        printf("port_src is %d\n", backup_pair->l4_5tuple.port_src);
				        printf("port_dst is %d\n", backup_pair->l4_5tuple.port_dst);
				        printf("proto is %d\n", backup_pair->l4_5tuple.proto);
				        printf("ip_server is "IPv4_BYTES_FMT " \n", IPv4_BYTES(backup_pair->states.ipserver));
				        printf("dip is "IPv4_BYTES_FMT " \n", IPv4_BYTES(backup_pair->states.dip));
				        printf("dport is %d\n", backup_pair->states.dip);
				        printf("dip is "IPv4_BYTES_FMT " \n", IPv4_BYTES(backup_pair->states.bip));
   				        setStates(&(backup_pair->l4_5tuple), &(backup_pair->states));
   				        printf("payload is %s\n", payload);
   				    }
  				}
				printf("\n");
			}

			/* Free any unsent packets. */
			// if (unlikely(nb_tx < nb_rx)) {
				// uint16_t buf;
				// for (buf = nb_tx; buf < nb_rx; buf++)
					// rte_pktmbuf_free(bufs[buf]);
			// }
		}
	}
	return 0;
}

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int
main(int argc, char *argv[])
{
	struct rte_mempool *mbuf_pool;
	struct rte_mempool *manager_mbuf_pool;
	unsigned nb_ports, lcore_id;
	uint8_t portid;

	/* Initialize the Environment Abstraction Layer (EAL). */
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

	argc -= ret;
	argv += ret;

	/* parse application arguments (after the EAL ones) */
	ret = parse_args(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid arguments\n");

	nb_ports = rte_eth_dev_count();
	if (nb_ports == 0)
		rte_exit(EXIT_FAILURE, "Error: no ports found\n");

	/* Creates a new mempool in memory to hold the mbufs. */
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
		MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	manager_mbuf_pool = rte_pktmbuf_pool_create("MANAGER_MBUF_POOL", 
		NUM_MANAGER_MBUFS, MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, 
 		rte_socket_id());
	if (manager_mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

    single_port_param.nf_mempool = mbuf_pool;
    single_port_param.manager_mempool = manager_mbuf_pool;

	setup_hash((int)rte_socket_id());//now is a single socket version

	/* check if portmask has non-existent ports */
	if (enabled_port_mask & ~(RTE_LEN2MASK(nb_ports, unsigned)))
		rte_exit(EXIT_FAILURE, "Non-existent ports in portmask!\n");

	/* Initialize all ports. */
	for (portid = 0; portid < nb_ports; portid++)
		if (port_init(portid, mbuf_pool, manager_mbuf_pool) == 0)
			printf("Initialize port %u, finshed!\n", portid);
		else 
			printf("Initialize port %u, failed!\n", portid);
    
    /* Initialize about ECMP by QiaoYi */
    ecmp_predict_init(manager_mbuf_pool);

    /* Create and initialize ring between nf and manager */
    nf_manager_ring = rte_ring_create("NF_MANAGER_RING", RX_RING_SIZE, 
     				   				  rte_socket_id(), 
      				   				  RING_F_SP_ENQ | RING_F_SC_DEQ);
	if (nf_manager_ring == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create ring between nf and manager\n");

	check_all_ports_link_status((uint8_t)nb_ports, enabled_port_mask);

	RTE_LCORE_FOREACH_SLAVE(lcore_id) {
		rte_eal_remote_launch(lcore_nf, NULL, lcore_id);
	}

	lcore_manager(NULL);

	rte_eal_mp_wait_lcore();

	return 0;
}
