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

#define RX_RING_SIZE 128
#define TX_RING_SIZE 512

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32
#define MAX_RX_QUEUE_PER_LCORE 16
#define DIP_MAX 10000001

#ifndef IPv4_BYTES
#define IPv4_BYTES_FMT "%" PRIu8 ".%" PRIu8 ".%" PRIu8 ".%" PRIu8
#define IPv4_BYTES(addr) \
		(uint8_t) (((addr) >> 24) & 0xFF),\
		(uint8_t) (((addr) >> 16) & 0xFF),\
		(uint8_t) (((addr) >> 8) & 0xFF),\
		(uint8_t) ((addr) & 0xFF)
#endif

static const struct rte_eth_conf port_conf_default = {
	.rxmode = {
        .max_rx_pkt_len = ETHER_MAX_LEN
    }, //1518
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
        .drop_queue = 127,
        .mask = {
            .vlan_tci_mask = 0x0,
            .ipv4_mask = {
                .src_ip = 0xFFFFFFFF,
                .dst_ip = 0xFFFFFFFF,
            },
            .ipv6_mask = {
                .src_ip = {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF},
                .dst_ip = {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF},
            },
            .src_port_mask = 0xFFFF,
            .dst_port_mask = 0xFFFF,
            .mac_addr_byte_mask = 0xFF,
            .tunnel_type_mask = 1,
            .tunnel_id_mask = 0xFFFFFFFF,
        },
    },
};

static const struct rte_eth_fdir_filter fdir_filter_arg = {
    .soft_id = 1,
    .input = {
        .flow_type = RTE_ETH_FLOW_NONFRAG_IPV4_UDP,
        .flow = {
            .udp4_flow = {
                .ip = {
                    .src_ip = 0x03020202,
                    .dst_ip = 0x05020202,
                }
                .src_port = rte_cpu_to_be_16(1024),
                .dst_port = rte_cpu_to_be_16(1024),
            }
        }
    }
    .action = {
        .rx_queue = 1,
        .behavior = RTE_ETH_FDIR_ACCEPT,
        .report_status = RTE_ETH_FDIR_REPORT_ID,
    }

};

static rte_eth_rss_reta_entry64 reta_conf[2];

static int enabled_port_mask = 0;

struct ipv4_5tuple {
	uint32_t ip_dst;
	uint32_t ip_src;
	uint16_t port_dst;
	uint16_t port_src;
	uint8_t  proto;
} __rte_cache_aligned;
struct ipv4_5tuple ipv4_5tuples;

//share variables
uint32_t dip[DIP_MAX];

static inline void state_set(void){
	dip[0] = 1;
	//just an example
}

static inline uint32_t state_get(void){
	return dip[0];
}

static inline int
rss_hash_set(uint32_t nb_nf_lcore, uint8_t port)
{
    int idx, i, j = 0;
    for (idx = 0; i < 2; idx++) {
        reta_conf[idx].mask = ~0ULL;
        for (i = 0; i < RTE_RETA_GROUP_SIZE; i++, j++) {
            if (j == nb_nf_lcore)
                j = 0;
            reta_conf[i] = j;
        }
    }
    rte_eth_dev_rss_reta_query(port, reta_conf, 128);
}

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */
static inline int
port_init(uint8_t port, struct rte_mempool *mbuf_pool)
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

	/* Allocate and set up 1 RX queue per Ethernet port. */
	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
				rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
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
    rte_eth_dev_filter_ctrl(port, RTE_ETH_FILTER_FDIR, 
                            RTE_ETH_FILTER_ADD, &fdir_filter_arg);

    /* Set hash array of RSS */
    rss_hash_set(uint32_t nb_nf_lcore, uint8_t port);

	/* Display the port MAC address. */
	struct ether_addr addr;
	rte_eth_macaddr_get(port, &addr);
	printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
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

			
			const uint16_t nb_tx = rte_eth_tx_burst(port , 0, bufs, nb_rx);

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

				rte_pktmbuf_adj(bufs[i], (uint16_t)sizeof(struct ether_hdr));
				struct ipv4_hdr *ip_hdr;
				uint32_t ip_dst;
				uint32_t ip_src;
				ip_hdr = rte_pktmbuf_mtod(bufs[i], struct ipv4_hdr *);
				ip_dst = rte_be_to_cpu_32(ip_hdr->dst_addr);
				ip_src = rte_be_to_cpu_32(ip_hdr->src_addr);
				printf("ip_dst is "IPv4_BYTES_FMT " \n", IPv4_BYTES(ip_dst));
				printf("ip_src is "IPv4_BYTES_FMT " \n", IPv4_BYTES(ip_src));
				printf("\n");

				//parse tcp/udp

			}

			/* Free any unsent packets. */
			if (unlikely(nb_tx < nb_rx)) {
				uint16_t buf;
				for (buf = nb_tx; buf < nb_rx; buf++)
					rte_pktmbuf_free(bufs[buf]);
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
	printf("\nCore %u manage states in gateway.\n",
			rte_lcore_id());
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

	/* check if portmask has non-existent ports */
	if (enabled_port_mask & ~(RTE_LEN2MASK(nb_ports, unsigned)))
		rte_exit(EXIT_FAILURE, "Non-existent ports in portmask!\n");

	/* Initialize all ports. */
	for (portid = 0; portid < nb_ports; portid++)
		if (port_init(portid, mbuf_pool) == 0)//use mbuf_pool to cache RX/TX
			printf("Initialize port %u, finshed!\n", portid);

	RTE_LCORE_FOREACH_SLAVE(lcore_id) {
		rte_eal_remote_launch(lcore_nf, NULL, lcore_id);
	}

	lcore_manager(NULL);

	rte_eal_mp_wait_lcore();

	return 0;
}
