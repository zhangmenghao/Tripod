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

#include "main.h"

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

//configurations
uint32_t dip_pool[DIP_POOL_SIZE]={
	IPv4(100,10,0,0),
	IPv4(100,10,0,1),
	IPv4(100,10,0,2),
	IPv4(100,10,0,3),
	IPv4(100,10,0,4),
};

struct rte_ring* nf_manager_ring;
struct rte_ring* nf_pull_wait_ring;

struct port_param single_port_param;

int enabled_port_mask = 0;

static struct rte_eth_rss_reta_entry64 reta_conf[2];

static uint32_t manager_rx_queue_mask = 0x2;

uint32_t statelessBackupIP = IPv4(172,16,4,2);

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

void
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
	snprintf(s, sizeof(s), "ipv4_state_hash_%d", socketid);
	hash_params.name = s;
	hash_params.socket_id = socketid;
	state_hash_table[socketid] =
		rte_hash_create(&hash_params);

	struct rte_hash_parameters hash_paramss = {
		.name = NULL,
		.entries = HASH_ENTRIES,
		.key_len = sizeof(union ipv4_5tuple_host),
		.hash_func = ipv4_hash_crc,
		.hash_func_init_val = 0,
	};
	char ss[64];
	snprintf(ss, sizeof(ss), "ipv4_index_hash_%d", socketid);
	hash_paramss.name = ss;
	hash_paramss.socket_id = socketid;
	index_hash_table[socketid] =
		rte_hash_create(&hash_paramss);

	if (state_hash_table[socketid] == NULL||index_hash_table[socketid] == NULL)
		rte_exit(EXIT_FAILURE,
			"Unable to create the hash on socket %d\n",
			socketid);
    #ifdef __DEBUG_LV1
	printf("setup hash_table for state and index %s\n", s);
    #endif
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
int
port_init(uint8_t port, struct rte_mempool *mbuf_pool, 
 		struct rte_mempool *manager_mbuf_pool)
{
	if ((enabled_port_mask & (1 << port)) == 0) {
		#ifdef __DEBUG_LV1
		printf("Skipping disabled port %d\n", port);
		#endif
		return 1;
	}

	struct rte_eth_conf port_conf = port_conf_default;
	const uint16_t rx_rings = 2, tx_rings = 1;
	uint16_t nb_rxd = RX_RING_SIZE;
	uint16_t nb_txd = TX_RING_SIZE;
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
		#ifdef __DEBUG_LV1
		printf("Init queue %d for port %d\n", q, port);
		#endif
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
        #ifdef __DEBUG_LV2
        printf("flow_types_mask[%d]: %08x\n", j, fdir_info.flow_types_mask[j]);
        #endif

    /* Set hash array of RSS */
    retval = rss_hash_set(1, port);
	if (retval < 0)
		return retval;

	/* Display the port MAC address. */
	struct ether_addr addr;
	rte_eth_macaddr_get(port, &addr);
    #ifdef __DEBUG_LV1
	printf("Port %u MAC: %02" PRIx8 ":%02" PRIx8 ":%02" PRIx8
			   ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 "\n",
			(unsigned)port,
			addr.addr_bytes[0], addr.addr_bytes[1],
			addr.addr_bytes[2], addr.addr_bytes[3],
			addr.addr_bytes[4], addr.addr_bytes[5]);
    #endif

	/* Enable RX in promiscuous mode for the Ethernet device. */
	rte_eth_promiscuous_enable(port);

	return 0;
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
int
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

void
check_all_ports_link_status(uint8_t port_num, uint32_t port_mask)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90 /* 9s (90 * 100ms) in total */
	uint8_t portid, count, all_ports_up, print_flag = 0;
	struct rte_eth_link link;

    #ifdef __DEBUG_LV1
	printf("\nChecking link status");
	fflush(stdout);
    #endif
	for (count = 0; count <= MAX_CHECK_TIME; count++) {
		all_ports_up = 1;
		for (portid = 0; portid < port_num; portid++) {
			if ((port_mask & (1 << portid)) == 0)
				continue;
			memset(&link, 0, sizeof(link));
			rte_eth_link_get_nowait(portid, &link);
			/* print link status if flag set */
			if (print_flag == 1) {
				if (link.link_status) {
					#ifdef __DEBUG_LV1
					printf("Port %d Link Up - speed %u "
						"Mbps - %s\n", (uint8_t)portid,
						(unsigned)link.link_speed,
				(link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
					("full-duplex") : ("half-duplex\n"));
					#endif
				}
				else {
					#ifdef __DEBUG_LV1
					printf("Port %d Link Down\n",
							(uint8_t)portid);
					#endif
				}
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
			#ifdef __DEBUG_LV1
			printf(".");
			fflush(stdout);
			#endif
			rte_delay_ms(CHECK_INTERVAL);
		}

		/* set the print_flag if all ports up or timeout */
		if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
			print_flag = 1;
			#ifdef __DEBUG_LV1
			printf("\ndone\n");
			#endif
		}
	}
}

int 
lcore_main_loop(__attribute__((unused)) void *arg)
{
    unsigned lcore;

    lcore = rte_lcore_id();
    if (lcore == 1)
        lcore_nf(NULL);
    else if (lcore == 2)
        lcore_manager_slave(NULL);
    else
        lcore_manager(NULL);
}
