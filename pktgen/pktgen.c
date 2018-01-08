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
#include <unistd.h>
#include <stdint.h>
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_arp.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_byteorder.h>
#include <rte_cycles.h>
#include <rte_timer.h>
#define RX_RING_SIZE 512
#define TX_RING_SIZE 512

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32


#define RTE_BE_TO_CPU_16(be_16_v)  rte_be_to_cpu_16((be_16_v))

#ifndef IPv4_BYTES
#define IPv4_BYTES_FMT "%" PRIu8 ".%" PRIu8 ".%" PRIu8 ".%" PRIu8
#define IPv4_BYTES(addr) \
		(uint8_t) (((addr) >> 24) & 0xFF),\
		(uint8_t) (((addr) >> 16) & 0xFF),\
		(uint8_t) (((addr) >> 8) & 0xFF),\
		(uint8_t) ((addr) & 0xFF)
#endif
#define TIMER_RESOLUTION_CYCLES 2399987461ULL
#define N_TEST_FLOWS 50

int arped = 0;
int count = 0;
static const struct rte_eth_conf port_conf_default = {
	.rxmode = { .max_rx_pkt_len = ETHER_MAX_LEN,
		    .hw_ip_checksum = 0 }
};

unsigned long long rx_byte = 0;
unsigned long long tx_byte = 0;
unsigned long long last_rx_byte = 0;
unsigned long long last_tx_byte = 0;

unsigned long long rx_pkts = 0;
unsigned long long tx_pkts = 0;
unsigned long long last_rx_pkts = 0;
unsigned long long last_tx_pkts = 0;

static struct rte_timer timer;

static uint64_t prev_tsc = 0, cur_tsc , diff_tsc;

struct ether_addr interface_MAC = {
    .addr_bytes[0] = 0x48,
    .addr_bytes[1] = 0x6E,
    .addr_bytes[2] = 0x73,
    .addr_bytes[3] = 0x00,
    .addr_bytes[4] = 0x04,
    .addr_bytes[5] = 0xDB,
};

struct rte_mbuf* syn_pkts[N_TEST_FLOWS];
struct rte_mbuf* data_pkts[N_TEST_FLOWS];


static void
timer_cb( __attribute__((unused)) struct rte_timer *tim, __attribute__((unused)) void *arg)
{

	printf("rx_throughput: %llu Mbps, tx_throughput: %llu Mbps\n",(rx_byte - last_rx_byte)*8/1024/1024,
		(tx_byte-last_tx_byte)*8/1024/1024);	
	printf("rx_byte: %llu, tx_byte: %llu\n",rx_byte ,tx_byte);	
	printf("rx_pkts_sec: %llu, tx_pkt_sec: %llu\n",rx_pkts - last_rx_pkts,tx_pkts-last_tx_pkts);	
	printf("rx_byte: %llu, tx_byte: %llu\n\n",rx_pkts ,tx_pkts);	
	last_rx_byte = rx_byte;
	last_tx_byte = tx_byte;
	last_rx_pkts = rx_pkts;
	last_tx_pkts = tx_pkts;
}


static inline 
void recompute_cksum(struct rte_mbuf* mbuf){
	struct ether_hdr* eth_h = (struct ether_hdr*)rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
   	struct ipv4_hdr *ip_hdr = (struct ipv4_hdr*)((char*)eth_h + sizeof(struct ether_hdr));
	ip_hdr->hdr_checksum = 0;
	ip_hdr->hdr_checksum = rte_ipv4_cksum(ip_hdr);
}


static inline 
struct ipv4_hdr* get_ip_hdr(struct rte_mbuf* mbuf){
	struct ether_hdr* eth_h = (struct ether_hdr*)rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
   	struct ipv4_hdr *ip_hdr = (struct ipv4_hdr*)((char*)eth_h + sizeof(struct ether_hdr));
	return ip_hdr;
}


static inline 
struct tcp_hdr* get_tcp_hdr(struct rte_mbuf* mbuf){
	struct ether_hdr* eth_h = (struct ether_hdr*)rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
   	struct ipv4_hdr *ip_hdr = (struct ipv4_hdr*)((char*)eth_h + sizeof(struct ether_hdr));
	struct tcp_hdr *tcph = (struct tcp_hdr*)((char*)ip_hdr + sizeof(struct ipv4_hdr));
	return tcph;
}


static inline 
void init_pkts(struct rte_mbuf* mbuf,int flags){
    struct rte_mbuf* probing_packet;
    struct ether_hdr *eth_hdr;
    struct ipv4_hdr *iph;
    struct tcp_hdr *tcp_h;
    char* payload;
    probing_packet = mbuf;
    eth_hdr = (struct ether_hdr *) rte_pktmbuf_append(probing_packet, sizeof(struct ether_hdr));
    iph = (struct ipv4_hdr *)rte_pktmbuf_append(probing_packet, sizeof(struct ipv4_hdr));
    tcp_h = (struct tcp_hdr *) rte_pktmbuf_append(probing_packet,sizeof(struct tcp_hdr));
    //a packet has minimum size 64B
    payload = (char*) rte_pktmbuf_append(probing_packet,256);
    eth_hdr->ether_type =  rte_cpu_to_be_16(ETHER_TYPE_IPv4);
    ether_addr_copy(&interface_MAC, &eth_hdr->d_addr);
    struct ether_addr addr;
    rte_eth_macaddr_get(0, &addr);
    ether_addr_copy(&addr, &eth_hdr->s_addr);
    memset((char *)iph, 0, sizeof(struct ipv4_hdr));
    iph->src_addr=rte_cpu_to_be_32(IPv4(192,168,0,1));
    iph->dst_addr=rte_cpu_to_be_32(IPv4(172,17,17,2));
    iph->version_ihl = (4 << 4) | 5;
    iph->total_length = rte_cpu_to_be_16(52);
    iph->packet_id= 0xd84c;/* NO USE */
    iph->time_to_live=4;
    iph->next_proto_id = 0x6;
    iph->hdr_checksum = 0;
    uint16_t ck1 = rte_ipv4_cksum(iph);
    iph->hdr_checksum = ck1;
    tcp_h->src_port = rte_cpu_to_be_16(0);
    tcp_h->dst_port = rte_cpu_to_be_16(0);
    tcp_h->tcp_flags=flags;
}


static inline 
void pktgen_init(struct rte_mempool* mbuf_pool){
	printf("initing pkts\n");
	int i;
	for(i = 0;i < N_TEST_FLOWS;i++){
		syn_pkts[i] = rte_pktmbuf_alloc(mbuf_pool);
		data_pkts[i] = rte_pktmbuf_alloc(mbuf_pool);
		init_pkts(syn_pkts[i],2);
		init_pkts(data_pkts[i],0);

		get_ip_hdr(syn_pkts[i])->src_addr = rte_cpu_to_be_32(IPv4(172,17,17, 3));
		get_tcp_hdr(syn_pkts[i])->dst_port = rte_cpu_to_be_16(i);
		get_tcp_hdr(syn_pkts[i])->src_port = rte_cpu_to_be_16(i);
		recompute_cksum(syn_pkts[i]);

		get_ip_hdr(data_pkts[i])->src_addr = rte_cpu_to_be_32(IPv4(172,17,17,3));
		get_tcp_hdr(data_pkts[i])->dst_port = rte_cpu_to_be_16(i);
		get_tcp_hdr(data_pkts[i])->src_port = rte_cpu_to_be_16(i);
		recompute_cksum(data_pkts[i]);
	}
	printf("initing pkts finished\n");
}


static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
	struct rte_eth_conf port_conf = port_conf_default;
	const uint16_t rx_rings = 1, tx_rings = 1;
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

	/* Display the port MAC address. */
	struct ether_addr addr;
	rte_eth_macaddr_get(port, &addr);
	printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			port,
			addr.addr_bytes[0], addr.addr_bytes[1],
			addr.addr_bytes[2], addr.addr_bytes[3],
			addr.addr_bytes[4], addr.addr_bytes[5]);

	/* Enable RX in promiscuous mode for the Ethernet device. */
	rte_eth_promiscuous_enable(port);

	return 0;
}


static __attribute__((noreturn)) void
lcore_main(void)
{
	const uint16_t nb_ports = rte_eth_dev_count();
	uint16_t port;

	/*
	 * Check that the port is on the same NUMA node as the polling thread
	 * for best performance.
	 */
	for (port = 0; port < nb_ports; port++)
		if (rte_eth_dev_socket_id(port) > 0 &&
				rte_eth_dev_socket_id(port) !=
						(int)rte_socket_id())
			printf("WARNING, port %u is on remote NUMA node to "
					"polling thread.\n\tPerformance will "
					"not be optimal.\n", port);

	printf("\nCore %u forwarding packets. [Ctrl+C to quit]\n",
			rte_lcore_id());

	/* Run until the application is quit or killed. */
	for (;;) {
		cur_tsc = rte_rdtsc();
		diff_tsc = cur_tsc - prev_tsc;
		if (diff_tsc > TIMER_RESOLUTION_CYCLES/100) {
			rte_timer_manage();
			prev_tsc = cur_tsc;
		}
		if(arped == 1 && count < 1){
			//printf("attempting to send a packet\n");
			int j;
			for(j = 0;j < N_TEST_FLOWS;j++){
	 			rte_eth_tx_burst(0, 0, &syn_pkts[j], 1);
				tx_pkts ++;
				usleep(100);
				tx_byte += syn_pkts[j]->data_len;
			}
			count++;
		}
		if(arped == 1 && count >=1){
			
			rte_eth_tx_burst(0, 0, &data_pkts[count % N_TEST_FLOWS], 1);
			tx_pkts ++;
			tx_byte += data_pkts[count%N_TEST_FLOWS]->data_len;
			count++;
			
		}
		for (port = 0; port < 1; port++) {

			/* Get burst of RX packets, from first port of pair. */
			struct rte_mbuf *bufs[BURST_SIZE];
			const uint16_t nb_rx = rte_eth_rx_burst(0, 0,
					bufs, BURST_SIZE);

			if (unlikely(nb_rx == 0))
				continue;

            struct ether_hdr* eth_h;
			int i;
			for (i = 0;i < nb_rx;i++){
				struct rte_mbuf *mbuf = bufs[i];
				//rte_pktmbuf_dump(stdout,bufs[i],100);
				//printf("data len: %d\n",mbuf->data_len);
	            eth_h = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
			
				if(eth_h->ether_type == rte_cpu_to_be_16(ETHER_TYPE_IPv4)){
					rx_pkts ++;
					rx_byte += mbuf->data_len;
				}	
	            if(eth_h->ether_type == 1544){
			    	if(arped == 0){
						arped = 1;
				   
						printf("processing arp request\n");
						struct arp_hdr * arp_h = (struct arp_hdr *)((char*)eth_h + sizeof(struct ether_hdr));

		                struct ether_addr addr;
		                rte_eth_macaddr_get(0, &addr);

						printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
						   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
						1,
						addr.addr_bytes[0], addr.addr_bytes[1],
						addr.addr_bytes[2], addr.addr_bytes[3],
						addr.addr_bytes[4], addr.addr_bytes[5]);

	                    ether_addr_copy(&eth_h->s_addr, &eth_h->d_addr);
	                    //ether_addr_copy(&eth_h->s_addr, &interface_MAC);
	                    /* Set source MAC address with MAC address of TX port */
	                    ether_addr_copy(&addr, &eth_h->s_addr);

	                    arp_h->arp_op = rte_cpu_to_be_16(ARP_OP_REPLY);
	                    ether_addr_copy(&arp_h->arp_data.arp_sha, &arp_h->arp_data.arp_tha);
	                    ether_addr_copy(&eth_h->s_addr, &arp_h->arp_data.arp_sha);

	                    /* Swap IP addresses in ARP payload */
	                    uint32_t ip_addr = arp_h->arp_data.arp_sip;
	                    arp_h->arp_data.arp_sip = arp_h->arp_data.arp_tip;
	                    arp_h->arp_data.arp_tip = ip_addr;
						uint32_t ipv4_addr = arp_h->arp_data.arp_sip;
	                    printf("%d.%d.%d.%d\n", (ipv4_addr >> 24) & 0xFF,
	                                (ipv4_addr >> 16) & 0xFF, (ipv4_addr >> 8) & 0xFF,
	                                ipv4_addr & 0xFF);

						ipv4_addr = ip_addr;
	                    printf("%d.%d.%d.%d\n", (ipv4_addr >> 24) & 0xFF,
	                                (ipv4_addr >> 16) & 0xFF, (ipv4_addr >> 8) & 0xFF,
	                                ipv4_addr & 0xFF);

		                const uint16_t nb_tx = rte_eth_tx_burst(0, 0,
	                                           bufs, nb_rx);
	                    printf("end processing arp: %d\n",nb_tx);
					}
				}
			}                
			int kk = 0;
			for (kk = 0; kk< nb_rx; kk ++){
				rte_pktmbuf_free(bufs[kk]);
			}
		}
	}
}


int
main(int argc, char *argv[])
{
	struct rte_mempool *mbuf_pool;
	struct rte_mempool *mbuf_pool2;
	unsigned nb_ports;
	uint16_t portid;

	/* Initialize the Environment Abstraction Layer (EAL). */
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

	argc -= ret;
	argv += ret;

	/* Check that there is an even number of ports to send/receive on. */
	nb_ports = rte_eth_dev_count();
	if (nb_ports < 2 || (nb_ports & 1))
		//rte_exit(EXIT_FAILURE, "Error: number of ports must be even\n");

	/* Creates a new mempool in memory to hold the mbufs. */
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
		MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

	mbuf_pool2 = rte_pktmbuf_pool_create("MBUF_POOL2", 2000,
		MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());


	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");
	if (mbuf_pool2 == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool2\n");

	/* Initialize all ports. */
	for (portid = 0; portid < nb_ports; portid++)
		if (port_init(portid, mbuf_pool) != 0)
			rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n",
					portid);
	rte_timer_subsystem_init();
	rte_timer_init(&timer);
	uint64_t hz;	
	unsigned lcore_id;
	hz = rte_get_timer_hz();
	lcore_id = rte_lcore_id();
	printf("hz: %llu, lcore: %u\n",hz,lcore_id);
	rte_timer_reset(&timer,hz,PERIODICAL,lcore_id,timer_cb,NULL);
	pktgen_init(mbuf_pool2);
	if (rte_lcore_count() > 1)
		printf("\nWARNING: Too many lcores enabled. Only 1 used.\n");

	/* Call lcore_main on the master core only. */
	lcore_main();

	return 0;
}
