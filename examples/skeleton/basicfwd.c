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

#define RX_RING_SIZE 128
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
int test_receive = 1;
int arped = 0;
int count = 0;
static const struct rte_eth_conf port_conf_default = {
	.rxmode = { .max_rx_pkt_len = ETHER_MAX_LEN,
		    .hw_ip_checksum = 0 }
};


#define N_MACHINE_MAX 8
struct machine_IP_pair{
	uint8_t id;
	uint32_t ip;
};
struct machine_IP_pair topo[N_MACHINE_MAX];
struct machine_IP_pair* this_machine;


struct rte_mbuf* probing_packet;
struct ether_hdr *eth_hdr;
struct ipv4_hdr *iph;
struct tcp_hdr *tcp_h;
struct udp_hdr *udp_h;
char* l4_hdr;
char* payload;
struct ipv4_hdr *iph;
struct ether_hdr interface_MAC;

uint8_t no_this_machine;

uint32_t probing_ip;



static inline void dump_ip_hdr(struct ipv4_hdr* iph_h){
	uint32_t ip_dst;
	uint32_t ip_src;
	ip_dst = rte_be_to_cpu_32(iph_h->dst_addr);
	ip_src = rte_be_to_cpu_32(iph_h->src_addr);
	uint32_t ipv4_addr = ip_dst;
	printf("%d.%d.%d.%d\n", (ipv4_addr >> 24) & 0xFF,
	    (ipv4_addr >> 16) & 0xFF, (ipv4_addr >> 8) & 0xFF,
	    ipv4_addr & 0xFF);

	ipv4_addr = ip_src;
	printf("%d.%d.%d.%d\n", (ipv4_addr >> 24) & 0xFF,
	    (ipv4_addr >> 16) & 0xFF, (ipv4_addr >> 8) & 0xFF,
	    ipv4_addr & 0xFF);

	printf("%x\n",iph_h->version_ihl);
	printf("%x\n",iph_h->type_of_service);
	printf("%x\n",rte_be_to_cpu_16(iph_h->total_length));
	printf("%x\n",rte_be_to_cpu_16(iph_h->packet_id));
	printf("%x\n",iph_h->fragment_offset);
	printf("%x\n",iph_h->time_to_live);
	printf("%x\n",iph_h->next_proto_id);
	printf("%x\n",iph_h->hdr_checksum);
	printf("checksum correct?(should be 0xffff):%x\n",rte_ipv4_cksum(iph_h));



}
static inline void ecmp_predict_init(struct rte_mempool * mbuf_pool){

	probing_packet = rte_pktmbuf_alloc(mbuf_pool);
	eth_hdr = (struct ether_hdr *) rte_pktmbuf_append(probing_packet, sizeof(struct ether_hdr));
	iph = (struct ipv4_hdr *)rte_pktmbuf_append(probing_packet, sizeof(struct ipv4_hdr));
	tcp_h = (struct tcp_hdr *) rte_pktmbuf_append(probing_packet,sizeof(struct tcp_hdr));
/*
	udp_h = (struct udp_hdr *) rte_pktmbuf_append(probing_packet,sizeof(struct udp_hdr));
	payload = (char*) rte_pktmbuf_append(probing_packet,18);	
*/
	payload = (char*) rte_pktmbuf_append(probing_packet,6);	

	printf("data len: %d\n",probing_packet->pkt_len);

	printf("%d\n",sizeof(struct tcp_hdr));
	printf("%x\n",eth_hdr);
	printf("%x\n",iph);
	

	topo[0].id = 1;
	topo[0].ip = IPv4(172,16,0,2);


	topo[1].id = 2;
	topo[1].ip = IPv4(172,16,1,2);
	

	topo[2].id = 4;
	topo[2].ip = IPv4(172,16,2,2);

	this_machine = &(topo[1]);


	probing_ip = IPv4(172,17,17,2); 
}
static uint16_t
ipv4_hdr_cksum(struct ipv4_hdr *ip_h)
{
        uint16_t *v16_h;
        uint32_t ip_cksum;

        /*
         * Compute the sum of successive 16-bit words of the IPv4 header,
         * skipping the checksum field of the header.
         */
        v16_h = (unaligned_uint16_t *) ip_h;
        ip_cksum = v16_h[0] + v16_h[1] + v16_h[2] + v16_h[3] +
                v16_h[4] + v16_h[6] + v16_h[7] + v16_h[8] + v16_h[9];

        /* reduce 32 bit checksum to 16 bits and complement it */
        ip_cksum = (ip_cksum & 0xffff) + (ip_cksum >> 16);
        ip_cksum = (ip_cksum & 0xffff) + (ip_cksum >> 16);
        ip_cksum = (~ip_cksum) & 0x0000FFFF;
        return (ip_cksum == 0) ? 0xFFFF : (uint16_t) ip_cksum;
}


static inline  void backup_receive_probe_packet(struct rte_mbuf* mbuf){


	struct ether_hdr* eth_h = (struct ether_hdr*)rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
	struct ipv4_hdr *ip_hdr = (struct ipv4_hdr*)((char*)eth_h + sizeof(struct ether_hdr));

	char* payload = (char*)ip_hdr
		      + sizeof(struct ipv4_hdr)
		      + sizeof(struct tcp_hdr);
	uint32_t dst_ip = *((uint32_t*)payload);
	
	ip_hdr->dst_addr = rte_be_to_cpu_32(dst_ip);


	*((uint32_t*)payload) = this_machine->id;
	uint32_t ipv4_addr = dst_ip;
	 printf("%d.%d.%d.%d\n", (ipv4_addr >> 24) & 0xFF,
            (ipv4_addr >> 16) & 0xFF, (ipv4_addr >> 8) & 0xFF,
            ipv4_addr & 0xFF);


}


static inline uint32_t master_receive_probe_reply(struct rte_mbuf* mbuf){


	struct ether_hdr* eth_h = (struct ether_hdr*)rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
       
	ether_addr_copy(&interface_MAC, &eth_hdr->d_addr);
        struct ether_addr addr;
        rte_eth_macaddr_get(0, &addr);
        ether_addr_copy(&addr, &eth_hdr->s_addr); 
 	struct ipv4_hdr *ip_hdr = (struct ipv4_hdr*)((char*)eth_h + sizeof(struct ether_hdr));

        char* payload = (char*)ip_hdr
                      + sizeof(struct ipv4_hdr)
                      + sizeof(struct tcp_hdr);

	//dump_ip_hdr(ip_hdr);
	rte_pktmbuf_dump(stdout,mbuf,100);
	printf("%d\n",*((uint32_t*)payload));
	return *((uint32_t*)payload);



}





static inline void build_probe_packet(){
	eth_hdr->ether_type =  rte_cpu_to_be_16(ETHER_TYPE_IPv4);
	//eth_hdr->ether_type =  rte_cpu_to_be_16(ETHER_TYPE_ARP);
	//eth_hdr->ether_type =  0;
	//printf("%x\n",eth_hdr->ether_type);
        ether_addr_copy(&interface_MAC, &eth_hdr->d_addr);
	struct ether_addr addr;
	rte_eth_macaddr_get(0, &addr);
        ether_addr_copy(&addr, &eth_hdr->s_addr);
/*
	printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
                           " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
                       1,
                        addr.addr_bytes[0], addr.addr_bytes[1],
                        addr.addr_bytes[2], addr.addr_bytes[3],
                        addr.addr_bytes[4], addr.addr_bytes[5]);
*/
/*
        ether_addr_copy(&eth_hdr->d_addr, &addr);
	printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
                           " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
                        1,
                        addr.addr_bytes[0], addr.addr_bytes[1],
                        addr.addr_bytes[2], addr.addr_bytes[3],
                        addr.addr_bytes[4], addr.addr_bytes[5]);
*/	
	memset((char *)iph, 0, sizeof(struct ipv4_hdr));
	//static uint32_t ip = 0;
	iph->src_addr=rte_cpu_to_be_32(IPv4(11,11,12,15));
	iph->dst_addr=rte_cpu_to_be_32(probing_ip);
	iph->version_ihl = (4 << 4) | 5;
	iph->total_length = rte_cpu_to_be_16(46);
	iph->packet_id= 0xd84c;
	iph->time_to_live=4;
	iph->next_proto_id = 0x6;
	//iph->total_length= rte_cpu_to_be_16(sizeof(struct ipv4_hdr));
	iph->hdr_checksum = 0;
	uint16_t ck1 = rte_ipv4_cksum(iph);  
	uint16_t ck2 = ipv4_hdr_cksum(iph);
	//printf("%x\n",ck1);
	//printf("%x\n",ck2);
	iph->hdr_checksum = ck1;
	
	//dump_ip_hdr(iph);

	tcp_h->src_port = 22220;
	tcp_h->dst_port = 22221;


	*((uint32_t*)payload) = this_machine->ip;

/*
	udp_h->src_port = 10000;
	udp_h->dst_port = 10001;
	udp_h->dgram_len = 26;
	udp_h->dgram_cksum = 0;
	rte_ipv4_udptcp_cksum(iph,udp_h);

	//rte_pktmbuf_dump(stdout,probing_packet,100);
*/
}















/* basicfwd.c: Basic DPDK skeleton forwarding example. */

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */
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

/*
 * The lcore main. This is the main thread that does the work, reading from
 * an input port and writing to an output port.
 */
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
		/*
		 * Receive packets on a port and forward them on the paired
		 * port. The mapping is 0 -> 1, 1 -> 0, 2 -> 3, 3 -> 2, etc.
		 */
		for (port = 0; port < 1; port++) {

			/* Get burst of RX packets, from first port of pair. */
			struct rte_mbuf *bufs[BURST_SIZE];
			const uint16_t nb_rx = rte_eth_rx_burst(0, 0,
					bufs, BURST_SIZE);

			if (unlikely(nb_rx == 0))
				continue;

            //modifify by qiaoyi 171214
            	//printf("---------------INFO, received packet from port: %d\n",port^1);

                struct ether_hdr* eth_h;
		int i;
		for (i = 0;i < nb_rx;i++){
                struct rte_mbuf *mbuf = bufs[i];
		//rte_pktmbuf_dump(stdout,bufs[i],100);
		//printf("data len: %d\n",mbuf->data_len);
                eth_h = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
		if(eth_h->ether_type == rte_cpu_to_be_16(ETHER_TYPE_IPv4)){
			
			//printf("received ipv4 packet: %d\n",port);
			struct ether_addr addr;
                        rte_eth_macaddr_get(0, &addr);

			ether_addr_copy(&interface_MAC, &eth_h->d_addr);
/*
			printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
                           " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
                        1,
                        eth_h->d_addr.addr_bytes[0], eth_h->d_addr.addr_bytes[1],
                        eth_h->d_addr.addr_bytes[2], eth_h->d_addr.addr_bytes[3],
                        eth_h->d_addr.addr_bytes[4], eth_h->d_addr.addr_bytes[5]);
*/
                        ether_addr_copy(&addr,&eth_h->s_addr);
				struct ipv4_hdr *ip_hdr = (struct ipv4_hdr*)((char*)eth_h + sizeof(struct ether_hdr));
				//dump_ip_hdr(ip_hdr);

			uint32_t dst_addr = rte_be_to_cpu_32(ip_hdr->dst_addr);
			uint32_t ipv4_addr = dst_addr;
	 printf("received ip: %d.%d.%d.%d\n", (ipv4_addr >> 24) & 0xFF,
            (ipv4_addr >> 16) & 0xFF, (ipv4_addr >> 8) & 0xFF,
            ipv4_addr & 0xFF);

			if(dst_addr == probing_ip){
				backup_receive_probe_packet(bufs[i]);
				rte_eth_tx_burst(0,0,&bufs[i],1);
				//printf("in here\n");
			}
				
			else if(dst_addr == this_machine->ip){
				printf("in here2\n");
				master_receive_probe_reply(bufs[i]);

			}
			
			

		}	
                if(eth_h->ether_type == 1544)
                {
		    if(arped == 0){
                    	arped = 1;
		   
                    printf("processing arp request\n");
                    struct arp_hdr * arp_h = (struct arp_hdr *)((char*)eth_h + sizeof(struct ether_hdr));
                    /*
                    printf("%d.%d.%d.%d\n", (ipv4_addr >> 24) & 0xFF,
                                    (ipv4_addr >> 16) & 0xFF, (ipv4_addr >> 8) & 0xFF,
                                    ipv4_addr & 0xFF);
                    */

	                        struct ether_addr addr;
	                        rte_eth_macaddr_get(0, &addr);

			printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			1,
			addr.addr_bytes[0], addr.addr_bytes[1],
			addr.addr_bytes[2], addr.addr_bytes[3],
			addr.addr_bytes[4], addr.addr_bytes[5]);

                            ether_addr_copy(&eth_h->s_addr, &eth_h->d_addr);
                            ether_addr_copy(&eth_h->s_addr, &interface_MAC);
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
			/* Send burst of TX packets, to second port of pair. */
                    
			const uint16_t nb_tx = rte_eth_tx_burst(0,0,bufs,nb_rx);

			/* Free any unsent packets. */
			if (unlikely(nb_tx < nb_rx)) {
				uint16_t buf;
				for (buf = nb_tx; buf < nb_rx; buf++)
					rte_pktmbuf_free(bufs[buf]);
			}
/*
			if(arped == 1) {	
				build_probe_packet();
				bufs[0] = probing_packet;
				printf("attempt to send a probign packet\n");
			 	rte_eth_tx_burst(port^1, 0, bufs, 1);
			}
*/

		}
			//if(arped == 1) {	

			if(arped == 1&& count < 1){


				struct rte_mbuf *bufs[32];

				count ++;
						
				build_probe_packet();
				
				iph->src_addr = rte_cpu_to_be_32(IPv4(172,17,17,92));
 				iph->hdr_checksum = 0;
        			uint16_t ck1 = rte_ipv4_cksum(iph);
				iph->hdr_checksum = ck1;
				tcp_h->tcp_flags = 0x2;

				bufs[0] = probing_packet;
			
				printf("attempt to send a probign packet\n");
			 	rte_eth_tx_burst(0, 0, bufs, 1);
			}
	
	}
}

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
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
//		rte_exit(EXIT_FAILURE, "Error: number of ports must be even\n");

	/* Creates a new mempool in memory to hold the mbufs. */
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
		MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

	mbuf_pool2 = rte_pktmbuf_pool_create("MBUF_POOL2", 4,
		0 , 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());


	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");
	if (mbuf_pool2 == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool2\n");

	/* Initialize all ports. */
	for (portid = 0; portid < nb_ports; portid++)
		if (port_init(portid, mbuf_pool) != 0)
			rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n",
					portid);
	ecmp_predict_init(mbuf_pool2);
	build_probe_packet();
	dump_ip_hdr(iph);
	if (rte_lcore_count() > 1)
		printf("\nWARNING: Too many lcores enabled. Only 1 used.\n");

	/* Call lcore_main on the master core only. */
	lcore_main();

	return 0;
}
