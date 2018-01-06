#ifndef _ECMP_PREDICT_H_
#define _ECMP_PREDICT_H_
#include <stdlib.h>
#include <stdint.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_byteorder.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <inttypes.h>
#include <rte_byteorder.h>

#include "main.h"

struct machine_IP_pair topo[N_MACHINE_MAX];
struct machine_IP_pair* this_machine;

static struct rte_mempool* ecmp_mbuf_pool;
struct ether_addr interface_MAC = {
    .addr_bytes[0] = 0x48,
    .addr_bytes[1] = 0x6E,
    .addr_bytes[2] = 0x73,
    .addr_bytes[3] = 0x00,
    .addr_bytes[4] = 0x04,
    .addr_bytes[5] = 0xDB,
};

uint32_t probing_ip;

uint32_t this_machine_index;

uint32_t reverse_table[N_INTERFACE_MAX];
/*
	A tool function for dumping ALL of the ip header fields.
	The last line being 0xffff indicates that the cksum is correct.

*/
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
	printf("%x\n",iph_h->hdr_checksum); printf("checksum correct?(should be 0xffff):%x\n",rte_ipv4_cksum(iph_h)); 
}

/*
	Initialization of ECMP Predict.
	Should be called in initializtion, for example together with port init
	NOTE: The rte_mempool should be different from those holding traffic packets.We should build another rte_mempool specifcally for management packets.
*/
void ecmp_predict_init(struct rte_mempool * mbuf_pool){

    ecmp_mbuf_pool = mbuf_pool;

	//printf("data len: %d\n",probing_packet->pkt_len);

	//printf("%d\n",sizeof(struct tcp_hdr));
	//printf("%x\n",eth_hdr);
	//printf("%x\n",iph);
	
	//TODO: need a configuration process when boot
	topo[0].id = 1;
	topo[0].ip = IPv4(172,16,0,2);

	topo[1].id = 2;
	topo[1].ip = IPv4(172,16,1,2);

	topo[2].id = 3;
	topo[2].ip = IPv4(172,16,2,2);

	topo[3].id = 4;
	topo[3].ip = IPv4(172,16,3,2);

    this_machine_index = 1;

	this_machine = &(topo[this_machine_index]);

	probing_ip = IPv4(172,16,253,2); 

	reverse_table[1] = 0;
	reverse_table[2] = 1;
	reverse_table[3] = 2;
	reverse_table[4] = 3;
	printf("this machine.ip = " IPv4_BYTES_FMT " \n", IPv4_BYTES(this_machine->ip));
}

/*
	An implementation of IP checksum from testpmd.Proved the same as rte_ipv4_cksum()
*/
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


/*
	The function called when master receives probe reply.
	Decapsulate and get the payload.
	The caller decides when to call this function. In our scenario, when receiving IP packets with dip=172.16.x.2 and proto=6.

	Input: the probe reply mbuf
	Output: the ID of the probed backup machine


*/
void master_receive_probe_reply(struct rte_mbuf* mbuf,uint32_t* machine_ip1 ,uint32_t* machine_ip2, struct ipv4_5tuple** ip_5tuple){


	struct ether_hdr* eth_h = (struct ether_hdr*)rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
       /*
	ether_addr_copy(&interface_MAC, &eth_hdr->d_addr);
        struct ether_addr addr;
        rte_eth_macaddr_get(0, &addr);
        ether_addr_copy(&addr, &eth_hdr->s_addr);
	*/

 	struct ipv4_hdr *ip_hdr = (struct ipv4_hdr*)((char*)eth_h + sizeof(struct ether_hdr));
	struct tcp_hdr *tcph = (struct tcp_hdr*)((char*)ip_hdr + sizeof(struct ipv4_hdr));

    char* payload = (char*)ip_hdr
                      + sizeof(struct ipv4_hdr)
                      + sizeof(struct tcp_hdr);
    
    uint32_t index = *((uint32_t*)payload);
	printf("index: %d\n",index);
    *machine_ip1 = topo[index].ip;
    *machine_ip2 = topo[index+1].ip;
    *ip_5tuple = *((struct ipv4_5tuple**)(payload+4));
	//printf("debug: test%x\n", *((uint32_t*)(payload+4)));

	// uint32_t backup_port_N = *((uint32_t*)payload);
	// uint32_t flow_dip = *((uint32_t*)(payload+4));

	// uint32_t backup_port_N_minus_1;
    // uint32_t index;
	// if(backup_port_N >= this_machine->id){
		// index = reverse_table[backup_port_N];
		// backup_port_N_minus_1 = topo[index+1].id;	
            // *machine_ip = topo[index+1].ip;
	// }
	// else{
		// index = reverse_table[backup_port_N];
		// backup_port_N_minus_1 = backup_port_N;
            // *machine_ip = topo[index].ip;
	// }
	// //printf("payload: %d\n",*((uint32_t*)payload));
    
	// printf("in master_receive, will send state to port:%d, index: %d\n",backup_port_N_minus_1,index);
        // *sip = rte_be_to_cpu_32(ip_hdr->src_addr);
        // *dip = flow_dip;
        // *sport = rte_be_to_cpu_16(tcph->src_port);
        // *dport = rte_be_to_cpu_16(tcph->dst_port);
	// printf("dport: %x\n",*dport);
	// printf("sport: %x\n",*sport);


}


/*
	The function called when master needs to send probe request.
	The function modifies a global variable probing_packet.The caller can send this packet after this function is done.
	TODO: need rework
	(1) the 5-tuple as input
	(2) build a new mbuf for every packet

*/


struct rte_mbuf* build_probe_packet(struct ipv4_5tuple* ip_5tuple){
    struct rte_mbuf* probing_packet;
    struct ether_hdr *eth_hdr;
    struct ipv4_hdr *iph;
    struct tcp_hdr *tcp_h;
    char* payload;
    probing_packet = rte_pktmbuf_alloc(ecmp_mbuf_pool);
    eth_hdr = (struct ether_hdr *) rte_pktmbuf_append(probing_packet, sizeof(struct ether_hdr));
    iph = (struct ipv4_hdr *)rte_pktmbuf_append(probing_packet, sizeof(struct ipv4_hdr));
    tcp_h = (struct tcp_hdr *) rte_pktmbuf_append(probing_packet,sizeof(struct tcp_hdr));
    //a packet has minimum size 64B
    payload = (char*) rte_pktmbuf_append(probing_packet,12);
	eth_hdr->ether_type =  rte_cpu_to_be_16(ETHER_TYPE_IPv4);
	//eth_hdr->ether_type =  rte_cpu_to_be_16(ETHER_TYPE_ARP);
	//eth_hdr->ether_type =  0;
	//printf("%x\n",eth_hdr->ether_type);
    ether_addr_copy(&interface_MAC, &eth_hdr->d_addr);
	struct ether_addr addr;
	rte_eth_macaddr_get(0, &addr);
    ether_addr_copy(&addr, &eth_hdr->s_addr);
	/*printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
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
	iph->dst_addr=rte_cpu_to_be_32(probing_ip);
	iph->version_ihl = (4 << 4) | 5;
	iph->total_length = rte_cpu_to_be_16(52);
	iph->packet_id= 0xd84c;/* NO USE */
	iph->time_to_live=4;
	iph->next_proto_id = 0x6;
	//iph->total_length= rte_cpu_to_be_16(sizeof(struct ipv4_hdr));
	//printf("%x\n",ck1);
	//printf("%x\n",ck2);

    if (ip_5tuple == NULL) {
        iph->src_addr=rte_cpu_to_be_32(0);
        tcp_h->src_port = rte_cpu_to_be_16(0);
        tcp_h->dst_port = rte_cpu_to_be_16(0);
	    *((struct ipv4_5tuple**)(payload+4)) = 0;
    }
    else {
        iph->src_addr=rte_cpu_to_be_32(ip_5tuple->ip_src);
        tcp_h->src_port = rte_cpu_to_be_16(ip_5tuple->port_src);
        tcp_h->dst_port = rte_cpu_to_be_16(ip_5tuple->port_dst);
	    *((struct ipv4_5tuple**)(payload+4)) = ip_5tuple;
    }

	iph->hdr_checksum = 0;
	uint16_t ck1 = rte_ipv4_cksum(iph);  
	uint16_t ck2 = ipv4_hdr_cksum(iph);
	iph->hdr_checksum = ck1;
	
	//dump_ip_hdr(iph);

	*((uint32_t*)payload) = this_machine->ip;
    //printf("debug: ip_5tuple %lx\n", ip_5tuple);
    //printf("debug: test bpp %x\n", *((uint32_t*)(payload+4)));
    //printf("debug: payload %lx\n", *((struct ipv4_5tuple**)(payload+4)));

/*
	udp_h->src_port = 10000;
	udp_h->dst_port = 10001;
	udp_h->dgram_len = 26;
	udp_h->dgram_cksum = 0;
	rte_ipv4_udptcp_cksum(iph,udp_h);

	rte_pktmbuf_dump(stdout,probing_packet,100);
*/
    return probing_packet;
}


/*
	The function called when a certain machine receives a probe packet
	The machine extracts the source of the probe packet and MODIFIES the mbuf.
	The caller should resend the SAME mbuf.

*/

struct rte_mbuf* backup_receive_probe_packet(struct rte_mbuf* mbuf){


    struct rte_mbuf* probing_packet;
    struct ether_hdr *eth_hdr;
    struct ipv4_hdr *iph;
    struct tcp_hdr *tcp_h;
    char* payload;
    probing_packet = build_probe_packet(0);
    eth_hdr = rte_pktmbuf_mtod(probing_packet, struct ether_hdr *);
    iph = (struct ipv4_hdr *)((u_char*)eth_hdr + sizeof(struct ether_hdr));
    tcp_h = (struct tcp_hdr *)((u_char*)iph + sizeof(struct ipv4_hdr));
    //a packet has minimum size 64B
    payload = (char*)((u_char*)tcp_h + sizeof(struct tcp_hdr));

    struct ether_hdr* eth_h = (struct ether_hdr*)rte_pktmbuf_mtod(mbuf, struct ether_hdr *);

/*
            struct ether_addr addr;
                    rte_eth_macaddr_get(0, &addr);

                    ether_addr_copy(&interface_MAC, &eth_h->d_addr);
                    ether_addr_copy(&addr,&eth_h->s_addr);
*/

    struct ipv4_hdr *ip_hdr = (struct ipv4_hdr*)((char*)eth_h + sizeof(struct ether_hdr));
	struct tcp_hdr *tcph = (struct tcp_hdr*)((char*)ip_hdr + sizeof(struct ipv4_hdr));

    char* payload22 = (char*)ip_hdr
                  + sizeof(struct ipv4_hdr)
                  + sizeof(struct tcp_hdr);
    uint32_t dst_ip = *((uint32_t*)payload22);

    iph->src_addr = ip_hdr->src_addr;
    iph->dst_addr = rte_be_to_cpu_32(dst_ip);

    iph->hdr_checksum = 0;
    uint16_t ck1 = rte_ipv4_cksum(iph);
    iph->hdr_checksum = ck1;

    *((uint32_t*)payload) = this_machine_index;
	//printf("debug: %lx\n", *((uint64_t*)(payload22+4)));
    *((struct ipv4_5tuple**)(payload+4)) = *((struct ipv4_5tuple**)(payload22+4));
    uint32_t ipv4_addr = dst_ip;

	//printf("debug: test brp %x\n", *((uint32_t*)(payload+4)));

	tcp_h->src_port = tcph->src_port;
        tcp_h->dst_port = tcph->dst_port;
/*
     printf("in func: %d.%d.%d.%d\n", (ipv4_addr >> 24) & 0xFF,
        (ipv4_addr >> 16) & 0xFF, (ipv4_addr >> 8) & 0xFF,
        ipv4_addr & 0xFF);
*/
	//rte_pktmbuf_dump(stdout,probing_packet,100);

    return probing_packet;

}

#endif /*_ECMP_PREDICT_H_*/

