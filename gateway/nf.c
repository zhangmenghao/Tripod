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
#include <rte_memory.h>

#include "main.h"

struct nf_indexs indexs[10000];

//share variables
struct rte_hash *state_hash_table[NB_SOCKETS];
struct rte_hash *index_hash_table[NB_SOCKETS];

int flow_counts = 0;
int index_counts = 0;

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

void 
setIndexs(struct ipv4_5tuple *ip_5tuple, struct nf_indexs *index){
	union ipv4_5tuple_host newkey;
	convert_ipv4_5tuple(ip_5tuple, &newkey);
	int ret =  rte_hash_add_key_data(index_hash_table[0], &newkey, index);
	if (ret == 0)
	{
		printf("nf: set index success!\n");
		//broadcast
	}
	else{
		printf("nf: error found in setIndexs!\n");
		return;
	}
}

int
getIndexs(struct ipv4_5tuple *ip_5tuple, struct nf_indexs **index){
	union ipv4_5tuple_host newkey;
	convert_ipv4_5tuple(ip_5tuple, &newkey);
	int ret = rte_hash_lookup_data(index_hash_table[0], &newkey, (void **) index);
	if (ret == 0){
		printf("nf: get index success!\n");
	}
	if (ret == EINVAL){
		printf("nf: parameter invalid in getIndexs!\n");
	}
	if (ret == ENOENT){
		printf("nf: key not found in getIndexs!\n");
		//ask index table
	}
	return ret;
}

void 
setStates(struct ipv4_5tuple *ip_5tuple, struct nf_states *state){
	union ipv4_5tuple_host newkey;
	convert_ipv4_5tuple(ip_5tuple, &newkey);
	int ret =  rte_hash_add_key_data(state_hash_table[0], &newkey, state);
	if (ret == 0)
	{
		printf("nf: set state success!\n");
		//communicate with Manager
		if (rte_ring_enqueue(nf_manager_ring, ip_5tuple) == 0) {
			printf("nf: enqueue success in setStates!\n");
		}
		else{
			printf("nf: enqueue failed in setStates!!!\n");
		}
	}
	else{
		printf("nf: error found in setStates!\n");
		return;
	}
}

int
getStates(struct ipv4_5tuple *ip_5tuple, struct nf_states ** state){
	union ipv4_5tuple_host newkey;
	convert_ipv4_5tuple(ip_5tuple, &newkey);
	int ret = rte_hash_lookup_data(state_hash_table[0], &newkey, (void **) state);
	if (ret == 0){
		printf("nf: get state success!\n");
	}
	if (ret == EINVAL){
		printf("nf: parameter invalid in getStates\n");
	}
	if (ret == ENOENT){
		printf("nf: key not found in getStates!\n");
		//ask index table
		struct nf_indexs *index;
		int ret1 =  getIndexs(&ip_5tuple, &index);
		if (ret1 == 0){
			//getRemoteState(index, state);
		}
		if (ret1 == ENOENT){
			printf("this is an attack!\n");
		}
	}
	return ret;
}



static void
print_ethaddr(const char *name, struct ether_addr *eth_addr)
{
	char buf[ETHER_ADDR_FMT_SIZE];
	ether_format_addr(buf, ETHER_ADDR_FMT_SIZE, eth_addr);
	printf("nf: %s is %s\n", name, buf);
}

/*
 * gateway network funtions.
 */
int
lcore_nf(__attribute__((unused)) void *arg)
{
	const uint8_t nb_ports = rte_eth_dev_count();
	uint8_t port;
	int i;

	for (port = 0; port < nb_ports; port++)
		if (rte_eth_dev_socket_id(port) > 0 &&
				rte_eth_dev_socket_id(port) !=
						(int)rte_socket_id())
			printf("nf: WARNING, port %u is on remote NUMA node to "
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
				printf("nf: packet comes from %u\n", port);

				struct ether_hdr *eth_hdr;
				eth_hdr = rte_pktmbuf_mtod(bufs[i], struct ether_hdr *);
				struct ether_addr eth_s_addr;
				eth_s_addr = eth_hdr->s_addr;
				struct ether_addr eth_d_addr;
				eth_d_addr = eth_hdr->d_addr;

				print_ethaddr("eth_s_addr", &eth_s_addr);
				print_ethaddr("eth_d_addr", &eth_d_addr);

 				if (eth_hdr->ether_type == rte_be_to_cpu_16(ETHER_TYPE_ARP)) {
  				    /* arp message to keep live with switch */
   				    struct arp_hdr* arp_h;
   				    struct ether_addr self_eth_addr;
   				    uint32_t ip_addr;
  				    arp_h = (struct arp_hdr*)
  				    		((u_char*)eth_hdr + sizeof(struct ether_hdr));
  				    rte_eth_macaddr_get(port, &self_eth_addr);
  				    ether_addr_copy(&(eth_hdr->s_addr), &(eth_hdr->d_addr));
  				    ether_addr_copy(&(eth_hdr->s_addr), &interface_MAC);
  				    /* Set source MAC address with MAC of TX Port */
  				    ether_addr_copy(&self_eth_addr, &(eth_hdr->s_addr));
  				    arp_h->arp_op = rte_cpu_to_be_16(ARP_OP_REPLY);
  				    ether_addr_copy(&(arp_h->arp_data.arp_sha)
   				    			, &(arp_h->arp_data.arp_tha));
  				    ether_addr_copy(&(eth_hdr->s_addr)
   				    			, &(arp_h->arp_data.arp_sha));
  				    /* Swap IP address in ARP payload */
  				    ip_addr = arp_h->arp_data.arp_sip;
  				    arp_h->arp_data.arp_sip = arp_h->arp_data.arp_tip;
  				    arp_h->arp_data.arp_tip = ip_addr;
  				    rte_eth_tx_burst(port, 0, &bufs[i], 1);
				    printf("This is arp request message\n");
				    printf("\n");
  				    continue;
  				}

				struct ipv4_hdr *ip_hdr = (struct ipv4_hdr*)((char*)eth_hdr + sizeof(struct ether_hdr));

				struct ipv4_5tuple ip_5tuple;
				ip_5tuple.ip_dst = rte_be_to_cpu_32(ip_hdr->dst_addr);
				ip_5tuple.ip_src = rte_be_to_cpu_32(ip_hdr->src_addr);
				ip_5tuple.proto = ip_hdr->next_proto_id;

				printf("nf: ip_dst is "IPv4_BYTES_FMT " \n", IPv4_BYTES(ip_5tuple.ip_dst));
				printf("nf: ip_src is "IPv4_BYTES_FMT " \n", IPv4_BYTES(ip_5tuple.ip_src));
				printf("nf: next_proto_id is %u\n", ip_5tuple.proto);
				
				if (ip_5tuple.proto == 17){
					struct udp_hdr * upd_hdrs = (struct udp_hdr*)((char*)ip_hdr + sizeof(struct ipv4_hdr));
					ip_5tuple.port_src = rte_be_to_cpu_16(upd_hdrs->src_port);
					ip_5tuple.port_dst = rte_be_to_cpu_16(upd_hdrs->dst_port);
					printf("nf: udp packets! pass!\n");
				}
				else if (ip_5tuple.proto == 6){
					struct tcp_hdr * tcp_hdrs = (struct tcp_hdr*)((char*)ip_hdr + sizeof(struct ipv4_hdr));
					ip_5tuple.port_src = rte_be_to_cpu_16(tcp_hdrs->src_port);
					ip_5tuple.port_dst = rte_be_to_cpu_16(tcp_hdrs->dst_port);
					printf("nf: tcp_flags is %u\n", tcp_hdrs->tcp_flags);
					if (tcp_hdrs->tcp_flags == 2){
						printf("nf: recerive a new flow!\n");
						struct nf_states * state = rte_malloc(NULL, sizeof(*state), 0);
						state->ipserver = dip_pool[flow_counts % DIP_POOL_SIZE];
						setStates(&ip_5tuple, state);
						ip_hdr->dst_addr = rte_cpu_to_be_32(state->ipserver);
						printf("nf: tcp_syn new_ip_dst is "IPv4_BYTES_FMT " \n", IPv4_BYTES(rte_be_to_cpu_32(ip_hdr->dst_addr)));
						const uint16_t nb_tx = rte_eth_tx_burst(port, 0, &bufs[i], 1);
						rte_pktmbuf_free(bufs[i]);
						flow_counts ++;
					}
					else{
						struct nf_states *state;
						int ret =  getStates(&ip_5tuple, &state);
						//printf("%x\n", state);
						//printf("the value of states is %u XXXXXXXXXXXXXXXXXXXXx\n", state->ipserver);
						if (ret == ENOENT){
							printf("nf: packet wait, state not found!\n");
							//getIndex();
							//if else
						}
						else{
							ip_hdr->dst_addr = rte_cpu_to_be_32(state->ipserver);
							printf("nf: tcp new_ip_dst is "IPv4_BYTES_FMT " \n", IPv4_BYTES(rte_be_to_cpu_32(ip_hdr->dst_addr)));
							const uint16_t nb_tx = rte_eth_tx_burst(port, 0, &bufs[i], 1);
							rte_pktmbuf_free(bufs[i]);
						}
						
					}
					printf("nf: port_src and port_dst is %u and %u\n", ip_5tuple.port_src, ip_5tuple.port_dst);
				}
				printf("\n");
			}

		}
	}
	return 0;
}

