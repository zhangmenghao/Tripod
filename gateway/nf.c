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
#include <rte_malloc.h>
#include <rte_debug.h>



#include "main.h"

//share variables
struct rte_hash *state_hash_table[NB_SOCKETS];
struct rte_hash *index_hash_table[NB_SOCKETS];

uint32_t flow_counts = 0;
uint32_t last_flow_counts = 0;
uint32_t malicious_packet_counts = 0;
/* Data nf received statistics */

unsigned long long nf_rx_bytes[NF_CORE_COUNT];
unsigned long long last_nf_rx_bytes[NF_CORE_COUNT];
unsigned long long nf_rx_pkts[NF_CORE_COUNT];
unsigned long long last_nf_rx_pkts[NF_CORE_COUNT];
/* Data nf transmitted statistics */
unsigned long long nf_tx_bytes[NF_CORE_COUNT];
unsigned long long last_nf_tx_bytes[NF_CORE_COUNT];
unsigned long long nf_tx_pkts[NF_CORE_COUNT];
unsigned long long last_nf_tx_pkts[NF_CORE_COUNT];
unsigned long long nf_rx[NF_CORE_COUNT];

rte_rwlock_t numa_hash_lock;

void
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
		#ifdef __DEBUG_LV2
		printf("nf: set index success!\n");
		#endif
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
	if (ret >= 0){
		#ifdef __DEBUG_LV2
		printf("nf: get index success!\n");
		#endif
	}
	else if (ret == -EINVAL){
		#ifdef __DEBUG_LV1
		printf("nf: parameter invalid in getIndexs!\n");
		#endif
	}
	else if (ret == -ENOENT){
		#ifdef __DEBUG_LV1
		printf("nf: key not found in getIndexs!\n");
		#endif
	}
	else{
		printf("nf: get index error!\n");
	}
	return ret;
}

void
setStates(struct ipv4_5tuple *ip_5tuple, struct nf_states *state, unsigned hash_table_index){
	union ipv4_5tuple_host newkey;
	convert_ipv4_5tuple(ip_5tuple, &newkey);
	// rte_rwlock_write_lock(&numa_hash_lock);
	// printf("DEBUG: Table item set in table %d.\n", hash_table_index);
	int ret =  rte_hash_add_key_data(state_hash_table[hash_table_index], &newkey, state);
	// printf("DEBUG: setStates done\n");
	// rte_rwlock_write_unlock(&numa_hash_lock);
	if (ret == 0)
	{
		#ifdef __DEBUG_LV2
		printf("nf: set state success!\n");
		#endif
		//communicate with Manager
		/*
		if (rte_ring_enqueue(nf_manager_ring, ip_5tuple) == 0) {
			#ifdef __DEBUG_LV2
			printf("nf: enqueue success in setStates!\n");
			#endif
		}
		else{
			printf("nf: enqueue failed in setStates!!!\n");
		}
		*/
	}
	else{
		printf("nf: error found in setStates!\n");
		return;
	}
}

int
getStates(struct ipv4_5tuple *ip_5tuple, struct nf_states ** state, unsigned own_hash_table_index){
	union ipv4_5tuple_host newkey;
	convert_ipv4_5tuple(ip_5tuple, &newkey);
	int i;
    int ret;
	/* look up in its own table first */
	ret = rte_hash_lookup_data(state_hash_table[own_hash_table_index], &newkey, (void **) state);
    if(ret < 0){
		/* table 0 for manager, 1~NF_CORE_COUNT for nfs */
		for(i = NF_CORE_COUNT;i >= 0;i--){
			if(i == own_hash_table_index)
				continue;
			ret = rte_hash_lookup_data(state_hash_table[i], &newkey, (void **) state);
			if(ret >= 0)
				break;
		}
	}
	// int ret = rte_hash_lookup_data(state_hash_table[1], &newkey, (void **) state);
	// if (ret < 0){
	// 	ret = rte_hash_lookup_data(state_hash_table[0], &newkey, (void **) state);
	// }
	// // printf("ret, EINVAL, ENOENT is %d, %u and %u\n", ret, EINVAL, ENOENT);
	if (ret >= 0){
		#ifdef __DEBUG_LV2
		printf("nf: get state success!\n");
		#endif
	}
	else if (ret == -EINVAL){
		#ifdef __DEBUG_LV1
		printf("nf: parameter invalid in getStates\n");
		#endif
	}
	else if (ret == -ENOENT){
		#ifdef __DEBUG_LV1
		printf("nf: key not found in getStates!\n");
		#endif
		//ask index table
		struct nf_indexs *index;
	/*
		index = rte_malloc(NULL,sizeof(struct nf_indexs),0);
		index->backupip[0] = topo[1].ip;
		ret = 1;
		*/
		ret =  getIndexs(ip_5tuple, &index);
		if (ret >= 0){
			//getRemoteState(index, state);
			ret = pullState(1, 0, ip_5tuple, index, state);
		}
		else{
			#ifdef __DEBUG_LV1
			printf("nf: this is an attack!\n");
			#endif
		}
	}
	else{
		printf("nf: get state error!\n");
	}
	return ret;
}


static void
print_ethaddr(const char *name, struct ether_addr *eth_addr)
{
	char buf[ETHER_ADDR_FMT_SIZE];
	ether_format_addr(buf, ETHER_ADDR_FMT_SIZE, eth_addr);
	#ifdef __DEBUG_LV2
	printf("nf: %s is %s\n", name, buf);
	#endif
}

void
nf_arp_process(uint8_t port, struct ether_hdr *eth_hdr,
	uint16_t tx_queue_id, struct rte_mbuf ** bufs_i)
{
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
	rte_eth_tx_burst(port, tx_queue_id, bufs_i, 1);
	#ifdef __DEBUG_LV1
	printf("This is arp request message\n");
	printf("\n");
	#endif
	return;
}


/*
 * gateway network funtions.
 */
int
lcore_nf(/*__attribute__((unused)) void *arg, */const struct nf_inst_info* nf_info)
{
	const uint8_t nb_ports = rte_eth_dev_count();
	struct ipv4_5tuple *ip_5tuple;
	struct nf_states * state;
	uint8_t port;
	int i;

	for (port = 0; port < nb_ports; port++)
		if (rte_eth_dev_socket_id(port) > 0 &&
				rte_eth_dev_socket_id(port) !=
						(int)rte_socket_id())
			printf("nf: WARNING, port %u is on remote NUMA node to "
					"polling thread.\n\tPerformance will "
					"not be optimal.\n NF core id %u\n", port, rte_lcore_id());

	printf("\nCore %u processing packets.\n",
			rte_lcore_id());

	/* Run until the application is quit or killed. */
	for (;;) {
		for (port = 0; port < nb_ports; port++) {
			if ((enabled_port_mask & (1 << port)) == 0) {
				continue;
			}

			struct rte_mbuf *bufs[BURST_SIZE];
			const uint16_t nb_rx_l = rte_eth_rx_burst(port, nf_info->rx_queue_id,
					bufs, BURST_SIZE);

            nf_rx[nf_info->nf_id] = nb_rx_l;
			if (unlikely(nb_rx_l == 0)){
				continue;
			}

			for (i = 0; i < nb_rx_l; i ++){
				//*************************/
				/* extract ethernet       */
				//*************************/
				// printf("DEBUG...%d\n", bufs[i]->hash.rss);
				struct ether_hdr *eth_hdr;
				eth_hdr = rte_pktmbuf_mtod(bufs[i], struct ether_hdr *);
				struct ether_addr eth_s_addr;
				eth_s_addr = eth_hdr->s_addr;
				struct ether_addr eth_d_addr;
				eth_d_addr = eth_hdr->d_addr;

				//print_ethaddr("eth_s_addr", &eth_s_addr);
				//print_ethaddr("eth_d_addr", &eth_d_addr);

 				if (eth_hdr->ether_type == rte_be_to_cpu_16(ETHER_TYPE_ARP)) {
					 nf_arp_process(port, eth_hdr, nf_info->tx_queue_id, &bufs[i]);
					 continue;
  				}

				//*************************/
				/* extract ip             */
				//*************************/
				struct ipv4_hdr *ip_hdr = (struct ipv4_hdr*)((char*)eth_hdr + sizeof(struct ether_hdr));

				struct ipv4_5tuple ip_5tuples;
				ip_5tuples.ip_dst = rte_be_to_cpu_32(ip_hdr->dst_addr);
				ip_5tuples.ip_src = rte_be_to_cpu_32(ip_hdr->src_addr);
				ip_5tuples.proto = ip_hdr->next_proto_id;

				#ifdef __DEBUG_LV2
				printf("nf: ip_dst is "IPv4_BYTES_FMT " \n", IPv4_BYTES(ip_5tuples.ip_dst));
				printf("nf: ip_src is "IPv4_BYTES_FMT " \n", IPv4_BYTES(ip_5tuples.ip_src));
				printf("nf: next_proto_id is %u\n", ip_5tuples.proto);
				#endif

				switch (ip_5tuples.proto){
					case IP_PROTO_UDP:
					{
						//*************************/
						/* extract udp            */
						//*************************/
						struct udp_hdr * upd_hdrs = (struct udp_hdr*)((char*)ip_hdr + sizeof(struct ipv4_hdr));
						ip_5tuples.port_src = rte_be_to_cpu_16(upd_hdrs->src_port);
						ip_5tuples.port_dst = rte_be_to_cpu_16(upd_hdrs->dst_port);
						printf("nf: udp packets! pass!\n");
						break;
					}
					case IP_PROTO_TCP:
					{
						nf_rx_pkts[nf_info->nf_id] += 1;
						nf_rx_bytes[nf_info->nf_id] += bufs[i]->data_len;
						//*************************/
						/* extract tcp            */
						//*************************/
						struct tcp_hdr * tcp_hdrs = (struct tcp_hdr*)((char*)ip_hdr + sizeof(struct ipv4_hdr));
						ip_5tuples.port_src = rte_be_to_cpu_16(tcp_hdrs->src_port);
						ip_5tuples.port_dst = rte_be_to_cpu_16(tcp_hdrs->dst_port);
						#ifdef __DEBUG_LV1
						printf("nf: tcp_flags is %u\n", tcp_hdrs->tcp_flags);
						#endif

						// if it's not the start of a flow
						// getStates
						if ((tcp_hdrs->tcp_flags & TCP_FLAG_SYN) == TCP_FLAG_SYN) {
							// SYN or SYN+ACK
							ip_5tuple = rte_malloc(NULL, sizeof(*ip_5tuple), 0);
							if (!ip_5tuple)
								rte_panic("nf: ip_5tuple malloc failed!");
							ip_5tuple->ip_src = ip_5tuples.ip_src;
							ip_5tuple->ip_dst = ip_5tuples.ip_dst;
							ip_5tuple->proto = ip_5tuples.proto;
							ip_5tuple->port_dst = ip_5tuples.port_dst;
							ip_5tuple->port_src = ip_5tuples.port_src;
							state = rte_malloc(NULL, sizeof(*state), 0);
							if (!state)
								rte_panic("nf: state malloc failed!");
						}
						else {
							// SYN bit is 0
							// not SYN nor SYN+ACK
                            int ret = 1;
							ret =  getStates(&ip_5tuples, &state, nf_info->hash_table_index);
							if (ret < 0) {
								rte_pktmbuf_free(bufs[i]);
								malicious_packet_counts ++;
								#ifdef __DEBUG_LV1
								printf("nf: state not found!%d %d\n",flow_counts ,malicious_packet_counts);
								#endif
								continue;
							}
						}

						// TODO
						// nf_load_balance();
						// nf_nat();
						// nf_stateful_firewall();








						if (tcp_hdrs->tcp_flags == 0x12 || tcp_hdrs->tcp_flags == 0x02) {
							#ifdef __DEBUG_LV1
							printf("nf: recerive a new flow!\n");
							#endif


							state->ipserver = dip_pool[flow_counts % DIP_POOL_SIZE];
							setStates(ip_5tuple, state, nf_info->hash_table_index);

							ip_hdr->dst_addr = rte_cpu_to_be_32(state->ipserver);
							ip_hdr->hdr_checksum = 0;
							ip_hdr->hdr_checksum = rte_ipv4_cksum(ip_hdr);
							ether_addr_copy(&eth_s_addr,&eth_hdr->d_addr);
							ether_addr_copy(&eth_d_addr,&eth_hdr->s_addr);
							#ifdef __DEBUG_LV1
							printf("nf: tcp_syn new_ip_dst is "IPv4_BYTES_FMT " \n", IPv4_BYTES(rte_be_to_cpu_32(ip_hdr->dst_addr)));
							#endif
                            /*
							if (rte_eth_tx_burst(port, nf_info->tx_queue_id, &bufs[i], 1) != 1){
								rte_pktmbuf_free(bufs[i]);
								//printf("nf: error in tx packets\n");
							}
							//rte_pktmbuf_free(bufs[i]);
							nf_tx_pkts[nf_info->nf_id] += 1;
							nf_tx_bytes[nf_info->nf_id] += bufs[i]->data_len;
                            */
							flow_counts ++;
							//if (flow_counts >= 73000){
								//rte_exit(EXIT_FAILURE, "this is just a test\n");
							//}

						}
						else{
							//printf("%x\n", state);
							//printf("the value of states is %u XXXXXXXXXXXXXXXXXXXXx\n", state->ipserver);
							// if (ret >= 0){
								ip_hdr->dst_addr = rte_cpu_to_be_32(state->ipserver);
								ip_hdr->hdr_checksum = 0;
								ether_addr_copy(&eth_s_addr,&eth_hdr->d_addr);
								ether_addr_copy(&eth_d_addr,&eth_hdr->s_addr);
								ip_hdr->hdr_checksum = rte_ipv4_cksum(ip_hdr);
								#ifdef __DEBUG_LV1
								printf("nf: tcp new_ip_dst is "IPv4_BYTES_FMT " \n", IPv4_BYTES(rte_be_to_cpu_32(ip_hdr->dst_addr)));
								#endif
                            /*
								if (rte_eth_tx_burst(port, nf_info->tx_queue_id, &bufs[i], 1) != 1){
									rte_pktmbuf_free(bufs[i]);
									//printf("nf: error in tx packets\n");
								}
								nf_tx_pkts[nf_info->nf_id] += 1;
								nf_tx_bytes[nf_info->nf_id] += bufs[i]->data_len;
                                */
							// }

						}
						#ifdef __DEBUG_LV1
						printf("nf: this is very important! port_src and port_dst is %u and %u\n", ip_5tuples.port_src, ip_5tuples.port_dst);
						#endif
						break;
					}
					default:
					{
						printf("nf: not tcp and udp packets!\n");
						rte_pktmbuf_free(bufs[i]);
					}
				}
			#ifdef __DEBUG_LV1
			printf("\n");
			#endif
			}
            // tx batch
            //

			const uint16_t nb_tx_l = rte_eth_tx_burst(port, nf_info->rx_queue_id,
					bufs, nb_rx_l);
		}
	}
	return 0;
}

