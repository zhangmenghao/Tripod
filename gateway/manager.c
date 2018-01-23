#include <stdint.h>
#include <stdlib.h>
#include <time.h>
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
#include <rte_timer.h>

#include "main.h"

struct states_5tuple_pair {
    struct ipv4_5tuple l4_5tuple;
    struct nf_states states;
};

struct indexs_5tuple_pair {
    struct ipv4_5tuple l4_5tuple;
    struct nf_indexs indexs;
};

static uint32_t drop_packet_counts = 0;

static struct rte_timer manager_timer;
/* Control message received statistics */
static unsigned long long ctrl_rx_bytes = 0;
static unsigned long long last_ctrl_rx_bytes = 0;
static unsigned long long ctrl_rx_pkts = 0;
static unsigned long long last_ctrl_rx_pkts = 0;
/* Control message transmitted statistics */
static unsigned long long ctrl_tx_bytes = 0;
static unsigned long long last_ctrl_tx_bytes = 0;
static unsigned long long ctrl_tx_pkts = 0;
static unsigned long long last_ctrl_tx_pkts = 0;
/* Data transmitted by manager statistics */
unsigned long long mg_nf_tx_bytes = 0;
unsigned long long last_mg_nf_tx_bytes = 0;
unsigned long long mg_nf_tx_pkts = 0;
unsigned long long last_mg_nf_tx_pkts = 0;

static void
manager_timer_cb(__attribute__((unused)) struct rte_timer *tim,
         __attribute__((unused)) void *arg)
{
    printf("Manager Statistics\n");
    printf("ctrl_rx_throughput: %llu Mbps, ctrl_tx_throughput: %llu Mbps\n",
           (ctrl_rx_bytes - last_ctrl_rx_bytes) * 8 / 1024 / 1024,
           (ctrl_tx_bytes - last_ctrl_tx_bytes +
            nf_ctrl_tx_bytes - last_nf_ctrl_tx_bytes) * 8 / 1024 / 1024);
    printf("ctrl_rx_bytes: %llu, ctrl_tx_bytes: %llu\n",
           ctrl_rx_bytes, ctrl_tx_bytes + nf_ctrl_tx_bytes);
    printf("ctrl_rx_pkts_sec: %llu, ctrl_tx_pkts_sec: %llu\n",
           ctrl_rx_pkts - last_ctrl_rx_pkts,
           ctrl_tx_pkts - last_ctrl_tx_pkts +
           nf_ctrl_tx_pkts - last_nf_ctrl_tx_pkts);
    printf("ctrl_rx_pkts: %llu, ctrl_tx_pkts: %llu\n",
           ctrl_rx_pkts, ctrl_tx_pkts + nf_ctrl_tx_pkts);
    printf("NF Statistics\n");
    printf("nf_rx_throughput: %llu Mbps, nf_tx_throughput: %llu Mbps\n",
           (nf_rx_bytes - last_nf_rx_bytes) * 8 / 1024 / 1024,
           (nf_tx_bytes - last_nf_tx_bytes +
            mg_nf_tx_bytes - last_mg_nf_tx_bytes) * 8 / 1024 / 1024);
    printf("nf_rx_bytes: %llu, nf_tx_bytes: %llu\n",
           nf_rx_bytes, nf_tx_bytes + mg_nf_tx_bytes);
    printf("nf_rx_pkts_sec: %llu, nf_tx_pkts_sec: %llu\n",
           nf_rx_pkts - last_nf_rx_pkts,
           nf_tx_pkts - last_nf_tx_pkts + mg_nf_tx_pkts - last_mg_nf_tx_pkts);
    printf("nf_rx_pkts: %llu, nf_tx_pkts: %llu\n",
           nf_rx_pkts, nf_tx_pkts + mg_nf_tx_pkts);
    printf("Other Statistics\n");
    printf("malicious_packet_counts: %u\n", malicious_packet_counts);
    printf("drop_packet_counts(timeout): %u\n", drop_packet_counts);
    printf("flow_counts: %u, flow_counts_sec: %u\n\n",
           flow_counts, flow_counts - last_flow_counts);

    last_ctrl_rx_bytes = ctrl_rx_bytes;
    last_ctrl_rx_pkts = ctrl_rx_pkts;
    last_ctrl_tx_bytes = ctrl_tx_bytes;
    last_ctrl_tx_pkts = ctrl_tx_pkts;
    last_nf_ctrl_tx_bytes = nf_ctrl_tx_bytes;
    last_nf_ctrl_tx_pkts = nf_ctrl_tx_pkts;
    last_nf_rx_bytes = nf_rx_bytes;
    last_nf_rx_pkts = nf_rx_pkts;
    last_nf_tx_bytes = nf_tx_bytes;
    last_nf_tx_pkts = nf_tx_pkts;
    last_mg_nf_tx_bytes = mg_nf_tx_bytes;
    last_mg_nf_tx_pkts = mg_nf_tx_pkts;
    last_flow_counts = flow_counts;
}

/*
 * As manager doesn't need to enqueue 5tuple to nf_manager_ring,
 * so it need a more simple version of setStates
 */
static void
managerSetStates(struct ipv4_5tuple *ip_5tuple, struct nf_states *state)
{
    union ipv4_5tuple_host newkey;
    convert_ipv4_5tuple(ip_5tuple, &newkey);
    int ret =  rte_hash_add_key_data(state_hash_table[0], &newkey, state);
    if (ret == 0) {
        #ifdef __DEBUG_LV2
        printf("mg: set state success!\n");
        #endif
    }
    else {
        printf("mg: error found in setStates!\n");
        return;
    }
}

static int
managerGetStates(struct ipv4_5tuple *ip_5tuple, struct nf_states ** state)
{
    union ipv4_5tuple_host newkey;
    convert_ipv4_5tuple(ip_5tuple, &newkey);
    int ret = rte_hash_lookup_data(state_hash_table[1], &newkey, (void **) state);
    if (ret < 0) {
        ret = rte_hash_lookup_data(state_hash_table[0], &newkey, (void **) state);
    }
    //printf("ret, EINVAL, ENOENT is %d, %u and %u\n", ret, EINVAL, ENOENT);
    if (ret >= 0) {
        #ifdef __DEBUG_LV2
        printf("mg: get state success!\n");
        #endif
    }
    else if (ret == -EINVAL) {
        printf("mg: parameter invalid in getStates\n");
    }
    else if (ret == -ENOENT) {
        #ifdef __DEBUG_LV1
        printf("mg: key not found in getStates!\n");
        #endif
    }
    else{
        printf("mg: get state error!\n");
    }
    return ret;
}

static struct rte_mbuf*
build_backup_packet(uint8_t port,uint32_t backup_machine_ip,uint16_t packet_id,
                    struct ipv4_5tuple* ip_5tuple, struct nf_states* states)
{
    struct rte_mbuf* backup_packet;
    struct ether_hdr* eth_h;
    struct ipv4_hdr* ip_h;
    struct states_5tuple_pair* payload;
    struct ether_addr self_eth_addr;
    /* Allocate space */
    backup_packet = rte_pktmbuf_alloc(single_port_param.manager_mempool);
    if (backup_packet == NULL) {
        printf("mg: backup_packet alloc failed\n");
    }
    eth_h = (struct ether_hdr *)
        rte_pktmbuf_append(backup_packet, sizeof(struct ether_hdr));
    ip_h = (struct ipv4_hdr *)
        rte_pktmbuf_append(backup_packet, sizeof(struct ipv4_hdr));
    payload = (struct states_5tuple_pair*)
        rte_pktmbuf_append(backup_packet, sizeof(struct states_5tuple_pair));
    /* Set the packet ether header */
    eth_h->ether_type =  rte_cpu_to_be_16(ETHER_TYPE_IPv4);
    ether_addr_copy(&interface_MAC, &(eth_h->d_addr));
    rte_eth_macaddr_get(port, &self_eth_addr);
    ether_addr_copy(&self_eth_addr, &(eth_h->s_addr));
    /* Set the packet ip header */
    memset((char *)ip_h, 0, sizeof(struct ipv4_hdr));
    ip_h->src_addr=rte_cpu_to_be_32(this_machine->ip);
    ip_h->dst_addr=rte_cpu_to_be_32(backup_machine_ip);
    ip_h->version_ihl = (4 << 4) | 5;
    ip_h->total_length = rte_cpu_to_be_16(20+sizeof(struct states_5tuple_pair));
    /*
     * packet_id indicates nf_id: 0 means general state backup,
     * other means response for nf's state pull request
     */
    ip_h->packet_id = rte_cpu_to_be_16(packet_id);
    ip_h->time_to_live=4;
    /* In HPSMS, proto A0 indicate this is state backup message */
    ip_h->next_proto_id = 0xA0;
    ip_h->hdr_checksum = rte_ipv4_cksum(ip_h);
    /* Set the packet payload(5tuple:states) */
    payload->l4_5tuple.ip_dst = ip_5tuple->ip_dst;
    payload->l4_5tuple.ip_src = ip_5tuple->ip_src;
    payload->l4_5tuple.port_dst = ip_5tuple->port_dst;
    payload->l4_5tuple.port_src = ip_5tuple->port_src;
    payload->l4_5tuple.proto = ip_5tuple->proto;
    if (states != NULL) {
        payload->states.ipserver = states->ipserver;
        payload->states.dip = states->dip;
        payload->states.dport = states->dport;
        payload->states.bip = states->bip;
    }
    else {
        payload->states.ipserver = 0;
        payload->states.dip = 0;
        payload->states.dport = 0;
        payload->states.bip = 0;
    }
    ctrl_tx_pkts += 1;
    ctrl_tx_bytes += backup_packet->data_len;
    return backup_packet;
}

static struct rte_mbuf*
build_pull_packet(uint8_t port, uint32_t target_ip, uint16_t nf_id,
                  struct ipv4_5tuple* ip_5tuple, void* callback_arg)
{
    struct rte_mbuf* pull_packet;
    struct ether_hdr* eth_h;
    struct ipv4_hdr* ip_h;
    struct ipv4_5tuple* payload;
    struct ether_addr self_eth_addr;
    /* Allocate space */
    pull_packet = rte_pktmbuf_alloc(single_port_param.manager_mempool);
    if (pull_packet == NULL) {
        printf("mg: pull_packet alloc failed\n");
    }
    eth_h = (struct ether_hdr *)
        rte_pktmbuf_append(pull_packet, sizeof(struct ether_hdr));
    ip_h = (struct ipv4_hdr *)
        rte_pktmbuf_append(pull_packet, sizeof(struct ipv4_hdr));
    payload = (struct ipv4_5tuple*)
      rte_pktmbuf_append(pull_packet, sizeof(struct ipv4_5tuple)+sizeof(void*));
    /* Set the packet ether header */
    eth_h->ether_type =  rte_cpu_to_be_16(ETHER_TYPE_IPv4);
    ether_addr_copy(&interface_MAC, &(eth_h->d_addr));
    rte_eth_macaddr_get(port, &self_eth_addr);
    ether_addr_copy(&self_eth_addr, &(eth_h->s_addr));
    /* Set the packet ip header */
    memset((char *)ip_h, 0, sizeof(struct ipv4_hdr));
    ip_h->src_addr=rte_cpu_to_be_32(this_machine->ip);
    ip_h->dst_addr=rte_cpu_to_be_32(target_ip);
    ip_h->version_ihl = (4 << 4) | 5;
    ip_h->total_length = rte_cpu_to_be_16(
        20 + sizeof(struct ipv4_5tuple) + sizeof(void*)
    );
    /*
     * packet_id indicates nf_id: 0 means general state backup,
     * other means response for nf's state pull request
     */
    ip_h->packet_id = rte_cpu_to_be_16(nf_id);
    ip_h->time_to_live=4;
    /* In HPSMS, proto A1 indicate this is state pull message */
    ip_h->next_proto_id = 0xA1;
    ip_h->hdr_checksum = rte_ipv4_cksum(ip_h);
    /* Set the packet payload(5tuple:states) */
    payload->ip_dst = ip_5tuple->ip_dst;
    payload->ip_src = ip_5tuple->ip_src;
    payload->port_dst = ip_5tuple->port_dst;
    payload->port_src = ip_5tuple->port_src;
    payload->proto = ip_5tuple->proto;
    *((void**)((u_char*)payload + sizeof(struct ipv4_5tuple))) = callback_arg;
    nf_ctrl_tx_pkts += 1;
    nf_ctrl_tx_bytes += pull_packet->data_len;
    return pull_packet;
}

static struct rte_mbuf*
build_keyset_packet(uint32_t target_ip, struct nf_indexs* indexs,
                    uint8_t port, struct ipv4_5tuple* ip_5tuple)
{
    struct rte_mbuf* keyset_packet;
    struct ether_hdr* eth_h;
    struct ipv4_hdr* ip_h;
    struct indexs_5tuple_pair* payload;
    struct ether_addr self_eth_addr;
    /* Allocate space */
    keyset_packet = rte_pktmbuf_alloc(single_port_param.manager_mempool);
    if (keyset_packet == NULL) {
        printf("mg: keyset_packet alloc failed\n");
    }
    eth_h = (struct ether_hdr *)
        rte_pktmbuf_append(keyset_packet, sizeof(struct ether_hdr));
    ip_h = (struct ipv4_hdr *)
        rte_pktmbuf_append(keyset_packet, sizeof(struct ipv4_hdr));
    payload = (struct indexs_5tuple_pair*)
        rte_pktmbuf_append(keyset_packet, sizeof(struct indexs_5tuple_pair));
    /* Set the packet ether header */
    eth_h->ether_type =  rte_cpu_to_be_16(ETHER_TYPE_IPv4);
    ether_addr_copy(&interface_MAC, &(eth_h->d_addr));
    rte_eth_macaddr_get(port, &self_eth_addr);
    ether_addr_copy(&self_eth_addr, &(eth_h->s_addr));
    /* Set the packet ip header */
    memset((char *)ip_h, 0, sizeof(struct ipv4_hdr));
    ip_h->src_addr=rte_cpu_to_be_32(this_machine->ip);
    ip_h->dst_addr=rte_cpu_to_be_32(target_ip);
    ip_h->version_ihl = (4 << 4) | 5;
    ip_h->total_length = rte_cpu_to_be_16(20+sizeof(struct indexs_5tuple_pair));
    ip_h->packet_id = 0;/* NO USE */
    ip_h->time_to_live=4;
    /* In HPSMS, proto A2 indicate this is keyset broadcast message */
    ip_h->next_proto_id = 0xA2;
    ip_h->hdr_checksum = rte_ipv4_cksum(ip_h);
    /* Set the packet payload(5tuple:states) */
    payload->l4_5tuple.ip_dst = ip_5tuple->ip_dst;
    payload->l4_5tuple.ip_src = ip_5tuple->ip_src;
    payload->l4_5tuple.port_dst = ip_5tuple->port_dst;
    payload->l4_5tuple.port_src = ip_5tuple->port_src;
    payload->l4_5tuple.proto = ip_5tuple->proto;
    payload->indexs.backupip[0] = indexs->backupip[0];
    payload->indexs.backupip[1] = indexs->backupip[1];
    ctrl_tx_pkts += 1;
    ctrl_tx_bytes += keyset_packet->data_len;
    return keyset_packet;
}

static struct rte_mbuf*
build_pullback_packet(uint8_t port,uint32_t backup_machine_ip,
                      uint16_t packet_id, struct ipv4_5tuple* ip_5tuple,
                      struct nf_states* states, void* callback_arg)
{
    struct rte_mbuf* backup_packet;
    struct ether_hdr* eth_h;
    struct ipv4_hdr* ip_h;
    struct states_5tuple_pair* payload;
    struct ether_addr self_eth_addr;
    /* Allocate space */
    backup_packet = rte_pktmbuf_alloc(single_port_param.manager_mempool);
    if (backup_packet == NULL) {
        printf("mg: backup_packet alloc failed!\n");
    }
    eth_h = (struct ether_hdr *)
      rte_pktmbuf_append(backup_packet, sizeof(struct ether_hdr));
    ip_h = (struct ipv4_hdr *)
        rte_pktmbuf_append(backup_packet, sizeof(struct ipv4_hdr));
    payload = (struct states_5tuple_pair*)
        rte_pktmbuf_append(
            backup_packet, sizeof(struct states_5tuple_pair) + sizeof(void*)
        );
    /* Set the packet ether header */
    eth_h->ether_type =  rte_cpu_to_be_16(ETHER_TYPE_IPv4);
    ether_addr_copy(&interface_MAC, &(eth_h->d_addr));
    rte_eth_macaddr_get(port, &self_eth_addr);
    ether_addr_copy(&self_eth_addr, &(eth_h->s_addr));
    /* Set the packet ip header */
    memset((char *)ip_h, 0, sizeof(struct ipv4_hdr));
    ip_h->src_addr=rte_cpu_to_be_32(this_machine->ip);
    ip_h->dst_addr=rte_cpu_to_be_32(backup_machine_ip);
    ip_h->version_ihl = (4 << 4) | 5;
    ip_h->total_length = rte_cpu_to_be_16(
        20 + sizeof(struct states_5tuple_pair) + sizeof(void*)
    );
    /*
     * packet_id indicates nf_id: 0 means general state backup,
     * other means response for nf's state pull request
     */
    ip_h->packet_id = rte_cpu_to_be_16(packet_id);
    ip_h->time_to_live=4;
    /* In HPSMS, proto A0 indicate this is state backup message */
    ip_h->next_proto_id = 0xA0;
    ip_h->hdr_checksum = rte_ipv4_cksum(ip_h);
    /* Set the packet payload(5tuple:states) */
    payload->l4_5tuple.ip_dst = ip_5tuple->ip_dst;
    payload->l4_5tuple.ip_src = ip_5tuple->ip_src;
    payload->l4_5tuple.port_dst = ip_5tuple->port_dst;
    payload->l4_5tuple.port_src = ip_5tuple->port_src;
    payload->l4_5tuple.proto = ip_5tuple->proto;
    if (states == NULL) {
        payload->states.ipserver = 0;
        payload->states.dip = 0;
        payload->states.dport = 0;
        payload->states.bip = 0;
    }
    else {
        payload->states.ipserver = states->ipserver;
        payload->states.dip = states->dip;
        payload->states.dport = states->dport;
        payload->states.bip = states->bip;
    }
    *((void**)
    ((u_char*)payload + sizeof(struct states_5tuple_pair))) = callback_arg;
    ctrl_tx_pkts += 1;
    ctrl_tx_bytes += backup_packet->data_len;
    return backup_packet;
}

static struct nf_states*
backup_to_machine(struct states_5tuple_pair* backup_pair)
{
    #ifdef __DEBUG_LV1
    printf("mg: ip_src is "IPv4_BYTES_FMT " \n",
           IPv4_BYTES(backup_pair->l4_5tuple.ip_src));
    printf("mg: ip_dst is "IPv4_BYTES_FMT " \n",
           IPv4_BYTES(backup_pair->l4_5tuple.ip_dst));
    printf("mg: ip_server is "IPv4_BYTES_FMT " \n",
           IPv4_BYTES(backup_pair->states.ipserver));
    #endif
    #ifdef __DEBUG_LV2
    printf("mg: port_src is 0x%x\n", backup_pair->l4_5tuple.port_src);
    printf("mg: port_dst is 0x%x\n", backup_pair->l4_5tuple.port_dst);
    printf("mg: proto is 0x%x\n", backup_pair->l4_5tuple.proto);
    printf("mg: dip is "IPv4_BYTES_FMT " \n",
           IPv4_BYTES(backup_pair->states.dip));
    printf("mg: dport is 0x%x\n", backup_pair->states.dport);
    printf("mg: dip is "IPv4_BYTES_FMT " \n",
           IPv4_BYTES(backup_pair->states.bip));
    #endif
    struct nf_states* states = rte_malloc(NULL, sizeof(struct nf_states), 0);
    if (!states) {
        rte_panic("mg: states malloc failed!");
    }
    states->ipserver = backup_pair->states.ipserver;
    states->dip = backup_pair->states.dip;
    states->dport = backup_pair->states.dport;
    states->bip = backup_pair->states.bip;
    managerSetStates(&(backup_pair->l4_5tuple), states);
    return states;
}

static void
keyset_to_machine(struct indexs_5tuple_pair* keyset_pair)
{
    #ifdef __DEBUG_LV1
    printf("mg: ip_src is "IPv4_BYTES_FMT " \n",
           IPv4_BYTES(keyset_pair->l4_5tuple.ip_src));
    printf("mg: ip_dst is "IPv4_BYTES_FMT " \n",
           IPv4_BYTES(keyset_pair->l4_5tuple.ip_dst));
    printf("mg: backup_ip is "IPv4_BYTES_FMT " \n",
           IPv4_BYTES(keyset_pair->indexs.backupip[0]));
    #endif
    #ifdef __DEBUG_LV2
    printf("mg: port_src is 0x%x\n", keyset_pair->l4_5tuple.port_src);
    printf("mg: port_dst is 0x%x\n", keyset_pair->l4_5tuple.port_dst);
    printf("mg: proto is 0x%x\n", keyset_pair->l4_5tuple.proto);
    #endif
    struct nf_indexs* indexs = rte_malloc(NULL, sizeof(struct nf_indexs), 0);
    if (!indexs) {
        rte_panic("mg: indexs malloc failed!");
    }
    indexs->backupip[0] = keyset_pair->indexs.backupip[0];
    indexs->backupip[1] = keyset_pair->indexs.backupip[1];
    setIndexs(&(keyset_pair->l4_5tuple), indexs);
}

int
pullState(uint16_t nf_id, uint8_t port, void* callback_arg,
          struct ipv4_5tuple* ip_5tuple, struct nf_indexs* target_indexs,
          struct nf_states** target_states)
{
    struct rte_mbuf* pull_packet;
    uint64_t prev_tsc, cur_tsc, diff_tsc;
    /* build and send pull request packet */
    pull_packet = build_pull_packet(
        port, target_indexs->backupip[0], nf_id, ip_5tuple, callback_arg
    );

    if (rte_eth_tx_burst(port, 3, &pull_packet, 1) != 1) {
        printf("mg: tx pullState failed!\n");
        rte_pktmbuf_free(pull_packet);
    }

    /* If the second index is set, send 2 pull request packet */
    if (target_indexs->backupip[1] != 0) {
        pull_packet = build_pull_packet(
            port, target_indexs->backupip[1], nf_id, ip_5tuple, callback_arg
        );
        if (rte_eth_tx_burst(port, 3, &pull_packet, 1) != 1) {
            printf("mg: tx pullState2 failed!\n");
            rte_pktmbuf_free(pull_packet);
        }
    }
    /* This is just temporary method */
    else if (target_indexs->backupip[0] == IPv4(172, 16, 0, 2)) {
        rte_pktmbuf_free((struct rte_mbuf*)callback_arg);
        return 0;
    }

    return 0;
}

int
backup_to_remote(struct ipv4_5tuple* ip_5tuple, uint8_t backup_num)
{
    struct rte_mbuf* backup_packet;
    struct nf_states* backup_states;
    struct rte_mbuf* keyset_packet;
    struct nf_indexs *indexs;
    int ret = managerGetStates(ip_5tuple, &backup_states);
    int i, idx, rnd, last_rnd = this_machine_index;
    if (ret < 0) {
        printf("mg: state not found!\n");
        return ret;
    }

    indexs = rte_malloc(NULL, sizeof(struct nf_indexs), 0);
    memset((void*)indexs, 0, sizeof(struct nf_indexs));
    if (!indexs) {
        rte_panic("mg: indexs malloc failed!");
        return -1;
    }

    for (i = 0; i < backup_num; i++) {
        do {
            rnd = rand() % N_MACHINE;
        }
        while (rnd == this_machine_index || rnd == last_rnd);
        last_rnd = rnd;
        indexs->backupip[i] = topo[rnd].ip;
        backup_packet = build_backup_packet(
            0, indexs->backupip[i], 0x00,
            ip_5tuple, backup_states
        );
        /* Send control message from port 0 queue 2 */
        if (rte_eth_tx_burst(0, 1, &backup_packet, 1) != 1) {
            printf("mg: tx backup_packet failed!\n");
            rte_pktmbuf_free(backup_packet);
        }
    }

    setIndexs(ip_5tuple, indexs);

    for (idx = 0; idx < N_MACHINE; idx++) {
        if (idx == this_machine_index)
            continue;
        keyset_packet = build_keyset_packet(
            topo[idx].ip, indexs, 0, ip_5tuple
        );
        /* Send control message from port 0 queue 2 */
        if (rte_eth_tx_burst(0, 1, &keyset_packet, 1) != 1) {
            printf("mg: tx keyset_packet failed!\n");
            rte_pktmbuf_free(keyset_packet);
        }
    }

    return 0;
}

/*
 * gateway manager.
 */
int
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

    printf("\nCore %u manage states in gateway.\n", rte_lcore_id());

	rte_timer_subsystem_init();
	rte_timer_init(&manager_timer);
	rte_timer_reset(
        &manager_timer, rte_get_timer_hz()/5, PERIODICAL,
        rte_lcore_id(), manager_timer_cb, NULL
    );

    srand((int)time(NULL));

	/* Run until the application is quit or killed. */
    for (;;) {
        uint64_t prev_tsc = 0, cur_tsc , diff_tsc;
        cur_tsc = rte_rdtsc();
        diff_tsc = cur_tsc - prev_tsc;
        if (diff_tsc > TIMER_RESOLUTION_CYCLES/100) {
            rte_timer_manage();
            prev_tsc = cur_tsc;
        }
        for (port = 0; port < nb_ports; port++) {
            if ((enabled_port_mask & (1 << port)) == 0) {
                //printf("Skipping %u\n", port);
                continue;
            }
            struct rte_mbuf *bufs[BURST_SIZE];
            uint16_t nb_rx = rte_eth_rx_burst(port, 1, bufs, BURST_SIZE);
            if (unlikely(nb_rx == 0))
                continue;
            /*
             * for (i = 0; i < nb_rx; i++) {
             *     rte_pktmbuf_free(bufs[i]);
             * }
             * continue;
             */
             
            for (i = 0; i < nb_rx; i ++) {
                #ifdef __DEBUG_LV1
                printf("mg: packet comes from port %u queue 1\n", port);
                #endif
                eth_h = rte_pktmbuf_mtod(bufs[i], struct ether_hdr *);
                ip_h = (struct ipv4_hdr*)
                       ((u_char*)eth_h + sizeof(struct ether_hdr));
                ip_proto = ip_h->next_proto_id;
                #ifdef __DEBUG_LV1
                printf("mg: dst ip "IPv4_BYTES_FMT " \n",
                       IPv4_BYTES(ip_h->dst_addr));
                printf("mg: proto: %x\n",ip_proto);
                #endif
                if (ip_proto == 0xA0) {
                    /* Control message about state backup */
                    /* Destination ip is 172.16.X.Y */
                    /* This is state backup message */
                    ctrl_rx_pkts += 1;
                    ctrl_rx_bytes += bufs[i]->data_len;
                    #ifdef __DEBUG_LV1
                    printf("mg: This is state backup message\n");
                    #endif
                    payload = (u_char*)ip_h + ((ip_h->version_ihl)&0x0F)*4;
                    if (ip_h->packet_id == 0) {
                        /* General state backup message */
                        backup_to_machine((struct states_5tuple_pair*)payload);
                    }
                    else if (rte_be_to_cpu_16(ip_h->packet_id) == 1) {
                        /* Specific state backup message for nf */
                        struct states_5tuple_pair* backup_pair;
                        struct nf_states* tmp_states;
                        int ret;
                        backup_pair = (struct states_5tuple_pair*)payload;
                        ret = managerGetStates(
                            &backup_pair->l4_5tuple, &tmp_states
                        );
                        if (ret < 0) {
                            pullStateCallback(
                                backup_to_machine(
                                    (struct states_5tuple_pair*)payload
                                ),
                                *((void**)
                                ((u_char*)payload + sizeof(struct states_5tuple_pair)))
                            );
                        }
                    }
                }
                else if (ip_proto == 0xA1) {
                    /* Control message about state pull */
                    struct ipv4_5tuple* ip_5tuple;
                    struct rte_mbuf* backup_packet;
                    struct nf_states* request_states;
                    struct ether_addr self_eth_addr;
                    uint32_t request_ip;
                    void* callback_arg;
                    ctrl_rx_pkts += 1;
                    ctrl_rx_bytes += bufs[i]->data_len;
                    #ifdef __DEBUG_LV1
                    printf("mg: This is state pull message\n");
                    #endif
                    payload = (u_char*)ip_h + ((ip_h->version_ihl)&0x0F)*4;
                    /* Get the 5tuple and relevant state, build and send */
                    ip_5tuple = (struct ipv4_5tuple*)payload;
                    callback_arg = *((void**)(payload + sizeof(struct ipv4_5tuple)));
                    int ret = managerGetStates(ip_5tuple, &request_states);
                    if (ret < 0) {
                        printf("mg: state not found for remote machine!\n");
                        backup_packet = build_pullback_packet(
                            port, rte_be_to_cpu_32(ip_h->src_addr),
                            rte_be_to_cpu_16(ip_h->packet_id), ip_5tuple,
                            NULL, callback_arg
                        );
                    }
                    else {
                        backup_packet = build_pullback_packet(
                            port, rte_be_to_cpu_32(ip_h->src_addr),
                            rte_be_to_cpu_16(ip_h->packet_id), ip_5tuple,
                            request_states, callback_arg
                        );
                    }
                    if (rte_eth_tx_burst(port, 2, &backup_packet, 1) != 1) {
                        printf("mg: tx backup_packet failed!\n");
                        rte_pktmbuf_free(backup_packet);
                    }
                }
                else if (ip_proto == 0xA2) {
                    /* Control message about keyset broadcast */
                    ctrl_rx_pkts += 1;
                    ctrl_rx_bytes += bufs[i]->data_len;
                    #ifdef __DEBUG_LV1
                    printf("mg: This is keyset broadcast message\n");
                    #endif
                    payload = (u_char*)ip_h + ((ip_h->version_ihl)&0x0F)*4;
                    keyset_to_machine((struct indexs_5tuple_pair*)payload);
                }
                #ifdef __DEBUG_LV1
                printf("\n");
                #endif
                rte_pktmbuf_free(bufs[i]);
            }
        }
	}
	return 0;
}

int
lcore_manager_slave(__attribute__((unused)) void *arg)
{
    const uint8_t nb_ports = rte_eth_dev_count();
    uint8_t port;
    struct ipv4_5tuple* ip_5tuple;
    printf("\nCore %u process request from nf\n", rte_lcore_id());
    for (;;) {
        for (port = 0; port < nb_ports; port++) {
            if ((enabled_port_mask & (1 << port)) == 0) {
                //printf("Skipping %u\n", port);
                continue;
            }
            if (rte_ring_dequeue(nf_manager_ring, (void**)&ip_5tuple) == 0) {
                // printf("debug: size %d ip_5tuple %lx\n",
                       // sizeof(ip_5tuple), ip_5tuple);
                #ifdef __DEBUG_LV1
                printf("mg-salve: Receive backup request from nf\n");
                printf("mg-salve: ip_dst is "IPv4_BYTES_FMT " \n",
                       IPv4_BYTES(ip_5tuple->ip_dst));
                printf("mg-salve: ip_src is "IPv4_BYTES_FMT " \n",
                       IPv4_BYTES(ip_5tuple->ip_src));
                #endif
                #ifdef __DEBUG_LV2
                printf("mg-salve: port_src is %u\n", ip_5tuple->port_src);
                printf("mg-salve: port_dst is %u\n", ip_5tuple->port_dst);
                printf("mg-salve: proto is %u\n", ip_5tuple->proto);
                #endif
                #ifdef __DEBUG_LV1
                printf("\n");
                #endif
                backup_to_remote(ip_5tuple, 1);
            }
        }
    }
    return 0;
}
