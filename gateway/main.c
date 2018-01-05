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

#include "main.h"

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
		if (port_init(portid, mbuf_pool, manager_mbuf_pool) == 0) {
			if (debug_mode > 0)
			printf("Initialize port %u, finshed!\n", portid);
		}
		else {
			if (debug_mode > 0)
			printf("Initialize port %u, failed!\n", portid);
		}
    
    /* Initialize about ECMP by QiaoYi */
    ecmp_predict_init(manager_mbuf_pool);

    /* Create and initialize ring between nf and manager */
    nf_manager_ring = rte_ring_create("NF_MANAGER_RING", RX_RING_SIZE, 
     				   				  rte_socket_id(), 
      				   				  RING_F_SP_ENQ | RING_F_SC_DEQ);
	if (nf_manager_ring == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create ring between nf and manager\n");
    /* Create and initialize ring for nf to wait pull state */
    nf_pull_wait_ring = rte_ring_create("NF_PULL_WAIT_RING", RX_RING_SIZE, 
     				   				  rte_socket_id(), 
      				   				  RING_F_SP_ENQ | RING_F_SC_DEQ);
	if (nf_pull_wait_ring == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create ring for nf to wait pulled state\n");

	check_all_ports_link_status((uint8_t)nb_ports, enabled_port_mask);

	// RTE_LCORE_FOREACH_SLAVE(lcore_id) {
		// rte_eal_remote_launch(lcore_nf, NULL, lcore_id);
	// }

	// lcore_manager(NULL);

	// rte_eal_mp_wait_lcore();

	/* Launch per-lcore init on every lcore */
	rte_eal_mp_remote_launch(lcore_main_loop, NULL, CALL_MASTER);
	RTE_LCORE_FOREACH_SLAVE(lcore_id) {
		if (rte_eal_wait_lcore(lcore_id) < 0) {
			return -1;
		}
	}

	return 0;
}
