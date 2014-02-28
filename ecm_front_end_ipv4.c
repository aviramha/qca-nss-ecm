/*
 **************************************************************************
 * Copyright (c) 2014, The Linux Foundation.  All rights reserved.
 * Permission to use, copy, modify, and/or distribute this software for
 * any purpose with or without fee is hereby granted, provided that the
 * above copyright notice and this permission notice appear in all copies.
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 **************************************************************************
 */

#include <linux/types.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/icmp.h>
#include <linux/sysctl.h>
#include <linux/kthread.h>
#include <linux/sysdev.h>
#include <linux/fs.h>
#include <linux/pkt_sched.h>
#include <linux/string.h>
#include <net/route.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <asm/unaligned.h>
#include <asm/uaccess.h>	/* for put_user */
#include <net/ipv6.h>
#include <linux/inet.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>

#include <linux/inetdevice.h>
#include <linux/if_arp.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_bridge.h>
#include <linux/if_bridge.h>
#include <net/arp.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_acct.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_l4proto.h>
#include <net/netfilter/nf_conntrack_l3proto.h>
#include <net/netfilter/nf_conntrack_zones.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/ipv4/nf_conntrack_ipv4.h>
#include <net/netfilter/ipv4/nf_defrag_ipv4.h>
#include <linux/../../net/8021q/vlan.h>
#include <linux/if_vlan.h>
#include <linux/../../net/offload/offload.h>

/*
 * Debug output levels
 * 0 = OFF
 * 1 = ASSERTS / ERRORS
 * 2 = 1 + WARN
 * 3 = 2 + INFO
 * 4 = 3 + TRACE
 */
#define DEBUG_LEVEL ECM_FRONT_END_IPV4_DEBUG_LEVEL

#include <nss_api_if.h>

#include "ecm_types.h"
#include "ecm_db_types.h"
#include "ecm_tracker.h"
#include "ecm_classifier.h"
#include "ecm_front_end_types.h"
#include "ecm_tracker_datagram.h"
#include "ecm_tracker_udp.h"
#include "ecm_tracker_tcp.h"
#include "ecm_db.h"
#include "ecm_classifier_default.h"
#include "ecm_classifier_nl.h"
#include "ecm_classifier_hyfi.h"
#include "ecm_interface.h"

/*
 * Magic numbers
 */
#define ECM_FRONT_END_IPV4_CONNECTION_TCP_INSTANCE_MAGIC 0xEB12
#define ECM_FRONT_END_IPV4_CONNECTION_UDP_INSTANCE_MAGIC 0xEA67
#define ECM_FRONT_END_IPV4_CONNECTION_NON_PORTED_INSTANCE_MAGIC 0xEC34

/*
 * struct ecm_front_end_ipv4_connection_tcp_instance
 *	A connection specific front end instance for TCP connections
 */
struct ecm_front_end_ipv4_connection_tcp_instance {
	struct ecm_front_end_connection_instance base;		/* Base class */

	struct ecm_db_connection_instance *ci;			/* RO: The connection instance relating to this instance. */

	bool can_accel;						/* RO: True when the connection can be accelerated */
	ecm_classifier_acceleration_mode_t accel_mode;
								/* Indicates  the type of acceleration being applied to a connection, if any. */
	int accel_count;					/* Number of times this connection has been accelerated */
	int accel_limit;					/* Limit to the number of times acceleration can be applied to this connection */

	spinlock_t lock;					/* Lock for structure data */

	int refs;						/* Integer to trap we never go negative */
#if (DEBUG_LEVEL > 0)
	uint16_t magic;
#endif
};

/*
 * struct ecm_front_end_ipv4_connection_udp_instance
 *	A connection specific front end instance for UDP connections
 */
struct ecm_front_end_ipv4_connection_udp_instance {
	struct ecm_front_end_connection_instance base;		/* Base class */

	struct ecm_db_connection_instance *ci;			/* RO: The connection instance relating to this instance. */

	bool can_accel;						/* RO: True when the connection can be accelerated */
	ecm_classifier_acceleration_mode_t accel_mode;
								/* Indicates  the type of acceleration being applied to a connection, if any. */
	int accel_count;					/* Number of times this connection has been accelerated */
	int accel_limit;					/* Limit to the number of times acceleration can be applied to this connection */

	spinlock_t lock;					/* Lock for structure dtaa */

	int refs;						/* Integer to trap we never go negative */
#if (DEBUG_LEVEL > 0)
	uint16_t magic;
#endif
};

/*
 * struct ecm_front_end_ipv4_connection_non_ported_instance
 *	A connection specific front end instance for Non-Ported connections
 */
struct ecm_front_end_ipv4_connection_non_ported_instance {
	struct ecm_front_end_connection_instance base;		/* Base class */

	struct ecm_db_connection_instance *ci;			/* RO: The connection instance relating to this instance. */

	bool can_accel;						/* RO: True when the connection can be accelerated */
	ecm_classifier_acceleration_mode_t accel_mode;
								/* Indicates  the type of acceleration being applied to a connection, if any. */
	int accel_count;					/* Number of times this connection has been accelerated */
	int accel_limit;					/* Limit to the number of times acceleration can be applied to this connection */

	spinlock_t lock;					/* Lock for structure dtaa */

	int refs;						/* Integer to trap we never go negative */
#if (DEBUG_LEVEL > 0)
	uint16_t magic;
#endif
};

static int ecm_front_end_ipv4_accel_limit_default = 250;		/* Default acceleration limit */

/*
 * Locking of the classifier - concurrency control
 */
static spinlock_t ecm_front_end_ipv4_lock;			/* Protect against SMP access between netfilter, events and private threaded function. */

/*
 * SysFS linkage
 */
static struct sys_device ecm_front_end_ipv4_sys_dev;		/* SysFS linkage */

/*
 * General operational control
 */
static int ecm_front_end_ipv4_stopped = 0;			/* When non-zero further traffic will not be processed */

/*
 * Management thread control
 */
static bool ecm_front_end_ipv4_terminate_pending = false;		/* True when the user has signalled we should quit */
static int ecm_front_end_ipv4_thread_refs = 0;			/* >0 when the thread must stay active */
static struct task_struct *ecm_front_end_ipv4_thread = NULL;		/* Control thread */

static void *ecm_front_end_ipv4_nss_ipv4_context = NULL;		/* Registration for IPv4 rules */

/*
 * Expose what should be a static flag in the TCP connection tracker.
 */
extern int nf_ct_tcp_no_window_check;
extern int nf_ct_tcp_be_liberal;

/*
 * ecm_front_end_ipv4_connection_final_tcp()
 *	Invoked when the connection becomes finalised
 */
static void ecm_front_end_ipv4_connection_final_tcp(void *arg)
{
	/*
	 * No longer need the ref to the thread
	 */
	spin_lock_bh(&ecm_front_end_ipv4_lock);
	ecm_front_end_ipv4_thread_refs--;
	DEBUG_ASSERT(ecm_front_end_ipv4_thread_refs >= 0, "Thread refs wrap %d\n", ecm_front_end_ipv4_thread_refs);
	spin_unlock_bh(&ecm_front_end_ipv4_lock);
	wake_up_process(ecm_front_end_ipv4_thread);
}

/*
 * ecm_front_end_ipv4_connection_final_udp()
 *	Invoked when the connection becomes finalised
 */
static void ecm_front_end_ipv4_connection_final_udp(void *arg)
{
	/*
	 * No longer need the ref to the thread
	 */
	spin_lock_bh(&ecm_front_end_ipv4_lock);
	ecm_front_end_ipv4_thread_refs--;
	DEBUG_ASSERT(ecm_front_end_ipv4_thread_refs >= 0, "Thread refs wrap %d\n", ecm_front_end_ipv4_thread_refs);
	spin_unlock_bh(&ecm_front_end_ipv4_lock);
	wake_up_process(ecm_front_end_ipv4_thread);
}

/*
 * ecm_front_end_ipv4_connection_final_non_ported()
 *	Invoked when the connection becomes finalised
 */
static void ecm_front_end_ipv4_connection_final_non_ported(void *arg)
{
	/*
	 * No longer need the ref to the thread
	 */
	spin_lock_bh(&ecm_front_end_ipv4_lock);
	ecm_front_end_ipv4_thread_refs--;
	DEBUG_ASSERT(ecm_front_end_ipv4_thread_refs >= 0, "Thread refs wrap %d\n", ecm_front_end_ipv4_thread_refs);
	spin_unlock_bh(&ecm_front_end_ipv4_lock);
	wake_up_process(ecm_front_end_ipv4_thread);
}

/*
 * ecm_front_end_ipv4_node_final()
 *	A node object we created has been destroyed
 */
static void ecm_front_end_ipv4_node_final(void *arg)
{
	/*
	 * No longer need the ref to the thread
	 */
	spin_lock_bh(&ecm_front_end_ipv4_lock);
	ecm_front_end_ipv4_thread_refs--;
	DEBUG_ASSERT(ecm_front_end_ipv4_thread_refs >= 0, "Thread refs wrap %d\n", ecm_front_end_ipv4_thread_refs);
	spin_unlock_bh(&ecm_front_end_ipv4_lock);
	wake_up_process(ecm_front_end_ipv4_thread);
}

/*
 * ecm_front_end_ipv4_host_final()
 *	A host object we created has been destroyed
 */
static void ecm_front_end_ipv4_host_final(void *arg)
{
	/*
	 * No longer need the ref to the thread
	 */
	spin_lock_bh(&ecm_front_end_ipv4_lock);
	ecm_front_end_ipv4_thread_refs--;
	DEBUG_ASSERT(ecm_front_end_ipv4_thread_refs >= 0, "Thread refs wrap %d\n", ecm_front_end_ipv4_thread_refs);
	spin_unlock_bh(&ecm_front_end_ipv4_lock);
	wake_up_process(ecm_front_end_ipv4_thread);
}

/*
 * ecm_front_end_ipv4_mapping_final()
 *	A mapping object we created has been destroyed
 */
static void ecm_front_end_ipv4_mapping_final(void *arg)
{
	/*
	 * No longer need the ref to the thread
	 */
	spin_lock_bh(&ecm_front_end_ipv4_lock);
	ecm_front_end_ipv4_thread_refs--;
	DEBUG_ASSERT(ecm_front_end_ipv4_thread_refs >= 0, "Thread refs wrap %d\n", ecm_front_end_ipv4_thread_refs);
	spin_unlock_bh(&ecm_front_end_ipv4_lock);
	wake_up_process(ecm_front_end_ipv4_thread);
}

/*
 * ecm_front_end_ipv4_node_establish_and_ref()
 *	Returns a reference to a node, possibly creating one if necessary.
 *
 * Returns NULL on failure.
 */
static struct ecm_db_node_instance *ecm_front_end_ipv4_node_establish_and_ref(struct net_device *dev, uint8_t *node_mac_addr)
{
	struct ecm_db_node_instance *ni;
	struct ecm_db_node_instance *nni;
	struct ecm_db_iface_instance *ii;

	DEBUG_INFO("Establish node for %pM\n", node_mac_addr);

	/*
	 * Locate the node
	 */
	ni = ecm_db_node_find_and_ref(node_mac_addr);
	if (ni) {
		DEBUG_TRACE("%p: node established\n", ni);
		return ni;
	}

	/*
	 * No node - establish iface
	 */
	ii = ecm_interface_establish_and_ref(dev);
	if (!ii) {
		DEBUG_WARN("Failed to establish iface\n");
		return NULL;
	}

	/*
	 * No node - create one
	 */
	nni = ecm_db_node_alloc();
	if (!nni) {
		DEBUG_WARN("Failed to establish node\n");
		ecm_db_iface_deref(ii);
		return NULL;
	}

	/*
	 * Add node into the database, atomically to avoid races creating the same thing
	 */
	spin_lock_bh(&ecm_front_end_ipv4_lock);
	ni = ecm_db_node_find_and_ref(node_mac_addr);
	if (ni) {
		spin_unlock_bh(&ecm_front_end_ipv4_lock);
		ecm_db_node_deref(nni);
		ecm_db_iface_deref(ii);
		return ni;
	}

	ecm_db_node_add(nni, ii, node_mac_addr, ecm_front_end_ipv4_node_final, nni);

	/*
	 * Don't need iface instance now
	 */
	ecm_db_iface_deref(ii);

	/*
	 * Ensure our thread persists (and hence this module) for as long as the connection and its supporting framework is alive
	 * as we could get callbacks from the database
	 */
	ecm_front_end_ipv4_thread_refs++;
	DEBUG_ASSERT(ecm_front_end_ipv4_thread_refs > 0, "Thread refs wrap %d\n", ecm_front_end_ipv4_thread_refs);
	spin_unlock_bh(&ecm_front_end_ipv4_lock);

	DEBUG_TRACE("%p: node established\n", nni);
	return nni;
}

/*
 * ecm_front_end_ipv4_host_establish_and_ref()
 *	Returns a reference to a host, possibly creating one if necessary.
 *
 * Returns NULL on failure.
 */
static struct ecm_db_host_instance *ecm_front_end_ipv4_host_establish_and_ref(struct net_device *dev, ip_addr_t addr)
{
	struct ecm_db_host_instance *hi;
	struct ecm_db_host_instance *nhi;
	struct ecm_db_node_instance *ni;
	uint8_t node_mac_addr[6];
	ip_addr_t gw_addr = ECM_IP_ADDR_NULL;
	bool on_link;

	DEBUG_INFO("Establish host for " ECM_IP_ADDR_DOT_FMT "\n", ECM_IP_ADDR_TO_DOT(addr));

	/*
	 * Locate the host
	 */
	hi = ecm_db_host_find_and_ref(addr);
	if (hi) {
		DEBUG_TRACE("%p: host established\n", hi);
		return hi;
	}

	/*
	 * No host - establish node
	 * Get its MAC address (or some kind of equivalent we can use for the node address).
	 */
	if (!ecm_interface_mac_addr_get(addr, node_mac_addr, &on_link, gw_addr)) {
		__be32 ipv4_addr;
		__be32 src_ip;
		DEBUG_TRACE("failed to obtain mac for host " ECM_IP_ADDR_DOT_FMT "\n", ECM_IP_ADDR_TO_DOT(addr));

		/*
		 * Issue an ARP request for it, select the src_ip from which to issue the request.
		 */
		ECM_IP_ADDR_TO_NIN4_ADDR(ipv4_addr, addr);
		src_ip = inet_select_addr(dev, ipv4_addr, RT_SCOPE_LINK);
		if (!src_ip) {
			DEBUG_TRACE("failed to lookup IP for %pI4\n", &ipv4_addr);
			return NULL;
		}

		/*
		 * If we have a GW for this address, then we have to send ARP request to the GW
		 */
		if (!ECM_IP_ADDR_IS_NULL(gw_addr)) {
			ECM_IP_ADDR_COPY(addr, gw_addr);
		}

		DEBUG_TRACE("Send ARP for %pI4 using src_ip as %pI4\n", &ipv4_addr, &src_ip);
		arp_send(ARPOP_REQUEST, ETH_P_ARP, ipv4_addr, dev, src_ip, NULL, NULL, NULL);

		/*
		 * By returning NULL the connection will not be created and the packet dropped.
		 * However the sending will no doubt re-try the transmission and by that time we shall have the MAC for it.
		 */
		return NULL;
	}

	ni = ecm_front_end_ipv4_node_establish_and_ref(dev, node_mac_addr);
	if (!ni) {
		DEBUG_WARN("Failed to establish node\n");
		return NULL;
	}

	/*
	 * No host - create one
	 */
	nhi = ecm_db_host_alloc();
	if (!nhi) {
		DEBUG_WARN("Failed to establish host\n");
		ecm_db_node_deref(ni);
		return NULL;
	}

	/*
	 * Add host into the database, atomically to avoid races creating the same thing
	 */
	spin_lock_bh(&ecm_front_end_ipv4_lock);
	hi = ecm_db_host_find_and_ref(addr);
	if (hi) {
		spin_unlock_bh(&ecm_front_end_ipv4_lock);
		ecm_db_host_deref(nhi);
		ecm_db_node_deref(ni);
		return hi;
	}

	ecm_db_host_add(nhi, ni, addr, on_link, ecm_front_end_ipv4_host_final, nhi);

	/*
	 * Ensure our thread persists (and hence this module) for as long as the connection and its supporting framework is alive
	 * as we could get callbacks from the database
	 */
	ecm_front_end_ipv4_thread_refs++;
	DEBUG_ASSERT(ecm_front_end_ipv4_thread_refs > 0, "Thread refs wrap %d\n", ecm_front_end_ipv4_thread_refs);
	spin_unlock_bh(&ecm_front_end_ipv4_lock);

	/*
	 * Don't need node instance now
	 */
	ecm_db_node_deref(ni);

	DEBUG_TRACE("%p: host established\n", nhi);
	return nhi;
}

/*
 * _ecm_front_end_ipv4_mapping_establish_and_ref()
 *	Returns a reference to a mapping, possibly creating one if necessary.
 *
 * Returns NULL on failure.
 */
static struct ecm_db_mapping_instance *ecm_front_end_ipv4_mapping_establish_and_ref(struct net_device *dev, ip_addr_t addr, int port)
{
	struct ecm_db_mapping_instance *mi;
	struct ecm_db_mapping_instance *nmi;
	struct ecm_db_host_instance *hi;

	DEBUG_INFO("Establish mapping for " ECM_IP_ADDR_DOT_FMT ":%d\n", ECM_IP_ADDR_TO_DOT(addr), port);

	/*
	 * Locate the mapping
	 */
	mi = ecm_db_mapping_find_and_ref(addr, port);
	if (mi) {
		DEBUG_TRACE("%p: mapping established\n", mi);
		return mi;
	}

	/*
	 * No mapping - establish host existence
	 */
	hi = ecm_front_end_ipv4_host_establish_and_ref(dev, addr);
	if (!hi) {
		DEBUG_WARN("Failed to establish host\n");
		return NULL;
	}

	/*
	 * Create mapping instance
	 */
	nmi = ecm_db_mapping_alloc();
	if (!nmi) {
		ecm_db_host_deref(hi);
		DEBUG_WARN("Failed to establish mapping\n");
		return NULL;
	}

	/*
	 * Add mapping into the database, atomically to avoid races creating the same thing
	 */
	spin_lock_bh(&ecm_front_end_ipv4_lock);
	mi = ecm_db_mapping_find_and_ref(addr, port);
	if (mi) {
		spin_unlock_bh(&ecm_front_end_ipv4_lock);
		ecm_db_mapping_deref(nmi);
		ecm_db_host_deref(hi);
		return mi;
	}

	ecm_db_mapping_add(nmi, hi, port, ecm_front_end_ipv4_mapping_final, nmi);

	/*
	 * Ensure our thread persists (and hence this module) for as long as the connection and its supporting framework is alive
	 * as we could get callbacks from the database
	 */
	ecm_front_end_ipv4_thread_refs++;
	DEBUG_ASSERT(ecm_front_end_ipv4_thread_refs > 0, "Thread refs wrap %d\n", ecm_front_end_ipv4_thread_refs);
	spin_unlock_bh(&ecm_front_end_ipv4_lock);

	/*
	 * Don't need the host instance now - the mapping maintains a reference to it now.
	 */
	ecm_db_host_deref(hi);

	/*
	 * Return the mapping instance
	 */
	DEBUG_INFO("%p: mapping established\n", nmi);
	return nmi;
}

/*
 * ecm_front_end_ipv4_connection_tcp_front_end_accelerate()
 *	Accelerate a connection
 */
static void ecm_front_end_ipv4_connection_tcp_front_end_accelerate(struct ecm_front_end_connection_instance *feci,
									struct ecm_classifier_process_response *pr)
{
	struct ecm_front_end_ipv4_connection_tcp_instance *fecti = (struct ecm_front_end_ipv4_connection_tcp_instance *)feci;
	int32_t from_ifaces_first;
	int32_t to_ifaces_first;
	struct ecm_db_iface_instance *from_ifaces[ECM_DB_IFACE_HEIRARCHY_MAX];
	struct ecm_db_iface_instance *to_ifaces[ECM_DB_IFACE_HEIRARCHY_MAX];
	struct ecm_db_iface_instance *from_nss_iface;
	struct ecm_db_iface_instance *to_nss_iface;
	int32_t from_nss_iface_id;
	int32_t to_nss_iface_id;
	uint8_t from_nss_iface_address[ETH_ALEN];
	uint8_t to_nss_iface_address[ETH_ALEN];
	struct nf_conntrack_tuple_hash *h;
	struct nf_conntrack_tuple tuple;
	ip_addr_t addr;
	struct nss_ipv4_create create;
	struct ecm_classifier_instance *assignments[ECM_CLASSIFIER_TYPES];
	int aci_index;
	int assignment_count;
	nss_tx_status_t nss_tx_status;
	int32_t list_index;
	int32_t interface_type_counts[ECM_DB_IFACE_TYPE_COUNT];
	bool rule_invalid;

	DEBUG_CHECK_MAGIC(fecti, ECM_FRONT_END_IPV4_CONNECTION_TCP_INSTANCE_MAGIC, "%p: magic failed", fecti);

	/*
	 * Can this connection be accelerated at all?
	 */
	DEBUG_INFO("%p: Accel conn: %p\n", fecti, fecti->ci);
	spin_lock_bh(&fecti->lock);
	if (!fecti->can_accel) {
		spin_unlock_bh(&fecti->lock);
		DEBUG_TRACE("%p: accel %p denied\n", fecti, fecti->ci);
		return;
	}

	/*
	 * Have we tried to accelerate unsuccessfully too many times?
	 */
	if (fecti->accel_count >= fecti->accel_limit) {
		spin_unlock_bh(&fecti->lock);
		DEBUG_WARN("%p: accel limit reached for %p\n", fecti, fecti->ci);
		return;
	}

	/*
	 * If acceleration mode is currently different then switch modes
	 */
	if (fecti->accel_mode == ECM_CLASSIFIER_ACCELERATION_MODE_ACCEL) {
		spin_unlock_bh(&fecti->lock);
		DEBUG_TRACE("%p: Ignoring duplicate accel for conn: %p\n", fecti, fecti->ci);
		return;
	}
	fecti->accel_mode = ECM_CLASSIFIER_ACCELERATION_MODE_ACCEL;
	fecti->accel_count++;
	spin_unlock_bh(&fecti->lock);

	/*
	 * Okay construct an accel command.
	 * Initialise creation structure
	 */
	memset(&create, 0, sizeof(create));

	/*
	 * Initialize VLAN tag information
	 */
	create.ingress_vlan_tag = ECM_NSS_CONNMGR_VLAN_ID_NOT_CONFIGURED;
	create.egress_vlan_tag = ECM_NSS_CONNMGR_VLAN_ID_NOT_CONFIGURED;

	/*
	 * Get the interface lists of the connection
	 */
	from_ifaces_first = ecm_db_connection_from_interfaces_get_and_ref(fecti->ci, from_ifaces);
	to_ifaces_first = ecm_db_connection_to_interfaces_get_and_ref(fecti->ci, to_ifaces);

	/*
	 * Must have at least one interface in each list
	 */
	if ((from_ifaces_first == ECM_DB_IFACE_HEIRARCHY_MAX) || (to_ifaces_first == ECM_DB_IFACE_HEIRARCHY_MAX)) {
		DEBUG_WARN("%p: Accel attempt failed - no interfaces in lists?!\n", fecti);
		spin_lock_bh(&fecti->lock);
		if (fecti->accel_mode == ECM_CLASSIFIER_ACCELERATION_MODE_ACCEL) {
			fecti->accel_mode = ECM_CLASSIFIER_ACCELERATION_MODE_NO;
		}
		spin_unlock_bh(&fecti->lock);
		return;
	}

	/*
	 * First interface in each must be a known nss interface
	 */
	from_nss_iface = from_ifaces[from_ifaces_first];
	to_nss_iface = to_ifaces[to_ifaces_first];
	from_nss_iface_id = ecm_db_iface_nss_interface_identifier_get(from_nss_iface);
	to_nss_iface_id = ecm_db_iface_nss_interface_identifier_get(to_nss_iface);
	if ((from_nss_iface_id < 0) || (to_nss_iface_id < 0)) {
		DEBUG_TRACE("%p: from_nss_iface_id: %d, to_nss_iface_id: %d\n", fecti, from_nss_iface_id, to_nss_iface_id);
		spin_lock_bh(&fecti->lock);
		if (fecti->accel_mode == ECM_CLASSIFIER_ACCELERATION_MODE_ACCEL) {
			fecti->accel_mode = ECM_CLASSIFIER_ACCELERATION_MODE_NO;
		}
		spin_unlock_bh(&fecti->lock);
		ecm_db_connection_interfaces_deref(from_ifaces, from_ifaces_first);
		ecm_db_connection_interfaces_deref(to_ifaces, to_ifaces_first);
		return;
	}

	/*
	 * Set interface numbers involved in accelerating this connection.
	 * These are the outer facing addresses from the heirarchy interface lists we got above.
	 * These may be overridden later if we detect special interface types e.g. ipsec.
	 */
	create.src_interface_num = from_nss_iface_id;
	create.dest_interface_num = to_nss_iface_id;

	/*
	 * We know that each outward facing interface is known to the NSS and so this connection could be accelerated.
	 * However the lists may also specify other interesting details that must be included in the creation command,
	 * for example, ethernet MAC, VLAN tagging or PPPoE session information.
	 * We get this information by walking from the outer to the innermost interface for each list and examine the interface types.
	 *
	 * Start with the 'from' (src) side.
	 * NOTE: The lists may contain a complex heirarchy of similar type of interface e.g. multiple vlans or tunnels within tunnels.
	 * This NSS cannot handle that - there is no way to describe this in the rule - if we see multiple types that would conflict we have to abort.
	 */
	DEBUG_TRACE("%p: Examine from/src heirarchy list\n", fecti);
	memset(interface_type_counts, 0, sizeof(interface_type_counts));
	rule_invalid = false;
	for (list_index = from_ifaces_first; !rule_invalid && (list_index < ECM_DB_IFACE_HEIRARCHY_MAX); list_index++) {
		struct ecm_db_iface_instance *ii;
		ecm_db_iface_type_t ii_type;
		char *ii_name;

		ii = from_ifaces[list_index];
		ii_type = ecm_db_connection_iface_type_get(ii);
		ii_name = ecm_db_interface_type_to_string(ii_type);
		DEBUG_TRACE("%p: list_index: %d, ii: %p, type: %d (%s)\n", fecti, list_index, ii, ii_type, ii_name);

		/*
		 * Extract information from this interface type if it is applicable to the rule.
		 * Conflicting information may cause accel to be unsupported.
		 */
		switch (ii_type) {
			struct ecm_db_interface_info_pppoe pppoe_info;
			struct ecm_db_interface_info_vlan vlan_info;

		case ECM_DB_IFACE_TYPE_ETHERNET:
			DEBUG_TRACE("%p: Ethernet\n", fecti);
			if (interface_type_counts[ii_type] != 0) {
				/*
				 * Ignore additional mac addresses, these are usually as a result of address propagation
				 * from bridges down to ports etc.
				 */
				DEBUG_TRACE("%p: Ethernet - ignore additional\n", fecti);
				break;
			}

			/*
			 * Can only handle one MAC, the first outermost mac.
			 */
			ecm_db_iface_ethernet_address_get(ii, from_nss_iface_address);
			DEBUG_TRACE("%p: Ethernet - mac: %pM\n", fecti, from_nss_iface_address);
			break;
		case ECM_DB_IFACE_TYPE_PPPOE:
			/*
			 * GGG TODO For now we don't support PPPoE so this is an invalid rule
			 */
			DEBUG_TRACE("%p: PPPoE - unsupported right now\n", fecti);
			rule_invalid = true;

			if (interface_type_counts[ii_type] != 0) {
				DEBUG_TRACE("%p: PPPoE - additional unsupported\n", fecti);
				rule_invalid = true;
				break;
			}

			/*
			 * Copy pppoe session info to the creation structure.
			 */
			ecm_db_iface_pppoe_session_info_get(ii, &pppoe_info);
			create.flow_pppoe_session_id = pppoe_info.pppoe_session_id;
			memcpy(create.flow_pppoe_remote_mac, pppoe_info.remote_mac, ETH_ALEN);
			DEBUG_TRACE("%p: PPPoE - session: %x, mac: %pM\n", fecti, create.flow_pppoe_session_id, create.flow_pppoe_remote_mac);
			break;
		case ECM_DB_IFACE_TYPE_VLAN:
			DEBUG_TRACE("%p: VLAN\n", fecti);
			if (interface_type_counts[ii_type] != 0) {
				/*
				 * Can only support one vlan
				 */
				rule_invalid = true;
				DEBUG_TRACE("%p: VLAN - additional unsupported\n", fecti);
				break;
			}
			ecm_db_iface_vlan_info_get(ii, &vlan_info);
			create.ingress_vlan_tag = vlan_info.vlan_tag;

			/*
			 * If we have not yet got an ethernet mac then take this one (very unlikely as mac should have been propagated to the slave (outer) device
			 */
			if (interface_type_counts[ECM_DB_IFACE_TYPE_ETHERNET] == 0) {
				memcpy(from_nss_iface_address, vlan_info.address, ETH_ALEN);
				interface_type_counts[ECM_DB_IFACE_TYPE_ETHERNET]++;
				DEBUG_TRACE("%p: VLAN use mac: %pM\n", fecti, from_nss_iface_address);
			}
			DEBUG_TRACE("%p: vlan tag: %x\n", fecti, create.ingress_vlan_tag);
			break;
		case ECM_DB_IFACE_TYPE_IPSEC_TUNNEL:
			DEBUG_TRACE("%p: IPSEC\n", fecti);
			if (interface_type_counts[ii_type] != 0) {
				/*
				 * Can only support one ipsec
				 */
				rule_invalid = true;
				DEBUG_TRACE("%p: IPSEC - additional unsupported\n", fecti);
				break;
			}
			create.src_interface_num = NSS_C2C_TX_INTERFACE;
			break;
		default:
			DEBUG_TRACE("%p: Ignoring: %d (%s)\n", fecti, ii_type, ii_name);
		}

		/*
		 * Seen an interface of this type
		 */
		interface_type_counts[ii_type]++;
	}
	if (rule_invalid) {
		DEBUG_WARN("%p: from/src Rule invalid\n", fecti);
		spin_lock_bh(&fecti->lock);
		if (fecti->accel_mode == ECM_CLASSIFIER_ACCELERATION_MODE_ACCEL) {
			fecti->accel_mode = ECM_CLASSIFIER_ACCELERATION_MODE_NO;
		}
		spin_unlock_bh(&fecti->lock);
		ecm_db_connection_interfaces_deref(from_ifaces, from_ifaces_first);
		ecm_db_connection_interfaces_deref(to_ifaces, to_ifaces_first);
		return;
	}

	/*
	 * Now examine the TO / DEST heirarchy list to construct the destination part of the rule
	 */
	DEBUG_TRACE("%p: Examine to/dest heirarchy list\n", fecti);
	memset(interface_type_counts, 0, sizeof(interface_type_counts));
	rule_invalid = false;
	for (list_index = to_ifaces_first; !rule_invalid && (list_index < ECM_DB_IFACE_HEIRARCHY_MAX); list_index++) {
		struct ecm_db_iface_instance *ii;
		ecm_db_iface_type_t ii_type;
		char *ii_name;

		ii = to_ifaces[list_index];
		ii_type = ecm_db_connection_iface_type_get(ii);
		ii_name = ecm_db_interface_type_to_string(ii_type);
		DEBUG_TRACE("%p: list_index: %d, ii: %p, type: %d (%s)\n", fecti, list_index, ii, ii_type, ii_name);

		/*
		 * Extract information from this interface type if it is applicable to the rule.
		 * Conflicting information may cause accel to be unsupported.
		 */
		switch (ii_type) {
			struct ecm_db_interface_info_pppoe pppoe_info;
			struct ecm_db_interface_info_vlan vlan_info;

		case ECM_DB_IFACE_TYPE_ETHERNET:
			DEBUG_TRACE("%p: Ethernet\n", fecti);
			if (interface_type_counts[ii_type] != 0) {
				/*
				 * Ignore additional mac addresses, these are usually as a result of address propagation
				 * from bridges down to ports etc.
				 */
				DEBUG_TRACE("%p: Ethernet - ignore additional\n", fecti);
				break;
			}

			/*
			 * Can only handle one MAC, the first outermost mac.
			 */
			ecm_db_iface_ethernet_address_get(ii, to_nss_iface_address);
			DEBUG_TRACE("%p: Ethernet - mac: %pM\n", fecti, to_nss_iface_address);
			break;
		case ECM_DB_IFACE_TYPE_PPPOE:
			/*
			 * GGG TODO For now we don't support PPPoE so this is an invalid rule
			 */
			DEBUG_TRACE("%p: PPPoE - unsupported right now\n", fecti);
			rule_invalid = true;

			if (interface_type_counts[ii_type] != 0) {
				DEBUG_TRACE("%p: PPPoE - additional unsupported\n", fecti);
				rule_invalid = true;
				break;
			}

			/*
			 * Copy pppoe session info to the creation structure.
			 */
			ecm_db_iface_pppoe_session_info_get(ii, &pppoe_info);
			create.return_pppoe_session_id = pppoe_info.pppoe_session_id;
			memcpy(create.return_pppoe_remote_mac, pppoe_info.remote_mac, ETH_ALEN);
			DEBUG_TRACE("%p: PPPoE - session: %x, mac: %pM\n", fecti, create.return_pppoe_session_id, create.return_pppoe_remote_mac);
			break;
		case ECM_DB_IFACE_TYPE_VLAN:
			DEBUG_TRACE("%p: VLAN\n", fecti);
			if (interface_type_counts[ii_type] != 0) {
				/*
				 * Can only support one vlan
				 */
				rule_invalid = true;
				DEBUG_TRACE("%p: VLAN - additional unsupported\n", fecti);
				break;
			}
			ecm_db_iface_vlan_info_get(ii, &vlan_info);
			create.egress_vlan_tag = vlan_info.vlan_tag;

			/*
			 * If we have not yet got an ethernet mac then take this one (very unlikely as mac should have been propagated to the slave (outer) device
			 */
			if (interface_type_counts[ECM_DB_IFACE_TYPE_ETHERNET] == 0) {
				memcpy(to_nss_iface_address, vlan_info.address, ETH_ALEN);
				interface_type_counts[ECM_DB_IFACE_TYPE_ETHERNET]++;
				DEBUG_TRACE("%p: VLAN use mac: %pM\n", fecti, to_nss_iface_address);
			}
			DEBUG_TRACE("%p: vlan tag: %x\n", fecti, create.egress_vlan_tag);
			break;
		case ECM_DB_IFACE_TYPE_IPSEC_TUNNEL:
			DEBUG_TRACE("%p: IPSEC\n", fecti);
			if (interface_type_counts[ii_type] != 0) {
				/*
				 * Can only support one ipsec
				 */
				rule_invalid = true;
				DEBUG_TRACE("%p: IPSEC - additional unsupported\n", fecti);
				break;
			}
			create.dest_interface_num = NSS_C2C_TX_INTERFACE;
			break;
		default:
			DEBUG_TRACE("%p: Ignoring: %d (%s)\n", fecti, ii_type, ii_name);
		}

		/*
		 * Seen an interface of this type
		 */
		interface_type_counts[ii_type]++;
	}
	if (rule_invalid) {
		DEBUG_WARN("%p: to/dest Rule invalid\n", fecti);
		spin_lock_bh(&fecti->lock);
		if (fecti->accel_mode == ECM_CLASSIFIER_ACCELERATION_MODE_ACCEL) {
			fecti->accel_mode = ECM_CLASSIFIER_ACCELERATION_MODE_NO;
		}
		spin_unlock_bh(&fecti->lock);
		ecm_db_connection_interfaces_deref(from_ifaces, from_ifaces_first);
		ecm_db_connection_interfaces_deref(to_ifaces, to_ifaces_first);
		return;
	}

	/*
	 * Routed or bridged?
	 */
	if (ecm_db_connection_is_routed_get(fecti->ci)) {
		create.flags |= NSS_IPV4_CREATE_FLAG_ROUTED;
	} else {
		create.flags |= NSS_IPV4_CREATE_FLAG_BRIDGE_FLOW;
	}

	/*
	 * Store the skb->priority as the qos tag
	 */
	create.qos_tag = (uint32_t)pr->qos_tag;

	/*
	 * Set protocol
	 */
	create.protocol = (int32_t)IPPROTO_TCP;

	/*
	 * The src_ip is where the connection established from
	 */
	ecm_db_connection_from_address_get(fecti->ci, addr);
	ECM_IP_ADDR_TO_HIN4_ADDR(create.src_ip, addr);

	/*
	 * The dest_ip is where the connection is established to, however, in the case of ingress
	 * the dest_ip would be the routers WAN IP - i.e. the NAT'ed version.
	 * Getting the NAT'ed version here works for ingress or egress packets, for egress
	 * the NAT'ed version would be the same as the normal address
	 */
	ecm_db_connection_to_address_nat_get(fecti->ci, addr);
	ECM_IP_ADDR_TO_HIN4_ADDR(create.dest_ip, addr);

	/*
	 * When the packet is forwarded to the next interface get the address the source IP of the
	 * packet should be translated to.  For egress this is the NAT'ed from address.
	 * This also works for ingress as the NAT'ed version of the WAN host would be the same as non-NAT'ed
	 */
	ecm_db_connection_from_address_nat_get(fecti->ci, addr);
	ECM_IP_ADDR_TO_HIN4_ADDR(create.src_ip_xlate, addr);

	/*
	 * The destination address is what the destination IP is translated to as it is forwarded to the next interface.
	 * For egress this would yield the normal wan host and for ingress this would correctly NAT back to the LAN host
	 */
	ecm_db_connection_to_address_get(fecti->ci, addr);
	ECM_IP_ADDR_TO_HIN4_ADDR(create.dest_ip_xlate, addr);

	/*
	 * Same approach as above for port information
	 */
	create.src_port = ecm_db_connection_from_port_get(fecti->ci);
	create.dest_port = ecm_db_connection_to_port_nat_get(fecti->ci);
	create.src_port_xlate = ecm_db_connection_from_port_nat_get(fecti->ci);
	create.dest_port_xlate = ecm_db_connection_to_port_get(fecti->ci);

	/*
	 * Get mac addresses.
	 * The src_mac is the mac address of the node that established the connection.
	 * This will work whether the from_node is LAN (egress) or WAN (ingress).
	 */
	ecm_db_connection_from_node_address_get(fecti->ci, create.src_mac);

	/*
	 * The dest_mac is more complex.  For egress it is the node address of the 'to' side of the connection.
	 * For ingress it is the node adress of the NAT'ed 'to' IP.
	 * Essentially it is the MAC of node associated with create.dest_ip and this is "to nat" side.
	 */
	ecm_db_connection_to_nat_node_address_get(fecti->ci, create.dest_mac);

	/*
	 * The src_mac_xlate is the mac address to replace the src_mac when sent onto the next interface
	 * This is, therefore, the interface mac of the 'to' side of the connection.
	 */
	memcpy(create.src_mac_xlate, to_nss_iface_address, ETH_ALEN);

	/*
	 * The dest_mac_xlate replaces the destination mac of a packet when sent on the next interface.
	 * By getting the MAC of node associated with dest_ip_xlate we can satisfy ingress and egress cases.
	 */
	ecm_db_connection_to_node_address_get(fecti->ci, create.dest_mac_xlate);

	/*
	 * Need window scaling and remarking information if available
	 * Start by looking up the conntrack connection
	 */
	memset(&tuple, 0, sizeof(tuple));
	tuple.src.u3.ip = htonl(create.src_ip);
	tuple.src.u.all = (__be16)htons(create.src_port);
	tuple.src.l3num = AF_INET;

	tuple.dst.u3.ip = htonl(create.dest_ip);
	tuple.dst.dir = IP_CT_DIR_ORIGINAL;
	tuple.dst.protonum = (uint8_t)IPPROTO_TCP;
	tuple.dst.u.all = (__be16)htons(create.dest_port);

	h = nf_conntrack_find_get(&init_net, NF_CT_DEFAULT_ZONE, &tuple);
	if (!h) {
		/*
		 * No conntrack so no need to check window sequence space
		 */
		DEBUG_TRACE("%p: TCP Accel no ct from conn %p to get window data\n", fecti, fecti->ci);
		create.flags |= NSS_IPV4_CREATE_FLAG_NO_SEQ_CHECK;
	} else {
		struct nf_conn *ct;
		ct = nf_ct_tuplehash_to_ctrack(h);

		DEBUG_TRACE("%p: TCP Accel Get window data from ct %p for conn %p\n", fecti, ct, fecti->ci);
		spin_lock_bh(&ct->lock);
		create.flow_window_scale = ct->proto.tcp.seen[0].td_scale;
		create.flow_max_window = ct->proto.tcp.seen[0].td_maxwin;
		create.flow_end = ct->proto.tcp.seen[0].td_end;
		create.flow_max_end = ct->proto.tcp.seen[0].td_maxend;
		create.return_window_scale = ct->proto.tcp.seen[1].td_scale;
		create.return_max_window = ct->proto.tcp.seen[1].td_maxwin;
		create.return_end = ct->proto.tcp.seen[1].td_end;
		create.return_max_end = ct->proto.tcp.seen[1].td_maxend;
		if (nf_ct_tcp_be_liberal || nf_ct_tcp_no_window_check
				|| (ct->proto.tcp.seen[0].flags & IP_CT_TCP_FLAG_BE_LIBERAL)
				|| (ct->proto.tcp.seen[1].flags & IP_CT_TCP_FLAG_BE_LIBERAL)) {
			create.flags |= NSS_IPV4_CREATE_FLAG_NO_SEQ_CHECK;
		}
		spin_unlock_bh(&ct->lock);

		/*
		 * Initialize DSCP MARKING information
		 */
		if (offload_dscpremark_get_target_info(ct, &create.dscp_imask, &create.dscp_itag, &create.dscp_omask, &create.dscp_oval)) {
			DEBUG_TRACE("%p: DSCP remark information present on: %p\n\timask: %x, itag: %x, omask: %x, oval: %x\n",
				fecti->ci, ct, create.dscp_imask, create.dscp_itag, create.dscp_omask, create.dscp_oval);
			create.flags |= NSS_IPV4_CREATE_FLAG_DSCP_MARKING;
		} else {
			DEBUG_TRACE("%p: DSCP remark information is not present on: %p\n", fecti->ci, ct);
			create.dscp_itag = ECM_NSS_CONNMGR_DSCP_MARKING_NOT_CONFIGURED;
			create.dscp_imask = ECM_NSS_CONNMGR_DSCP_MARKING_NOT_CONFIGURED;
			create.dscp_omask = ECM_NSS_CONNMGR_DSCP_MARKING_NOT_CONFIGURED;
			create.dscp_oval = ECM_NSS_CONNMGR_DSCP_MARKING_NOT_CONFIGURED;
		}

		/*
		 * Initialize VLAN MARKING information
		 */
		if (offload_vlantag_get_target_info(ct, &create.vlan_imask, &create.vlan_itag, &create.vlan_omask, &create.vlan_oval)) {
			DEBUG_TRACE("%p: VLAN marking information present on: %p\n\timask: %x, itag: %x, omask: %x, oval: %x\n",
				fecti->ci, ct, create.vlan_imask, create.vlan_itag, create.vlan_omask, create.vlan_oval);
			create.flags |= NSS_IPV4_CREATE_FLAG_VLAN_MARKING;
		} else {
			DEBUG_TRACE("%p: VLAN marking information is not present on: %p\n", fecti->ci, ct);
			create.vlan_itag = ECM_NSS_CONNMGR_VLAN_MARKING_NOT_CONFIGURED;
			create.vlan_imask= ECM_NSS_CONNMGR_VLAN_MARKING_NOT_CONFIGURED;
			create.vlan_omask = ECM_NSS_CONNMGR_VLAN_MARKING_NOT_CONFIGURED;
			create.vlan_oval = ECM_NSS_CONNMGR_VLAN_MARKING_NOT_CONFIGURED;
		}

		nf_ct_put(ct);
	}

	/*
	 * Get MTU information
	 */
	create.from_mtu = (uint32_t)ecm_db_connection_from_iface_mtu_get(fecti->ci);
	create.to_mtu = (uint32_t)ecm_db_connection_to_iface_mtu_get(fecti->ci);

	/*
	 * Sync our creation command from the assigned classifiers to get specific additional creation rules.
	 * NOTE: These are called in ascending order of priority and so the last classifier (highest) shall
	 * override any preceding classifiers.
	 * This also gives the classifiers a chance to see that acceleration is being attempted.
	 */
	assignment_count = ecm_db_connection_classifier_assignments_get_and_ref(fecti->ci, assignments);
	for (aci_index = 0; aci_index < assignment_count; ++aci_index) {
		struct ecm_classifier_instance *aci;

		aci = assignments[aci_index];
		DEBUG_TRACE("%p: sync from: %p, type: %d\n", fecti, aci, aci->type_get(aci));
		aci->sync_from_v4(aci, &create);
	}
	ecm_db_connection_assignments_release(assignment_count, assignments);

	/*
	 * Release the interface lists
	 */
	ecm_db_connection_interfaces_deref(from_ifaces, from_ifaces_first);
	ecm_db_connection_interfaces_deref(to_ifaces, to_ifaces_first);

	DEBUG_INFO("%p: TCP Accelerate connection %p\n"
			"Protocol: %d\n"
			"from_mtu: %u\n"
			"to_mtu: %u\n"
			"from_ip: %pI4h:%d\n"
			"to_ip: %pI4h:%d\n"
			"from_ip_xlate: %pI4h:%d\n"
			"to_ip_xlate: %pI4h:%d\n"
			"from_mac: %pM\n"
			"to_mac: %pM\n"
			"from_mac_xlate: %pM\n"
			"to_mac_xlate: %pM\n"
			"src_iface_num: %u\n"
			"dest_iface_num: %u\n"
			"flow_window_scale: %u\n"
			"flow_max_window: %u\n"
			"flow_end: %u\n"
			"flow_max_end: %u\n"
			"return_window_scale: %u\n"
			"return_max_window: %u\n"
			"return_end: %u\n"
			"return_max_end: %u\n"
			"ingress_vlan_tag: %u\n"
			"egress_vlan_tag: %u\n"
			"vlan_itag: %x\n"
			"vlan_imask: %x\n"
			"vlan_omask: %x\n"
			"vlan_oval: %x\n"
			"dscp_itag: %x\n"
			"dscp_imask: %x\n"
			"dscp_omask: %x\n"
			"dscp_oval: %x\n"
			"flags: %x\n"
			"return_pppoe_session_id: %u\n"
			"return_pppoe_remote_mac: %pM\n"
			"flow_pppoe_session_id: %u\n"
			"flow_pppoe_remote_mac: %pM\n"
			"qos_tag: %x (%u)\n",
			fecti,
			fecti->ci,
			create.protocol,
			create.from_mtu,
			create.to_mtu,
			&create.src_ip, create.src_port,
			&create.dest_ip, create.dest_port,
			&create.src_ip_xlate, create.src_port_xlate,
			&create.dest_ip_xlate, create.dest_port_xlate,
			create.src_mac,
			create.dest_mac,
			create.src_mac_xlate,
			create.dest_mac_xlate,
			create.src_interface_num,
			create.dest_interface_num,
			create.flow_window_scale,
			create.flow_max_window,
			create.flow_end,
			create.flow_max_end,
			create.return_window_scale,
			create.return_max_window,
			create.return_end,
			create.return_max_end,
			create.ingress_vlan_tag,
			create.egress_vlan_tag,
			create.vlan_itag,
			create.vlan_imask,
			create.vlan_omask,
			create.vlan_oval,
			create.dscp_itag,
			create.dscp_imask,
			create.dscp_omask,
			create.dscp_oval,
			create.flags,
			create.return_pppoe_session_id,
			create.return_pppoe_remote_mac,
			create.flow_pppoe_session_id,
			create.flow_pppoe_remote_mac,
			create.qos_tag, create.qos_tag);

	/*
	 * Call the relevant rule create function
	 */
	if (create.dscp_oval == ECM_NSS_CONNMGR_DSCP_MARKING_NOT_CONFIGURED &&
			create.vlan_oval == ECM_NSS_CONNMGR_VLAN_MARKING_NOT_CONFIGURED) {
		nss_tx_status = nss_tx_create_ipv4_rule(ecm_front_end_ipv4_nss_ipv4_context, &create);
	} else {
		nss_tx_status = nss_tx_create_ipv4_rule1(ecm_front_end_ipv4_nss_ipv4_context, &create);
	}
	if (nss_tx_status == NSS_TX_SUCCESS) {
		return;
	}

	/*
	 * Revert accel mode if necessary
	 */
	DEBUG_WARN("%p: Accel attempt failed\n", fecti);
	spin_lock_bh(&fecti->lock);
	if (fecti->accel_mode == ECM_CLASSIFIER_ACCELERATION_MODE_ACCEL) {
		fecti->accel_mode = ECM_CLASSIFIER_ACCELERATION_MODE_NO;
	}
	spin_unlock_bh(&fecti->lock);
}

/*
 * ecm_front_end_ipv4_connection_tcp_front_end_decelerate()
 *	Decelerate a connection
 */
static void ecm_front_end_ipv4_connection_tcp_front_end_decelerate(struct ecm_front_end_connection_instance *feci)
{
	struct ecm_front_end_ipv4_connection_tcp_instance *fecti = (struct ecm_front_end_ipv4_connection_tcp_instance *)feci;
	struct nss_ipv4_destroy destroy;
	ip_addr_t addr;

	DEBUG_CHECK_MAGIC(fecti, ECM_FRONT_END_IPV4_CONNECTION_TCP_INSTANCE_MAGIC, "%p: magic failed", fecti);

	destroy.protocol = (int32_t)IPPROTO_TCP;

	/*
	 * Get addressing information
	 */
	ecm_db_connection_from_address_get(fecti->ci, addr);
	ECM_IP_ADDR_TO_NIN4_ADDR(destroy.src_ip, addr);
	ecm_db_connection_to_address_nat_get(fecti->ci, addr);
	ECM_IP_ADDR_TO_NIN4_ADDR(destroy.dest_ip, addr);
	destroy.src_port = ecm_db_connection_from_port_get(fecti->ci);
	destroy.dest_port = ecm_db_connection_to_port_nat_get(fecti->ci);

	DEBUG_INFO("%p: TCP Connection %p decelerate\n"
			"src_ip: %pI4:%d\n"
			"dest_ip: %pI4:%d\n",
			fecti, fecti->ci,
			&destroy.src_ip, destroy.src_port,
			&destroy.dest_ip, destroy.dest_port);

	/*
	 * Destroy the Network Accelerator connection cache entries.
	 */
	nss_tx_destroy_ipv4_rule(ecm_front_end_ipv4_nss_ipv4_context, &destroy);
}

/*
 * ecm_front_end_ipv4_connection_tcp_front_end_accel_state_get()
 *	Get acceleration state
 */
static void ecm_front_end_ipv4_connection_tcp_front_end_accel_state_get(struct ecm_front_end_connection_instance *feci,
								ecm_classifier_acceleration_mode_t *accel_mode,
								int *count, int *limit, bool *can_accel)
{
	struct ecm_front_end_ipv4_connection_tcp_instance *fecti = (struct ecm_front_end_ipv4_connection_tcp_instance *)feci;

	DEBUG_CHECK_MAGIC(fecti, ECM_FRONT_END_IPV4_CONNECTION_TCP_INSTANCE_MAGIC, "%p: magic failed", fecti);
	spin_lock_bh(&fecti->lock);
	*accel_mode = fecti->accel_mode;
	*count = fecti->accel_count;
	*limit = fecti->accel_limit;
	*can_accel = fecti->can_accel;
	spin_unlock_bh(&fecti->lock);
}

/*
 * ecm_front_end_ipv4_connection_tcp_front_end_accel_count_reset()
 *	Reset the accel counter - because the NA has sent a sync message indicating that some data was accelerated.
 */
static void ecm_front_end_ipv4_connection_tcp_front_end_accel_count_reset(struct ecm_front_end_connection_instance *feci)
{
	struct ecm_front_end_ipv4_connection_tcp_instance *fecti = (struct ecm_front_end_ipv4_connection_tcp_instance *)feci;

	DEBUG_CHECK_MAGIC(fecti, ECM_FRONT_END_IPV4_CONNECTION_TCP_INSTANCE_MAGIC, "%p: magic failed", fecti);
	DEBUG_INFO("%p: reset accel count\n", fecti);
	spin_lock_bh(&fecti->lock);
	fecti->accel_count = 0;
	spin_unlock_bh(&fecti->lock);
}

/*
 * ecm_front_end_ipv4_connection_tcp_front_end_accel_ceased()
 *	NA has indicated that acceleration has stopped.
 */
static void ecm_front_end_ipv4_connection_tcp_front_end_accel_ceased(struct ecm_front_end_connection_instance *feci)
{
	struct ecm_front_end_ipv4_connection_tcp_instance *fecti = (struct ecm_front_end_ipv4_connection_tcp_instance *)feci;

	DEBUG_CHECK_MAGIC(fecti, ECM_FRONT_END_IPV4_CONNECTION_TCP_INSTANCE_MAGIC, "%p: magic failed", fecti);
	DEBUG_INFO("%p: accel ceased\n", fecti);
	spin_lock_bh(&fecti->lock);
	fecti->accel_mode = ECM_CLASSIFIER_ACCELERATION_MODE_NO;
	spin_unlock_bh(&fecti->lock);
}

/*
 * ecm_front_end_ipv4_connection_tcp_front_end_ref()
 *	Ref a connection front end instance
 */
static void ecm_front_end_ipv4_connection_tcp_front_end_ref(struct ecm_front_end_connection_instance *feci)
{
	struct ecm_front_end_ipv4_connection_tcp_instance *fecti = (struct ecm_front_end_ipv4_connection_tcp_instance *)feci;

	DEBUG_CHECK_MAGIC(fecti, ECM_FRONT_END_IPV4_CONNECTION_TCP_INSTANCE_MAGIC, "%p: magic failed", fecti);
	spin_lock_bh(&fecti->lock);
	fecti->refs++;
	DEBUG_TRACE("%p: fecti ref %d\n", fecti, fecti->refs);
	DEBUG_ASSERT(fecti->refs > 0, "%p: ref wrap\n", fecti);
	spin_unlock_bh(&fecti->lock);
}

/*
 * ecm_front_end_ipv4_connection_tcp_front_end_deref()
 *	Deref a connection front end instance
 */
static int ecm_front_end_ipv4_connection_tcp_front_end_deref(struct ecm_front_end_connection_instance *feci)
{
	struct ecm_front_end_ipv4_connection_tcp_instance *fecti = (struct ecm_front_end_ipv4_connection_tcp_instance *)feci;

	DEBUG_CHECK_MAGIC(fecti, ECM_FRONT_END_IPV4_CONNECTION_TCP_INSTANCE_MAGIC, "%p: magic failed", fecti);

	spin_lock_bh(&fecti->lock);
	fecti->refs--;
	DEBUG_ASSERT(fecti->refs >= 0, "%p: ref wrap\n", fecti);

	if (fecti->refs > 0) {
		int refs = fecti->refs;
		spin_unlock_bh(&fecti->lock);
		DEBUG_TRACE("%p: fecti deref %d\n", fecti, refs);
		return refs;
	}
	spin_unlock_bh(&fecti->lock);

	/*
	 * We can now destroy the instance
	 */
	DEBUG_TRACE("%p: fecti final\n", fecti);
	kfree(fecti);
	DEBUG_CLEAR_MAGIC(fecti);

	/*
	 * No longer need ref to thread for this object
	 */
	spin_lock_bh(&ecm_front_end_ipv4_lock);
	ecm_front_end_ipv4_thread_refs--;
	DEBUG_ASSERT(ecm_front_end_ipv4_thread_refs >= 0, "Thread refs wrap %d\n", ecm_front_end_ipv4_thread_refs);
	spin_unlock_bh(&ecm_front_end_ipv4_lock);

	/*
	 * Thread may be able to exit on object destruction
	 */
	wake_up_process(ecm_front_end_ipv4_thread);
	return 0;
}

/*
 * ecm_front_end_ipv4_connection_tcp_front_end_xml_state_get()
 *	Return an XML element containing the state of this TCP front end instance
 */
static int ecm_front_end_ipv4_connection_tcp_front_end_xml_state_get(struct ecm_front_end_connection_instance *feci, char *buf, int buf_sz)
{
	bool can_accel;
	ecm_classifier_acceleration_mode_t accel_mode;
	int accel_count;
	int accel_limit;
	struct ecm_front_end_ipv4_connection_tcp_instance *fecti = (struct ecm_front_end_ipv4_connection_tcp_instance *)feci;

	DEBUG_CHECK_MAGIC(fecti, ECM_FRONT_END_IPV4_CONNECTION_TCP_INSTANCE_MAGIC, "%p: magic failed", fecti);

	spin_lock_bh(&fecti->lock);
	can_accel = fecti->can_accel;
	accel_mode = fecti->accel_mode;
	accel_count = fecti->accel_count;
	accel_limit = fecti->accel_limit;
	spin_unlock_bh(&fecti->lock);

	return snprintf(buf, buf_sz, "<front_end_tcp can_accel=\"%u\" accel_mode=\"%d\" "
			"accel_count=\"%d\" accel_limit=\"%d\"/>\n",
			can_accel,
			accel_mode,
			accel_count,
			accel_limit);

}

/*
 * ecm_front_end_ipv4_connection_tcp_instance_alloc()
 *	Create a front end instance specific for TCP connection
 */
static struct ecm_front_end_ipv4_connection_tcp_instance *ecm_front_end_ipv4_connection_tcp_instance_alloc(
								struct ecm_db_connection_instance *ci,
								struct ecm_db_mapping_instance *src_mi,
								struct ecm_db_mapping_instance *dest_mi,
								bool can_accel)
{
	struct ecm_front_end_ipv4_connection_tcp_instance *fecti;

	fecti = (struct ecm_front_end_ipv4_connection_tcp_instance *)kzalloc(sizeof(struct ecm_front_end_ipv4_connection_tcp_instance), GFP_ATOMIC | __GFP_NOWARN);
	if (!fecti) {
		DEBUG_WARN("TCP Front end alloc failed\n");
		return NULL;
	}

	/*
	 * Refs is 1 for the creator of the connection
	 */
	fecti->refs = 1;
	DEBUG_SET_MAGIC(fecti, ECM_FRONT_END_IPV4_CONNECTION_TCP_INSTANCE_MAGIC);
	spin_lock_init(&fecti->lock);

	fecti->accel_mode = ECM_CLASSIFIER_ACCELERATION_MODE_NO;
	fecti->can_accel = can_accel;
	spin_lock_bh(&ecm_front_end_ipv4_lock);
	fecti->accel_limit = ecm_front_end_ipv4_accel_limit_default;
	spin_unlock_bh(&ecm_front_end_ipv4_lock);

	/*
	 * Copy reference to connection - no need to ref ci as ci maintains a ref to this instance instead (this instance persists for as long as ci does)
	 */
	fecti->ci = ci;

	/*
	 * Populate the methods and callbacks
	 */
	fecti->base.ref = ecm_front_end_ipv4_connection_tcp_front_end_ref;
	fecti->base.deref = ecm_front_end_ipv4_connection_tcp_front_end_deref;
	fecti->base.decelerate = ecm_front_end_ipv4_connection_tcp_front_end_decelerate;
	fecti->base.accel_state_get = ecm_front_end_ipv4_connection_tcp_front_end_accel_state_get;
	fecti->base.accel_count_reset = ecm_front_end_ipv4_connection_tcp_front_end_accel_count_reset;
	fecti->base.accel_ceased = ecm_front_end_ipv4_connection_tcp_front_end_accel_ceased;
	fecti->base.xml_state_get = ecm_front_end_ipv4_connection_tcp_front_end_xml_state_get;

	/*
	 * Ensure our thread persists (and hence this module) for as long as the connection and its supporting framework is alive
	 * as we could get callbacks from the database
	 */
	spin_lock_bh(&ecm_front_end_ipv4_lock);
	ecm_front_end_ipv4_thread_refs++;
	DEBUG_ASSERT(ecm_front_end_ipv4_thread_refs > 0, "Thread refs wrap %d\n", ecm_front_end_ipv4_thread_refs);
	spin_unlock_bh(&ecm_front_end_ipv4_lock);
	return fecti;
}

/*
 * ecm_front_end_ipv4_connection_udp_front_end_accelerate()
 *	Accelerate a connection
 */
static void ecm_front_end_ipv4_connection_udp_front_end_accelerate(struct ecm_front_end_connection_instance *feci,
									struct ecm_classifier_process_response *pr)
{
	struct ecm_front_end_ipv4_connection_udp_instance *fecui = (struct ecm_front_end_ipv4_connection_udp_instance *)feci;
	int32_t from_ifaces_first;
	int32_t to_ifaces_first;
	struct ecm_db_iface_instance *from_ifaces[ECM_DB_IFACE_HEIRARCHY_MAX];
	struct ecm_db_iface_instance *to_ifaces[ECM_DB_IFACE_HEIRARCHY_MAX];
	struct ecm_db_iface_instance *from_nss_iface;
	struct ecm_db_iface_instance *to_nss_iface;
	int32_t from_nss_iface_id;
	int32_t to_nss_iface_id;
	uint8_t from_nss_iface_address[ETH_ALEN];
	uint8_t to_nss_iface_address[ETH_ALEN];
	struct nf_conntrack_tuple_hash *h;
	struct nf_conntrack_tuple tuple;
	ip_addr_t addr;
	struct nss_ipv4_create create;
	struct ecm_classifier_instance *assignments[ECM_CLASSIFIER_TYPES];
	int aci_index;
	int assignment_count;
	nss_tx_status_t nss_tx_status;
	int32_t list_index;
	int32_t interface_type_counts[ECM_DB_IFACE_TYPE_COUNT];
	bool rule_invalid;

	DEBUG_CHECK_MAGIC(fecui, ECM_FRONT_END_IPV4_CONNECTION_UDP_INSTANCE_MAGIC, "%p: magic failed", fecui);

	/*
	 * Can this connection be accelerated at all?
	 */
	DEBUG_INFO("%p: Accel conn: %p\n", fecui, fecui->ci);
	spin_lock_bh(&fecui->lock);
	if (!fecui->can_accel) {
		spin_unlock_bh(&fecui->lock);
		DEBUG_TRACE("%p: accel %p denied\n", fecui, fecui->ci);
		return;
	}

	/*
	 * Have we tried to accelerate unsuccessfully too many times?
	 */
	if (fecui->accel_count >= fecui->accel_limit) {
		spin_unlock_bh(&fecui->lock);
		DEBUG_WARN("%p: accel limit reached for %p\n", fecui, fecui->ci);
		return;
	}

	/*
	 * If acceleration mode is currently different then switch modes
	 */
	if (fecui->accel_mode == ECM_CLASSIFIER_ACCELERATION_MODE_ACCEL) {
		spin_unlock_bh(&fecui->lock);
		DEBUG_TRACE("%p: Ignoring duplicate accel for conn: %p\n", fecui, fecui->ci);
		return;
	}
	fecui->accel_mode = ECM_CLASSIFIER_ACCELERATION_MODE_ACCEL;
	fecui->accel_count++;
	spin_unlock_bh(&fecui->lock);

	/*
	 * Okay construct an accel command.
	 * Initialise creation structure
	 */
	memset(&create, 0, sizeof(create));

	/*
	 * Initialize VLAN tag information
	 */
	create.ingress_vlan_tag = ECM_NSS_CONNMGR_VLAN_ID_NOT_CONFIGURED;
	create.egress_vlan_tag = ECM_NSS_CONNMGR_VLAN_ID_NOT_CONFIGURED;

	/*
	 * Get the interface lists of the connection
	 */
	from_ifaces_first = ecm_db_connection_from_interfaces_get_and_ref(fecui->ci, from_ifaces);
	to_ifaces_first = ecm_db_connection_to_interfaces_get_and_ref(fecui->ci, to_ifaces);

	/*
	 * Must have at least one interface in each list
	 */
	if ((from_ifaces_first == ECM_DB_IFACE_HEIRARCHY_MAX) || (to_ifaces_first == ECM_DB_IFACE_HEIRARCHY_MAX)) {
		DEBUG_WARN("%p: Accel attempt failed - no interfaces in lists?!\n", fecui);
		spin_lock_bh(&fecui->lock);
		if (fecui->accel_mode == ECM_CLASSIFIER_ACCELERATION_MODE_ACCEL) {
			fecui->accel_mode = ECM_CLASSIFIER_ACCELERATION_MODE_NO;
		}
		spin_unlock_bh(&fecui->lock);
		return;
	}

	/*
	 * First interface in each must be a known nss interface
	 */
	from_nss_iface = from_ifaces[from_ifaces_first];
	to_nss_iface = to_ifaces[to_ifaces_first];
	from_nss_iface_id = ecm_db_iface_nss_interface_identifier_get(from_nss_iface);
	to_nss_iface_id = ecm_db_iface_nss_interface_identifier_get(to_nss_iface);
	if ((from_nss_iface_id < 0) || (to_nss_iface_id < 0)) {
		DEBUG_TRACE("%p: from_nss_iface_id: %d, to_nss_iface_id: %d\n", fecui, from_nss_iface_id, to_nss_iface_id);
		spin_lock_bh(&fecui->lock);
		if (fecui->accel_mode == ECM_CLASSIFIER_ACCELERATION_MODE_ACCEL) {
			fecui->accel_mode = ECM_CLASSIFIER_ACCELERATION_MODE_NO;
		}
		spin_unlock_bh(&fecui->lock);
		ecm_db_connection_interfaces_deref(from_ifaces, from_ifaces_first);
		ecm_db_connection_interfaces_deref(to_ifaces, to_ifaces_first);
		return;
	}

	/*
	 * Set interface numbers involved in accelerating this connection.
	 * These are the outer facing addresses from the heirarchy interface lists we got above.
	 * These may be overridden later if we detect special interface types e.g. ipsec.
	 */
	create.src_interface_num = from_nss_iface_id;
	create.dest_interface_num = to_nss_iface_id;

	/*
	 * We know that each outward facing interface is known to the NSS and so this connection could be accelerated.
	 * However the lists may also specify other interesting details that must be included in the creation command,
	 * for example, ethernet MAC, VLAN tagging or PPPoE session information.
	 * We get this information by walking from the outer to the innermost interface for each list and examine the interface types.
	 *
	 * Start with the 'from' (src) side.
	 * NOTE: The lists may contain a complex heirarchy of similar type of interface e.g. multiple vlans or tunnels within tunnels.
	 * This NSS cannot handle that - there is no way to describe this in the rule - if we see multiple types that would conflict we have to abort.
	 */
	DEBUG_TRACE("%p: Examine from/src heirarchy list\n", fecui);
	memset(interface_type_counts, 0, sizeof(interface_type_counts));
	rule_invalid = false;
	for (list_index = from_ifaces_first; !rule_invalid && (list_index < ECM_DB_IFACE_HEIRARCHY_MAX); list_index++) {
		struct ecm_db_iface_instance *ii;
		ecm_db_iface_type_t ii_type;
		char *ii_name;

		ii = from_ifaces[list_index];
		ii_type = ecm_db_connection_iface_type_get(ii);
		ii_name = ecm_db_interface_type_to_string(ii_type);
		DEBUG_TRACE("%p: list_index: %d, ii: %p, type: %d (%s)\n", fecui, list_index, ii, ii_type, ii_name);

		/*
		 * Extract information from this interface type if it is applicable to the rule.
		 * Conflicting information may cause accel to be unsupported.
		 */
		switch (ii_type) {
			struct ecm_db_interface_info_pppoe pppoe_info;
			struct ecm_db_interface_info_vlan vlan_info;

		case ECM_DB_IFACE_TYPE_ETHERNET:
			DEBUG_TRACE("%p: Ethernet\n", fecui);
			if (interface_type_counts[ii_type] != 0) {
				/*
				 * Ignore additional mac addresses, these are usually as a result of address propagation
				 * from bridges down to ports etc.
				 */
				DEBUG_TRACE("%p: Ethernet - ignore additional\n", fecui);
				break;
			}

			/*
			 * Can only handle one MAC, the first outermost mac.
			 */
			ecm_db_iface_ethernet_address_get(ii, from_nss_iface_address);
			DEBUG_TRACE("%p: Ethernet - mac: %pM\n", fecui, from_nss_iface_address);
			break;
		case ECM_DB_IFACE_TYPE_PPPOE:
			/*
			 * GGG TODO For now we don't support PPPoE so this is an invalid rule
			 */
			DEBUG_TRACE("%p: PPPoE - unsupported right now\n", fecui);
			rule_invalid = true;

			if (interface_type_counts[ii_type] != 0) {
				DEBUG_TRACE("%p: PPPoE - additional unsupported\n", fecui);
				rule_invalid = true;
				break;
			}

			/*
			 * Copy pppoe session info to the creation structure.
			 */
			ecm_db_iface_pppoe_session_info_get(ii, &pppoe_info);
			create.flow_pppoe_session_id = pppoe_info.pppoe_session_id;
			memcpy(create.flow_pppoe_remote_mac, pppoe_info.remote_mac, ETH_ALEN);
			DEBUG_TRACE("%p: PPPoE - session: %x, mac: %pM\n", fecui, create.flow_pppoe_session_id, create.flow_pppoe_remote_mac);
			break;
		case ECM_DB_IFACE_TYPE_VLAN:
			DEBUG_TRACE("%p: VLAN\n", fecui);
			if (interface_type_counts[ii_type] != 0) {
				/*
				 * Can only support one vlan
				 */
				rule_invalid = true;
				DEBUG_TRACE("%p: VLAN - additional unsupported\n", fecui);
				break;
			}
			ecm_db_iface_vlan_info_get(ii, &vlan_info);
			create.ingress_vlan_tag = vlan_info.vlan_tag;

			/*
			 * If we have not yet got an ethernet mac then take this one (very unlikely as mac should have been propagated to the slave (outer) device
			 */
			if (interface_type_counts[ECM_DB_IFACE_TYPE_ETHERNET] == 0) {
				memcpy(from_nss_iface_address, vlan_info.address, ETH_ALEN);
				interface_type_counts[ECM_DB_IFACE_TYPE_ETHERNET]++;
				DEBUG_TRACE("%p: VLAN use mac: %pM\n", fecui, from_nss_iface_address);
			}
			DEBUG_TRACE("%p: vlan tag: %x\n", fecui, create.ingress_vlan_tag);
			break;
		case ECM_DB_IFACE_TYPE_IPSEC_TUNNEL:
			DEBUG_TRACE("%p: IPSEC\n", fecui);
			if (interface_type_counts[ii_type] != 0) {
				/*
				 * Can only support one ipsec
				 */
				rule_invalid = true;
				DEBUG_TRACE("%p: IPSEC - additional unsupported\n", fecui);
				break;
			}
			create.src_interface_num = NSS_C2C_TX_INTERFACE;
			break;
		default:
			DEBUG_TRACE("%p: Ignoring: %d (%s)\n", fecui, ii_type, ii_name);
		}

		/*
		 * Seen an interface of this type
		 */
		interface_type_counts[ii_type]++;
	}
	if (rule_invalid) {
		DEBUG_WARN("%p: from/src Rule invalid\n", fecui);
		spin_lock_bh(&fecui->lock);
		if (fecui->accel_mode == ECM_CLASSIFIER_ACCELERATION_MODE_ACCEL) {
			fecui->accel_mode = ECM_CLASSIFIER_ACCELERATION_MODE_NO;
		}
		spin_unlock_bh(&fecui->lock);
		ecm_db_connection_interfaces_deref(from_ifaces, from_ifaces_first);
		ecm_db_connection_interfaces_deref(to_ifaces, to_ifaces_first);
		return;
	}

	/*
	 * Now examine the TO / DEST heirarchy list to construct the destination part of the rule
	 */
	DEBUG_TRACE("%p: Examine to/dest heirarchy list\n", fecui);
	memset(interface_type_counts, 0, sizeof(interface_type_counts));
	rule_invalid = false;
	for (list_index = to_ifaces_first; !rule_invalid && (list_index < ECM_DB_IFACE_HEIRARCHY_MAX); list_index++) {
		struct ecm_db_iface_instance *ii;
		ecm_db_iface_type_t ii_type;
		char *ii_name;

		ii = to_ifaces[list_index];
		ii_type = ecm_db_connection_iface_type_get(ii);
		ii_name = ecm_db_interface_type_to_string(ii_type);
		DEBUG_TRACE("%p: list_index: %d, ii: %p, type: %d (%s)\n", fecui, list_index, ii, ii_type, ii_name);

		/*
		 * Extract information from this interface type if it is applicable to the rule.
		 * Conflicting information may cause accel to be unsupported.
		 */
		switch (ii_type) {
			struct ecm_db_interface_info_pppoe pppoe_info;
			struct ecm_db_interface_info_vlan vlan_info;

		case ECM_DB_IFACE_TYPE_ETHERNET:
			DEBUG_TRACE("%p: Ethernet\n", fecui);
			if (interface_type_counts[ii_type] != 0) {
				/*
				 * Ignore additional mac addresses, these are usually as a result of address propagation
				 * from bridges down to ports etc.
				 */
				DEBUG_TRACE("%p: Ethernet - ignore additional\n", fecui);
				break;
			}

			/*
			 * Can only handle one MAC, the first outermost mac.
			 */
			ecm_db_iface_ethernet_address_get(ii, to_nss_iface_address);
			DEBUG_TRACE("%p: Ethernet - mac: %pM\n", fecui, to_nss_iface_address);
			break;
		case ECM_DB_IFACE_TYPE_PPPOE:
			/*
			 * GGG TODO For now we don't support PPPoE so this is an invalid rule
			 */
			DEBUG_TRACE("%p: PPPoE - unsupported right now\n", fecui);
			rule_invalid = true;

			if (interface_type_counts[ii_type] != 0) {
				DEBUG_TRACE("%p: PPPoE - additional unsupported\n", fecui);
				rule_invalid = true;
				break;
			}

			/*
			 * Copy pppoe session info to the creation structure.
			 */
			ecm_db_iface_pppoe_session_info_get(ii, &pppoe_info);
			create.return_pppoe_session_id = pppoe_info.pppoe_session_id;
			memcpy(create.return_pppoe_remote_mac, pppoe_info.remote_mac, ETH_ALEN);
			DEBUG_TRACE("%p: PPPoE - session: %x, mac: %pM\n", fecui, create.return_pppoe_session_id, create.return_pppoe_remote_mac);
			break;
		case ECM_DB_IFACE_TYPE_VLAN:
			DEBUG_TRACE("%p: VLAN\n", fecui);
			if (interface_type_counts[ii_type] != 0) {
				/*
				 * Can only support one vlan
				 */
				rule_invalid = true;
				DEBUG_TRACE("%p: VLAN - additional unsupported\n", fecui);
				break;
			}
			ecm_db_iface_vlan_info_get(ii, &vlan_info);
			create.egress_vlan_tag = vlan_info.vlan_tag;

			/*
			 * If we have not yet got an ethernet mac then take this one (very unlikely as mac should have been propagated to the slave (outer) device
			 */
			if (interface_type_counts[ECM_DB_IFACE_TYPE_ETHERNET] == 0) {
				memcpy(to_nss_iface_address, vlan_info.address, ETH_ALEN);
				interface_type_counts[ECM_DB_IFACE_TYPE_ETHERNET]++;
				DEBUG_TRACE("%p: VLAN use mac: %pM\n", fecui, to_nss_iface_address);
			}
			DEBUG_TRACE("%p: vlan tag: %x\n", fecui, create.egress_vlan_tag);
			break;
		case ECM_DB_IFACE_TYPE_IPSEC_TUNNEL:
			DEBUG_TRACE("%p: IPSEC\n", fecui);
			if (interface_type_counts[ii_type] != 0) {
				/*
				 * Can only support one ipsec
				 */
				rule_invalid = true;
				DEBUG_TRACE("%p: IPSEC - additional unsupported\n", fecui);
				break;
			}
			create.dest_interface_num = NSS_C2C_TX_INTERFACE;
			break;
		default:
			DEBUG_TRACE("%p: Ignoring: %d (%s)\n", fecui, ii_type, ii_name);
		}

		/*
		 * Seen an interface of this type
		 */
		interface_type_counts[ii_type]++;
	}
	if (rule_invalid) {
		DEBUG_WARN("%p: to/dest Rule invalid\n", fecui);
		spin_lock_bh(&fecui->lock);
		if (fecui->accel_mode == ECM_CLASSIFIER_ACCELERATION_MODE_ACCEL) {
			fecui->accel_mode = ECM_CLASSIFIER_ACCELERATION_MODE_NO;
		}
		spin_unlock_bh(&fecui->lock);
		ecm_db_connection_interfaces_deref(from_ifaces, from_ifaces_first);
		ecm_db_connection_interfaces_deref(to_ifaces, to_ifaces_first);
		return;
	}

	/*
	 * Routed or bridged?
	 */
	if (ecm_db_connection_is_routed_get(fecui->ci)) {
		create.flags |= NSS_IPV4_CREATE_FLAG_ROUTED;
	} else {
		create.flags |= NSS_IPV4_CREATE_FLAG_BRIDGE_FLOW;
	}

	/*
	 * Store the skb->priority as the qos tag
	 */
	create.qos_tag = (uint32_t)pr->qos_tag;

	/*
	 * Set protocol
	 */
	create.protocol = (int32_t)IPPROTO_UDP;

	/*
	 * The src_ip is where the connection established from
	 */
	ecm_db_connection_from_address_get(fecui->ci, addr);
	ECM_IP_ADDR_TO_HIN4_ADDR(create.src_ip, addr);

	/*
	 * The dest_ip is where the connection is established to, however, in the case of ingress
	 * the dest_ip would be the routers WAN IP - i.e. the NAT'ed version.
	 * Getting the NAT'ed version here works for ingress or egress packets, for egress
	 * the NAT'ed version would be the same as the normal address
	 */
	ecm_db_connection_to_address_nat_get(fecui->ci, addr);
	ECM_IP_ADDR_TO_HIN4_ADDR(create.dest_ip, addr);

	/*
	 * When the packet is forwarded to the next interface get the address the source IP of the
	 * packet should be translated to.  For egress this is the NAT'ed from address.
	 * This also works for ingress as the NAT'ed version of the WAN host would be the same as non-NAT'ed
	 */
	ecm_db_connection_from_address_nat_get(fecui->ci, addr);
	ECM_IP_ADDR_TO_HIN4_ADDR(create.src_ip_xlate, addr);

	/*
	 * The destination address is what the destination IP is translated to as it is forwarded to the next interface.
	 * For egress this would yield the normal wan host and for ingress this would correctly NAT back to the LAN host
	 */
	ecm_db_connection_to_address_get(fecui->ci, addr);
	ECM_IP_ADDR_TO_HIN4_ADDR(create.dest_ip_xlate, addr);

	/*
	 * Same approach as above for port information
	 */
	create.src_port = ecm_db_connection_from_port_get(fecui->ci);
	create.dest_port = ecm_db_connection_to_port_nat_get(fecui->ci);
	create.src_port_xlate = ecm_db_connection_from_port_nat_get(fecui->ci);
	create.dest_port_xlate = ecm_db_connection_to_port_get(fecui->ci);

	/*
	 * Get mac addresses.
	 * The src_mac is the mac address of the node that established the connection.
	 * This will work whether the from_node is LAN (egress) or WAN (ingress).
	 */
	ecm_db_connection_from_node_address_get(fecui->ci, create.src_mac);

	/*
	 * The dest_mac is more complex.  For egress it is the node address of the 'to' side of the connection.
	 * For ingress it is the node adress of the NAT'ed 'to' IP.
	 * Essentially it is the MAC of node associated with create.dest_ip and this is "to nat" side.
	 */
	ecm_db_connection_to_nat_node_address_get(fecui->ci, create.dest_mac);

	/*
	 * The src_mac_xlate is the mac address to replace the src_mac when sent onto the next interface
	 * This is, therefore, the interface mac of the 'to' side of the connection.
	 */
	memcpy(create.src_mac_xlate, to_nss_iface_address, ETH_ALEN);

	/*
	 * The dest_mac_xlate replaces the destination mac of a packet when sent on the next interface.
	 * By getting the MAC of node associated with dest_ip_xlate we can satisfy ingress and egress cases.
	 */
	ecm_db_connection_to_node_address_get(fecui->ci, create.dest_mac_xlate);

	/*
	 * Need window scaling and remarking information if available
	 * Start by looking up the conntrack connection
	 */
	memset(&tuple, 0, sizeof(tuple));
	tuple.src.u3.ip = htonl(create.src_ip);
	tuple.src.u.all = (__be16)htons(create.src_port);
	tuple.src.l3num = AF_INET;

	tuple.dst.u3.ip = htonl(create.dest_ip);
	tuple.dst.dir = IP_CT_DIR_ORIGINAL;
	tuple.dst.protonum = (uint8_t)IPPROTO_UDP;
	tuple.dst.u.all = (__be16)htons(create.dest_port);

	h = nf_conntrack_find_get(&init_net, NF_CT_DEFAULT_ZONE, &tuple);
	if (h) {
		struct nf_conn *ct;
		ct = nf_ct_tuplehash_to_ctrack(h);

		/*
		 * Initialize DSCP MARKING information
		 */
		if (offload_dscpremark_get_target_info(ct, &create.dscp_imask, &create.dscp_itag, &create.dscp_omask, &create.dscp_oval)) {
			DEBUG_TRACE("%p: DSCP remark information present on: %p\n\timask: %x, itag: %x, omask: %x, oval: %x\n",
				fecui->ci, ct, create.dscp_imask, create.dscp_itag, create.dscp_omask, create.dscp_oval);
			create.flags |= NSS_IPV4_CREATE_FLAG_DSCP_MARKING;
		} else {
			DEBUG_TRACE("%p: DSCP remark information is not present on: %p\n", fecui->ci, ct);
			create.dscp_itag = ECM_NSS_CONNMGR_DSCP_MARKING_NOT_CONFIGURED;
			create.dscp_imask = ECM_NSS_CONNMGR_DSCP_MARKING_NOT_CONFIGURED;
			create.dscp_omask = ECM_NSS_CONNMGR_DSCP_MARKING_NOT_CONFIGURED;
			create.dscp_oval = ECM_NSS_CONNMGR_DSCP_MARKING_NOT_CONFIGURED;
		}

		/*
		 * Initialize VLAN MARKING information
		 */
		if (offload_vlantag_get_target_info(ct, &create.vlan_imask, &create.vlan_itag, &create.vlan_omask, &create.vlan_oval)) {
			DEBUG_TRACE("%p: VLAN marking information present on: %p\n\timask: %x, itag: %x, omask: %x, oval: %x\n",
				fecui->ci, ct, create.vlan_imask, create.vlan_itag, create.vlan_omask, create.vlan_oval);
			create.flags |= NSS_IPV4_CREATE_FLAG_VLAN_MARKING;
		} else {
			DEBUG_TRACE("%p: VLAN marking information is not present on: %p\n", fecui->ci, ct);
			create.vlan_itag = ECM_NSS_CONNMGR_VLAN_MARKING_NOT_CONFIGURED;
			create.vlan_imask= ECM_NSS_CONNMGR_VLAN_MARKING_NOT_CONFIGURED;
			create.vlan_omask = ECM_NSS_CONNMGR_VLAN_MARKING_NOT_CONFIGURED;
			create.vlan_oval = ECM_NSS_CONNMGR_VLAN_MARKING_NOT_CONFIGURED;
		}

		nf_ct_put(ct);
	}

	/*
	 * Get MTU information
	 */
	create.from_mtu = (uint32_t)ecm_db_connection_from_iface_mtu_get(fecui->ci);
	create.to_mtu = (uint32_t)ecm_db_connection_to_iface_mtu_get(fecui->ci);

	/*
	 * Sync our creation command from the assigned classifiers to get specific additional creation rules.
	 * NOTE: These are called in ascending order of priority and so the last classifier (highest) shall
	 * override any preceding classifiers.
	 * This also gives the classifiers a chance to see that acceleration is being attempted.
	 */
	assignment_count = ecm_db_connection_classifier_assignments_get_and_ref(fecui->ci, assignments);
	for (aci_index = 0; aci_index < assignment_count; ++aci_index) {
		struct ecm_classifier_instance *aci;

		aci = assignments[aci_index];
		DEBUG_TRACE("%p: sync from: %p, type: %d\n", fecui, aci, aci->type_get(aci));
		aci->sync_from_v4(aci, &create);
	}
	ecm_db_connection_assignments_release(assignment_count, assignments);

	/*
	 * Release the interface lists
	 */
	ecm_db_connection_interfaces_deref(from_ifaces, from_ifaces_first);
	ecm_db_connection_interfaces_deref(to_ifaces, to_ifaces_first);

	DEBUG_INFO("%p: UDP Accelerate connection %p\n"
			"Protocol: %d\n"
			"from_mtu: %u\n"
			"to_mtu: %u\n"
			"from_ip: %pI4h:%d\n"
			"to_ip: %pI4h:%d\n"
			"from_ip_xlate: %pI4h:%d\n"
			"to_ip_xlate: %pI4h:%d\n"
			"from_mac: %pM\n"
			"to_mac: %pM\n"
			"from_mac_xlate: %pM\n"
			"to_mac_xlate: %pM\n"
			"src_iface_num: %u\n"
			"dest_iface_num: %u\n"
			"ingress_vlan_tag: %u\n"
			"egress_vlan_tag: %u\n"
			"vlan_itag: %x\n"
			"vlan_imask: %x\n"
			"vlan_omask: %x\n"
			"vlan_oval: %x\n"
			"dscp_itag: %x\n"
			"dscp_imask: %x\n"
			"dscp_omask: %x\n"
			"dscp_oval: %x\n"
			"flags: %x\n"
			"return_pppoe_session_id: %u\n"
			"return_pppoe_remote_mac: %pM\n"
			"flow_pppoe_session_id: %u\n"
			"flow_pppoe_remote_mac: %pM\n"
			"qos_tag: %x (%u)\n",
			fecui,
			fecui->ci,
			create.protocol,
			create.from_mtu,
			create.to_mtu,
			&create.src_ip, create.src_port,
			&create.dest_ip, create.dest_port,
			&create.src_ip_xlate, create.src_port_xlate,
			&create.dest_ip_xlate, create.dest_port_xlate,
			create.src_mac,
			create.dest_mac,
			create.src_mac_xlate,
			create.dest_mac_xlate,
			create.src_interface_num,
			create.dest_interface_num,
			create.ingress_vlan_tag,
			create.egress_vlan_tag,
			create.vlan_itag,
			create.vlan_imask,
			create.vlan_omask,
			create.vlan_oval,
			create.dscp_itag,
			create.dscp_imask,
			create.dscp_omask,
			create.dscp_oval,
			create.flags,
			create.return_pppoe_session_id,
			create.return_pppoe_remote_mac,
			create.flow_pppoe_session_id,
			create.flow_pppoe_remote_mac,
			create.qos_tag, create.qos_tag);

	/*
	 * Call the relevant rule create function
	 */
	if (create.dscp_oval == ECM_NSS_CONNMGR_DSCP_MARKING_NOT_CONFIGURED &&
			create.vlan_oval == ECM_NSS_CONNMGR_VLAN_MARKING_NOT_CONFIGURED) {
		nss_tx_status = nss_tx_create_ipv4_rule(ecm_front_end_ipv4_nss_ipv4_context, &create);
	} else {
		nss_tx_status = nss_tx_create_ipv4_rule1(ecm_front_end_ipv4_nss_ipv4_context, &create);
	}
	if (nss_tx_status == NSS_TX_SUCCESS) {
		return;
	}

	/*
	 * Revert accel mode if necessary
	 */
	DEBUG_WARN("%p: Accel attempt failed\n", fecui);
	spin_lock_bh(&fecui->lock);
	if (fecui->accel_mode == ECM_CLASSIFIER_ACCELERATION_MODE_ACCEL) {
		fecui->accel_mode = ECM_CLASSIFIER_ACCELERATION_MODE_NO;
	}
	spin_unlock_bh(&fecui->lock);
}

/*
 * ecm_front_end_ipv4_connection_udp_front_end_decelerate()
 *	Decelerate a connection
 */
static void ecm_front_end_ipv4_connection_udp_front_end_decelerate(struct ecm_front_end_connection_instance *feci)
{
	struct ecm_front_end_ipv4_connection_udp_instance *fecui = (struct ecm_front_end_ipv4_connection_udp_instance *)feci;
	struct nss_ipv4_destroy destroy;
	ip_addr_t addr;

	DEBUG_CHECK_MAGIC(fecui, ECM_FRONT_END_IPV4_CONNECTION_UDP_INSTANCE_MAGIC, "%p: magic failed", fecui);

	destroy.protocol = (int32_t)IPPROTO_UDP;

	/*
	 * Get addressing information
	 */
	ecm_db_connection_from_address_get(fecui->ci, addr);
	ECM_IP_ADDR_TO_NIN4_ADDR(destroy.src_ip, addr);
	ecm_db_connection_to_address_nat_get(fecui->ci, addr);
	ECM_IP_ADDR_TO_NIN4_ADDR(destroy.dest_ip, addr);
	destroy.src_port = ecm_db_connection_from_port_get(fecui->ci);
	destroy.dest_port = ecm_db_connection_to_port_nat_get(fecui->ci);

	DEBUG_INFO("%p: UDP Connection %p decelerate\n"
			"src_ip: %pI4:%d\n"
			"dest_ip: %pI4:%d\n",
			fecui, fecui->ci,
			&destroy.src_ip, destroy.src_port,
			&destroy.dest_ip, destroy.dest_port);

	/*
	 * Destroy the Network Accelerator connection cache entries.
	 */
	nss_tx_destroy_ipv4_rule(ecm_front_end_ipv4_nss_ipv4_context, &destroy);
}

/*
 * ecm_front_end_ipv4_connection_udp_front_end_accel_state_get()
 *	Get acceleration state
 */
static void ecm_front_end_ipv4_connection_udp_front_end_accel_state_get(struct ecm_front_end_connection_instance *feci,
								ecm_classifier_acceleration_mode_t *accel_mode,
								int *count, int *limit, bool *can_accel)
{
	struct ecm_front_end_ipv4_connection_udp_instance *fecui = (struct ecm_front_end_ipv4_connection_udp_instance *)feci;

	DEBUG_CHECK_MAGIC(fecui, ECM_FRONT_END_IPV4_CONNECTION_UDP_INSTANCE_MAGIC, "%p: magic failed", fecui);
	spin_lock_bh(&fecui->lock);
	*accel_mode = fecui->accel_mode;
	*count = fecui->accel_count;
	*limit = fecui->accel_limit;
	*can_accel = fecui->can_accel;
	spin_unlock_bh(&fecui->lock);
}

/*
 * ecm_front_end_ipv4_connection_udp_front_end_accel_count_reset()
 *	Reset the accel counter - because the NA has sent a sync message indicating that some data was accelerated.
 */
static void ecm_front_end_ipv4_connection_udp_front_end_accel_count_reset(struct ecm_front_end_connection_instance *feci)
{
	struct ecm_front_end_ipv4_connection_udp_instance *fecui = (struct ecm_front_end_ipv4_connection_udp_instance *)feci;

	DEBUG_CHECK_MAGIC(fecui, ECM_FRONT_END_IPV4_CONNECTION_UDP_INSTANCE_MAGIC, "%p: magic failed", fecui);
	DEBUG_INFO("%p: reset accel count\n", fecui);
	spin_lock_bh(&fecui->lock);
	fecui->accel_count = 0;
	spin_unlock_bh(&fecui->lock);
}

/*
 * ecm_front_end_ipv4_connection_udp_front_end_accel_ceased()
 *	NA has indicated that acceleration has stopped.
 */
static void ecm_front_end_ipv4_connection_udp_front_end_accel_ceased(struct ecm_front_end_connection_instance *feci)
{
	struct ecm_front_end_ipv4_connection_udp_instance *fecui = (struct ecm_front_end_ipv4_connection_udp_instance *)feci;

	DEBUG_CHECK_MAGIC(fecui, ECM_FRONT_END_IPV4_CONNECTION_UDP_INSTANCE_MAGIC, "%p: magic failed", fecui);
	DEBUG_INFO("%p: accel ceased\n", fecui);
	spin_lock_bh(&fecui->lock);
	fecui->accel_mode = ECM_CLASSIFIER_ACCELERATION_MODE_NO;
	spin_unlock_bh(&fecui->lock);
}

/*
 * ecm_front_end_ipv4_connection_udp_front_end_ref()
 *	Ref a connection front end instance
 */
static void ecm_front_end_ipv4_connection_udp_front_end_ref(struct ecm_front_end_connection_instance *feci)
{
	struct ecm_front_end_ipv4_connection_udp_instance *fecui = (struct ecm_front_end_ipv4_connection_udp_instance *)feci;

	DEBUG_CHECK_MAGIC(fecui, ECM_FRONT_END_IPV4_CONNECTION_UDP_INSTANCE_MAGIC, "%p: magic failed", fecui);
	spin_lock_bh(&fecui->lock);
	fecui->refs++;
	DEBUG_TRACE("%p: fecui ref %d\n", fecui, fecui->refs);
	DEBUG_ASSERT(fecui->refs > 0, "%p: ref wrap\n", fecui);
	spin_unlock_bh(&fecui->lock);
}

/*
 * ecm_front_end_ipv4_connection_udp_front_end_deref()
 *	Deref a connection front end instance
 */
static int ecm_front_end_ipv4_connection_udp_front_end_deref(struct ecm_front_end_connection_instance *feci)
{
	struct ecm_front_end_ipv4_connection_udp_instance *fecui = (struct ecm_front_end_ipv4_connection_udp_instance *)feci;

	DEBUG_CHECK_MAGIC(fecui, ECM_FRONT_END_IPV4_CONNECTION_UDP_INSTANCE_MAGIC, "%p: magic failed", fecui);

	spin_lock_bh(&fecui->lock);
	fecui->refs--;
	DEBUG_ASSERT(fecui->refs >= 0, "%p: ref wrap\n", fecui);

	if (fecui->refs > 0) {
		int refs = fecui->refs;
		spin_unlock_bh(&fecui->lock);
		DEBUG_TRACE("%p: fecui deref %d\n", fecui, refs);
		return refs;
	}
	spin_unlock_bh(&fecui->lock);

	/*
	 * We can now destroy the instance
	 */
	DEBUG_TRACE("%p: fecui final\n", fecui);
	kfree(fecui);
	DEBUG_CLEAR_MAGIC(fecui);

	/*
	 * No longer need ref to thread for this object
	 */
	spin_lock_bh(&ecm_front_end_ipv4_lock);
	ecm_front_end_ipv4_thread_refs--;
	DEBUG_ASSERT(ecm_front_end_ipv4_thread_refs >= 0, "Thread refs wrap %d\n", ecm_front_end_ipv4_thread_refs);
	spin_unlock_bh(&ecm_front_end_ipv4_lock);

	/*
	 * Thread may be able to exit on object destruction
	 */
	wake_up_process(ecm_front_end_ipv4_thread);
	return 0;
}

/*
 * ecm_front_end_ipv4_connection_udp_front_end_xml_state_get()
 *	Return an XML element containing the state of this UDP front end instance
 */
static int ecm_front_end_ipv4_connection_udp_front_end_xml_state_get(struct ecm_front_end_connection_instance *feci, char *buf, int buf_sz)
{
	bool can_accel;
	ecm_classifier_acceleration_mode_t accel_mode;
	int accel_count;
	int accel_limit;
	struct ecm_front_end_ipv4_connection_udp_instance *fecui = (struct ecm_front_end_ipv4_connection_udp_instance *)feci;

	DEBUG_CHECK_MAGIC(fecui, ECM_FRONT_END_IPV4_CONNECTION_UDP_INSTANCE_MAGIC, "%p: magic failed", fecui);

	spin_lock_bh(&fecui->lock);
	can_accel = fecui->can_accel;
	accel_mode = fecui->accel_mode;
	accel_count = fecui->accel_count;
	accel_limit = fecui->accel_limit;
	spin_unlock_bh(&fecui->lock);

	return snprintf(buf, buf_sz, "<front_end_udp can_accel=\"%u\" accel_mode=\"%d\" "
			"accel_count=\"%d\" accel_limit=\"%d\"/>\n",
			can_accel,
			accel_mode,
			accel_count,
			accel_limit);

}

/*
 * ecm_front_end_ipv4_connection_udp_instance_alloc()
 *	Create a front end instance specific for UDP connection
 */
static struct ecm_front_end_ipv4_connection_udp_instance *ecm_front_end_ipv4_connection_udp_instance_alloc(
								struct ecm_db_connection_instance *ci,
								struct ecm_db_mapping_instance *src_mi,
								struct ecm_db_mapping_instance *dest_mi,
								bool can_accel)
{
	struct ecm_front_end_ipv4_connection_udp_instance *fecui;

	fecui = (struct ecm_front_end_ipv4_connection_udp_instance *)kzalloc(sizeof(struct ecm_front_end_ipv4_connection_udp_instance), GFP_ATOMIC | __GFP_NOWARN);
	if (!fecui) {
		DEBUG_WARN("UDP Front end alloc failed\n");
		return NULL;
	}

	/*
	 * Refs is 1 for the creator of the connection
	 */
	fecui->refs = 1;
	DEBUG_SET_MAGIC(fecui, ECM_FRONT_END_IPV4_CONNECTION_UDP_INSTANCE_MAGIC);
	spin_lock_init(&fecui->lock);

	fecui->can_accel = can_accel;
	fecui->accel_mode = ECM_CLASSIFIER_ACCELERATION_MODE_NO;
	spin_lock_bh(&ecm_front_end_ipv4_lock);
	fecui->accel_limit = ecm_front_end_ipv4_accel_limit_default;
	spin_unlock_bh(&ecm_front_end_ipv4_lock);

	/*
	 * Copy reference to connection - no need to ref ci as ci maintains a ref to this instance instead (this instance persists for as long as ci does)
	 */
	fecui->ci = ci;

	/*
	 * Populate the methods and callbacks
	 */
	fecui->base.ref = ecm_front_end_ipv4_connection_udp_front_end_ref;
	fecui->base.deref = ecm_front_end_ipv4_connection_udp_front_end_deref;
	fecui->base.decelerate = ecm_front_end_ipv4_connection_udp_front_end_decelerate;
	fecui->base.accel_state_get = ecm_front_end_ipv4_connection_udp_front_end_accel_state_get;
	fecui->base.accel_count_reset = ecm_front_end_ipv4_connection_udp_front_end_accel_count_reset;
	fecui->base.accel_ceased = ecm_front_end_ipv4_connection_udp_front_end_accel_ceased;
	fecui->base.xml_state_get = ecm_front_end_ipv4_connection_udp_front_end_xml_state_get;

	/*
	 * Ensure our thread persists (and hence this module) for as long as the connection and its supporting framework is alive
	 * as we could get callbacks from the database
	 */
	spin_lock_bh(&ecm_front_end_ipv4_lock);
	ecm_front_end_ipv4_thread_refs++;
	DEBUG_ASSERT(ecm_front_end_ipv4_thread_refs > 0, "Thread refs wrap %d\n", ecm_front_end_ipv4_thread_refs);
	spin_unlock_bh(&ecm_front_end_ipv4_lock);
	return fecui;
}

/*
 * ecm_front_end_ipv4_connection_non_ported_front_end_accelerate()
 *	Accelerate a connection
 */
static void ecm_front_end_ipv4_connection_non_ported_front_end_accelerate(struct ecm_front_end_connection_instance *feci,
									struct ecm_classifier_process_response *pr)
{
	struct ecm_front_end_ipv4_connection_non_ported_instance *fecnpi = (struct ecm_front_end_ipv4_connection_non_ported_instance *)feci;
	int protocol;
	int32_t from_ifaces_first;
	int32_t to_ifaces_first;
	struct ecm_db_iface_instance *from_ifaces[ECM_DB_IFACE_HEIRARCHY_MAX];
	struct ecm_db_iface_instance *to_ifaces[ECM_DB_IFACE_HEIRARCHY_MAX];
	struct ecm_db_iface_instance *from_nss_iface;
	struct ecm_db_iface_instance *to_nss_iface;
	int32_t from_nss_iface_id;
	int32_t to_nss_iface_id;
	uint8_t from_nss_iface_address[ETH_ALEN];
	uint8_t to_nss_iface_address[ETH_ALEN];
	struct nf_conntrack_tuple_hash *h;
	struct nf_conntrack_tuple tuple;
	ip_addr_t addr;
	struct nss_ipv4_create create;
	struct ecm_classifier_instance *assignments[ECM_CLASSIFIER_TYPES];
	int aci_index;
	int assignment_count;
	nss_tx_status_t nss_tx_status;
	int32_t list_index;
	int32_t interface_type_counts[ECM_DB_IFACE_TYPE_COUNT];
	bool rule_invalid;

	DEBUG_CHECK_MAGIC(fecnpi, ECM_FRONT_END_IPV4_CONNECTION_NON_PORTED_INSTANCE_MAGIC, "%p: magic failed", fecnpi);

	/*
	 * Can this connection be accelerated at all?
	 */
	DEBUG_INFO("%p: Accel conn: %p\n", fecnpi, fecnpi->ci);
	spin_lock_bh(&fecnpi->lock);
	if (!fecnpi->can_accel) {
		spin_unlock_bh(&fecnpi->lock);
		DEBUG_TRACE("%p: accel %p denied\n", fecnpi, fecnpi->ci);
		return;
	}

	/*
	 * Have we tried to accelerate unsuccessfully too many times?
	 */
	if (fecnpi->accel_count >= fecnpi->accel_limit) {
		spin_unlock_bh(&fecnpi->lock);
		DEBUG_WARN("%p: accel limit reached for %p\n", fecnpi, fecnpi->ci);
		return;
	}

	/*
	 * If acceleration mode is currently different then switch modes
	 */
	if (fecnpi->accel_mode == ECM_CLASSIFIER_ACCELERATION_MODE_ACCEL) {
		spin_unlock_bh(&fecnpi->lock);
		DEBUG_TRACE("%p: Ignoring duplicate accel for conn: %p\n", fecnpi, fecnpi->ci);
		return;
	}
	fecnpi->accel_mode = ECM_CLASSIFIER_ACCELERATION_MODE_ACCEL;
	fecnpi->accel_count++;
	spin_unlock_bh(&fecnpi->lock);

	/*
	 * For non-ported protocols we only support IPv6 in 4 or ESP
	 */
	protocol = ecm_db_connection_protocol_get(fecnpi->ci);
	if ((protocol != IPPROTO_IPV6) && (protocol != IPPROTO_ESP)) {
		DEBUG_TRACE("%p: unsupported protocol: %d\n", fecnpi, protocol);
		return;
	}

	/*
	 * Okay construct an accel command.
	 * Initialise creation structure
	 */
	memset(&create, 0, sizeof(create));

	/*
	 * Initialize VLAN tag information
	 */
	create.ingress_vlan_tag = ECM_NSS_CONNMGR_VLAN_ID_NOT_CONFIGURED;
	create.egress_vlan_tag = ECM_NSS_CONNMGR_VLAN_ID_NOT_CONFIGURED;

	/*
	 * Get the interface lists of the connection
	 */
	from_ifaces_first = ecm_db_connection_from_interfaces_get_and_ref(fecnpi->ci, from_ifaces);
	to_ifaces_first = ecm_db_connection_to_interfaces_get_and_ref(fecnpi->ci, to_ifaces);

	/*
	 * Must have at least one interface in each list
	 */
	if ((from_ifaces_first == ECM_DB_IFACE_HEIRARCHY_MAX) || (to_ifaces_first == ECM_DB_IFACE_HEIRARCHY_MAX)) {
		DEBUG_WARN("%p: Accel attempt failed - no interfaces in lists?!\n", fecnpi);
		spin_lock_bh(&fecnpi->lock);
		if (fecnpi->accel_mode == ECM_CLASSIFIER_ACCELERATION_MODE_ACCEL) {
			fecnpi->accel_mode = ECM_CLASSIFIER_ACCELERATION_MODE_NO;
		}
		spin_unlock_bh(&fecnpi->lock);
		return;
	}

	/*
	 * First interface in each must be a known nss interface
	 */
	from_nss_iface = from_ifaces[from_ifaces_first];
	to_nss_iface = to_ifaces[to_ifaces_first];
	from_nss_iface_id = ecm_db_iface_nss_interface_identifier_get(from_nss_iface);
	to_nss_iface_id = ecm_db_iface_nss_interface_identifier_get(to_nss_iface);
	if ((from_nss_iface_id < 0) || (to_nss_iface_id < 0)) {
		DEBUG_TRACE("%p: from_nss_iface_id: %d, to_nss_iface_id: %d\n", fecnpi, from_nss_iface_id, to_nss_iface_id);
		spin_lock_bh(&fecnpi->lock);
		if (fecnpi->accel_mode == ECM_CLASSIFIER_ACCELERATION_MODE_ACCEL) {
			fecnpi->accel_mode = ECM_CLASSIFIER_ACCELERATION_MODE_NO;
		}
		spin_unlock_bh(&fecnpi->lock);
		ecm_db_connection_interfaces_deref(from_ifaces, from_ifaces_first);
		ecm_db_connection_interfaces_deref(to_ifaces, to_ifaces_first);
		return;
	}

	/*
	 * Set interface numbers involved in accelerating this connection.
	 * These are the outer facing addresses from the heirarchy interface lists we got above.
	 * These may be overridden later if we detect special interface types e.g. ipsec.
	 */
	create.src_interface_num = from_nss_iface_id;
	create.dest_interface_num = to_nss_iface_id;

	/*
	 * We know that each outward facing interface is known to the NSS and so this connection could be accelerated.
	 * However the lists may also specify other interesting details that must be included in the creation command,
	 * for example, ethernet MAC, VLAN tagging or PPPoE session information.
	 * We get this information by walking from the outer to the innermost interface for each list and examine the interface types.
	 *
	 * Start with the 'from' (src) side.
	 * NOTE: The lists may contain a complex heirarchy of similar type of interface e.g. multiple vlans or tunnels within tunnels.
	 * This NSS cannot handle that - there is no way to describe this in the rule - if we see multiple types that would conflict we have to abort.
	 */
	DEBUG_TRACE("%p: Examine from/src heirarchy list\n", fecnpi);
	memset(interface_type_counts, 0, sizeof(interface_type_counts));
	rule_invalid = false;
	for (list_index = from_ifaces_first; !rule_invalid && (list_index < ECM_DB_IFACE_HEIRARCHY_MAX); list_index++) {
		struct ecm_db_iface_instance *ii;
		ecm_db_iface_type_t ii_type;
		char *ii_name;

		ii = from_ifaces[list_index];
		ii_type = ecm_db_connection_iface_type_get(ii);
		ii_name = ecm_db_interface_type_to_string(ii_type);
		DEBUG_TRACE("%p: list_index: %d, ii: %p, type: %d (%s)\n", fecnpi, list_index, ii, ii_type, ii_name);

		/*
		 * Extract information from this interface type if it is applicable to the rule.
		 * Conflicting information may cause accel to be unsupported.
		 */
		switch (ii_type) {
			struct ecm_db_interface_info_pppoe pppoe_info;
			struct ecm_db_interface_info_vlan vlan_info;

		case ECM_DB_IFACE_TYPE_ETHERNET:
			DEBUG_TRACE("%p: Ethernet\n", fecnpi);
			if (interface_type_counts[ii_type] != 0) {
				/*
				 * Ignore additional mac addresses, these are usually as a result of address propagation
				 * from bridges down to ports etc.
				 */
				DEBUG_TRACE("%p: Ethernet - ignore additional\n", fecnpi);
				break;
			}

			/*
			 * Can only handle one MAC, the first outermost mac.
			 */
			ecm_db_iface_ethernet_address_get(ii, from_nss_iface_address);
			DEBUG_TRACE("%p: Ethernet - mac: %pM\n", fecnpi, from_nss_iface_address);
			break;
		case ECM_DB_IFACE_TYPE_PPPOE:
			/*
			 * GGG TODO For now we don't support PPPoE so this is an invalid rule
			 */
			DEBUG_TRACE("%p: PPPoE - unsupported right now\n", fecnpi);
			rule_invalid = true;

			if (interface_type_counts[ii_type] != 0) {
				DEBUG_TRACE("%p: PPPoE - additional unsupported\n", fecnpi);
				rule_invalid = true;
				break;
			}

			/*
			 * Copy pppoe session info to the creation structure.
			 */
			ecm_db_iface_pppoe_session_info_get(ii, &pppoe_info);
			create.flow_pppoe_session_id = pppoe_info.pppoe_session_id;
			memcpy(create.flow_pppoe_remote_mac, pppoe_info.remote_mac, ETH_ALEN);
			DEBUG_TRACE("%p: PPPoE - session: %x, mac: %pM\n", fecnpi, create.flow_pppoe_session_id, create.flow_pppoe_remote_mac);
			break;
		case ECM_DB_IFACE_TYPE_VLAN:
			DEBUG_TRACE("%p: VLAN\n", fecnpi);
			if (interface_type_counts[ii_type] != 0) {
				/*
				 * Can only support one vlan
				 */
				rule_invalid = true;
				DEBUG_TRACE("%p: VLAN - additional unsupported\n", fecnpi);
				break;
			}
			ecm_db_iface_vlan_info_get(ii, &vlan_info);
			create.ingress_vlan_tag = vlan_info.vlan_tag;

			/*
			 * If we have not yet got an ethernet mac then take this one (very unlikely as mac should have been propagated to the slave (outer) device
			 */
			if (interface_type_counts[ECM_DB_IFACE_TYPE_ETHERNET] == 0) {
				memcpy(from_nss_iface_address, vlan_info.address, ETH_ALEN);
				interface_type_counts[ECM_DB_IFACE_TYPE_ETHERNET]++;
				DEBUG_TRACE("%p: VLAN use mac: %pM\n", fecnpi, from_nss_iface_address);
			}
			DEBUG_TRACE("%p: vlan tag: %x\n", fecnpi, create.ingress_vlan_tag);
			break;
		case ECM_DB_IFACE_TYPE_IPSEC_TUNNEL:
			DEBUG_TRACE("%p: IPSEC\n", fecnpi);
			if (interface_type_counts[ii_type] != 0) {
				/*
				 * Can only support one ipsec
				 */
				rule_invalid = true;
				DEBUG_TRACE("%p: IPSEC - additional unsupported\n", fecnpi);
				break;
			}
			create.src_interface_num = NSS_C2C_TX_INTERFACE;
			break;
		default:
			DEBUG_TRACE("%p: Ignoring: %d (%s)\n", fecnpi, ii_type, ii_name);
		}

		/*
		 * Seen an interface of this type
		 */
		interface_type_counts[ii_type]++;
	}
	if (rule_invalid) {
		DEBUG_WARN("%p: from/src Rule invalid\n", fecnpi);
		spin_lock_bh(&fecnpi->lock);
		if (fecnpi->accel_mode == ECM_CLASSIFIER_ACCELERATION_MODE_ACCEL) {
			fecnpi->accel_mode = ECM_CLASSIFIER_ACCELERATION_MODE_NO;
		}
		spin_unlock_bh(&fecnpi->lock);
		ecm_db_connection_interfaces_deref(from_ifaces, from_ifaces_first);
		ecm_db_connection_interfaces_deref(to_ifaces, to_ifaces_first);
		return;
	}

	/*
	 * Now examine the TO / DEST heirarchy list to construct the destination part of the rule
	 */
	DEBUG_TRACE("%p: Examine to/dest heirarchy list\n", fecnpi);
	memset(interface_type_counts, 0, sizeof(interface_type_counts));
	rule_invalid = false;
	for (list_index = to_ifaces_first; !rule_invalid && (list_index < ECM_DB_IFACE_HEIRARCHY_MAX); list_index++) {
		struct ecm_db_iface_instance *ii;
		ecm_db_iface_type_t ii_type;
		char *ii_name;

		ii = to_ifaces[list_index];
		ii_type = ecm_db_connection_iface_type_get(ii);
		ii_name = ecm_db_interface_type_to_string(ii_type);
		DEBUG_TRACE("%p: list_index: %d, ii: %p, type: %d (%s)\n", fecnpi, list_index, ii, ii_type, ii_name);

		/*
		 * Extract information from this interface type if it is applicable to the rule.
		 * Conflicting information may cause accel to be unsupported.
		 */
		switch (ii_type) {
			struct ecm_db_interface_info_pppoe pppoe_info;
			struct ecm_db_interface_info_vlan vlan_info;

		case ECM_DB_IFACE_TYPE_ETHERNET:
			DEBUG_TRACE("%p: Ethernet\n", fecnpi);
			if (interface_type_counts[ii_type] != 0) {
				/*
				 * Ignore additional mac addresses, these are usually as a result of address propagation
				 * from bridges down to ports etc.
				 */
				DEBUG_TRACE("%p: Ethernet - ignore additional\n", fecnpi);
				break;
			}

			/*
			 * Can only handle one MAC, the first outermost mac.
			 */
			ecm_db_iface_ethernet_address_get(ii, to_nss_iface_address);
			DEBUG_TRACE("%p: Ethernet - mac: %pM\n", fecnpi, to_nss_iface_address);
			break;
		case ECM_DB_IFACE_TYPE_PPPOE:
			/*
			 * GGG TODO For now we don't support PPPoE so this is an invalid rule
			 */
			DEBUG_TRACE("%p: PPPoE - unsupported right now\n", fecnpi);
			rule_invalid = true;

			if (interface_type_counts[ii_type] != 0) {
				DEBUG_TRACE("%p: PPPoE - additional unsupported\n", fecnpi);
				rule_invalid = true;
				break;
			}

			/*
			 * Copy pppoe session info to the creation structure.
			 */
			ecm_db_iface_pppoe_session_info_get(ii, &pppoe_info);
			create.return_pppoe_session_id = pppoe_info.pppoe_session_id;
			memcpy(create.return_pppoe_remote_mac, pppoe_info.remote_mac, ETH_ALEN);
			DEBUG_TRACE("%p: PPPoE - session: %x, mac: %pM\n", fecnpi, create.return_pppoe_session_id, create.return_pppoe_remote_mac);
			break;
		case ECM_DB_IFACE_TYPE_VLAN:
			DEBUG_TRACE("%p: VLAN\n", fecnpi);
			if (interface_type_counts[ii_type] != 0) {
				/*
				 * Can only support one vlan
				 */
				rule_invalid = true;
				DEBUG_TRACE("%p: VLAN - additional unsupported\n", fecnpi);
				break;
			}
			ecm_db_iface_vlan_info_get(ii, &vlan_info);
			create.egress_vlan_tag = vlan_info.vlan_tag;

			/*
			 * If we have not yet got an ethernet mac then take this one (very unlikely as mac should have been propagated to the slave (outer) device
			 */
			if (interface_type_counts[ECM_DB_IFACE_TYPE_ETHERNET] == 0) {
				memcpy(to_nss_iface_address, vlan_info.address, ETH_ALEN);
				interface_type_counts[ECM_DB_IFACE_TYPE_ETHERNET]++;
				DEBUG_TRACE("%p: VLAN use mac: %pM\n", fecnpi, to_nss_iface_address);
			}
			DEBUG_TRACE("%p: vlan tag: %x\n", fecnpi, create.egress_vlan_tag);
			break;
		case ECM_DB_IFACE_TYPE_IPSEC_TUNNEL:
			DEBUG_TRACE("%p: IPSEC\n", fecnpi);
			if (interface_type_counts[ii_type] != 0) {
				/*
				 * Can only support one ipsec
				 */
				rule_invalid = true;
				DEBUG_TRACE("%p: IPSEC - additional unsupported\n", fecnpi);
				break;
			}
			create.dest_interface_num = NSS_C2C_TX_INTERFACE;
			break;
		default:
			DEBUG_TRACE("%p: Ignoring: %d (%s)\n", fecnpi, ii_type, ii_name);
		}

		/*
		 * Seen an interface of this type
		 */
		interface_type_counts[ii_type]++;
	}
	if (rule_invalid) {
		DEBUG_WARN("%p: to/dest Rule invalid\n", fecnpi);
		spin_lock_bh(&fecnpi->lock);
		if (fecnpi->accel_mode == ECM_CLASSIFIER_ACCELERATION_MODE_ACCEL) {
			fecnpi->accel_mode = ECM_CLASSIFIER_ACCELERATION_MODE_NO;
		}
		spin_unlock_bh(&fecnpi->lock);
		ecm_db_connection_interfaces_deref(from_ifaces, from_ifaces_first);
		ecm_db_connection_interfaces_deref(to_ifaces, to_ifaces_first);
		return;
	}

	/*
	 * Routed or bridged?
	 */
	if (ecm_db_connection_is_routed_get(fecnpi->ci)) {
		create.flags |= NSS_IPV4_CREATE_FLAG_ROUTED;
	} else {
		create.flags |= NSS_IPV4_CREATE_FLAG_BRIDGE_FLOW;
	}

	/*
	 * Store the skb->priority as the qos tag
	 */
	create.qos_tag = (uint32_t)pr->qos_tag;

	/*
	 * Set protocol
	 */
	create.protocol = (int32_t)protocol;

	/*
	 * The src_ip is where the connection established from
	 */
	ecm_db_connection_from_address_get(fecnpi->ci, addr);
	ECM_IP_ADDR_TO_HIN4_ADDR(create.src_ip, addr);

	/*
	 * The dest_ip is where the connection is established to, however, in the case of ingress
	 * the dest_ip would be the routers WAN IP - i.e. the NAT'ed version.
	 * Getting the NAT'ed version here works for ingress or egress packets, for egress
	 * the NAT'ed version would be the same as the normal address
	 */
	ecm_db_connection_to_address_nat_get(fecnpi->ci, addr);
	ECM_IP_ADDR_TO_HIN4_ADDR(create.dest_ip, addr);

	/*
	 * When the packet is forwarded to the next interface get the address the source IP of the
	 * packet should be translated to.  For egress this is the NAT'ed from address.
	 * This also works for ingress as the NAT'ed version of the WAN host would be the same as non-NAT'ed
	 */
	ecm_db_connection_from_address_nat_get(fecnpi->ci, addr);
	ECM_IP_ADDR_TO_HIN4_ADDR(create.src_ip_xlate, addr);

	/*
	 * The destination address is what the destination IP is translated to as it is forwarded to the next interface.
	 * For egress this would yield the normal wan host and for ingress this would correctly NAT back to the LAN host
	 */
	ecm_db_connection_to_address_get(fecnpi->ci, addr);
	ECM_IP_ADDR_TO_HIN4_ADDR(create.dest_ip_xlate, addr);

	/*
	 * Same approach as above for port information
	 */
	create.src_port = ecm_db_connection_from_port_get(fecnpi->ci);
	create.dest_port = ecm_db_connection_to_port_nat_get(fecnpi->ci);
	create.src_port_xlate = ecm_db_connection_from_port_nat_get(fecnpi->ci);
	create.dest_port_xlate = ecm_db_connection_to_port_get(fecnpi->ci);

	/*
	 * Get mac addresses.
	 * The src_mac is the mac address of the node that established the connection.
	 * This will work whether the from_node is LAN (egress) or WAN (ingress).
	 */
	ecm_db_connection_from_node_address_get(fecnpi->ci, create.src_mac);

	/*
	 * The dest_mac is more complex.  For egress it is the node address of the 'to' side of the connection.
	 * For ingress it is the node adress of the NAT'ed 'to' IP.
	 * Essentially it is the MAC of node associated with create.dest_ip and this is "to nat" side.
	 */
	ecm_db_connection_to_nat_node_address_get(fecnpi->ci, create.dest_mac);

	/*
	 * The src_mac_xlate is the mac address to replace the src_mac when sent onto the next interface
	 * This is, therefore, the interface mac of the 'to' side of the connection.
	 */
	memcpy(create.src_mac_xlate, to_nss_iface_address, ETH_ALEN);

	/*
	 * The dest_mac_xlate replaces the destination mac of a packet when sent on the next interface.
	 * By getting the MAC of node associated with dest_ip_xlate we can satisfy ingress and egress cases.
	 */
	ecm_db_connection_to_node_address_get(fecnpi->ci, create.dest_mac_xlate);

	/*
	 * Need window scaling and remarking information if available
	 * Start by looking up the conntrack connection
	 */
	memset(&tuple, 0, sizeof(tuple));
	tuple.src.u3.ip = htonl(create.src_ip);
	tuple.src.u.all = (__be16)htons(create.src_port);
	tuple.src.l3num = AF_INET;

	tuple.dst.u3.ip = htonl(create.dest_ip);
	tuple.dst.dir = IP_CT_DIR_ORIGINAL;
	tuple.dst.protonum = (uint8_t)protocol;
	tuple.dst.u.all = (__be16)htons(create.dest_port);

	h = nf_conntrack_find_get(&init_net, NF_CT_DEFAULT_ZONE, &tuple);
	if (h) {
		struct nf_conn *ct;
		ct = nf_ct_tuplehash_to_ctrack(h);

		/*
		 * Initialize DSCP MARKING information
		 */
		if (offload_dscpremark_get_target_info(ct, &create.dscp_imask, &create.dscp_itag, &create.dscp_omask, &create.dscp_oval)) {
			DEBUG_TRACE("%p: DSCP remark information present on: %p\n\timask: %x, itag: %x, omask: %x, oval: %x\n",
				fecnpi->ci, ct, create.dscp_imask, create.dscp_itag, create.dscp_omask, create.dscp_oval);
			create.flags |= NSS_IPV4_CREATE_FLAG_DSCP_MARKING;
		} else {
			DEBUG_TRACE("%p: DSCP remark information is not present on: %p\n", fecnpi->ci, ct);
			create.dscp_itag = ECM_NSS_CONNMGR_DSCP_MARKING_NOT_CONFIGURED;
			create.dscp_imask = ECM_NSS_CONNMGR_DSCP_MARKING_NOT_CONFIGURED;
			create.dscp_omask = ECM_NSS_CONNMGR_DSCP_MARKING_NOT_CONFIGURED;
			create.dscp_oval = ECM_NSS_CONNMGR_DSCP_MARKING_NOT_CONFIGURED;
		}

		/*
		 * Initialize VLAN MARKING information
		 */
		if (offload_vlantag_get_target_info(ct, &create.vlan_imask, &create.vlan_itag, &create.vlan_omask, &create.vlan_oval)) {
			DEBUG_TRACE("%p: VLAN marking information present on: %p\n\timask: %x, itag: %x, omask: %x, oval: %x\n",
				fecnpi->ci, ct, create.vlan_imask, create.vlan_itag, create.vlan_omask, create.vlan_oval);
			create.flags |= NSS_IPV4_CREATE_FLAG_VLAN_MARKING;
		} else {
			DEBUG_TRACE("%p: VLAN marking information is not present on: %p\n", fecnpi->ci, ct);
			create.vlan_itag = ECM_NSS_CONNMGR_VLAN_MARKING_NOT_CONFIGURED;
			create.vlan_imask= ECM_NSS_CONNMGR_VLAN_MARKING_NOT_CONFIGURED;
			create.vlan_omask = ECM_NSS_CONNMGR_VLAN_MARKING_NOT_CONFIGURED;
			create.vlan_oval = ECM_NSS_CONNMGR_VLAN_MARKING_NOT_CONFIGURED;
		}

		nf_ct_put(ct);
	}

	/*
	 * Get MTU information
	 */
	create.from_mtu = (uint32_t)ecm_db_connection_from_iface_mtu_get(fecnpi->ci);
	create.to_mtu = (uint32_t)ecm_db_connection_to_iface_mtu_get(fecnpi->ci);

	/*
	 * Sync our creation command from the assigned classifiers to get specific additional creation rules.
	 * NOTE: These are called in ascending order of priority and so the last classifier (highest) shall
	 * override any preceding classifiers.
	 * This also gives the classifiers a chance to see that acceleration is being attempted.
	 */
	assignment_count = ecm_db_connection_classifier_assignments_get_and_ref(fecnpi->ci, assignments);
	for (aci_index = 0; aci_index < assignment_count; ++aci_index) {
		struct ecm_classifier_instance *aci;

		aci = assignments[aci_index];
		DEBUG_TRACE("%p: sync from: %p, type: %d\n", fecnpi, aci, aci->type_get(aci));
		aci->sync_from_v4(aci, &create);
	}
	ecm_db_connection_assignments_release(assignment_count, assignments);

	/*
	 * Release the interface lists
	 */
	ecm_db_connection_interfaces_deref(from_ifaces, from_ifaces_first);
	ecm_db_connection_interfaces_deref(to_ifaces, to_ifaces_first);

	DEBUG_INFO("%p: NON_PORTED Accelerate connection %p\n"
			"Protocol: %d\n"
			"from_mtu: %u\n"
			"to_mtu: %u\n"
			"from_ip: %pI4h:%d\n"
			"to_ip: %pI4h:%d\n"
			"from_ip_xlate: %pI4h:%d\n"
			"to_ip_xlate: %pI4h:%d\n"
			"from_mac: %pM\n"
			"to_mac: %pM\n"
			"from_mac_xlate: %pM\n"
			"to_mac_xlate: %pM\n"
			"src_iface_num: %u\n"
			"dest_iface_num: %u\n"
			"ingress_vlan_tag: %u\n"
			"egress_vlan_tag: %u\n"
			"vlan_itag: %x\n"
			"vlan_imask: %x\n"
			"vlan_omask: %x\n"
			"vlan_oval: %x\n"
			"dscp_itag: %x\n"
			"dscp_imask: %x\n"
			"dscp_omask: %x\n"
			"dscp_oval: %x\n"
			"flags: %x\n"
			"return_pppoe_session_id: %u\n"
			"return_pppoe_remote_mac: %pM\n"
			"flow_pppoe_session_id: %u\n"
			"flow_pppoe_remote_mac: %pM\n"
			"qos_tag: %x (%u)\n",
			fecnpi,
			fecnpi->ci,
			create.protocol,
			create.from_mtu,
			create.to_mtu,
			&create.src_ip, create.src_port,
			&create.dest_ip, create.dest_port,
			&create.src_ip_xlate, create.src_port_xlate,
			&create.dest_ip_xlate, create.dest_port_xlate,
			create.src_mac,
			create.dest_mac,
			create.src_mac_xlate,
			create.dest_mac_xlate,
			create.src_interface_num,
			create.dest_interface_num,
			create.ingress_vlan_tag,
			create.egress_vlan_tag,
			create.vlan_itag,
			create.vlan_imask,
			create.vlan_omask,
			create.vlan_oval,
			create.dscp_itag,
			create.dscp_imask,
			create.dscp_omask,
			create.dscp_oval,
			create.flags,
			create.return_pppoe_session_id,
			create.return_pppoe_remote_mac,
			create.flow_pppoe_session_id,
			create.flow_pppoe_remote_mac,
			create.qos_tag, create.qos_tag);

	/*
	 * Call the relevant rule create function
	 */
	if (create.dscp_oval == ECM_NSS_CONNMGR_DSCP_MARKING_NOT_CONFIGURED &&
			create.vlan_oval == ECM_NSS_CONNMGR_VLAN_MARKING_NOT_CONFIGURED) {
		nss_tx_status = nss_tx_create_ipv4_rule(ecm_front_end_ipv4_nss_ipv4_context, &create);
	} else {
		nss_tx_status = nss_tx_create_ipv4_rule1(ecm_front_end_ipv4_nss_ipv4_context, &create);
	}
	if (nss_tx_status == NSS_TX_SUCCESS) {
		return;
	}

	/*
	 * Revert accel mode if necessary
	 */
	DEBUG_WARN("%p: Accel attempt failed\n", fecnpi);
	spin_lock_bh(&fecnpi->lock);
	if (fecnpi->accel_mode == ECM_CLASSIFIER_ACCELERATION_MODE_ACCEL) {
		fecnpi->accel_mode = ECM_CLASSIFIER_ACCELERATION_MODE_NO;
	}
	spin_unlock_bh(&fecnpi->lock);
}

/*
 * ecm_front_end_ipv4_connection_non_ported_front_end_decelerate()
 *	Decelerate a connection
 */
static void ecm_front_end_ipv4_connection_non_ported_front_end_decelerate(struct ecm_front_end_connection_instance *feci)
{
	struct ecm_front_end_ipv4_connection_non_ported_instance *fecnpi = (struct ecm_front_end_ipv4_connection_non_ported_instance *)feci;
	struct nss_ipv4_destroy destroy;
	ip_addr_t addr;
	int protocol;

	DEBUG_CHECK_MAGIC(fecnpi, ECM_FRONT_END_IPV4_CONNECTION_NON_PORTED_INSTANCE_MAGIC, "%p: magic failed", fecnpi);

	/*
	 * For non-ported protocols we only support IPv6 in 4 or ESP
	 */
	protocol = ecm_db_connection_protocol_get(fecnpi->ci);
	if ((protocol != IPPROTO_IPV6) && (protocol != IPPROTO_ESP)) {
		DEBUG_TRACE("%p: unsupported protocol: %d\n", fecnpi, protocol);
		return;
	}

	destroy.protocol = (int32_t)protocol;

	/*
	 * Get addressing information
	 */
	ecm_db_connection_from_address_get(fecnpi->ci, addr);
	ECM_IP_ADDR_TO_NIN4_ADDR(destroy.src_ip, addr);
	ecm_db_connection_to_address_nat_get(fecnpi->ci, addr);
	ECM_IP_ADDR_TO_NIN4_ADDR(destroy.dest_ip, addr);
	destroy.src_port = ecm_db_connection_from_port_get(fecnpi->ci);
	destroy.dest_port = ecm_db_connection_to_port_nat_get(fecnpi->ci);

	DEBUG_INFO("%p: NON_PORTED Connection %p decelerate\n"
			"src_ip: %pI4:%d\n"
			"dest_ip: %pI4:%d\n",
			fecnpi, fecnpi->ci,
			&destroy.src_ip, destroy.src_port,
			&destroy.dest_ip, destroy.dest_port);

	/*
	 * Destroy the Network Accelerator connection cache entries.
	 */
	nss_tx_destroy_ipv4_rule(ecm_front_end_ipv4_nss_ipv4_context, &destroy);
}

/*
 * ecm_front_end_ipv4_connection_non_ported_front_end_accel_state_get()
 *	Get acceleration state
 */
static void ecm_front_end_ipv4_connection_non_ported_front_end_accel_state_get(struct ecm_front_end_connection_instance *feci,
								ecm_classifier_acceleration_mode_t *accel_mode,
								int *count, int *limit, bool *can_accel)
{
	struct ecm_front_end_ipv4_connection_non_ported_instance *fecnpi = (struct ecm_front_end_ipv4_connection_non_ported_instance *)feci;

	DEBUG_CHECK_MAGIC(fecnpi, ECM_FRONT_END_IPV4_CONNECTION_NON_PORTED_INSTANCE_MAGIC, "%p: magic failed", fecnpi);
	spin_lock_bh(&fecnpi->lock);
	*accel_mode = fecnpi->accel_mode;
	*count = fecnpi->accel_count;
	*limit = fecnpi->accel_limit;
	*can_accel = fecnpi->can_accel;
	spin_unlock_bh(&fecnpi->lock);
}

/*
 * ecm_front_end_ipv4_connection_non_ported_front_end_accel_count_reset()
 *	Reset the accel counter - because the NA has sent a sync message indicating that some data was accelerated.
 */
static void ecm_front_end_ipv4_connection_non_ported_front_end_accel_count_reset(struct ecm_front_end_connection_instance *feci)
{
	struct ecm_front_end_ipv4_connection_non_ported_instance *fecnpi = (struct ecm_front_end_ipv4_connection_non_ported_instance *)feci;

	DEBUG_CHECK_MAGIC(fecnpi, ECM_FRONT_END_IPV4_CONNECTION_NON_PORTED_INSTANCE_MAGIC, "%p: magic failed", fecnpi);

	DEBUG_INFO("%p: reset accel count\n", fecnpi);
	spin_lock_bh(&fecnpi->lock);
	fecnpi->accel_count = 0;
	spin_unlock_bh(&fecnpi->lock);
}

/*
 * ecm_front_end_ipv4_connection_non_ported_front_end_accel_ceased()
 *	NA has indicated that acceleration has stopped.
 */
static void ecm_front_end_ipv4_connection_non_ported_front_end_accel_ceased(struct ecm_front_end_connection_instance *feci)
{
	struct ecm_front_end_ipv4_connection_non_ported_instance *fecnpi = (struct ecm_front_end_ipv4_connection_non_ported_instance *)feci;

	DEBUG_CHECK_MAGIC(fecnpi, ECM_FRONT_END_IPV4_CONNECTION_NON_PORTED_INSTANCE_MAGIC, "%p: magic failed", fecnpi);

	DEBUG_INFO("%p: accel ceased\n", fecnpi);
	spin_lock_bh(&fecnpi->lock);
	fecnpi->accel_mode = ECM_CLASSIFIER_ACCELERATION_MODE_NO;
	spin_unlock_bh(&fecnpi->lock);
}

/*
 * ecm_front_end_ipv4_connection_non_ported_front_end_ref()
 *	Ref a connection front end instance
 */
static void ecm_front_end_ipv4_connection_non_ported_front_end_ref(struct ecm_front_end_connection_instance *feci)
{
	struct ecm_front_end_ipv4_connection_non_ported_instance *fecnpi = (struct ecm_front_end_ipv4_connection_non_ported_instance *)feci;

	DEBUG_CHECK_MAGIC(fecnpi, ECM_FRONT_END_IPV4_CONNECTION_NON_PORTED_INSTANCE_MAGIC, "%p: magic failed", fecnpi);
	spin_lock_bh(&fecnpi->lock);
	fecnpi->refs++;
	DEBUG_TRACE("%p: fecnpi ref %d\n", fecnpi, fecnpi->refs);
	DEBUG_ASSERT(fecnpi->refs > 0, "%p: ref wrap\n", fecnpi);
	spin_unlock_bh(&fecnpi->lock);
}

/*
 * ecm_front_end_ipv4_connection_non_ported_front_end_deref()
 *	Deref a connection front end instance
 */
static int ecm_front_end_ipv4_connection_non_ported_front_end_deref(struct ecm_front_end_connection_instance *feci)
{
	struct ecm_front_end_ipv4_connection_non_ported_instance *fecnpi = (struct ecm_front_end_ipv4_connection_non_ported_instance *)feci;

	DEBUG_CHECK_MAGIC(fecnpi, ECM_FRONT_END_IPV4_CONNECTION_NON_PORTED_INSTANCE_MAGIC, "%p: magic failed", fecnpi);

	spin_lock_bh(&fecnpi->lock);
	fecnpi->refs--;
	DEBUG_ASSERT(fecnpi->refs >= 0, "%p: ref wrap\n", fecnpi);

	if (fecnpi->refs > 0) {
		int refs = fecnpi->refs;
		spin_unlock_bh(&fecnpi->lock);
		DEBUG_TRACE("%p: fecnpi deref %d\n", fecnpi, refs);
		return refs;
	}
	spin_unlock_bh(&fecnpi->lock);

	/*
	 * We can now destroy the instance
	 */
	DEBUG_TRACE("%p: fecnpi final\n", fecnpi);
	kfree(fecnpi);
	DEBUG_CLEAR_MAGIC(fecnpi);

	/*
	 * No longer need ref to thread for this object
	 */
	spin_lock_bh(&ecm_front_end_ipv4_lock);
	ecm_front_end_ipv4_thread_refs--;
	DEBUG_ASSERT(ecm_front_end_ipv4_thread_refs >= 0, "Thread refs wrap %d\n", ecm_front_end_ipv4_thread_refs);
	spin_unlock_bh(&ecm_front_end_ipv4_lock);

	/*
	 * Thread may be able to exit on object destruction
	 */
	wake_up_process(ecm_front_end_ipv4_thread);
	return 0;
}

/*
 * ecm_front_end_ipv4_connection_non_ported_front_end_xml_state_get()
 *	Return an XML element containing the state of this Non ported front end instance
 */
static int ecm_front_end_ipv4_connection_non_ported_front_end_xml_state_get(struct ecm_front_end_connection_instance *feci, char *buf, int buf_sz)
{
	bool can_accel;
	ecm_classifier_acceleration_mode_t accel_mode;
	int accel_count;
	int accel_limit;
	struct ecm_front_end_ipv4_connection_non_ported_instance *fecnpi = (struct ecm_front_end_ipv4_connection_non_ported_instance *)feci;

	DEBUG_CHECK_MAGIC(fecnpi, ECM_FRONT_END_IPV4_CONNECTION_NON_PORTED_INSTANCE_MAGIC, "%p: magic failed", fecnpi);

	spin_lock_bh(&fecnpi->lock);
	can_accel = fecnpi->can_accel;
	accel_mode = fecnpi->accel_mode;
	accel_count = fecnpi->accel_count;
	accel_limit = fecnpi->accel_limit;
	spin_unlock_bh(&fecnpi->lock);

	return snprintf(buf, buf_sz, "<front_end_non_ported can_accel=\"%u\" accel_mode=\"%d\" "
			"accel_count=\"%d\" accel_limit=\"%d\"/>\n",
			can_accel,
			accel_mode,
			accel_count,
			accel_limit);

}

/*
 * ecm_front_end_ipv4_connection_non_ported_instance_alloc()
 *	Create a front end instance specific for NON_PORTED connection
 */
static struct ecm_front_end_ipv4_connection_non_ported_instance *ecm_front_end_ipv4_connection_non_ported_instance_alloc(
								struct ecm_db_connection_instance *ci,
								struct ecm_db_mapping_instance *src_mi,
								struct ecm_db_mapping_instance *dest_mi)
{
	struct ecm_front_end_ipv4_connection_non_ported_instance *fecnpi;

	fecnpi = (struct ecm_front_end_ipv4_connection_non_ported_instance *)kzalloc(sizeof(struct ecm_front_end_ipv4_connection_non_ported_instance), GFP_ATOMIC | __GFP_NOWARN);
	if (!fecnpi) {
		DEBUG_WARN("NON_PORTED Front end alloc failed\n");
		return NULL;
	}

	/*
	 * Refs is 1 for the creator of the connection
	 */
	fecnpi->refs = 1;
	DEBUG_SET_MAGIC(fecnpi, ECM_FRONT_END_IPV4_CONNECTION_NON_PORTED_INSTANCE_MAGIC);
	spin_lock_init(&fecnpi->lock);

	/*
	 * Copy reference to connection - no need to ref ci as ci maintains a ref to this instance instead (this instance persists for as long as ci does)
	 */
	fecnpi->ci = ci;

	/*
	 * Populate the methods and callbacks
	 */
	fecnpi->base.ref = ecm_front_end_ipv4_connection_non_ported_front_end_ref;
	fecnpi->base.deref = ecm_front_end_ipv4_connection_non_ported_front_end_deref;
	fecnpi->base.decelerate = ecm_front_end_ipv4_connection_non_ported_front_end_decelerate;
	fecnpi->base.accel_state_get = ecm_front_end_ipv4_connection_non_ported_front_end_accel_state_get;
	fecnpi->base.accel_count_reset = ecm_front_end_ipv4_connection_non_ported_front_end_accel_count_reset;
	fecnpi->base.accel_ceased = ecm_front_end_ipv4_connection_non_ported_front_end_accel_ceased;
	fecnpi->base.xml_state_get = ecm_front_end_ipv4_connection_non_ported_front_end_xml_state_get;

	/*
	 * Ensure our thread persists (and hence this module) for as long as the connection and its supporting framework is alive
	 * as we could get callbacks from the database
	 */
	spin_lock_bh(&ecm_front_end_ipv4_lock);
	ecm_front_end_ipv4_thread_refs++;
	DEBUG_ASSERT(ecm_front_end_ipv4_thread_refs > 0, "Thread refs wrap %d\n", ecm_front_end_ipv4_thread_refs);
	spin_unlock_bh(&ecm_front_end_ipv4_lock);
	return fecnpi;
}

/*
 * ecm_front_end_ipv4_assign_classifier()
 *	Instantiate and assign classifier of type upon the connection, also returning it if it could be allocated.
 */
static struct ecm_classifier_instance *ecm_front_end_ipv4_assign_classifier(struct ecm_db_connection_instance *ci, ecm_classifier_type_t type)
{
	DEBUG_TRACE("%p: Assign classifier of type: %d\n", ci, type);
	DEBUG_ASSERT(type != ECM_CLASSIFIER_TYPE_DEFAULT, "Must never need to instantiate default type in this way");

	if (type == ECM_CLASSIFIER_TYPE_NL) {
		struct ecm_classifier_nl_instance *cnli;
		cnli = ecm_classifier_nl_instance_alloc(ci);
		if (!cnli) {
			DEBUG_TRACE("%p: Failed to create Netlink classifier\n", ci);
			return NULL;
		}
		DEBUG_TRACE("%p: Created Netlink classifier: %p\n", ci, cnli);
		ecm_db_connection_classifier_assign(ci, (struct ecm_classifier_instance *)cnli);
		return (struct ecm_classifier_instance *)cnli;
	}

	if (type == ECM_CLASSIFIER_TYPE_HYFI) {
		struct ecm_classifier_hyfi_instance *chfi;
		chfi = ecm_classifier_hyfi_instance_alloc(ci);
		if (!chfi) {
			DEBUG_TRACE("%p: Failed to create HyFi classifier\n", ci);
			return NULL;
		}
		DEBUG_TRACE("%p: Created HyFi classifier: %p\n", ci, chfi);
		ecm_db_connection_classifier_assign(ci, (struct ecm_classifier_instance *)chfi);
		return (struct ecm_classifier_instance *)chfi;
	}

	// GGG TODO Add other classifier types.
	DEBUG_ASSERT(NULL, "%p: Unsupported type: %d\n", ci, type);
	return NULL;
}

/*
 * ecm_front_end_ipv4_reclassify()
 *	Signal reclassify upon the assigned classifiers.
 *
 * Classifiers that unassigned themselves we TRY to re-instantiate them.
 * Returns false if the function is not able to instantiate all missing classifiers.
 * This function does not release and references to classifiers in the assignments[].
 */
static bool ecm_front_end_ipv4_reclassify(struct ecm_db_connection_instance *ci, int assignment_count, struct ecm_classifier_instance *assignments[])
{
	ecm_classifier_type_t classifier_type;
	int i;
	bool full_reclassification = true;

	/*
	 * assignment_count will always be <= the number of classifier types available
	 */
	for (i = 0, classifier_type = ECM_CLASSIFIER_TYPE_DEFAULT; i < assignment_count; ++i, ++classifier_type) {
		ecm_classifier_type_t aci_type;
		struct ecm_classifier_instance *aci;

		aci = assignments[i];
		aci_type = aci->type_get(aci);
		DEBUG_TRACE("%p: Reclassify: %d\n", ci, aci_type);
		aci->reclassify(aci);

		/*
		 * If the connection has a full complement of assigned classifiers then these will match 1:1 with the classifier_type (all in same order).
		 * If not, we have to create the missing ones.
		 */
		if (aci_type == classifier_type) {
			continue;
		}

		/*
		 * Need to instantiate the missing classifier types until we get to the same type as aci_type then we are back in sync to continue reclassification
		 */
		while (classifier_type != aci_type) {
			struct ecm_classifier_instance *naci;
			DEBUG_TRACE("%p: Instantiate missing type: %d\n", ci, classifier_type);
			DEBUG_ASSERT(classifier_type < ECM_CLASSIFIER_TYPES, "Algorithm bad");

			naci = ecm_front_end_ipv4_assign_classifier(ci, classifier_type);
			if (!naci) {
				full_reclassification = false;
			} else {
				naci->deref(naci);
			}

			classifier_type++;
		}
	}

	/*
	 * Add missing types
	 */
	for (; classifier_type < ECM_CLASSIFIER_TYPES; ++classifier_type) {
		struct ecm_classifier_instance *naci;
		DEBUG_TRACE("%p: Instantiate missing type: %d\n", ci, classifier_type);

		naci = ecm_front_end_ipv4_assign_classifier(ci, classifier_type);
		if (!naci) {
			full_reclassification = false;
		} else {
			naci->deref(naci);
		}
	}

	DEBUG_TRACE("%p: reclassify done: %u\n", ci, full_reclassification);
	return full_reclassification;
}


/*
 * ecm_front_end_ipv4_tcp_process()
 *	Process a TCP packet
 */
static unsigned int ecm_front_end_ipv4_tcp_process(struct net_device *out_dev, struct net_device *in_dev, bool can_accel, bool is_routed, struct sk_buff *skb,
							struct ecm_tracker_ip_header *ip_hdr,
							struct nf_conn *ct, enum ip_conntrack_dir ct_dir, ecm_db_direction_t ecm_dir,
							struct nf_conntrack_tuple *orig_tuple, struct nf_conntrack_tuple *reply_tuple,
							ip_addr_t ip_src_addr, ip_addr_t ip_dest_addr, ip_addr_t ip_src_addr_nat, ip_addr_t ip_dest_addr_nat)
{
	struct tcphdr *tcp_hdr;
	struct tcphdr tcp_hdr_buff;
	int src_port;
	int src_port_nat;
	int dest_port;
	int dest_port_nat;
	struct ecm_db_connection_instance *ci;
	ecm_tracker_sender_type_t sender;
	ip_addr_t match_addr;
	struct ecm_classifier_instance *assignments[ECM_CLASSIFIER_TYPES];
	int aci_index;
	int assignment_count;
	ecm_db_timer_group_t ci_orig_timer_group;
	struct ecm_classifier_process_response prevalent_pr;

	/*
	 * Extract TCP header to obtain port information
	 */
	tcp_hdr = ecm_tracker_tcp_check_header_and_read(skb, ip_hdr, &tcp_hdr_buff);
	if (unlikely(!tcp_hdr)) {
		DEBUG_WARN("TCP packet header %p\n", skb);
		return NF_DROP;
	}

	/*
	 * Now extract information, if we have conntrack then use that (which would already be in the tuples)
	 */
	if (unlikely(!ct)) {
		orig_tuple->src.u.tcp.port = tcp_hdr->source;
		orig_tuple->dst.u.tcp.port = tcp_hdr->dest;
		reply_tuple->src.u.tcp.port = tcp_hdr->dest;
		reply_tuple->dst.u.tcp.port = tcp_hdr->source;
	}

	/*
	 * Extract transport port information
	 * Refer to the ecm_front_end_ipv4_process() for information on how we extract this information.
	 */
	if (ct_dir == IP_CT_DIR_ORIGINAL) {
		if (ecm_dir == ECM_DB_DIRECTION_EGRESS) {
			src_port = ntohs(orig_tuple->src.u.tcp.port);
			dest_port = ntohs(orig_tuple->dst.u.tcp.port);
			dest_port_nat = ntohs(reply_tuple->src.u.tcp.port);
			src_port_nat = ntohs(reply_tuple->dst.u.tcp.port);
		} else {
			src_port = ntohs(orig_tuple->src.u.tcp.port);
			dest_port_nat = ntohs(orig_tuple->dst.u.tcp.port);
			dest_port = ntohs(reply_tuple->src.u.tcp.port);
			src_port_nat = ntohs(reply_tuple->dst.u.tcp.port);
		}
	} else {
		if (ecm_dir == ECM_DB_DIRECTION_EGRESS) {
			dest_port = ntohs(orig_tuple->src.u.tcp.port);
			src_port = ntohs(orig_tuple->dst.u.tcp.port);
			src_port_nat = ntohs(reply_tuple->src.u.tcp.port);
			dest_port_nat = ntohs(reply_tuple->dst.u.tcp.port);
		} else {
			dest_port = ntohs(orig_tuple->src.u.tcp.port);
			src_port_nat = ntohs(orig_tuple->dst.u.tcp.port);
			src_port = ntohs(reply_tuple->src.u.tcp.port);
			dest_port_nat = ntohs(reply_tuple->dst.u.tcp.port);
		}
	}

	DEBUG_TRACE("TCP src: " ECM_IP_ADDR_DOT_FMT "(" ECM_IP_ADDR_DOT_FMT "):%d(%d), dest: " ECM_IP_ADDR_DOT_FMT "(" ECM_IP_ADDR_DOT_FMT "):%d(%d), dir %d\n",
			ECM_IP_ADDR_TO_DOT(ip_src_addr), ECM_IP_ADDR_TO_DOT(ip_src_addr_nat), src_port, src_port_nat, ECM_IP_ADDR_TO_DOT(ip_dest_addr),
			ECM_IP_ADDR_TO_DOT(ip_dest_addr_nat), dest_port, dest_port_nat, ecm_dir);

	/*
	 * Look up a connection
	 */
	ci = ecm_db_connection_find_and_ref(ip_src_addr, ip_dest_addr, IPPROTO_TCP, src_port, dest_port);

	/*
	 * If there is no existing connection then create a new one.
	 */
	if (unlikely(!ci)) {
		struct ecm_db_mapping_instance *src_mi;
		struct ecm_db_mapping_instance *dest_mi;
		struct ecm_db_mapping_instance *src_nat_mi;
		struct ecm_db_mapping_instance *dest_nat_mi;
		struct ecm_classifier_default_instance *dci;
		struct ecm_db_connection_instance *nci;
		ecm_classifier_type_t classifier_type;
		struct ecm_front_end_connection_instance *feci;
		int32_t to_list_first;
		struct ecm_db_iface_instance *to_list[ECM_DB_IFACE_HEIRARCHY_MAX];
		int32_t to_nat_list_first;
		struct ecm_db_iface_instance *to_nat_list[ECM_DB_IFACE_HEIRARCHY_MAX];
		int32_t from_list_first;
		struct ecm_db_iface_instance *from_list[ECM_DB_IFACE_HEIRARCHY_MAX];
		int32_t from_nat_list_first;
		struct ecm_db_iface_instance *from_nat_list[ECM_DB_IFACE_HEIRARCHY_MAX];

		DEBUG_INFO("New TCP connection from " ECM_IP_ADDR_DOT_FMT ":%u to " ECM_IP_ADDR_DOT_FMT ":%u\n",
				ECM_IP_ADDR_TO_DOT(ip_src_addr), src_port, ECM_IP_ADDR_TO_DOT(ip_dest_addr), dest_port);

		/*
		 * Before we attempt to create the connection are we being terminated?
		 */
		spin_lock_bh(&ecm_front_end_ipv4_lock);
		if (ecm_front_end_ipv4_terminate_pending) {
			spin_unlock_bh(&ecm_front_end_ipv4_lock);
			DEBUG_WARN("Terminating\n");

			/*
			 * As we are terminating we just allow the packet to pass - it's no longer our concern
			 */
			return NF_ACCEPT;
		}
		spin_unlock_bh(&ecm_front_end_ipv4_lock);

		/*
		 * Now allocate the new connection
		 */
		nci = ecm_db_connection_alloc();
		if (!nci) {
			DEBUG_WARN("Failed to allocate connection\n");
			return NF_DROP;
		}

		/*
		 * Get the src and destination mappings
		 */
		src_mi = ecm_front_end_ipv4_mapping_establish_and_ref(in_dev, ip_src_addr, src_port);
		if (!src_mi) {
			ecm_db_connection_deref(nci);
			DEBUG_WARN("Failed to establish src mapping\n");
			return NF_DROP;
		}

		dest_mi = ecm_front_end_ipv4_mapping_establish_and_ref(out_dev, ip_dest_addr, dest_port);
		if (!dest_mi) {
			ecm_db_mapping_deref(src_mi);
			ecm_db_connection_deref(nci);
			DEBUG_WARN("Failed to establish dest mapping\n");
			return NF_DROP;
		}

		/*
		 * Get the src and destination NAT mappings
		 */
		src_nat_mi = ecm_front_end_ipv4_mapping_establish_and_ref(in_dev, ip_src_addr_nat, src_port_nat);
		if (!src_nat_mi) {
			ecm_db_mapping_deref(dest_mi);
			ecm_db_mapping_deref(src_mi);
			ecm_db_connection_deref(nci);
			DEBUG_WARN("Failed to establish src nat mapping\n");
			return NF_DROP;
		}

		dest_nat_mi = ecm_front_end_ipv4_mapping_establish_and_ref(out_dev, ip_dest_addr_nat, dest_port_nat);
		if (!dest_nat_mi) {
			ecm_db_mapping_deref(src_nat_mi);
			ecm_db_mapping_deref(dest_mi);
			ecm_db_mapping_deref(src_mi);
			ecm_db_connection_deref(nci);
			DEBUG_WARN("Failed to establish dest mapping\n");
			return NF_DROP;
		}

		/*
		 * Connection must have a front end instance associated with it
		 */
		feci = (struct ecm_front_end_connection_instance *)ecm_front_end_ipv4_connection_tcp_instance_alloc(nci, src_mi, dest_mi, can_accel);
		if (!feci) {
			ecm_db_mapping_deref(dest_nat_mi);
			ecm_db_mapping_deref(src_nat_mi);
			ecm_db_mapping_deref(dest_mi);
			ecm_db_mapping_deref(src_mi);
			ecm_db_connection_deref(nci);
			DEBUG_WARN("Failed to allocate front end\n");
			return NF_DROP;
		}

		/*
		 * Every connection also needs a default classifier which is considered 'special'
		 */
		dci = ecm_classifier_default_instance_alloc(nci, IPPROTO_TCP, ecm_dir, src_port, dest_port);
		if (!dci) {
			feci->deref(feci);
			ecm_db_mapping_deref(dest_nat_mi);
			ecm_db_mapping_deref(src_nat_mi);
			ecm_db_mapping_deref(dest_mi);
			ecm_db_mapping_deref(src_mi);
			ecm_db_connection_deref(nci);
			DEBUG_WARN("Failed to allocate default classifier\n");
			return NF_DROP;
		}

		/*
		 * Every connection starts with a full complement of classifiers assigned.
		 * NOTE: Default classifier is a special case considered previously
		 */
		for (classifier_type = ECM_CLASSIFIER_TYPE_DEFAULT + 1; classifier_type < ECM_CLASSIFIER_TYPES; ++classifier_type) {
			struct ecm_classifier_instance *aci = ecm_front_end_ipv4_assign_classifier(nci, classifier_type);
			if (aci) {
				aci->deref(aci);
			} else {
				dci->base.deref((struct ecm_classifier_instance *)dci);
				feci->deref(feci);
				ecm_db_mapping_deref(dest_nat_mi);
				ecm_db_mapping_deref(src_nat_mi);
				ecm_db_mapping_deref(dest_mi);
				ecm_db_mapping_deref(src_mi);
				ecm_db_connection_deref(nci);
				DEBUG_WARN("Failed to allocate classifiers assignments\n");
				return NF_DROP;
			}
		}

		/*
		 * Get the initial interface lists the connection will be using
		 */
		DEBUG_TRACE("%p: Create the 'from' interface heirarchy list\n", nci);
		from_list_first = ecm_interface_heirarchy_construct(from_list, ip_dest_addr, ip_src_addr, IPPROTO_TCP);
		ecm_db_connection_from_interfaces_reset(nci, from_list, from_list_first);
		ecm_db_connection_interfaces_deref(from_list, from_list_first);

		DEBUG_TRACE("%p: Create the 'from NAT' interface heirarchy list\n", nci);
		from_nat_list_first = ecm_interface_heirarchy_construct(from_nat_list, ip_dest_addr, ip_src_addr_nat, IPPROTO_TCP);
		ecm_db_connection_from_nat_interfaces_reset(nci, from_nat_list, from_nat_list_first);
		ecm_db_connection_interfaces_deref(from_nat_list, from_nat_list_first);

		DEBUG_TRACE("%p: Create the 'to' interface heirarchy list\n", nci);
		to_list_first = ecm_interface_heirarchy_construct(to_list, ip_src_addr, ip_dest_addr, IPPROTO_TCP);
		ecm_db_connection_to_interfaces_reset(nci, to_list, to_list_first);
		ecm_db_connection_interfaces_deref(to_list, to_list_first);

		DEBUG_TRACE("%p: Create the 'to NAT' interface heirarchy list\n", nci);
		to_nat_list_first = ecm_interface_heirarchy_construct(to_nat_list, ip_src_addr, ip_dest_addr_nat, IPPROTO_TCP);
		ecm_db_connection_to_nat_interfaces_reset(nci, to_nat_list, to_nat_list_first);
		ecm_db_connection_interfaces_deref(to_nat_list, to_nat_list_first);

		/*
		 * Now add the connection into the database.
		 * NOTE: In an SMP situation such as ours there is a possibility that more than one packet for the same
		 * connection is being processed simultaneously.
		 * We *could* end up creating more than one connection instance for the same actual connection.
		 * To guard against this we now perform a mutex'd lookup of the connection + add once more - another cpu may have created it before us.
		 */
		spin_lock_bh(&ecm_front_end_ipv4_lock);
		ci = ecm_db_connection_find_and_ref(ip_src_addr, ip_dest_addr, IPPROTO_TCP, src_port, dest_port);
		if (ci) {
			/*
			 * Another cpu created the same connection before us - use the one we just found
			 */
			spin_unlock_bh(&ecm_front_end_ipv4_lock);
			ecm_db_connection_deref(nci);
		} else {
			ecm_db_timer_group_t tg;
			ecm_tracker_sender_state_t src_state;
			ecm_tracker_sender_state_t dest_state;
			ecm_tracker_connection_state_t state;
			struct ecm_tracker_instance *ti;

			/*
			 * Ask tracker for timer group to set the connection to initially.
			 */
			ti = dci->tracker_get_and_ref(dci);
			ti->state_get(ti, &src_state, &dest_state, &state, &tg);
			ti->deref(ti);

			/*
			 * Add the new connection we created into the database
			 * NOTE: assign to a short timer group for now - it is the assigned classifiers responsibility to do this
			 */
			ecm_db_connection_add(nci, feci, dci,
					src_mi, dest_mi, src_nat_mi, dest_nat_mi,
					IPPROTO_TCP, ecm_dir,
					ecm_front_end_ipv4_connection_final_tcp,
					tg, is_routed, nci);

			/*
			 * Ensure our thread persists (and hence this module) for as long as the connection and its supporting framework is alive
			 * as we could get callbacks or methods invoked
			 */
			ecm_front_end_ipv4_thread_refs++;
			DEBUG_ASSERT(ecm_front_end_ipv4_thread_refs > 0, "Thread refs wrap %d\n", ecm_front_end_ipv4_thread_refs);

			spin_unlock_bh(&ecm_front_end_ipv4_lock);

			ci = nci;
			DEBUG_INFO("%p: New TCP connection created\n", ci);
		}

		/*
		 * No longer need referenecs to the objects we created
		 */
		feci->deref(feci);
		dci->base.deref((struct ecm_classifier_instance *)dci);
		ecm_db_mapping_deref(src_mi);
		ecm_db_mapping_deref(dest_mi);
		ecm_db_mapping_deref(src_nat_mi);
		ecm_db_mapping_deref(dest_nat_mi);
	}

	/*
	 * Keep connection alive as we have seen activity
	 */
	if (!ecm_db_connection_defunct_timer_touch(ci)) {
		ecm_db_connection_deref(ci);
		return NF_DROP;
	}

	/*
	 * Do we need to action generation change?
	 */
	if (unlikely(ecm_db_connection_classifier_generation_changed(ci))) {
		int i;
		bool reclassify_allowed;
		int32_t to_list_first;
		struct ecm_db_iface_instance *to_list[ECM_DB_IFACE_HEIRARCHY_MAX];
		int32_t to_nat_list_first;
		struct ecm_db_iface_instance *to_nat_list[ECM_DB_IFACE_HEIRARCHY_MAX];
		int32_t from_list_first;
		struct ecm_db_iface_instance *from_list[ECM_DB_IFACE_HEIRARCHY_MAX];
		int32_t from_nat_list_first;
		struct ecm_db_iface_instance *from_nat_list[ECM_DB_IFACE_HEIRARCHY_MAX];

		DEBUG_INFO("%p: re-gen needed\n", ci);

		/*
		 * Update the interface lists - these may have changed, e.g. LAG path change etc.
		 * NOTE: We never have to change the usual mapping->host->node_iface arrangements for each side of the connection (to/from sides)
		 * This is because if these interfaces change then the connection is dead anyway.
		 * But a LAG slave might change the heirarchy the connection is using but the LAG master is still sane.
		 */
		DEBUG_TRACE("%p: Update the 'from' interface heirarchy list\n", ci);
		from_list_first = ecm_interface_heirarchy_construct(from_list, ip_dest_addr, ip_src_addr, IPPROTO_TCP);
		ecm_db_connection_from_interfaces_reset(ci, from_list, from_list_first);
		ecm_db_connection_interfaces_deref(from_list, from_list_first);

		DEBUG_TRACE("%p: Update the 'from NAT' interface heirarchy list\n", ci);
		from_nat_list_first = ecm_interface_heirarchy_construct(from_nat_list, ip_dest_addr, ip_src_addr_nat, IPPROTO_TCP);
		ecm_db_connection_from_nat_interfaces_reset(ci, from_nat_list, from_nat_list_first);
		ecm_db_connection_interfaces_deref(from_nat_list, from_nat_list_first);

		DEBUG_TRACE("%p: Update the 'to' interface heirarchy list\n", ci);
		to_list_first = ecm_interface_heirarchy_construct(to_list, ip_src_addr, ip_dest_addr, IPPROTO_TCP);
		ecm_db_connection_to_interfaces_reset(ci, to_list, to_list_first);
		ecm_db_connection_interfaces_deref(to_list, to_list_first);

		DEBUG_TRACE("%p: Update the 'to NAT' interface heirarchy list\n", ci);
		to_nat_list_first = ecm_interface_heirarchy_construct(to_nat_list, ip_src_addr, ip_dest_addr_nat, IPPROTO_TCP);
		ecm_db_connection_to_nat_interfaces_reset(ci, to_nat_list, to_nat_list_first);
		ecm_db_connection_interfaces_deref(to_nat_list, to_nat_list_first);

		/*
		 * Get list of assigned classifiers to reclassify.
		 * Remember: This also includes our default classifier too.
		 */
		assignment_count = ecm_db_connection_classifier_assignments_get_and_ref(ci, assignments);

		/*
		 * All of the assigned classifiers must permit reclassification.
		 */
		reclassify_allowed = true;
		for (i = 0; i < assignment_count; ++i) {
			DEBUG_TRACE("%p: Calling to reclassify: %p, type: %d\n", ci, assignments[i], assignments[i]->type_get(assignments[i]));
			if (!assignments[i]->reclassify_allowed(assignments[i])) {
				DEBUG_TRACE("%p: reclassify denied: %p, by type: %d\n", ci, assignments[i], assignments[i]->type_get(assignments[i]));
				reclassify_allowed = false;
				break;
			}
		}

		if (!reclassify_allowed) {
			DEBUG_WARN("%p: re-gen denied\n", ci);
		} else {
			/*
			 * Reclassify
			 */
			DEBUG_TRACE("%p: reclassify\n", ci);
			if (!ecm_front_end_ipv4_reclassify(ci, assignment_count, assignments)) {
				DEBUG_WARN("%p: Regeneration failed, dropping packet\n", ci);
				ecm_db_connection_assignments_release(assignment_count, assignments);
				ecm_db_connection_deref(ci);
				return NF_DROP;
			}
			DEBUG_TRACE("%p: reclassify success\n", ci);
		}

		/*
		 * Release the assignments and re-obtain them as there may be new ones been reassigned.
		 */
		ecm_db_connection_assignments_release(assignment_count, assignments);

		/*
		 * Interface lists are regenerated in any situation as they determine correct packet flow
		 * through the system - essential for correct interaction with the NSS and acceleration rule creation.
		 */
		DEBUG_TRACE("%p: Clearing interface lists\n", ci);
		ecm_db_connection_from_interfaces_clear(ci);
		ecm_db_connection_to_interfaces_clear(ci);
		ecm_db_connection_from_nat_interfaces_clear(ci);
		ecm_db_connection_to_nat_interfaces_clear(ci);
	}

	/*
	 * Identify which side of the connection is sending
	 */
	ecm_db_connection_from_address_get(ci, match_addr);
	if (ECM_IP_ADDR_MATCH(ip_src_addr, match_addr)) {
		sender = ECM_TRACKER_SENDER_TYPE_SRC;
	} else {
		sender = ECM_TRACKER_SENDER_TYPE_DEST;
	}

	/*
	 * Iterate the assignments and call to process!
	 * Policy implemented:
	 * 1. Classifiers that say they are not relevant are unassigned and not actioned further.
	 * 2. Any drop command from any classifier is honoured.
	 * 3. All classifiers must action acceleration for accel to be honoured, any classifiers not sure of their relevance will stop acceleration.
	 * 4. Only the highest priority classifier, that actions it, will have its qos tag honoured.
	 * 5. Only the highest priority classifier, that actions it, will have its timer group honoured.
	 */
	DEBUG_TRACE("%p: process begin, skb: %p\n", ci, skb);
	prevalent_pr.drop = false;
	prevalent_pr.qos_tag = skb->priority;
	prevalent_pr.accel_mode = ECM_CLASSIFIER_ACCELERATION_MODE_ACCEL;
	prevalent_pr.timer_group = ci_orig_timer_group = ecm_db_connection_timer_group_get(ci);

	assignment_count = ecm_db_connection_classifier_assignments_get_and_ref(ci, assignments);
	for (aci_index = 0; aci_index < assignment_count; ++aci_index) {
		struct ecm_classifier_process_response aci_pr;
		struct ecm_classifier_instance *aci;

		aci = assignments[aci_index];
		DEBUG_TRACE("%p: process: %p, type: %d\n", ci, aci, aci->type_get(aci));
		aci->process(aci, sender, ip_hdr, skb, &aci_pr);
		DEBUG_TRACE("%p: aci_pr: process actions: %x, became relevant: %u, relevance: %d, drop: %d, qos_tag: %u, accel_mode: %x, timer_group: %d\n",
				ci, aci_pr.process_actions, aci_pr.became_relevant, aci_pr.relevance, aci_pr.drop, aci_pr.qos_tag, aci_pr.accel_mode, aci_pr.timer_group);

		if (aci_pr.relevance == ECM_CLASSIFIER_RELEVANCE_NO) {
			ecm_classifier_type_t aci_type;

			/*
			 * This classifier can be unassigned - PROVIDED it is not the default classifier
			 */
			aci_type = aci->type_get(aci);
			if (aci_type == ECM_CLASSIFIER_TYPE_DEFAULT) {
				continue;
			}

			DEBUG_INFO("%p: Classifier not relevant, unassign: %d", ci, aci_type);
			ecm_db_connection_classifier_unassign(ci, aci);
			continue;
		}

		/*
		 * Yes or Maybe relevant.
		 */
		if (aci_pr.process_actions & ECM_CLASSIFIER_PROCESS_ACTION_DROP) {
			/*
			 * Drop command from any classifier is actioned.
			 */
			DEBUG_TRACE("%p: wants drop: %p, type: %d, skb: %p\n", ci, aci, aci->type_get(aci), skb);
			prevalent_pr.drop |= aci_pr.drop;
		}

		/*
		 * Accel mode permission
		 */
		if (aci_pr.relevance == ECM_CLASSIFIER_RELEVANCE_MAYBE) {
			/*
			 * Classifier not sure of its relevance - cannot accel yet
			 */
			DEBUG_TRACE("%p: accel denied by maybe: %p, type: %d\n", ci, aci, aci->type_get(aci));
			prevalent_pr.accel_mode = ECM_CLASSIFIER_ACCELERATION_MODE_NO;
		} else {
			if (aci_pr.process_actions & ECM_CLASSIFIER_PROCESS_ACTION_ACCEL_MODE) {
				if (aci_pr.accel_mode == ECM_CLASSIFIER_ACCELERATION_MODE_NO) {
					DEBUG_TRACE("%p: accel denied: %p, type: %d\n", ci, aci, aci->type_get(aci));
					prevalent_pr.accel_mode = ECM_CLASSIFIER_ACCELERATION_MODE_NO;
				}
				/* else yes or don't care about accel */
			}
		}

		/*
		 * Timer group (the last classifier i.e. the highest priority one) will 'win'
		 */
		if (aci_pr.process_actions & ECM_CLASSIFIER_PROCESS_ACTION_TIMER_GROUP) {
			DEBUG_TRACE("%p: timer group: %p, type: %d, group: %d\n", ci, aci, aci->type_get(aci), aci_pr.timer_group);
			prevalent_pr.timer_group = aci_pr.timer_group;
		}

		/*
		 * Qos tag (the last classifier i.e. the highest priority one) will 'win'
		 */
		if (aci_pr.process_actions & ECM_CLASSIFIER_PROCESS_ACTION_QOS_TAG) {
			DEBUG_TRACE("%p: qos_tag: %p, type: %d, qos tag: %u\n", ci, aci, aci->type_get(aci), aci_pr.qos_tag);
			prevalent_pr.qos_tag = aci_pr.qos_tag;
		}
	}
	ecm_db_connection_assignments_release(assignment_count, assignments);

	/*
	 * Change timer group?
	 */
	if (ci_orig_timer_group != prevalent_pr.timer_group) {
		DEBUG_TRACE("%p: change timer group from: %d to: %d\n", ci, ci_orig_timer_group, prevalent_pr.timer_group);
		ecm_db_connection_defunct_timer_reset(ci, prevalent_pr.timer_group);
	}

	/*
	 * Drop?
	 */
	if (prevalent_pr.drop) {
		DEBUG_TRACE("%p: drop: %p\n", ci, skb);
		ecm_db_connection_data_totals_update_dropped(ci, (sender == ECM_TRACKER_SENDER_TYPE_SRC)? true : false, skb->len, 1);
		ecm_db_connection_deref(ci);
		return NF_DROP;
	}
	ecm_db_connection_data_totals_update(ci, (sender == ECM_TRACKER_SENDER_TYPE_SRC)? true : false, skb->len, 1);

	/*
	 * Assign qos tag
	 */
	skb->priority = prevalent_pr.qos_tag;
	DEBUG_TRACE("%p: skb priority: %u\n", ci, skb->priority);

	/*
	 * Accelerate?
	 */
	if (prevalent_pr.accel_mode == ECM_CLASSIFIER_ACCELERATION_MODE_ACCEL) {
		struct ecm_front_end_connection_instance *feci;
		DEBUG_TRACE("%p: accel\n", ci);
		feci = ecm_db_connection_front_end_get_and_ref(ci);
		ecm_front_end_ipv4_connection_tcp_front_end_accelerate(feci, &prevalent_pr);
		feci->deref(feci);
	}
	ecm_db_connection_deref(ci);

	return NF_ACCEPT;
}

/*
 * ecm_front_end_ipv4_udp_process()
 *	Process a UDP packet
 */
static unsigned int ecm_front_end_ipv4_udp_process(struct net_device *out_dev, struct net_device *in_dev, bool can_accel, bool is_routed, struct sk_buff *skb,
							struct ecm_tracker_ip_header *ip_hdr,
							struct nf_conn *ct, enum ip_conntrack_dir ct_dir, ecm_db_direction_t ecm_dir,
							struct nf_conntrack_tuple *orig_tuple, struct nf_conntrack_tuple *reply_tuple,
							ip_addr_t ip_src_addr, ip_addr_t ip_dest_addr, ip_addr_t ip_src_addr_nat, ip_addr_t ip_dest_addr_nat)
{
	struct udphdr *udp_hdr;
	struct udphdr udp_hdr_buff;
	int src_port;
	int src_port_nat;
	int dest_port;
	int dest_port_nat;
	struct ecm_db_connection_instance *ci;
	ecm_tracker_sender_type_t sender;
	ip_addr_t match_addr;
	struct ecm_classifier_instance *assignments[ECM_CLASSIFIER_TYPES];
	int aci_index;
	int assignment_count;
	ecm_db_timer_group_t ci_orig_timer_group;
	struct ecm_classifier_process_response prevalent_pr;

	/*
	 * Extract UDP header to obtain port information
	 */
	udp_hdr = ecm_tracker_udp_check_header_and_read(skb, ip_hdr, &udp_hdr_buff);
	if (unlikely(!udp_hdr)) {
		DEBUG_WARN("Invalid UDP header in skb %p\n", skb);
		return NF_DROP;
	}

	/*
	 * Now extract information, if we have conntrack then use that (which would already be in the tuples)
	 */
	if (unlikely(!ct)) {
		orig_tuple->src.u.udp.port = udp_hdr->source;
		orig_tuple->dst.u.udp.port = udp_hdr->dest;
		reply_tuple->src.u.udp.port = udp_hdr->dest;
		reply_tuple->dst.u.udp.port = udp_hdr->source;
	}

	/*
	 * Extract transport port information
	 * Refer to the ecm_front_end_ipv4_process() for information on how we extract this information.
	 */
	if (ct_dir == IP_CT_DIR_ORIGINAL) {
		if (ecm_dir == ECM_DB_DIRECTION_EGRESS) {
			src_port = ntohs(orig_tuple->src.u.udp.port);
			dest_port = ntohs(orig_tuple->dst.u.udp.port);
			dest_port_nat = ntohs(reply_tuple->src.u.udp.port);
			src_port_nat = ntohs(reply_tuple->dst.u.udp.port);
		} else {
			src_port = ntohs(orig_tuple->src.u.udp.port);
			dest_port_nat = ntohs(orig_tuple->dst.u.udp.port);
			dest_port = ntohs(reply_tuple->src.u.udp.port);
			src_port_nat = ntohs(reply_tuple->dst.u.udp.port);
		}
	} else {
		if (ecm_dir == ECM_DB_DIRECTION_EGRESS) {
			dest_port = ntohs(orig_tuple->src.u.udp.port);
			src_port = ntohs(orig_tuple->dst.u.udp.port);
			src_port_nat = ntohs(reply_tuple->src.u.udp.port);
			dest_port_nat = ntohs(reply_tuple->dst.u.udp.port);
		} else {
			dest_port = ntohs(orig_tuple->src.u.udp.port);
			src_port_nat = ntohs(orig_tuple->dst.u.udp.port);
			src_port = ntohs(reply_tuple->src.u.udp.port);
			dest_port_nat = ntohs(reply_tuple->dst.u.udp.port);
		}
	}
	DEBUG_TRACE("UDP src: " ECM_IP_ADDR_DOT_FMT ":%d, dest: " ECM_IP_ADDR_DOT_FMT ":%d, dir %d\n",
			ECM_IP_ADDR_TO_DOT(ip_src_addr), src_port, ECM_IP_ADDR_TO_DOT(ip_dest_addr), dest_port, ecm_dir);

	/*
	 * Look up a connection
	 */
	ci = ecm_db_connection_find_and_ref(ip_src_addr, ip_dest_addr, IPPROTO_UDP, src_port, dest_port);

	/*
	 * If there is no existing connection then create a new one.
	 */
	if (unlikely(!ci)) {
		struct ecm_db_mapping_instance *src_mi;
		struct ecm_db_mapping_instance *dest_mi;
		struct ecm_db_mapping_instance *src_nat_mi;
		struct ecm_db_mapping_instance *dest_nat_mi;
		struct ecm_classifier_default_instance *dci;
		struct ecm_front_end_connection_instance *feci;
		struct ecm_db_connection_instance *nci;
		ecm_classifier_type_t classifier_type;
		int32_t to_list_first;
		struct ecm_db_iface_instance *to_list[ECM_DB_IFACE_HEIRARCHY_MAX];
		int32_t to_nat_list_first;
		struct ecm_db_iface_instance *to_nat_list[ECM_DB_IFACE_HEIRARCHY_MAX];
		int32_t from_list_first;
		struct ecm_db_iface_instance *from_list[ECM_DB_IFACE_HEIRARCHY_MAX];
		int32_t from_nat_list_first;
		struct ecm_db_iface_instance *from_nat_list[ECM_DB_IFACE_HEIRARCHY_MAX];

		DEBUG_INFO("New UDP connection from " ECM_IP_ADDR_DOT_FMT ":%u to " ECM_IP_ADDR_DOT_FMT ":%u\n", ECM_IP_ADDR_TO_DOT(ip_src_addr), src_port, ECM_IP_ADDR_TO_DOT(ip_dest_addr), dest_port);

		/*
		 * Before we attempt to create the connection are we being terminated?
		 */
		spin_lock_bh(&ecm_front_end_ipv4_lock);
		if (ecm_front_end_ipv4_terminate_pending) {
			spin_unlock_bh(&ecm_front_end_ipv4_lock);
			DEBUG_WARN("Terminating\n");

			/*
			 * As we are terminating we just allow the packet to pass - it's no longer our concern
			 */
			return NF_ACCEPT;
		}
		spin_unlock_bh(&ecm_front_end_ipv4_lock);

		/*
		 * Now allocate the new connection
		 */
		nci = ecm_db_connection_alloc();
		if (!nci) {
			DEBUG_WARN("Failed to allocate connection\n");
			return NF_DROP;
		}

		/*
		 * Get the src and destination mappings
		 */
		src_mi = ecm_front_end_ipv4_mapping_establish_and_ref(in_dev, ip_src_addr, src_port);
		if (!src_mi) {
			ecm_db_connection_deref(nci);
			DEBUG_WARN("Failed to establish src mapping\n");
			return NF_DROP;
		}

		dest_mi = ecm_front_end_ipv4_mapping_establish_and_ref(out_dev, ip_dest_addr, dest_port);
		if (!dest_mi) {
			ecm_db_mapping_deref(src_mi);
			ecm_db_connection_deref(nci);
			DEBUG_WARN("Failed to establish dest mapping\n");
			return NF_DROP;
		}

		/*
		 * Get the src and destination NAT mappings
		 */
		src_nat_mi = ecm_front_end_ipv4_mapping_establish_and_ref(in_dev, ip_src_addr_nat, src_port_nat);
		if (!src_nat_mi) {
			ecm_db_mapping_deref(dest_mi);
			ecm_db_mapping_deref(src_mi);
			ecm_db_connection_deref(nci);
			DEBUG_WARN("Failed to establish src nat mapping\n");
			return NF_DROP;
		}

		dest_nat_mi = ecm_front_end_ipv4_mapping_establish_and_ref(out_dev, ip_dest_addr_nat, dest_port_nat);
		if (!dest_nat_mi) {
			ecm_db_mapping_deref(src_nat_mi);
			ecm_db_mapping_deref(dest_mi);
			ecm_db_mapping_deref(src_mi);
			ecm_db_connection_deref(nci);
			DEBUG_WARN("Failed to establish dest mapping\n");
			return NF_DROP;
		}

		/*
		 * Connection must have a front end instance associated with it
		 */
		feci = (struct ecm_front_end_connection_instance *)ecm_front_end_ipv4_connection_udp_instance_alloc(nci, src_mi, dest_mi, can_accel);
		if (!feci) {
			ecm_db_mapping_deref(dest_nat_mi);
			ecm_db_mapping_deref(src_nat_mi);
			ecm_db_mapping_deref(dest_mi);
			ecm_db_mapping_deref(src_mi);
			ecm_db_connection_deref(nci);
			DEBUG_WARN("Failed to allocate front end\n");
			return NF_DROP;
		}

		/*
		 * Every connection also needs a default classifier
		 */
		dci = ecm_classifier_default_instance_alloc(nci, IPPROTO_UDP, ecm_dir, src_port, dest_port);
		if (!dci) {
			feci->deref(feci);
			ecm_db_mapping_deref(dest_nat_mi);
			ecm_db_mapping_deref(src_nat_mi);
			ecm_db_mapping_deref(dest_mi);
			ecm_db_mapping_deref(src_mi);
			ecm_db_connection_deref(nci);
			DEBUG_WARN("Failed to allocate default classifier\n");
			return NF_DROP;
		}

		/*
		 * Every connection starts with a full complement of classifiers assigned.
		 * NOTE: Default classifier is a special case considered previously
		 */
		for (classifier_type = ECM_CLASSIFIER_TYPE_DEFAULT + 1; classifier_type < ECM_CLASSIFIER_TYPES; ++classifier_type) {
			struct ecm_classifier_instance *aci = ecm_front_end_ipv4_assign_classifier(nci, classifier_type);
			if (aci) {
				aci->deref(aci);
			} else {
				dci->base.deref((struct ecm_classifier_instance *)dci);
				feci->deref(feci);
				ecm_db_mapping_deref(dest_nat_mi);
				ecm_db_mapping_deref(src_nat_mi);
				ecm_db_mapping_deref(dest_mi);
				ecm_db_mapping_deref(src_mi);
				ecm_db_connection_deref(nci);
				DEBUG_WARN("Failed to allocate classifiers assignments\n");
				return NF_DROP;
			}
		}

		/*
		 * Get the initial interface lists the connection will be using
		 */
		DEBUG_TRACE("%p: Create the 'from' interface heirarchy list\n", nci);
		from_list_first = ecm_interface_heirarchy_construct(from_list, ip_dest_addr, ip_src_addr, IPPROTO_UDP);
		ecm_db_connection_from_interfaces_reset(nci, from_list, from_list_first);
		ecm_db_connection_interfaces_deref(from_list, from_list_first);

		DEBUG_TRACE("%p: Create the 'from NAT' interface heirarchy list\n", nci);
		from_nat_list_first = ecm_interface_heirarchy_construct(from_nat_list, ip_dest_addr, ip_src_addr_nat, IPPROTO_UDP);
		ecm_db_connection_from_nat_interfaces_reset(nci, from_nat_list, from_nat_list_first);
		ecm_db_connection_interfaces_deref(from_nat_list, from_nat_list_first);

		DEBUG_TRACE("%p: Create the 'to' interface heirarchy list\n", nci);
		to_list_first = ecm_interface_heirarchy_construct(to_list, ip_src_addr, ip_dest_addr, IPPROTO_UDP);
		ecm_db_connection_to_interfaces_reset(nci, to_list, to_list_first);
		ecm_db_connection_interfaces_deref(to_list, to_list_first);

		DEBUG_TRACE("%p: Create the 'to NAT' interface heirarchy list\n", nci);
		to_nat_list_first = ecm_interface_heirarchy_construct(to_nat_list, ip_src_addr, ip_dest_addr_nat, IPPROTO_UDP);
		ecm_db_connection_to_nat_interfaces_reset(nci, to_nat_list, to_nat_list_first);
		ecm_db_connection_interfaces_deref(to_nat_list, to_nat_list_first);

		/*
		 * Now add the connection into the database.
		 * NOTE: In an SMP situation such as ours there is a possibility that more than one packet for the same
		 * connection is being processed simultaneously.
		 * We *could* end up creating more than one connection instance for the same actual connection.
		 * To guard against this we now perform a mutex'd lookup of the connection + add once more - another cpu may have created it before us.
		 */
		spin_lock_bh(&ecm_front_end_ipv4_lock);
		ci = ecm_db_connection_find_and_ref(ip_src_addr, ip_dest_addr, IPPROTO_UDP, src_port, dest_port);
		if (ci) {
			/*
			 * Another cpu created the same connection before us - use the one we just found
			 */
			spin_unlock_bh(&ecm_front_end_ipv4_lock);
			ecm_db_connection_deref(nci);
		} else {
			struct ecm_tracker_instance *ti;
			ecm_db_timer_group_t tg;
			ecm_tracker_sender_state_t src_state;
			ecm_tracker_sender_state_t dest_state;
			ecm_tracker_connection_state_t state;

			/*
			 * Ask tracker for timer group to set the connection to initially.
			 */
			ti = dci->tracker_get_and_ref(dci);
			ti->state_get(ti, &src_state, &dest_state, &state, &tg);
			ti->deref(ti);

			/*
			 * Add the new connection we created into the database
			 * NOTE: assign to a short timer group for now - it is the assigned classifiers responsibility to do this
			 */
			ecm_db_connection_add(nci, feci, dci,
					src_mi, dest_mi, src_nat_mi, dest_nat_mi,
					IPPROTO_UDP, ecm_dir,
					ecm_front_end_ipv4_connection_final_udp,
					tg, is_routed, nci);

			/*
			 * Ensure our thread persists (and hence this module) for as long as the connection and its supporting framework is alive
			 * as we could get callbacks or methods invoked
			 */
			ecm_front_end_ipv4_thread_refs++;
			DEBUG_ASSERT(ecm_front_end_ipv4_thread_refs > 0, "Thread refs wrap %d\n", ecm_front_end_ipv4_thread_refs);

			spin_unlock_bh(&ecm_front_end_ipv4_lock);

			ci = nci;
			DEBUG_INFO("%p: New UDP connection created\n", ci);
		}

		/*
		 * No longer need referenecs to the objects we created
		 */
		feci->deref(feci);
		dci->base.deref((struct ecm_classifier_instance *)dci);
		ecm_db_mapping_deref(src_mi);
		ecm_db_mapping_deref(dest_mi);
		ecm_db_mapping_deref(src_nat_mi);
		ecm_db_mapping_deref(dest_nat_mi);
	}

	/*
	 * Keep connection alive as we have seen activity
	 */
	if (!ecm_db_connection_defunct_timer_touch(ci)) {
		ecm_db_connection_deref(ci);
		return NF_DROP;
	}

	/*
	 * Do we need to action generation change?
	 */
	if (unlikely(ecm_db_connection_classifier_generation_changed(ci))) {
		int i;
		bool reclassify_allowed;
		int32_t to_list_first;
		struct ecm_db_iface_instance *to_list[ECM_DB_IFACE_HEIRARCHY_MAX];
		int32_t to_nat_list_first;
		struct ecm_db_iface_instance *to_nat_list[ECM_DB_IFACE_HEIRARCHY_MAX];
		int32_t from_list_first;
		struct ecm_db_iface_instance *from_list[ECM_DB_IFACE_HEIRARCHY_MAX];
		int32_t from_nat_list_first;
		struct ecm_db_iface_instance *from_nat_list[ECM_DB_IFACE_HEIRARCHY_MAX];

		DEBUG_INFO("%p: re-gen needed\n", ci);

		/*
		 * Update the interface lists - these may have changed, e.g. LAG path change etc.
		 * NOTE: We never have to change the usual mapping->host->node_iface arrangements for each side of the connection (to/from sides)
		 * This is because if these interfaces change then the connection is dead anyway.
		 * But a LAG slave might change the heirarchy the connection is using but the LAG master is still sane.
		 */
		DEBUG_TRACE("%p: Update the 'from' interface heirarchy list\n", ci);
		from_list_first = ecm_interface_heirarchy_construct(from_list, ip_dest_addr, ip_src_addr, IPPROTO_UDP);
		ecm_db_connection_from_interfaces_reset(ci, from_list, from_list_first);
		ecm_db_connection_interfaces_deref(from_list, from_list_first);

		DEBUG_TRACE("%p: Update the 'from NAT' interface heirarchy list\n", ci);
		from_nat_list_first = ecm_interface_heirarchy_construct(from_nat_list, ip_dest_addr, ip_src_addr_nat, IPPROTO_UDP);
		ecm_db_connection_from_nat_interfaces_reset(ci, from_nat_list, from_nat_list_first);
		ecm_db_connection_interfaces_deref(from_nat_list, from_nat_list_first);

		DEBUG_TRACE("%p: Update the 'to' interface heirarchy list\n", ci);
		to_list_first = ecm_interface_heirarchy_construct(to_list, ip_src_addr, ip_dest_addr, IPPROTO_UDP);
		ecm_db_connection_to_interfaces_reset(ci, to_list, to_list_first);
		ecm_db_connection_interfaces_deref(to_list, to_list_first);

		DEBUG_TRACE("%p: Update the 'to NAT' interface heirarchy list\n", ci);
		to_nat_list_first = ecm_interface_heirarchy_construct(to_nat_list, ip_src_addr, ip_dest_addr_nat, IPPROTO_UDP);
		ecm_db_connection_to_nat_interfaces_reset(ci, to_nat_list, to_nat_list_first);
		ecm_db_connection_interfaces_deref(to_nat_list, to_nat_list_first);

		/*
		 * Get list of assigned classifiers to reclassify.
		 * Remember: This also includes our default classifier too.
		 */
		assignment_count = ecm_db_connection_classifier_assignments_get_and_ref(ci, assignments);

		/*
		 * All of the assigned classifiers must permit reclassification.
		 */
		reclassify_allowed = true;
		for (i = 0; i < assignment_count; ++i) {
			DEBUG_TRACE("%p: Calling to reclassify: %p, type: %d\n", ci, assignments[i], assignments[i]->type_get(assignments[i]));
			if (!assignments[i]->reclassify_allowed(assignments[i])) {
				DEBUG_TRACE("%p: reclassify denied: %p, by type: %d\n", ci, assignments[i], assignments[i]->type_get(assignments[i]));
				reclassify_allowed = false;
				break;
			}
		}

		if (!reclassify_allowed) {
			DEBUG_WARN("%p: re-gen denied\n", ci);
		} else {
			/*
			 * Reclassify
			 */
			DEBUG_TRACE("%p: reclassify\n", ci);
			if (!ecm_front_end_ipv4_reclassify(ci, assignment_count, assignments)) {
				DEBUG_WARN("%p: Regeneration failed, dropping packet\n", ci);
				ecm_db_connection_assignments_release(assignment_count, assignments);
				ecm_db_connection_deref(ci);
				return NF_DROP;
			}
			DEBUG_TRACE("%p: reclassify success\n", ci);
		}

		/*
		 * Release the assignments and re-obtain them as there may be new ones been reassigned.
		 */
		ecm_db_connection_assignments_release(assignment_count, assignments);

		/*
		 * Interface lists are regenerated in any situation as they determine correct packet flow
		 * through the system - essential for correct interaction with the NSS and acceleration rule creation.
		 */
		DEBUG_TRACE("%p: Clearing interface lists\n", ci);
		ecm_db_connection_from_interfaces_clear(ci);
		ecm_db_connection_to_interfaces_clear(ci);
		ecm_db_connection_from_nat_interfaces_clear(ci);
		ecm_db_connection_to_nat_interfaces_clear(ci);
	}

	/*
	 * Identify which side of the connection is sending
	 */
	ecm_db_connection_from_address_get(ci, match_addr);
	if (ECM_IP_ADDR_MATCH(ip_src_addr, match_addr)) {
		sender = ECM_TRACKER_SENDER_TYPE_SRC;
	} else {
		sender = ECM_TRACKER_SENDER_TYPE_DEST;
	}

	/*
	 * Iterate the assignments and call to process!
	 * Policy implemented:
	 * 1. Classifiers that say they are not relevant are unassigned and not actioned further.
	 * 2. Any drop command from any classifier is honoured.
	 * 3. All classifiers must action acceleration for accel to be honoured, any classifiers not sure of their relevance will stop acceleration.
	 * 4. Only the highest priority classifier, that actions it, will have its qos tag honoured.
	 * 5. Only the highest priority classifier, that actions it, will have its timer group honoured.
	 */
	DEBUG_TRACE("%p: process begin, skb: %p\n", ci, skb);
	prevalent_pr.drop = false;
	prevalent_pr.qos_tag = skb->priority;
	prevalent_pr.accel_mode = ECM_CLASSIFIER_ACCELERATION_MODE_ACCEL;
	prevalent_pr.timer_group = ci_orig_timer_group = ecm_db_connection_timer_group_get(ci);

	assignment_count = ecm_db_connection_classifier_assignments_get_and_ref(ci, assignments);
	for (aci_index = 0; aci_index < assignment_count; ++aci_index) {
		struct ecm_classifier_process_response aci_pr;
		struct ecm_classifier_instance *aci;

		aci = assignments[aci_index];
		DEBUG_TRACE("%p: process: %p, type: %d\n", ci, aci, aci->type_get(aci));
		aci->process(aci, sender, ip_hdr, skb, &aci_pr);
		DEBUG_TRACE("%p: aci_pr: process actions: %x, became relevant: %u, relevance: %d, drop: %d, qos_tag: %u, accel_mode: %x, timer_group: %d\n",
				ci, aci_pr.process_actions, aci_pr.became_relevant, aci_pr.relevance, aci_pr.drop, aci_pr.qos_tag, aci_pr.accel_mode, aci_pr.timer_group);

		if (aci_pr.relevance == ECM_CLASSIFIER_RELEVANCE_NO) {
			ecm_classifier_type_t aci_type;

			/*
			 * This classifier can be unassigned - PROVIDED it is not the default classifier
			 */
			aci_type = aci->type_get(aci);
			if (aci_type == ECM_CLASSIFIER_TYPE_DEFAULT) {
				continue;
			}

			DEBUG_INFO("%p: Classifier not relevant, unassign: %d", ci, aci_type);
			ecm_db_connection_classifier_unassign(ci, aci);
			continue;
		}

		/*
		 * Yes or Maybe relevant.
		 */
		if (aci_pr.process_actions & ECM_CLASSIFIER_PROCESS_ACTION_DROP) {
			/*
			 * Drop command from any classifier is actioned.
			 */
			DEBUG_TRACE("%p: wants drop: %p, type: %d, skb: %p\n", ci, aci, aci->type_get(aci), skb);
			prevalent_pr.drop |= aci_pr.drop;
		}

		/*
		 * Accel mode permission
		 */
		if (aci_pr.relevance == ECM_CLASSIFIER_RELEVANCE_MAYBE) {
			/*
			 * Classifier not sure of its relevance - cannot accel yet
			 */
			DEBUG_TRACE("%p: accel denied by maybe: %p, type: %d\n", ci, aci, aci->type_get(aci));
			prevalent_pr.accel_mode = ECM_CLASSIFIER_ACCELERATION_MODE_NO;
		} else {
			if (aci_pr.process_actions & ECM_CLASSIFIER_PROCESS_ACTION_ACCEL_MODE) {
				if (aci_pr.accel_mode == ECM_CLASSIFIER_ACCELERATION_MODE_NO) {
					DEBUG_TRACE("%p: accel denied: %p, type: %d\n", ci, aci, aci->type_get(aci));
					prevalent_pr.accel_mode = ECM_CLASSIFIER_ACCELERATION_MODE_NO;
				}
				/* else yes or don't care about accel */
			}
		}

		/*
		 * Timer group (the last classifier i.e. the highest priority one) will 'win'
		 */
		if (aci_pr.process_actions & ECM_CLASSIFIER_PROCESS_ACTION_TIMER_GROUP) {
			DEBUG_TRACE("%p: timer group: %p, type: %d, group: %d\n", ci, aci, aci->type_get(aci), aci_pr.timer_group);
			prevalent_pr.timer_group = aci_pr.timer_group;
		}

		/*
		 * Qos tag (the last classifier i.e. the highest priority one) will 'win'
		 */
		if (aci_pr.process_actions & ECM_CLASSIFIER_PROCESS_ACTION_QOS_TAG) {
			DEBUG_TRACE("%p: qos_tag: %p, type: %d, qos tag: %u\n", ci, aci, aci->type_get(aci), aci_pr.qos_tag);
			prevalent_pr.qos_tag = aci_pr.qos_tag;
		}
	}
	ecm_db_connection_assignments_release(assignment_count, assignments);

	/*
	 * Change timer group?
	 */
	if (ci_orig_timer_group != prevalent_pr.timer_group) {
		DEBUG_TRACE("%p: change timer group from: %d to: %d\n", ci, ci_orig_timer_group, prevalent_pr.timer_group);
		ecm_db_connection_defunct_timer_reset(ci, prevalent_pr.timer_group);
	}

	/*
	 * Drop?
	 */
	if (prevalent_pr.drop) {
		DEBUG_TRACE("%p: drop: %p\n", ci, skb);
		ecm_db_connection_data_totals_update_dropped(ci, (sender == ECM_TRACKER_SENDER_TYPE_SRC)? true : false, skb->len, 1);
		ecm_db_connection_deref(ci);
		return NF_DROP;
	}
	ecm_db_connection_data_totals_update(ci, (sender == ECM_TRACKER_SENDER_TYPE_SRC)? true : false, skb->len, 1);

	/*
	 * Assign qos tag
	 */
	skb->priority = prevalent_pr.qos_tag;
	DEBUG_TRACE("%p: skb priority: %u\n", ci, skb->priority);

	/*
	 * Accelerate?
	 */
	if (prevalent_pr.accel_mode == ECM_CLASSIFIER_ACCELERATION_MODE_ACCEL) {
		struct ecm_front_end_connection_instance *feci;
		DEBUG_TRACE("%p: accel\n", ci);
		feci = ecm_db_connection_front_end_get_and_ref(ci);
		ecm_front_end_ipv4_connection_udp_front_end_accelerate(feci, &prevalent_pr);
		feci->deref(feci);
	}
	ecm_db_connection_deref(ci);

	return NF_ACCEPT;
}

/*
 * ecm_front_end_ipv4_non_ported_process()
 *	Process a protocol that does not have port based identifiers
 */
static unsigned int ecm_front_end_ipv4_non_ported_process(struct net_device *out_dev, struct net_device *in_dev, bool can_accel, bool is_routed, struct sk_buff *skb,
							struct ecm_tracker_ip_header *ip_hdr,
							struct nf_conn *ct, enum ip_conntrack_dir ct_dir, ecm_db_direction_t ecm_dir,
							struct nf_conntrack_tuple *orig_tuple, struct nf_conntrack_tuple *reply_tuple,
							ip_addr_t ip_src_addr, ip_addr_t ip_dest_addr, ip_addr_t ip_src_addr_nat, ip_addr_t ip_dest_addr_nat)
{
	struct ecm_db_connection_instance *ci;
	ecm_tracker_sender_type_t sender;
	int protocol;
	int src_port;
	int src_port_nat;
	int dest_port;
	int dest_port_nat;
	ip_addr_t match_addr;
	struct ecm_classifier_instance *assignments[ECM_CLASSIFIER_TYPES];
	int aci_index;
	int assignment_count;
	ecm_db_timer_group_t ci_orig_timer_group;
	struct ecm_classifier_process_response prevalent_pr;

	DEBUG_TRACE("Non-ported protocol src: " ECM_IP_ADDR_DOT_FMT ", dest: " ECM_IP_ADDR_DOT_FMT "\n", ECM_IP_ADDR_TO_DOT(ip_src_addr), ECM_IP_ADDR_TO_DOT(ip_dest_addr));

	/*
	 * Look up a connection.
	 */
	protocol = (int)orig_tuple->dst.protonum;
	if ((protocol == IPPROTO_IPV6) || (protocol == IPPROTO_ESP)) {
		src_port = 0;
		src_port_nat = 0;
		dest_port = 0;
		dest_port_nat = 0;
	} else {
		/*
		 * port numbers are just the negative protocol number equivalents for now.
		 * GGG They could eventually be used as protocol specific identifiers such as icmp id's etc.
		 */
		src_port = -protocol;
		src_port_nat = -protocol;
		dest_port = -protocol;
		dest_port_nat = -protocol;
	}
	ci = ecm_db_connection_find_and_ref(ip_src_addr, ip_dest_addr, protocol, src_port, dest_port);

	/*
	 * If there is no existing connection then create a new one.
	 */
	if (unlikely(!ci)) {
		struct ecm_db_mapping_instance *src_mi;
		struct ecm_db_mapping_instance *dest_mi;
		struct ecm_db_mapping_instance *src_nat_mi;
		struct ecm_db_mapping_instance *dest_nat_mi;
		struct ecm_classifier_default_instance *dci;
		struct ecm_front_end_connection_instance *feci;
		struct ecm_db_connection_instance *nci;
		ecm_classifier_type_t classifier_type;
		int32_t to_list_first;
		struct ecm_db_iface_instance *to_list[ECM_DB_IFACE_HEIRARCHY_MAX];
		int32_t to_nat_list_first;
		struct ecm_db_iface_instance *to_nat_list[ECM_DB_IFACE_HEIRARCHY_MAX];
		int32_t from_list_first;
		struct ecm_db_iface_instance *from_list[ECM_DB_IFACE_HEIRARCHY_MAX];
		int32_t from_nat_list_first;
		struct ecm_db_iface_instance *from_nat_list[ECM_DB_IFACE_HEIRARCHY_MAX];

		DEBUG_INFO("New connection from " ECM_IP_ADDR_DOT_FMT " to " ECM_IP_ADDR_DOT_FMT "\n", ECM_IP_ADDR_TO_DOT(ip_src_addr), ECM_IP_ADDR_TO_DOT(ip_dest_addr));

		/*
		 * Before we attempt to create the connection are we being terminated?
		 */
		spin_lock_bh(&ecm_front_end_ipv4_lock);
		if (ecm_front_end_ipv4_terminate_pending) {
			spin_unlock_bh(&ecm_front_end_ipv4_lock);
			DEBUG_WARN("Terminating\n");

			/*
			 * As we are terminating we just allow the packet to pass - it's no longer our concern
			 */
			return NF_ACCEPT;
		}
		spin_unlock_bh(&ecm_front_end_ipv4_lock);

		/*
		 * Now allocate the new connection
		 */
		nci = ecm_db_connection_alloc();
		if (!nci) {
			DEBUG_WARN("Failed to allocate connection\n");
			return NF_DROP;
		}

		/*
		 * Get the src and destination mappings
		 */
		src_mi = ecm_front_end_ipv4_mapping_establish_and_ref(in_dev, ip_src_addr, src_port);
		if (!src_mi) {
			ecm_db_connection_deref(nci);
			DEBUG_WARN("Failed to establish src mapping\n");
			return NF_DROP;
		}

		dest_mi = ecm_front_end_ipv4_mapping_establish_and_ref(out_dev, ip_dest_addr, dest_port);
		if (!dest_mi) {
			ecm_db_mapping_deref(src_mi);
			ecm_db_connection_deref(nci);
			DEBUG_WARN("Failed to establish dest mapping\n");
			return NF_DROP;
		}

		/*
		 * Get the src and destination NAT mappings
		 */
		src_nat_mi = ecm_front_end_ipv4_mapping_establish_and_ref(in_dev, ip_src_addr_nat, src_port_nat);
		if (!src_nat_mi) {
			ecm_db_mapping_deref(dest_mi);
			ecm_db_mapping_deref(src_mi);
			ecm_db_connection_deref(nci);
			DEBUG_WARN("Failed to establish src nat mapping\n");
			return NF_DROP;
		}

		dest_nat_mi = ecm_front_end_ipv4_mapping_establish_and_ref(out_dev, ip_dest_addr_nat, dest_port_nat);
		if (!dest_nat_mi) {
			ecm_db_mapping_deref(src_nat_mi);
			ecm_db_mapping_deref(dest_mi);
			ecm_db_mapping_deref(src_mi);
			ecm_db_connection_deref(nci);
			DEBUG_WARN("Failed to establish dest mapping\n");
			return NF_DROP;
		}

		/*
		 * Connection must have a front end instance associated with it
		 */
		feci = (struct ecm_front_end_connection_instance *)ecm_front_end_ipv4_connection_non_ported_instance_alloc(nci, src_mi, dest_mi);
		if (!feci) {
			ecm_db_mapping_deref(dest_nat_mi);
			ecm_db_mapping_deref(src_nat_mi);
			ecm_db_mapping_deref(dest_mi);
			ecm_db_mapping_deref(src_mi);
			ecm_db_connection_deref(nci);
			DEBUG_WARN("Failed to allocate front end\n");
			return NF_DROP;
		}

		/*
		 * Every connection also needs a default classifier
		 */
		dci = ecm_classifier_default_instance_alloc(nci, protocol, ecm_dir, src_port, dest_port);
		if (!dci) {
			feci->deref(feci);
			ecm_db_mapping_deref(dest_nat_mi);
			ecm_db_mapping_deref(src_nat_mi);
			ecm_db_mapping_deref(dest_mi);
			ecm_db_mapping_deref(src_mi);
			ecm_db_connection_deref(nci);
			DEBUG_WARN("Failed to allocate default classifier\n");
			return NF_DROP;
		}

		/*
		 * Every connection starts with a full complement of classifiers assigned.
		 * NOTE: Default classifier is a special case considered previously
		 */
		for (classifier_type = ECM_CLASSIFIER_TYPE_DEFAULT + 1; classifier_type < ECM_CLASSIFIER_TYPES; ++classifier_type) {
			struct ecm_classifier_instance *aci = ecm_front_end_ipv4_assign_classifier(nci, classifier_type);
			if (aci) {
				aci->deref(aci);
			} else {
				dci->base.deref((struct ecm_classifier_instance *)dci);
				feci->deref(feci);
				ecm_db_mapping_deref(dest_nat_mi);
				ecm_db_mapping_deref(src_nat_mi);
				ecm_db_mapping_deref(dest_mi);
				ecm_db_mapping_deref(src_mi);
				ecm_db_connection_deref(nci);
				DEBUG_WARN("Failed to allocate classifiers assignments\n");
				return NF_DROP;
			}
		}

		/*
		 * Get the initial interface lists the connection will be using
		 */
		DEBUG_TRACE("%p: Create the 'from' interface heirarchy list\n", nci);
		from_list_first = ecm_interface_heirarchy_construct(from_list, ip_dest_addr, ip_src_addr, protocol);
		ecm_db_connection_from_interfaces_reset(nci, from_list, from_list_first);
		ecm_db_connection_interfaces_deref(from_list, from_list_first);

		DEBUG_TRACE("%p: Create the 'from NAT' interface heirarchy list\n", nci);
		from_nat_list_first = ecm_interface_heirarchy_construct(from_nat_list, ip_dest_addr, ip_src_addr_nat, protocol);
		ecm_db_connection_from_nat_interfaces_reset(nci, from_nat_list, from_nat_list_first);
		ecm_db_connection_interfaces_deref(from_nat_list, from_nat_list_first);

		DEBUG_TRACE("%p: Create the 'to' interface heirarchy list\n", nci);
		to_list_first = ecm_interface_heirarchy_construct(to_list, ip_src_addr, ip_dest_addr, protocol);
		ecm_db_connection_to_interfaces_reset(nci, to_list, to_list_first);
		ecm_db_connection_interfaces_deref(to_list, to_list_first);

		DEBUG_TRACE("%p: Create the 'to NAT' interface heirarchy list\n", nci);
		to_nat_list_first = ecm_interface_heirarchy_construct(to_nat_list, ip_src_addr, ip_dest_addr_nat, protocol);
		ecm_db_connection_to_nat_interfaces_reset(nci, to_nat_list, to_nat_list_first);
		ecm_db_connection_interfaces_deref(to_nat_list, to_nat_list_first);

		/*
		 * Now add the connection into the database.
		 * NOTE: In an SMP situation such as ours there is a possibility that more than one packet for the same
		 * connection is being processed simultaneously.
		 * We *could* end up creating more than one connection instance for the same actual connection.
		 * To guard against this we now perform a mutex'd lookup of the connection + add once more - another cpu may have created it before us.
		 */
		spin_lock_bh(&ecm_front_end_ipv4_lock);
		ci = ecm_db_connection_find_and_ref(ip_src_addr, ip_dest_addr, protocol, src_port, dest_port);
		if (ci) {
			/*
			 * Another cpu created the same connection before us - use the one we just found
			 */
			spin_unlock_bh(&ecm_front_end_ipv4_lock);
			ecm_db_connection_deref(nci);
		} else {
			struct ecm_tracker_instance *ti;
			ecm_db_timer_group_t tg;
			ecm_tracker_sender_state_t src_state;
			ecm_tracker_sender_state_t dest_state;
			ecm_tracker_connection_state_t state;

			/*
			 * Ask tracker for timer group to set the connection to initially.
			 */
			ti = dci->tracker_get_and_ref(dci);
			ti->state_get(ti, &src_state, &dest_state, &state, &tg);
			ti->deref(ti);

			/*
			 * Add the new connection we created into the database
			 * NOTE: assign to a short timer group for now - it is the assigned classifiers responsibility to do this
			 */
			ecm_db_connection_add(nci, feci, dci,
					src_mi, dest_mi, src_nat_mi, dest_nat_mi,
					protocol, ecm_dir,
					ecm_front_end_ipv4_connection_final_non_ported,
					tg, is_routed, nci);

			/*
			 * Ensure our thread persists (and hence this module) for as long as the connection and its supporting framework is alive
			 * as we could get callbacks or methods invoked
			 */
			ecm_front_end_ipv4_thread_refs++;
			DEBUG_ASSERT(ecm_front_end_ipv4_thread_refs > 0, "Thread refs wrap %d\n", ecm_front_end_ipv4_thread_refs);

			spin_unlock_bh(&ecm_front_end_ipv4_lock);

			ci = nci;
			DEBUG_INFO("%p: New Non-ported protocol %d connection created\n", ci, protocol);
		}

		/*
		 * No longer need referenecs to the objects we created
		 */
		feci->deref(feci);
		dci->base.deref((struct ecm_classifier_instance *)dci);
		ecm_db_mapping_deref(src_mi);
		ecm_db_mapping_deref(dest_mi);
		ecm_db_mapping_deref(src_nat_mi);
		ecm_db_mapping_deref(dest_nat_mi);
	}

	/*
	 * Keep connection alive as we have seen activity
	 */
	if (!ecm_db_connection_defunct_timer_touch(ci)) {
		ecm_db_connection_deref(ci);
		return NF_DROP;
	}

	/*
	 * Do we need to action generation change?
	 */
	if (unlikely(ecm_db_connection_classifier_generation_changed(ci))) {
		int i;
		bool reclassify_allowed;
		int32_t to_list_first;
		struct ecm_db_iface_instance *to_list[ECM_DB_IFACE_HEIRARCHY_MAX];
		int32_t to_nat_list_first;
		struct ecm_db_iface_instance *to_nat_list[ECM_DB_IFACE_HEIRARCHY_MAX];
		int32_t from_list_first;
		struct ecm_db_iface_instance *from_list[ECM_DB_IFACE_HEIRARCHY_MAX];
		int32_t from_nat_list_first;
		struct ecm_db_iface_instance *from_nat_list[ECM_DB_IFACE_HEIRARCHY_MAX];

		DEBUG_INFO("%p: re-gen needed\n", ci);

		/*
		 * Update the interface lists - these may have changed, e.g. LAG path change etc.
		 * NOTE: We never have to change the usual mapping->host->node_iface arrangements for each side of the connection (to/from sides)
		 * This is because if these interfaces change then the connection is dead anyway.
		 * But a LAG slave might change the heirarchy the connection is using but the LAG master is still sane.
		 */
		DEBUG_TRACE("%p: Update the 'from' interface heirarchy list\n", ci);
		from_list_first = ecm_interface_heirarchy_construct(from_list, ip_dest_addr, ip_src_addr, protocol);
		ecm_db_connection_from_interfaces_reset(ci, from_list, from_list_first);
		ecm_db_connection_interfaces_deref(from_list, from_list_first);

		DEBUG_TRACE("%p: Update the 'from NAT' interface heirarchy list\n", ci);
		from_nat_list_first = ecm_interface_heirarchy_construct(from_nat_list, ip_dest_addr, ip_src_addr_nat, protocol);
		ecm_db_connection_from_nat_interfaces_reset(ci, from_nat_list, from_nat_list_first);
		ecm_db_connection_interfaces_deref(from_nat_list, from_nat_list_first);

		DEBUG_TRACE("%p: Update the 'to' interface heirarchy list\n", ci);
		to_list_first = ecm_interface_heirarchy_construct(to_list, ip_src_addr, ip_dest_addr, protocol);
		ecm_db_connection_to_interfaces_reset(ci, to_list, to_list_first);
		ecm_db_connection_interfaces_deref(to_list, to_list_first);

		DEBUG_TRACE("%p: Update the 'to NAT' interface heirarchy list\n", ci);
		to_nat_list_first = ecm_interface_heirarchy_construct(to_nat_list, ip_src_addr, ip_dest_addr_nat, protocol);
		ecm_db_connection_to_nat_interfaces_reset(ci, to_nat_list, to_nat_list_first);
		ecm_db_connection_interfaces_deref(to_nat_list, to_nat_list_first);

		/*
		 * Get list of assigned classifiers to reclassify.
		 * Remember: This also includes our default classifier too.
		 */
		assignment_count = ecm_db_connection_classifier_assignments_get_and_ref(ci, assignments);

		/*
		 * All of the assigned classifiers must permit reclassification.
		 */
		reclassify_allowed = true;
		for (i = 0; i < assignment_count; ++i) {
			DEBUG_TRACE("%p: Calling to reclassify: %p, type: %d\n", ci, assignments[i], assignments[i]->type_get(assignments[i]));
			if (!assignments[i]->reclassify_allowed(assignments[i])) {
				DEBUG_TRACE("%p: reclassify denied: %p, by type: %d\n", ci, assignments[i], assignments[i]->type_get(assignments[i]));
				reclassify_allowed = false;
				break;
			}
		}

		if (!reclassify_allowed) {
			DEBUG_WARN("%p: re-gen denied\n", ci);
		} else {
			/*
			 * Reclassify
			 */
			DEBUG_TRACE("%p: reclassify\n", ci);
			if (!ecm_front_end_ipv4_reclassify(ci, assignment_count, assignments)) {
				DEBUG_WARN("%p: Regeneration failed, dropping packet\n", ci);
				ecm_db_connection_assignments_release(assignment_count, assignments);
				ecm_db_connection_deref(ci);
				return NF_DROP;
			}
			DEBUG_TRACE("%p: reclassify success\n", ci);
		}

		/*
		 * Release the assignments and re-obtain them as there may be new ones been reassigned.
		 */
		ecm_db_connection_assignments_release(assignment_count, assignments);

		/*
		 * Interface lists are regenerated in any situation as they determine correct packet flow
		 * through the system - essential for correct interaction with the NSS and acceleration rule creation.
		 */
		DEBUG_TRACE("%p: Clearing interface lists\n", ci);
		ecm_db_connection_from_interfaces_clear(ci);
		ecm_db_connection_to_interfaces_clear(ci);
		ecm_db_connection_from_nat_interfaces_clear(ci);
		ecm_db_connection_to_nat_interfaces_clear(ci);
	}

	/*
	 * Identify which side of the connection is sending
	 */
	ecm_db_connection_from_address_get(ci, match_addr);
	if (ECM_IP_ADDR_MATCH(ip_src_addr, match_addr)) {
		sender = ECM_TRACKER_SENDER_TYPE_SRC;
	} else {
		sender = ECM_TRACKER_SENDER_TYPE_DEST;
	}

	/*
	 * Iterate the assignments and call to process!
	 * Policy implemented:
	 * 1. Classifiers that say they are not relevant are unassigned and not actioned further.
	 * 2. Any drop command from any classifier is honoured.
	 * 3. Accel is never allowed for non-ported type connections.
	 * 4. Only the highest priority classifier, that actions it, will have its qos tag honoured.
	 * 5. Only the highest priority classifier, that actions it, will have its timer group honoured.
	 */
	DEBUG_TRACE("%p: process begin, skb: %p\n", ci, skb);
	prevalent_pr.drop = false;
	prevalent_pr.qos_tag = skb->priority;
	prevalent_pr.accel_mode = ECM_CLASSIFIER_ACCELERATION_MODE_ACCEL;
	prevalent_pr.timer_group = ci_orig_timer_group = ecm_db_connection_timer_group_get(ci);

	assignment_count = ecm_db_connection_classifier_assignments_get_and_ref(ci, assignments);
	for (aci_index = 0; aci_index < assignment_count; ++aci_index) {
		struct ecm_classifier_process_response aci_pr;
		struct ecm_classifier_instance *aci;

		aci = assignments[aci_index];
		DEBUG_TRACE("%p: process: %p, type: %d\n", ci, aci, aci->type_get(aci));
		aci->process(aci, sender, ip_hdr, skb, &aci_pr);
		DEBUG_TRACE("%p: aci_pr: process actions: %x, became relevant: %u, relevance: %d, drop: %d, qos_tag: %u, accel_mode: %x, timer_group: %d\n",
				ci, aci_pr.process_actions, aci_pr.became_relevant, aci_pr.relevance, aci_pr.drop, aci_pr.qos_tag, aci_pr.accel_mode, aci_pr.timer_group);

		if (aci_pr.relevance == ECM_CLASSIFIER_RELEVANCE_NO) {
			ecm_classifier_type_t aci_type;

			/*
			 * This classifier can be unassigned - PROVIDED it is not the default classifier
			 */
			aci_type = aci->type_get(aci);
			if (aci_type == ECM_CLASSIFIER_TYPE_DEFAULT) {
				continue;
			}

			DEBUG_INFO("%p: Classifier not relevant, unassign: %d", ci, aci_type);
			ecm_db_connection_classifier_unassign(ci, aci);
			continue;
		}

		/*
		 * Yes or Maybe relevant.
		 */
		if (aci_pr.process_actions & ECM_CLASSIFIER_PROCESS_ACTION_DROP) {
			/*
			 * Drop command from any classifier is actioned.
			 */
			DEBUG_TRACE("%p: wants drop: %p, type: %d, skb: %p\n", ci, aci, aci->type_get(aci), skb);
			prevalent_pr.drop |= aci_pr.drop;
		}

		/*
		 * Accel mode permission
		 */
		if (aci_pr.relevance == ECM_CLASSIFIER_RELEVANCE_MAYBE) {
			/*
			 * Classifier not sure of its relevance - cannot accel yet
			 */
			DEBUG_TRACE("%p: accel denied by maybe: %p, type: %d\n", ci, aci, aci->type_get(aci));
			prevalent_pr.accel_mode = ECM_CLASSIFIER_ACCELERATION_MODE_NO;
		} else {
			if (aci_pr.process_actions & ECM_CLASSIFIER_PROCESS_ACTION_ACCEL_MODE) {
				if (aci_pr.accel_mode == ECM_CLASSIFIER_ACCELERATION_MODE_NO) {
					DEBUG_TRACE("%p: accel denied: %p, type: %d\n", ci, aci, aci->type_get(aci));
					prevalent_pr.accel_mode = ECM_CLASSIFIER_ACCELERATION_MODE_NO;
				}
				/* else yes or don't care about accel */
			}
		}

		/*
		 * Timer group (the last classifier i.e. the highest priority one) will 'win'
		 */
		if (aci_pr.process_actions & ECM_CLASSIFIER_PROCESS_ACTION_TIMER_GROUP) {
			DEBUG_TRACE("%p: timer group: %p, type: %d, group: %d\n", ci, aci, aci->type_get(aci), aci_pr.timer_group);
			prevalent_pr.timer_group = aci_pr.timer_group;
		}

		/*
		 * Qos tag (the last classifier i.e. the highest priority one) will 'win'
		 */
		if (aci_pr.process_actions & ECM_CLASSIFIER_PROCESS_ACTION_QOS_TAG) {
			DEBUG_TRACE("%p: qos_tag: %p, type: %d, qos tag: %u\n", ci, aci, aci->type_get(aci), aci_pr.qos_tag);
			prevalent_pr.qos_tag = aci_pr.qos_tag;
		}
	}
	ecm_db_connection_assignments_release(assignment_count, assignments);

	/*
	 * Change timer group?
	 */
	if (ci_orig_timer_group != prevalent_pr.timer_group) {
		DEBUG_TRACE("%p: change timer group from: %d to: %d\n", ci, ci_orig_timer_group, prevalent_pr.timer_group);
		ecm_db_connection_defunct_timer_reset(ci, prevalent_pr.timer_group);
	}

	/*
	 * Drop?
	 */
	if (prevalent_pr.drop) {
		DEBUG_TRACE("%p: drop: %p\n", ci, skb);
		ecm_db_connection_data_totals_update_dropped(ci, (sender == ECM_TRACKER_SENDER_TYPE_SRC)? true : false, skb->len, 1);
		ecm_db_connection_deref(ci);
		return NF_DROP;
	}
	ecm_db_connection_data_totals_update(ci, (sender == ECM_TRACKER_SENDER_TYPE_SRC)? true : false, skb->len, 1);

	/*
	 * Assign qos tag
	 */
	skb->priority = prevalent_pr.qos_tag;
	DEBUG_TRACE("%p: skb priority: %u\n", ci, skb->priority);

	/*
	 * Accelerate?
	 */
	if (prevalent_pr.accel_mode == ECM_CLASSIFIER_ACCELERATION_MODE_ACCEL) {
		struct ecm_front_end_connection_instance *feci;
		DEBUG_TRACE("%p: accel\n", ci);
		feci = ecm_db_connection_front_end_get_and_ref(ci);
		ecm_front_end_ipv4_connection_non_ported_front_end_accelerate(feci, &prevalent_pr);
		feci->deref(feci);
	}
	ecm_db_connection_deref(ci);

	return NF_ACCEPT;
}

/*
 * ecm_front_end_ipv4_ip_process()
 *	Process IP datagram skb
 */
static unsigned int ecm_front_end_ipv4_ip_process(struct net_device *out_dev, struct net_device *in_dev, bool can_accel, bool is_routed, struct sk_buff *skb)
{
	struct ecm_tracker_ip_header ip_hdr;
        struct nf_conn *ct;
        enum ip_conntrack_info ctinfo;
	struct nf_conntrack_tuple orig_tuple;
	struct nf_conntrack_tuple reply_tuple;
	enum ip_conntrack_dir ct_dir;
	ecm_db_direction_t ecm_dir;
	ip_addr_t ip_src_addr;
	ip_addr_t ip_dest_addr;
	ip_addr_t ip_src_addr_nat;
	ip_addr_t ip_dest_addr_nat;

	/*
	 * Obtain the IP header from the skb
	 */
	if (!ecm_tracker_ip_check_header_and_read(&ip_hdr, skb)) {
		DEBUG_WARN("Invalid ip header in skb %p\n", skb);
		return NF_DROP;
	}

	if (ip_hdr.fragmented) {
		DEBUG_TRACE("skb %p is fragmented\n", skb);
		return NF_ACCEPT;
	}

	/*
	 * Extract information, if we have conntrack then use that info as far as we can.
	 */
        ct = nf_ct_get(skb, &ctinfo);
	if (unlikely(!ct)) {
		DEBUG_TRACE("%p: no ct\n", skb);
		orig_tuple.src.u3.ip = ip_hdr.h.v4_hdr.saddr;
		orig_tuple.dst.u3.ip = ip_hdr.h.v4_hdr.daddr;
		orig_tuple.dst.protonum = ip_hdr.protocol;
		reply_tuple.src.u3.ip = orig_tuple.dst.u3.ip;
		reply_tuple.dst.u3.ip = orig_tuple.src.u3.ip;
		ct_dir = IP_CT_DIR_ORIGINAL;
	} else {
		if (unlikely(ct == &nf_conntrack_untracked)) {
			DEBUG_TRACE("%p: ct: untracked\n", skb);
			return NF_ACCEPT;
		}

		/*
		 * Extract conntrack connection information
		 */
		DEBUG_TRACE("%p: ct: %p, ctinfo: %x\n", skb, ct, ctinfo);
		orig_tuple = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple;
		reply_tuple = ct->tuplehash[IP_CT_DIR_REPLY].tuple;
		ct_dir = CTINFO2DIR(ctinfo);

		/*
		 * Is this a related connection?
		 */
		if ((ctinfo == IP_CT_RELATED) || (ctinfo == IP_CT_RELATED_REPLY)) {
			/*
			 * ct is related to the packet at hand.
			 * We can use the IP src/dest information and the direction information.
			 * We cannot use the protocol information from the ct (typically the packet at hand is ICMP error that is related to the ct we have here).
			 */
			orig_tuple.dst.protonum = ip_hdr.protocol;
			DEBUG_TRACE("%p: related ct, actual protocol: %u\n", skb, orig_tuple.dst.protonum);
		}
	}

	/*
	 * Work out if this packet involves NAT or not.
	 * If it does involve NAT then work out if this is an ingressing or egressing packet.
	 */
	if (orig_tuple.src.u3.ip != reply_tuple.dst.u3.ip) {
		/*
		 * Egressing NAT
		 */
		ecm_dir = ECM_DB_DIRECTION_EGRESS;
	} else if (orig_tuple.dst.u3.ip != reply_tuple.src.u3.ip) {
		/*
		 * Ingressing NAT
		 */
		ecm_dir = ECM_DB_DIRECTION_INGRESS;
	} else {
		ecm_dir = ECM_DB_DIRECTION_EGRESS;
		// GGG TODO - Factor in the interface type, e.g. a packet going to a wireless interface is egress so we apply more pressure to
		// qos in that direction.
	}

	DEBUG_TRACE("IP Packet ORIGINAL src: %pI4 ORIGINAL dst: %pI4 protocol: %u, ct_dir: %d ecm_dir: %d\n", &orig_tuple.src.u3.ip, &orig_tuple.dst.u3.ip, orig_tuple.dst.protonum, ct_dir, ecm_dir);

	/*
	 * Get IP addressing information.  This same logic is applied when extracting port information too.
	 * This is tricky to do as what we are after is src and destination addressing that is non-nat but we also need the nat information too.
	 * INGRESS connections have their conntrack information reversed!
	 * We have to keep in mind the connection direction AND the packet direction in order to be able to work out what is what.
	 *
	 * Example 1:
	 * An 'original' direction packet to an egress connection from 192.168.0.133:12345 to 80.132.221.34:80 via NAT'ing router mapping 10.10.10.30:33333 looks like:
	 *	orig_tuple->src == 192.168.0.133:12345		This becomes ip_src_addr
	 *	orig_tuple->dst == 80.132.221.34:80		This becomes ip_dest_addr
	 *	reply_tuple->src == 80.132.221.34:80		This becomes ip_dest_addr_nat
	 *	reply_tuple->dest == 10.10.10.30:33333		This becomes ip_src_addr_nat
	 *
	 * Example 2:
	 * However an 'original' direction packet to an ingress connection from 80.132.221.34:3321 to a LAN host (e.g. via DMZ) 192.168.0.133:12345 via NAT'ing router mapping 10.10.10.30:12345 looks like:
	 *	orig_tuple->src == 80.132.221.34:3321		This becomes ip_src_addr
	 *	orig_tuple->dst == 10.10.10.30:12345		This becomes ip_dest_addr_nat
	 *	reply_tuple->src == 192.168.0.133:12345		This becomes ip_dest_addr
	 *	reply_tuple->dest == 80.132.221.34:3321		This becomes ip_src_addr_nat
	 *
	 * When dealing with reply packets this confuses things even more.  Reply packets to the above two examples are as follows:
	 *
	 * Example 3:
	 * A 'reply' direction packet to the egress connection above:
	 *	orig_tuple->src == 192.168.0.133:12345		This becomes ip_dest_addr
	 *	orig_tuple->dst == 80.132.221.34:80		This becomes ip_src_addr
	 *	reply_tuple->src == 80.132.221.34:80		This becomes ip_src_addr_nat
	 *	reply_tuple->dest == 10.10.10.30:33333		This becomes ip_dest_addr_nat
	 *
	 * Example 4:
	 * A 'reply' direction packet to the ingress connection above:
	 *	orig_tuple->src == 80.132.221.34:3321		This becomes ip_dest_addr
	 *	orig_tuple->dst == 10.10.10.30:12345		This becomes ip_src_addr_nat
	 *	reply_tuple->src == 192.168.0.133:12345		This becomes ip_src_addr
	 *	reply_tuple->dest == 80.132.221.34:3321		This becomes ip_dest_addr_nat
	 *
	 * ip_src_addr and ip_dest_addr MUST always be the NON-NAT endpoint addresses and reflect PACKET direction and not connection direction 'dir'.
	 */
	if (ct_dir == IP_CT_DIR_ORIGINAL) {
		if (ecm_dir == ECM_DB_DIRECTION_EGRESS) {
			/*
			 * Example 1
			 */
			ECM_NIN4_ADDR_TO_IP_ADDR(ip_src_addr, orig_tuple.src.u3.ip);
			ECM_NIN4_ADDR_TO_IP_ADDR(ip_dest_addr, orig_tuple.dst.u3.ip);
			ECM_NIN4_ADDR_TO_IP_ADDR(ip_dest_addr_nat, reply_tuple.src.u3.ip);
			ECM_NIN4_ADDR_TO_IP_ADDR(ip_src_addr_nat, reply_tuple.dst.u3.ip);
		} else {
			/*
			 * Example 2
			 */
			ECM_NIN4_ADDR_TO_IP_ADDR(ip_src_addr, orig_tuple.src.u3.ip);
			ECM_NIN4_ADDR_TO_IP_ADDR(ip_dest_addr_nat, orig_tuple.dst.u3.ip);
			ECM_NIN4_ADDR_TO_IP_ADDR(ip_dest_addr, reply_tuple.src.u3.ip);
			ECM_NIN4_ADDR_TO_IP_ADDR(ip_src_addr_nat, reply_tuple.dst.u3.ip);
		}
	} else {
		if (ecm_dir == ECM_DB_DIRECTION_EGRESS) {
			/*
			 * Example 3
			 */
			ECM_NIN4_ADDR_TO_IP_ADDR(ip_dest_addr, orig_tuple.src.u3.ip);
			ECM_NIN4_ADDR_TO_IP_ADDR(ip_src_addr, orig_tuple.dst.u3.ip);
			ECM_NIN4_ADDR_TO_IP_ADDR(ip_src_addr_nat, reply_tuple.src.u3.ip);
			ECM_NIN4_ADDR_TO_IP_ADDR(ip_dest_addr_nat, reply_tuple.dst.u3.ip);
		} else {
			/*
			 * Example 4
			 */
			ECM_NIN4_ADDR_TO_IP_ADDR(ip_dest_addr, orig_tuple.src.u3.ip);
			ECM_NIN4_ADDR_TO_IP_ADDR(ip_src_addr_nat, orig_tuple.dst.u3.ip);
			ECM_NIN4_ADDR_TO_IP_ADDR(ip_src_addr, reply_tuple.src.u3.ip);
			ECM_NIN4_ADDR_TO_IP_ADDR(ip_dest_addr_nat, reply_tuple.dst.u3.ip);
		}
	}

	/*
	 * Non-unicast source or destination packets are ignored
	 * NOTE: Only need to check the non-nat src/dest addresses here.
	 */
	if (unlikely(ecm_ip_addr_is_non_unicast(ip_dest_addr))) {
		DEBUG_TRACE("skb %p non-unicast daddr " ECM_IP_ADDR_DOT_FMT "\n", skb, ECM_IP_ADDR_TO_DOT(ip_dest_addr));
		return NF_ACCEPT;
	}
	if (unlikely(ecm_ip_addr_is_non_unicast(ip_src_addr))) {
		DEBUG_TRACE("skb %p non-unicast saddr " ECM_IP_ADDR_DOT_FMT "\n", skb, ECM_IP_ADDR_TO_DOT(ip_src_addr));
		return NF_ACCEPT;
	}

	/*
	 * Process IP specific protocol
	 * TCP and UDP are the most likliest protocols.
	 */
	if (likely(orig_tuple.dst.protonum == IPPROTO_TCP)) {
		return ecm_front_end_ipv4_tcp_process(out_dev, in_dev, can_accel, is_routed, skb,
				&ip_hdr,
				ct, ct_dir, ecm_dir,
				&orig_tuple, &reply_tuple,
				ip_src_addr, ip_dest_addr, ip_src_addr_nat, ip_dest_addr_nat);
	} else if (likely(orig_tuple.dst.protonum == IPPROTO_UDP)) {
		return ecm_front_end_ipv4_udp_process(out_dev, in_dev, can_accel, is_routed, skb,
				&ip_hdr,
				ct, ct_dir, ecm_dir,
				&orig_tuple, &reply_tuple,
				ip_src_addr, ip_dest_addr, ip_src_addr_nat, ip_dest_addr_nat);
	}
	return ecm_front_end_ipv4_non_ported_process(out_dev, in_dev, can_accel, is_routed, skb,
				&ip_hdr,
				ct, ct_dir, ecm_dir,
				&orig_tuple, &reply_tuple,
				ip_src_addr, ip_dest_addr, ip_src_addr_nat, ip_dest_addr_nat);
}

/*
 * ecm_front_end_ipv4_post_routing_hook()
 *	Called for IP packets that are going out to interfaces after IP routing stage.
 */
static unsigned int ecm_front_end_ipv4_post_routing_hook(unsigned int hooknum,
				struct sk_buff *skb,
				const struct net_device *in_unused,
				const struct net_device *out,
				int (*okfn)(struct sk_buff *))
{
	struct net_device *in;
	bool can_accel = true;
	unsigned int result;

	DEBUG_TRACE("%p: Routing: %s\n", out, out->name);

	/*
	 * If operations have stopped then do not process packets
	 */
	spin_lock_bh(&ecm_front_end_ipv4_lock);
	if (unlikely(ecm_front_end_ipv4_stopped)) {
		spin_unlock_bh(&ecm_front_end_ipv4_lock);
		DEBUG_TRACE("Front end stopped\n");
		return NF_ACCEPT;
	}
	spin_unlock_bh(&ecm_front_end_ipv4_lock);

	/*
	 * Identify interface from where this packet came
	 */
	in = dev_get_by_index(&init_net, skb->skb_iif);
	if (unlikely(!in)) {
		/*
		 * Locally sourced packets cannot be accelerated
		 */
		can_accel = false;

		/*
		 * in becomes out!
		 */
		in = (struct net_device *)out;
		dev_hold(in);
	}

	DEBUG_TRACE("Post routing process skb %p, out: %p, in: %p\n", skb, out, in);
	result = ecm_front_end_ipv4_ip_process((struct net_device *)out, in, can_accel, true, skb);
	dev_put(in);
	return result;
}

/*
 * ecm_front_end_ipv4_input_hook()
 *	Called for IP packets that are being sent to local stack services
 */
static unsigned int ecm_front_end_ipv4_input_hook(unsigned int hooknum,
                                 struct sk_buff *skb,
                                 const struct net_device *in,
                                 const struct net_device *out,
                                 int (*okfn)(struct sk_buff *))
{
	DEBUG_TRACE("%p: Input: %s\n", in, in->name);

	/*
	 * If operations have stopped then do not process packets
	 */
	spin_lock_bh(&ecm_front_end_ipv4_lock);
	if (unlikely(ecm_front_end_ipv4_stopped)) {
		spin_unlock_bh(&ecm_front_end_ipv4_lock);
		DEBUG_TRACE("Front end stopped\n");
		return NF_ACCEPT;
	}
	spin_unlock_bh(&ecm_front_end_ipv4_lock);

	/*
	 * Input packets cannot be accelerated and this is not a routed path.
	 * The output interface will be the same on which the packet arrived.
	 */
	DEBUG_TRACE("%p: Name: %s, Input skb %p\n", in, in->name, skb);
	return ecm_front_end_ipv4_ip_process((struct net_device *)in, (struct net_device *)in, false, false, skb);
}

/*
 * ecm_front_end_ipv4_bridge_post_routing_hook()
 *	Called for packets that are going out to one of the bridge physical interfaces.
 *
 * These may have come from another bridged interface or from a non-bridged interface.
 * Conntrack information may be available or not if this skb is bridged.
 */
static unsigned int ecm_front_end_ipv4_bridge_post_routing_hook(unsigned int hooknum,
					struct sk_buff *skb,
					const struct net_device *in_unused,
					const struct net_device *out,
					int (*okfn)(struct sk_buff *))
{
	struct ethhdr *skb_eth_hdr;
	uint16_t eth_type;
	struct net_device *in;
	bool can_accel = true;
	unsigned int result;

	DEBUG_TRACE("%p: Bridge: %s\n", out, out->name);

	/*
	 * If operations have stopped then do not process packets
	 */
	spin_lock_bh(&ecm_front_end_ipv4_lock);
	if (unlikely(ecm_front_end_ipv4_stopped)) {
		spin_unlock_bh(&ecm_front_end_ipv4_lock);
		DEBUG_TRACE("Front end stopped\n");
		return NF_ACCEPT;
	}
	spin_unlock_bh(&ecm_front_end_ipv4_lock);

	/*
	 * Check packet is an IP Ethernet packet
	 */
	skb_eth_hdr = eth_hdr(skb);
	if (!skb_eth_hdr) {
		DEBUG_TRACE("%p: Not Eth\n", skb);
		return NF_ACCEPT;
	}
	eth_type = ntohs(skb_eth_hdr->h_proto);
	if (unlikely(eth_type != 0x0800)) {
		DEBUG_TRACE("%p: Not IP\n", skb);
		return NF_ACCEPT;
	}

	/*
	 * Identify interface from where this packet came
	 */
	in = dev_get_by_index(&init_net, skb->skb_iif);
	if (unlikely(!in)) {
		/*
		 * Locally sourced packets cannot be accelerated
		 */
		DEBUG_TRACE("Locally sourced packet to bridge port\n");
		can_accel = false;

		/*
		 * "in" becomes "out" as replies to local services will involve the same interface path.
		 */
		in = (struct net_device *)out;
		dev_hold(in);
	} else {
		/*
		 * This is bridge post routing so "out" is a bridge port (obvious).
		 * If the "in" device is NOT a port on this same bridge (non-bridged traffic)
		 * then this would have been handled in normal post routing hook so we don't duplicate effort.
		 */
		if (!in->master || (in->master != out->master)) {
			/*
			 * 'in' is either a non-slave device - so the packet has definately routed to this bridge
			 * or 'in' is a slave BUT it's a slave of a different master, again the packet has been routed to the bridge.
			 */
			DEBUG_TRACE("Ignoring bridge post routed packet: %p, in: %p (%s), in->master: %p (%s), out: %p (%s), out->master: %p (%s)\n",
					skb, in, in->name, in->master, (in->master)? in->master->name : "NULL",
					out, out->name, out->master, (out->master)? out->master->name : "NULL");
			dev_put(in);
			return NF_ACCEPT;
		}
	}

	DEBUG_TRACE("%p: Name: %s Bridge process skb %p, in: %p\n", out, out->name, skb, in);
	result = ecm_front_end_ipv4_ip_process((struct net_device *)out, in, can_accel, false, skb);
	dev_put(in);
	return result;
}

/*
 * ecm_front_end_ipv4_neigh_get()
 * 	Returns neighbour reference for a given IP address which must be released when you are done with it.
 *
 * Returns NULL on fail.
 */
static struct neighbour *ecm_front_end_ipv4_neigh_get(ip_addr_t addr)
{
	struct neighbour *neigh;
	struct rtable *rt;
	struct dst_entry *dst;
	__be32 ipv4_addr;

	ECM_IP_ADDR_TO_NIN4_ADDR(ipv4_addr, addr);
	rt = ip_route_output(&init_net, ipv4_addr, 0, 0, 0);
	if (IS_ERR(rt)) {
		return NULL;
	}
	dst = (struct dst_entry *)rt;
	neigh = dst_neigh_lookup(dst, &ipv4_addr);
	ip_rt_put(rt);
	return neigh;
}

/*
 * ecm_front_end_ipv4_net_dev_callback()
 *	Callback handler from the NSS.
 */
static void ecm_front_end_ipv4_net_dev_callback(struct nss_ipv4_cb_params *nicb)
{
	struct nss_ipv4_sync *sync;
	struct nf_conntrack_tuple_hash *h;
	struct nf_conntrack_tuple tuple;
	struct nf_conn *ct;
	struct nf_conn_counter *acct;
	struct ecm_db_connection_instance *ci;
	struct ecm_front_end_connection_instance *feci;
	struct neighbour *neigh;
	ip_addr_t src_ip;
	ip_addr_t dest_ip_xlate;
	ip_addr_t dest_ip;
	struct ecm_classifier_instance *assignments[ECM_CLASSIFIER_TYPES];
	int aci_index;
	int assignment_count;

	/*
	 * Only respond to sync messages
	 */
	if (nicb->reason != NSS_IPV4_CB_REASON_SYNC) {
		DEBUG_TRACE("Ignoring nicb: %p - not sync: %d", nicb, nicb->reason);
		return;
	}
	sync = &nicb->params.sync;

	/*
	 * Look up ecm connection with a view to synchronising the connection, classifier and data tracker.
	 * Note that we use _xlate versions for destination - for egressing connections this would be the wan IP address,
	 * but for ingressing this would be the LAN side (non-nat'ed) address and is what we need for lookup of our connection.
	 */
	DEBUG_INFO("%p: NSS Sync, lookup connection using\n"
			"Protocol: %d\n" \
			"src_addr: %pI4h:%d\n" \
			"dest_addr: %pI4h:%d\n",
			sync,
			(int)sync->protocol,
			&sync->src_ip, (int)sync->src_port,
			&sync->dest_ip_xlate, (int)sync->dest_port_xlate);

	ECM_HIN4_ADDR_TO_IP_ADDR(src_ip, sync->src_ip);
	ECM_HIN4_ADDR_TO_IP_ADDR(dest_ip_xlate, sync->dest_ip_xlate);
	if (likely(sync->protocol == IPPROTO_TCP)) {
		ci = ecm_db_connection_find_and_ref(src_ip, dest_ip_xlate, IPPROTO_TCP, (int)sync->src_port, (int)sync->dest_port_xlate);
	} else if (likely(sync->protocol == IPPROTO_UDP)) {
		ci = ecm_db_connection_find_and_ref(src_ip, dest_ip_xlate, IPPROTO_UDP, (int)sync->src_port, (int)sync->dest_port_xlate);
	} else {
		DEBUG_TRACE("%p: sync ignored for protocol %d\n", sync, sync->protocol);
		return;
	}
	if (!ci) {
		DEBUG_TRACE("%p: NSS Sync: no connection\n", sync);
		goto sync_conntrack;
	}
	DEBUG_TRACE("%p: Sync conn %p\n", sync, ci);

	/*
	 * Keep connection alive and updated
	 */
	if (!ecm_db_connection_defunct_timer_touch(ci)) {
		ecm_db_connection_deref(ci);
		goto sync_conntrack;
	}

	/*
	 * Get the front end instance
	 */
	feci = ecm_db_connection_front_end_get_and_ref(ci);

	if (sync->flow_tx_packet_count || sync->return_tx_packet_count) {
		DEBUG_TRACE("%p: flow_tx_packet_count: %u, flow_tx_byte_count: %u, return_tx_packet_count: %u, , return_tx_byte_count: %u\n",
				ci, sync->flow_tx_packet_count, sync->flow_tx_byte_count, sync->return_tx_packet_count, sync->return_tx_byte_count);
		ecm_db_connection_data_totals_update(ci, true, sync->return_tx_byte_count, sync->return_tx_packet_count);
		ecm_db_connection_data_totals_update(ci, false, sync->flow_tx_byte_count, sync->flow_tx_packet_count);

		/*
		 * As packets have been accelerated we reset the accel count for the connection
		 */
		feci->accel_count_reset(feci);
	}

	/*
	 * Sync assigned classifiers
	 */
	assignment_count = ecm_db_connection_classifier_assignments_get_and_ref(ci, assignments);
	for (aci_index = 0; aci_index < assignment_count; ++aci_index) {
		struct ecm_classifier_instance *aci;

		aci = assignments[aci_index];
		DEBUG_TRACE("%p: sync to: %p, type: %d\n", feci, aci, aci->type_get(aci));
		aci->sync_to_v4(aci, nicb);
	}
	ecm_db_connection_assignments_release(assignment_count, assignments);

	/*
	 * If this is the final sync message then acceleration has ceased
	 */
	switch(sync->reason) {
	case NSS_IPV4_SYNC_REASON_FLUSH:
	case NSS_IPV4_SYNC_REASON_EVICT:
	case NSS_IPV4_SYNC_REASON_DESTROY:
		DEBUG_INFO("%p: Final sync seen: %d\n", ci, sync->reason);

		/*
		 * As packets have been accelerated we reset the accel count for the connection
		 */
		feci->accel_ceased(feci);
		break;
	default:

		/*
		 * Update the neighbour entry for source IP address
		 */
		neigh = ecm_front_end_ipv4_neigh_get(src_ip);
		if (!neigh) {
			DEBUG_WARN("Neighbour entry for %pI4h not found\n", &sync->src_ip);
		} else {
			DEBUG_TRACE("Neighbour entry for %pI4h update: %p\n", &sync->src_ip, neigh);
			neigh_update(neigh, NULL, neigh->nud_state, NEIGH_UPDATE_F_WEAK_OVERRIDE);
			neigh_release(neigh);
		}

		/*
		 * Update the neighbour entry for destination IP address
		 */
		ECM_NIN4_ADDR_TO_IP_ADDR(dest_ip, sync->dest_ip);
		neigh = ecm_front_end_ipv4_neigh_get(dest_ip);
		if (!neigh) {
			DEBUG_WARN("Neighbour entry for %pI4h not found\n", &sync->dest_ip);
		} else {
			DEBUG_TRACE("Neighbour entry for %pI4h update: %p\n", &sync->dest_ip, neigh);
			neigh_update(neigh, NULL, neigh->nud_state, NEIGH_UPDATE_F_WEAK_OVERRIDE);
			neigh_release(neigh);
		}
	}

	/*
	 * If connection should be re-generated then we need to force a deceleration
	 */
	if (unlikely(ecm_db_connection_classifier_peek_generation_changed(ci))) {
		DEBUG_TRACE("%p: Connection generation changing, terminating acceleration", ci);
		feci->decelerate(feci);
	}

	feci->deref(feci);
	ecm_db_connection_deref(ci);

sync_conntrack:
	;

	/*
	 * Create a tuple so as to be able to look up a conntrack connection
	 */
	memset(&tuple, 0, sizeof(tuple));
	tuple.src.u3.ip = htonl(sync->src_ip);
	tuple.src.u.all = (__be16)htons(sync->src_port);
	tuple.src.l3num = AF_INET;

	tuple.dst.u3.ip = htonl(sync->dest_ip);
	tuple.dst.dir = IP_CT_DIR_ORIGINAL;
	tuple.dst.protonum = (uint8_t)sync->protocol;
	tuple.dst.u.all = (__be16)htons(sync->dest_port);

	DEBUG_TRACE("Conntrack sync, lookup conntrack connection using\n"
			"Protocol: %d\n"
			"src_addr: %pI4:%d\n"
			"dest_addr: %pI4:%d\n",
			(int)tuple.dst.protonum,
			&tuple.src.u3.ip, (int)tuple.src.u.all,
			&tuple.dst.u3.ip, (int)tuple.dst.u.all);

	/*
	 * Look up conntrack connection
	 */
	h = nf_conntrack_find_get(&init_net, NF_CT_DEFAULT_ZONE, &tuple);
	if (!h) {
		DEBUG_WARN("%p: NSS Sync: no conntrack connection\n", sync);
		return;
	}

	ct = nf_ct_tuplehash_to_ctrack(h);
	NF_CT_ASSERT(ct->timeout.data == (unsigned long)ct);
	DEBUG_TRACE("%p: NSS Sync: conntrack connection\n", ct);

	/*
	 * Only update if this is not a fixed timeout
	 */
	if (!test_bit(IPS_FIXED_TIMEOUT_BIT, &ct->status)) {
		spin_lock_bh(&ct->lock);
		ct->timeout.expires += sync->delta_jiffies;
		spin_unlock_bh(&ct->lock);
	}

	acct = nf_conn_acct_find(ct);
	if (acct) {
		spin_lock_bh(&ct->lock);
		atomic64_add(sync->flow_rx_packet_count, &acct[IP_CT_DIR_ORIGINAL].packets);
		atomic64_add(sync->flow_rx_byte_count, &acct[IP_CT_DIR_ORIGINAL].bytes);

		atomic64_add(sync->return_rx_packet_count, &acct[IP_CT_DIR_REPLY].packets);
		atomic64_add(sync->return_rx_byte_count, &acct[IP_CT_DIR_REPLY].bytes);
		spin_unlock_bh(&ct->lock);
	}

	switch (sync->protocol) {
	case IPPROTO_TCP:
		spin_lock_bh(&ct->lock);
		if (ct->proto.tcp.seen[0].td_maxwin < sync->flow_max_window) {
			ct->proto.tcp.seen[0].td_maxwin = sync->flow_max_window;
		}
		if ((int32_t)(ct->proto.tcp.seen[0].td_end - sync->flow_end) < 0) {
			ct->proto.tcp.seen[0].td_end = sync->flow_end;
		}
		if ((int32_t)(ct->proto.tcp.seen[0].td_maxend - sync->flow_max_end) < 0) {
			ct->proto.tcp.seen[0].td_maxend = sync->flow_max_end;
		}
		if (ct->proto.tcp.seen[1].td_maxwin < sync->return_max_window) {
			ct->proto.tcp.seen[1].td_maxwin = sync->return_max_window;
		}
		if ((int32_t)(ct->proto.tcp.seen[1].td_end - sync->return_end) < 0) {
			ct->proto.tcp.seen[1].td_end = sync->return_end;
		}
		if ((int32_t)(ct->proto.tcp.seen[1].td_maxend - sync->return_max_end) < 0) {
			ct->proto.tcp.seen[1].td_maxend = sync->return_max_end;
		}
		spin_unlock_bh(&ct->lock);
		break;
	}

	/*
	 * Release connection
	 */
	nf_ct_put(ct);
}

/*
 * struct nf_hook_ops ecm_front_end_ipv4_netfilter_hooks[]
 *	Hooks into netfilter packet monitoring points.
 */
static struct nf_hook_ops ecm_front_end_ipv4_netfilter_hooks[] __read_mostly = {
	/*
	 * Post routing hook is used to monitor packets going to interfaces that are NOT bridged in some way, e.g. packets to the WAN.
	 */
	{
		.hook           = ecm_front_end_ipv4_post_routing_hook,
		.owner          = THIS_MODULE,
		.pf             = PF_INET,
		.hooknum        = NF_INET_POST_ROUTING,
		.priority       = NF_IP_PRI_NAT_SRC + 1,
	},

	/*
	 * The input hook monitors packets going to the local stack services
	 */
	{
		.hook           = ecm_front_end_ipv4_input_hook,
		.owner          = THIS_MODULE,
		.pf             = PF_INET,
		.hooknum        = NF_INET_LOCAL_IN,
		.priority       = NF_IP_PRI_NAT_SRC + 1,
	},

	/*
	 * The bridge post routing hook monitors packets going to interfaces that are part of a bridge arrangement.
	 * For example Wireles LAN (WLAN) and Wired LAN (LAN).
	 */
	{
		.hook		= ecm_front_end_ipv4_bridge_post_routing_hook,
		.owner		= THIS_MODULE,
		.pf		= PF_BRIDGE,
		.hooknum	= NF_BR_POST_ROUTING,
		.priority	= NF_BR_PRI_FILTER_OTHER,
	},
};

/*
 * ecm_front_end_ipv4_connection_from_ct_get_and_ref()
 *	Return, if any, a connection given a ct
 */
static struct ecm_db_connection_instance *ecm_front_end_ipv4_connection_from_ct_get_and_ref(struct nf_conn *ct)
{
	struct nf_conntrack_tuple orig_tuple;
	struct nf_conntrack_tuple reply_tuple;
	ip_addr_t host1_addr;
	ip_addr_t host2_addr;
	int host1_port;
	int host2_port;
	int protocol;

	/*
	 * Look up the associated connection for this conntrack connection
	 */
	orig_tuple = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple;
	reply_tuple = ct->tuplehash[IP_CT_DIR_REPLY].tuple;
	ECM_NIN4_ADDR_TO_IP_ADDR(host1_addr, orig_tuple.src.u3.ip);
	ECM_NIN4_ADDR_TO_IP_ADDR(host2_addr, reply_tuple.src.u3.ip);
	protocol = orig_tuple.dst.protonum;
	if (protocol == IPPROTO_TCP) {
		host1_port = orig_tuple.src.u.tcp.port;
		host2_port = reply_tuple.src.u.tcp.port;
	} else if (protocol == IPPROTO_UDP) {
		host1_port = orig_tuple.src.u.udp.port;
		host2_port = reply_tuple.src.u.udp.port;
	} else if ((protocol == IPPROTO_IPV6) || (protocol == IPPROTO_ESP)) {
		host1_port = 0;
		host2_port = 0;
	} else {
		host1_port = -protocol;
		host2_port = -protocol;
	}

	DEBUG_TRACE("%p: lookup src: " ECM_IP_ADDR_DOT_FMT ":%d, "
		    "dest: " ECM_IP_ADDR_DOT_FMT ":%d, "
		    "protocol %d\n",
		    ct,
		    ECM_IP_ADDR_TO_DOT(host1_addr),
		    host1_port,
		    ECM_IP_ADDR_TO_DOT(host2_addr),
		    host2_port,
		    protocol);

	return ecm_db_connection_find_and_ref(host1_addr,
					      host2_addr,
					      protocol,
					      host1_port,
					      host2_port);
}

/*
 * ecm_front_end_ipv4_conntrack_event_destroy()
 *	Handles conntrack destroy events
 */
static void ecm_front_end_ipv4_conntrack_event_destroy(struct nf_conn *ct)
{
	struct ecm_db_connection_instance *ci;

	DEBUG_INFO("Destroy event for ct: %p\n", ct);

	ci = ecm_front_end_ipv4_connection_from_ct_get_and_ref(ct);
	if (!ci) {
		DEBUG_TRACE("%p: not found\n", ct);
		return;
	}
	DEBUG_INFO("%p: Connection defunct %p\n", ct, ci);

	/*
	 * Force destruction of the connection my making it defunct
	 */
	ecm_db_connection_make_defunct(ci);
	ecm_db_connection_deref(ci);
}

/*
 * ecm_front_end_ipv4_conntrack_event_mark()
 *	Handles conntrack mark events
 */
static void ecm_front_end_ipv4_conntrack_event_mark(struct nf_conn *ct)
{
	struct ecm_db_connection_instance *ci;
	struct ecm_classifier_instance *cls;

	DEBUG_INFO("Mark event for ct: %p\n", ct);

	/*
	 * Ignore transitions to zero
	 */
	if (ct->mark == 0) {
		return;
	}

	ci = ecm_front_end_ipv4_connection_from_ct_get_and_ref(ct);
	if (!ci) {
		DEBUG_TRACE("%p: not found\n", ct);
		return;
	}

	/*
	 * As of now, only the Netlink classifier is interested in conmark changes
	 * GGG TODO Add a classifier method to propagate this information to any and all types of classifier.
	 */
	cls = ecm_db_connection_assigned_classifier_find_and_ref(ci, ECM_CLASSIFIER_TYPE_NL);
	DEBUG_ASSERT(cls, "NL classifier should never have unassigned\n");
	ecm_classifier_nl_process_mark((struct ecm_classifier_nl_instance *)cls, ct->mark);
	cls->deref(cls);

	/*
	 * All done
	 */
	ecm_db_connection_deref(ci);
}

/*
 * ecm_front_end_ipv4_conntrack_event()
 *	Callback event invoked when conntrack connection state changes, currently we handle destroy events to quickly release state
 */
int ecm_front_end_ipv4_conntrack_event(unsigned long events, struct nf_conn *ct)
{
	/*
	 * If operations have stopped then do not process event
	 */
	spin_lock_bh(&ecm_front_end_ipv4_lock);
	if (unlikely(ecm_front_end_ipv4_stopped)) {
		DEBUG_WARN("Ignoring event - stopped\n");
		spin_unlock_bh(&ecm_front_end_ipv4_lock);
		return NOTIFY_DONE;
	}
	spin_unlock_bh(&ecm_front_end_ipv4_lock);

	if (!ct) {
		DEBUG_WARN("Error: no ct\n");
		return NOTIFY_DONE;
	}

	/*
	 * handle destroy events
	 */
	if (events & (1 << IPCT_DESTROY)) {
		DEBUG_TRACE("%p: Event is destroy\n", ct);
		ecm_front_end_ipv4_conntrack_event_destroy(ct);
	}

	/*
	 * handle mark change events
	 */
	if (events & (1 << IPCT_MARK)) {
		DEBUG_TRACE("%p: Event is mark\n", ct);
		ecm_front_end_ipv4_conntrack_event_mark(ct);
	}

	return NOTIFY_DONE;
}
EXPORT_SYMBOL(ecm_front_end_ipv4_conntrack_event);

/*
 * ecm_front_end_ipv4_get_terminate()
 */
static ssize_t ecm_front_end_ipv4_get_terminate(struct sys_device *dev,
				  struct sysdev_attribute *attr,
				  char *buf)
{
	ssize_t count;
	unsigned int n;

	spin_lock_bh(&ecm_front_end_ipv4_lock);
	n = ecm_front_end_ipv4_terminate_pending;
	spin_unlock_bh(&ecm_front_end_ipv4_lock);
	count = snprintf(buf, (ssize_t)PAGE_SIZE, "%u\n", n);
	return count;
}

/*
 * ecm_front_end_ipv4_set_terminate()
 *	Writing anything to this 'file' will cause the default classifier to terminate
 */
static ssize_t ecm_front_end_ipv4_set_terminate(struct sys_device *dev,
				  struct sysdev_attribute *attr,
				  const char *buf, size_t count)
{
	DEBUG_INFO("Terminate\n");

	/*
	 * Are we already signalled to terminate?
	 */
	spin_lock_bh(&ecm_front_end_ipv4_lock);
	if (ecm_front_end_ipv4_terminate_pending) {
		spin_unlock_bh(&ecm_front_end_ipv4_lock);
		return 0;
	}

	ecm_front_end_ipv4_terminate_pending = true;
	ecm_front_end_ipv4_thread_refs--;
	DEBUG_ASSERT(ecm_front_end_ipv4_thread_refs >= 0, "Thread ref wrap %d\n", ecm_front_end_ipv4_thread_refs);
	wake_up_process(ecm_front_end_ipv4_thread);
	spin_unlock_bh(&ecm_front_end_ipv4_lock);
	return count;
}

/*
 * ecm_front_end_ipv4_get_stop()
 */
static ssize_t ecm_front_end_ipv4_get_stop(struct sys_device *dev,
				  struct sysdev_attribute *attr,
				  char *buf)
{
	ssize_t count;
	int num;

	/*
	 * Operate under our locks
	 */
	spin_lock_bh(&ecm_front_end_ipv4_lock);
	num = ecm_front_end_ipv4_stopped;
	spin_unlock_bh(&ecm_front_end_ipv4_lock);

	count = snprintf(buf, (ssize_t)PAGE_SIZE, "%d\n", num);
	return count;
}

/*
 * ecm_front_end_ipv4_set_stop()
 */
static ssize_t ecm_front_end_ipv4_set_stop(struct sys_device *dev,
				  struct sysdev_attribute *attr,
				  const char *buf, size_t count)
{
	char num_buf[12];
	int num;

	/*
	 * Get the number from buf into a properly z-termed number buffer
	 */
	if (count > 11) {
		return 0;
	}
	memcpy(num_buf, buf, count);
	num_buf[count] = '\0';
	sscanf(num_buf, "%d", &num);
	DEBUG_TRACE("ecm_front_end_ipv4_stop = %d\n", num);

	/*
	 * Operate under our locks and stop further processing of packets
	 */
	spin_lock_bh(&ecm_front_end_ipv4_lock);
	ecm_front_end_ipv4_stopped = num;
	spin_unlock_bh(&ecm_front_end_ipv4_lock);

	return count;
}

/*
 * SysFS attributes for the default classifier itself.
 */
static SYSDEV_ATTR(terminate, 0644, ecm_front_end_ipv4_get_terminate, ecm_front_end_ipv4_set_terminate);
static SYSDEV_ATTR(stop, 0644, ecm_front_end_ipv4_get_stop, ecm_front_end_ipv4_set_stop);

/*
 * SysFS class of the ubicom default classifier
 * SysFS control points can be found at /sys/devices/system/ecm_front_end/ecm_front_endX/
 */
static struct sysdev_class ecm_front_end_ipv4_sysclass = {
	.name = "ecm_front_end_ipv4",
};

/*
 * ecm_front_end_ipv4_thread_fn()
 *	A thread to handle tasks that can only be done in thread context.
 */
static int ecm_front_end_ipv4_thread_fn(void *arg)
{
	int result;

	DEBUG_INFO("Thread start\n");

	/*
	 * Get reference to this module - we release it when the thread exits
	 */
	if (!try_module_get(THIS_MODULE)) {
		return -EINVAL;
	}

	/*
	 * Register the sysfs class
	 */
	result = sysdev_class_register(&ecm_front_end_ipv4_sysclass);
	if (result) {
		DEBUG_ERROR("Failed to register SysFS class %d\n", result);
		goto task_cleanup_1;
	}

	/*
	 * Register SYSFS device control
	 */
	memset(&ecm_front_end_ipv4_sys_dev, 0, sizeof(ecm_front_end_ipv4_sys_dev));
	ecm_front_end_ipv4_sys_dev.id = 0;
	ecm_front_end_ipv4_sys_dev.cls = &ecm_front_end_ipv4_sysclass;
	result = sysdev_register(&ecm_front_end_ipv4_sys_dev);
	if (result) {
		DEBUG_ERROR("Failed to register SysFS device %d\n", result);
		goto task_cleanup_2;
	}

	/*
	 * Create files, one for each parameter supported by this module
	 */
	result = sysdev_create_file(&ecm_front_end_ipv4_sys_dev, &attr_terminate);
	if (result) {
		DEBUG_ERROR("Failed to register terminate file %d\n", result);
		goto task_cleanup_3;
	}

	/*
	 * Register netfilter hooks
	 */
        result = nf_register_hooks(ecm_front_end_ipv4_netfilter_hooks, ARRAY_SIZE(ecm_front_end_ipv4_netfilter_hooks));
        if (result < 0) {
		DEBUG_ERROR("Can't register netfilter hooks.\n");
		goto task_cleanup_4;
        }

	result = sysdev_create_file(&ecm_front_end_ipv4_sys_dev, &attr_stop);
	if (result) {
		DEBUG_ERROR("Failed to register stop file %d\n", result);
		goto task_cleanup_5;
	}

	/*
	 * Register this module with the Linux NSS Network driver
	 */
	ecm_front_end_ipv4_nss_ipv4_context = nss_register_ipv4_mgr(ecm_front_end_ipv4_net_dev_callback);

	/*
	 * Allow wakeup signals
	 */
	allow_signal(SIGCONT);
	set_current_state(TASK_INTERRUPTIBLE);

	spin_lock_bh(&ecm_front_end_ipv4_lock);

	/*
	 * Set thread refs to 1 - user must terminate us now.
	 */
	ecm_front_end_ipv4_thread_refs = 1;

	while (ecm_front_end_ipv4_thread_refs) {
		/*
		 * Sleep and wait for an instruction
		 */
		spin_unlock_bh(&ecm_front_end_ipv4_lock);
		DEBUG_TRACE("ecm_front_end sleep\n");
		schedule();
		set_current_state(TASK_INTERRUPTIBLE);
		spin_lock_bh(&ecm_front_end_ipv4_lock);
	}
	DEBUG_INFO("ecm_front_end terminate\n");
	DEBUG_ASSERT(ecm_front_end_ipv4_terminate_pending, "User has not requested terminate\n");
	spin_unlock_bh(&ecm_front_end_ipv4_lock);

	result = 0;

	/*
	 * Unregister from the na
	 */
	nss_unregister_ipv4_mgr();

	/*
	 * Unregister stop file and other stuff
	 */
	sysdev_remove_file(&ecm_front_end_ipv4_sys_dev, &attr_stop);
task_cleanup_5:
	nf_unregister_hooks(ecm_front_end_ipv4_netfilter_hooks, ARRAY_SIZE(ecm_front_end_ipv4_netfilter_hooks));
task_cleanup_4:
	sysdev_remove_file(&ecm_front_end_ipv4_sys_dev, &attr_terminate);
task_cleanup_3:
	sysdev_unregister(&ecm_front_end_ipv4_sys_dev);
task_cleanup_2:
	sysdev_class_unregister(&ecm_front_end_ipv4_sysclass);
task_cleanup_1:

	module_put(THIS_MODULE);
	return result;
}

/*
 * ecm_front_end_ipv4_init()
 */
static int __init ecm_front_end_ipv4_init(void)
{
	DEBUG_INFO("ECM Front end IPv4 init\n");

	/*
	 * Initialise our global lock
	 */
	spin_lock_init(&ecm_front_end_ipv4_lock);

	/*
	 * Create a thread to handle the start/stop of the database.
	 * NOTE: We use a thread as some things we need to do cannot be done in this context
	 */
	ecm_front_end_ipv4_thread = kthread_create(ecm_front_end_ipv4_thread_fn, NULL, "%s", "ecm_front_end_ipv4");
	if (!ecm_front_end_ipv4_thread) {
		return -EINVAL;
	}
	wake_up_process(ecm_front_end_ipv4_thread);
	return 0;
}

/*
 * ecm_front_end_ipv4_exit()
 */
static void __exit ecm_front_end_ipv4_exit(void)
{
	DEBUG_INFO("ECM Front end IPv4 Module exit\n");
	DEBUG_ASSERT(!ecm_front_end_ipv4_thread_refs, "Thread has refs %d\n", ecm_front_end_ipv4_thread_refs);
}

module_init(ecm_front_end_ipv4_init)
module_exit(ecm_front_end_ipv4_exit)

MODULE_AUTHOR("Qualcomm Atheros, Inc.");
MODULE_DESCRIPTION("ECM Front end IPv4");
#ifdef MODULE_LICENSE
MODULE_LICENSE("Dual BSD/GPL");
#endif

