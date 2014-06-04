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

#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_bridge.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_l4proto.h>
#include <net/netfilter/nf_conntrack_l3proto.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/ipv4/nf_conntrack_ipv4.h>
#include <net/netfilter/ipv4/nf_defrag_ipv4.h>
#include <net/genetlink.h>

/*
 * Debug output levels
 * 0 = OFF
 * 1 = ASSERTS / ERRORS
 * 2 = 1 + WARN
 * 3 = 2 + INFO
 * 4 = 3 + TRACE
 */
#define DEBUG_LEVEL ECM_CLASSIFIER_NL_DEBUG_LEVEL

#include <nss_api_if.h>

#include "ecm_types.h"
#include "ecm_db_types.h"
#include "ecm_tracker.h"
#include "ecm_classifier.h"
#include "ecm_front_end_types.h"
#include "ecm_tracker_udp.h"
#include "ecm_tracker_tcp.h"
#include "ecm_classifier_nl.h"
#include "ecm_db.h"
#include "ecm_classifier_nl.h"

/*
 * Magic numbers
 */
#define ECM_CLASSIFIER_NL_INSTANCE_MAGIC 0xFE12

#define ECM_CLASSIFIER_NL_F_ACCEL	(1 << 0) /* acceleration requested */
#define ECM_CLASSIFIER_NL_F_ACCEL_OK	(1 << 1) /* acceleration confirmed */
#define ECM_CLASSIFIER_NL_F_CLOSED	(1 << 2) /* close event issued */

/*
 * struct ecm_classifier_nl_instance
 * 	State to allow tracking of dynamic qos for a connection
 */
struct ecm_classifier_nl_instance {
	struct ecm_classifier_instance base;			/* Base type */

	struct ecm_classifier_nl_instance *next;		/* Next classifier state instance (for accouting and reporting purposes) */
	struct ecm_classifier_nl_instance *prev;		/* Next classifier state instance (for accouting and reporting purposes) */

	struct ecm_db_connection_instance *ci;			/* Connection pointer, note that this is a copy of the connection pointer not a ref to it as this instance is ref'd by the connection itself. */
	struct ecm_classifier_process_response process_response;/* Last process response computed */
	int refs;						/* Integer to trap we never go negative */
	unsigned int flags;					/* See ECM_CLASSIFIER_NL_F_* */
#if (DEBUG_LEVEL > 0)
	uint16_t magic;
#endif
};

/*
 * Operational control
 */
static bool ecm_classifier_nl_enabled = false;		/* Operational behaviour */

/*
 * Management thread control
 */
static bool ecm_classifier_nl_terminate_pending = false;		/* True when the user wants us to terminate */

/*
 * Sys dev linkage
 */
static struct sys_device ecm_classifier_nl_sys_dev;		/* SysFS linkage */

/*
 * Locking of the classifier structures
 */
static spinlock_t ecm_classifier_nl_lock;			/* Protect SMP access. */

/*
 * List of our classifier instances
 */
static struct ecm_classifier_nl_instance *ecm_classifier_nl_instances = NULL;
									/* list of all active instances */
static int ecm_classifier_nl_count = 0;					/* Tracks number of instances allocated */

/*
 * Generic Netlink family and multicast group names
 */
static struct genl_multicast_group ecm_cl_nl_genl_mcgrp = {
	.name = ECM_CL_NL_GENL_MCGRP,
};

static struct genl_family ecm_cl_nl_genl_family = {
	.id = GENL_ID_GENERATE,
	.hdrsize = 0,
	.name = ECM_CL_NL_GENL_NAME,
	.version = ECM_CL_NL_GENL_VERSION,
	.maxattr = ECM_CL_NL_GENL_ATTR_MAX,
};

/*
 * helper for sending basic genl commands requiring only a tuple attribute
 */
static void
ecm_classifier_nl_send_genl_msg(enum ECM_CL_NL_GENL_CMD cmd,
				struct ecm_cl_nl_genl_attr_tuple *tuple)
{
	int ret;
	void *msg_head;
	struct sk_buff *skb;

	skb = nlmsg_new(NLMSG_GOODSIZE, GFP_ATOMIC);
	if (skb == NULL) {
		return;
	}

	msg_head = genlmsg_put(skb,
			       0, /* netlink PID */
			       0, /* sequence number */
			       &ecm_cl_nl_genl_family,
			       0, /* flags */
			       cmd);
	if (msg_head == NULL) {
		nlmsg_free(skb);
		return;
	}

	ret = nla_put(skb, ECM_CL_NL_GENL_ATTR_TUPLE, sizeof(*tuple), tuple);
	if (ret != 0) {
		nlmsg_free(skb);
		return;
	}

	ret = genlmsg_end(skb, msg_head);
	if (ret < 0) {
		nlmsg_free(skb);
		return;
	}

	genlmsg_multicast(skb, 0, ecm_cl_nl_genl_mcgrp.id, GFP_ATOMIC);
}

/*
 * Helper function to convert connection IP info into a genl_attr_tuple
 */
static int
ecm_cl_nl_genl_attr_tuple_encode(struct ecm_cl_nl_genl_attr_tuple *tuple,
				 int proto,
				 ip_addr_t src_ip,
				 int src_port,
				 ip_addr_t dst_ip,
				 int dst_port)
{
	memset(tuple, 0, sizeof(*tuple));
	tuple->proto = (uint8_t)proto;
	tuple->src_port = htons((uint16_t)src_port);
	tuple->dst_port = htons((uint16_t)dst_port);
	if (ECM_IP_ADDR_IS_V4(src_ip)) {
		tuple->af = AF_INET;
		ECM_IP_ADDR_TO_NIN4_ADDR(tuple->src_ip.in.s_addr, src_ip);
		ECM_IP_ADDR_TO_NIN4_ADDR(tuple->dst_ip.in.s_addr, dst_ip);
	} else {
		tuple->af = AF_INET6;
		ECM_IP_ADDR_TO_NIN6_ADDR(tuple->src_ip.in6, src_ip);
		ECM_IP_ADDR_TO_NIN6_ADDR(tuple->dst_ip.in6, dst_ip);
	}

	return 0;
}

/*
 * Helper function to convert a genl_attr_tuple into connection IP info
 */
static int
ecm_cl_nl_genl_attr_tuple_decode(struct ecm_cl_nl_genl_attr_tuple *tuple,
				 int *proto,
				 ip_addr_t src_ip,
				 int *src_port,
				 ip_addr_t dst_ip,
				 int *dst_port)
{
	*proto = tuple->proto;
	*src_port = ntohs(tuple->src_port);
	*dst_port = ntohs(tuple->dst_port);
	if (AF_INET == tuple->af) {
		ECM_NIN4_ADDR_TO_IP_ADDR(src_ip, tuple->src_ip.in.s_addr);
		ECM_NIN4_ADDR_TO_IP_ADDR(dst_ip, tuple->dst_ip.in.s_addr);
	} else if (AF_INET6 == tuple->af) {
		ECM_NIN6_ADDR_TO_IP_ADDR(src_ip, tuple->src_ip.in6);
		ECM_NIN6_ADDR_TO_IP_ADDR(dst_ip, tuple->dst_ip.in6);
	} else {
		return -EAFNOSUPPORT;
	}

	return 0;
}

static void
ecm_classifier_nl_genl_msg_ACCEL_OK(struct ecm_classifier_nl_instance *cnli)
{
	int ret;
	int proto;
	int src_port;
	int dst_port;
	ip_addr_t src_ip;
	ip_addr_t dst_ip;
	struct ecm_cl_nl_genl_attr_tuple tuple;

	spin_lock_bh(&ecm_classifier_nl_lock);

	/* if we've already issued an ACCEL_OK on this connection,
	   do not send it again */
	if (cnli->flags & ECM_CLASSIFIER_NL_F_ACCEL_OK) {
		spin_unlock_bh(&ecm_classifier_nl_lock);
		return;
	}

	cnli->flags |= ECM_CLASSIFIER_NL_F_ACCEL_OK;

	proto = ecm_db_connection_protocol_get(cnli->ci);
	ecm_db_connection_from_address_get(cnli->ci, src_ip);
	src_port = (uint16_t)ecm_db_connection_from_port_get(cnli->ci);
	ecm_db_connection_to_address_get(cnli->ci, dst_ip);
	dst_port = ecm_db_connection_to_port_get(cnli->ci);

	spin_unlock_bh(&ecm_classifier_nl_lock);

	ret = ecm_cl_nl_genl_attr_tuple_encode(&tuple,
					       proto,
					       src_ip,
					       src_port,
					       dst_ip,
					       dst_port);
	if (ret != 0) {
		DEBUG_WARN("failed to encode genl_attr_tuple: %d\n", ret);
		return;
	}

	ecm_classifier_nl_send_genl_msg(ECM_CL_NL_GENL_CMD_ACCEL_OK,
					&tuple);
}

static void
ecm_classifier_nl_genl_msg_CLOSED(struct ecm_classifier_nl_instance *cnli)
{
	int ret;
	int proto;
	int src_port;
	int dst_port;
	ip_addr_t src_ip;
	ip_addr_t dst_ip;
	struct ecm_cl_nl_genl_attr_tuple tuple;

	spin_lock_bh(&ecm_classifier_nl_lock);

	/* if we haven't issued an ACCEL_OK on this connection,
	   we do not need to send a CLOSED event */
	if (!(cnli->flags & ECM_CLASSIFIER_NL_F_ACCEL_OK)) {
		spin_unlock_bh(&ecm_classifier_nl_lock);
		return;
	}

	cnli->flags |= ECM_CLASSIFIER_NL_F_CLOSED;

	proto = ecm_db_connection_protocol_get(cnli->ci);
	ecm_db_connection_from_address_get(cnli->ci, src_ip);
	src_port = (uint16_t)ecm_db_connection_from_port_get(cnli->ci);
	ecm_db_connection_to_address_get(cnli->ci, dst_ip);
	dst_port = ecm_db_connection_to_port_get(cnli->ci);

	spin_unlock_bh(&ecm_classifier_nl_lock);

	ret = ecm_cl_nl_genl_attr_tuple_encode(&tuple,
					       proto,
					       src_ip,
					       src_port,
					       dst_ip,
					       dst_port);
	if (ret != 0) {
		DEBUG_WARN("failed to encode genl_attr_tuple: %d\n", ret);
		return;
	}

	ecm_classifier_nl_send_genl_msg(ECM_CL_NL_GENL_CMD_CONNECTION_CLOSED,
					&tuple);
}

/*
 * ecm_classifier_nl_genl_msg_ACCEL()
 *	handles a ECM_CL_NL_ACCEL message
 */
static int ecm_classifier_nl_genl_msg_ACCEL(struct sk_buff *skb,
					    struct genl_info *info)
{
	int ret;
	struct nlattr *na;
	struct ecm_cl_nl_genl_attr_tuple *tuple;
	struct ecm_db_connection_instance *ci;
	struct ecm_classifier_nl_instance *cnli;

	/* the netlink message comes to us in network order, but ECM
	   stores addresses in host order */
	int proto;
	int src_port;
	int dst_port;
	ip_addr_t src_ip;
	ip_addr_t dst_ip;

	/*
	 * Check if we are enabled
	 */
	spin_lock_bh(&ecm_classifier_nl_lock);
	if (!ecm_classifier_nl_enabled) {
		spin_unlock_bh(&ecm_classifier_nl_lock);
		return -ECONNREFUSED;
	}
	spin_unlock_bh(&ecm_classifier_nl_lock);

	na = info->attrs[ECM_CL_NL_GENL_ATTR_TUPLE];
	tuple = nla_data(na);

	ret = ecm_cl_nl_genl_attr_tuple_decode(tuple,
					       &proto,
					       src_ip,
					       &src_port,
					       dst_ip,
					       &dst_port);
	if (ret != 0) {
		DEBUG_WARN("failed to decode genl_attr_tuple: %d\n", ret);
		return ret;
	}

	/*
	 * Locate the connection using the tuple given
	 */
	DEBUG_TRACE("ACCEL: Lookup connection "
		    ECM_IP_ADDR_OCTAL_FMT ":%d <> "
		    ECM_IP_ADDR_OCTAL_FMT ":%d "
		    "protocol %d\n",
		    ECM_IP_ADDR_TO_OCTAL(src_ip),
		    src_port,
		    ECM_IP_ADDR_TO_OCTAL(dst_ip),
		    dst_port,
		    tuple->proto);
	ci = ecm_db_connection_find_and_ref(src_ip,
					    dst_ip,
					    proto,
					    src_port,
					    dst_port);
	if (!ci) {
		DEBUG_WARN("database connection not found\n");
		return -ENOENT;
	}
	DEBUG_TRACE("Connection found: %p\n", ci);

	/*
	 * Get the NL classifier for this connection
	 */
	cnli = (struct ecm_classifier_nl_instance *)
		ecm_db_connection_assigned_classifier_find_and_ref(ci,
			ECM_CLASSIFIER_TYPE_NL);
	DEBUG_ASSERT(cnli, "NL classifier should never have unassigned\n");
	if (!cnli) {
		ecm_db_connection_deref(ci);
		return -EUNATCH;
	}

	/*
	 * Allow acceleration of the connection.  This will be done as
	 * packets are processed in the usual way.
	 */
	DEBUG_TRACE("Permit accel: %p\n", ci);
	spin_lock_bh(&ecm_classifier_nl_lock);
	cnli->process_response.accel_mode =
		ECM_CLASSIFIER_ACCELERATION_MODE_ACCEL;
	cnli->flags |= ECM_CLASSIFIER_NL_F_ACCEL;
	spin_unlock_bh(&ecm_classifier_nl_lock);

	cnli->base.deref((struct ecm_classifier_instance *)cnli);
	ecm_db_connection_deref(ci);

	return 0;
}


/*
 * ecm_classifier_nl_ref()
 *	Ref
 */
static void ecm_classifier_nl_ref(struct ecm_classifier_instance *ci)
{
	struct ecm_classifier_nl_instance *cnli;
	cnli = (struct ecm_classifier_nl_instance *)ci;

	DEBUG_CHECK_MAGIC(cnli, ECM_CLASSIFIER_NL_INSTANCE_MAGIC, "%p: magic failed\n", cnli);
	spin_lock_bh(&ecm_classifier_nl_lock);
	cnli->refs++;
	DEBUG_TRACE("%p: cnli ref %d\n", cnli, cnli->refs);
	DEBUG_ASSERT(cnli->refs > 0, "%p: ref wrap\n", cnli);
	spin_unlock_bh(&ecm_classifier_nl_lock);
}

/*
 * ecm_classifier_nl_deref()
 *	Deref
 */
static int ecm_classifier_nl_deref(struct ecm_classifier_instance *ci)
{
	struct ecm_classifier_nl_instance *cnli;

	cnli = (struct ecm_classifier_nl_instance *)ci;

	DEBUG_CHECK_MAGIC(cnli, ECM_CLASSIFIER_NL_INSTANCE_MAGIC,
			  "%p: magic failed\n", cnli);

	spin_lock_bh(&ecm_classifier_nl_lock);
	cnli->refs--;
	DEBUG_ASSERT(cnli->refs >= 0, "%p: refs wrapped\n", cnli);
	DEBUG_TRACE("%p: Netlink classifier deref %d\n", cnli, cnli->refs);
	if (cnli->refs) {
		int refs = cnli->refs;
		spin_unlock_bh(&ecm_classifier_nl_lock);
		return refs;
	}

	/*
	 * send a closed event to multicast if we previously issued
	 * an accelerated-ok event.
	 */
	if (cnli->flags & ECM_CLASSIFIER_NL_F_ACCEL_OK) {
		spin_unlock_bh(&ecm_classifier_nl_lock);
		ecm_classifier_nl_genl_msg_CLOSED(cnli);
		spin_lock_bh(&ecm_classifier_nl_lock);
	}

	/*
	 * Object to be destroyed
	 */
	ecm_classifier_nl_count--;
	DEBUG_ASSERT(ecm_classifier_nl_count >= 0, "%p: ecm_classifier_nl_count wrap\n", cnli);

	/*
	 * UnLink the instance from our list
	 */
	if (cnli->next) {
		cnli->next->prev = cnli->prev;
	}
	if (cnli->prev) {
		cnli->prev->next = cnli->next;
	} else {
		DEBUG_ASSERT(ecm_classifier_nl_instances == cnli, "%p: list bad %p\n", cnli, ecm_classifier_nl_instances);
		ecm_classifier_nl_instances = cnli->next;
	}
	cnli->next = NULL;
	cnli->prev = NULL;

	spin_unlock_bh(&ecm_classifier_nl_lock);

	/*
	 * Final
	 */
	DEBUG_INFO("%p: Final Netlink classifier instance\n", cnli);
	kfree(cnli);

	return 0;
}

void
ecm_classifier_nl_process_mark(struct ecm_classifier_nl_instance *cnli,
			       uint32_t mark)
{
	int limit;
	int count;
	bool updated;
	bool can_accel;
	ecm_classifier_acceleration_mode_t accel_mode;
	struct ecm_front_end_connection_instance *feci;

	updated = false;

	spin_lock_bh(&ecm_classifier_nl_lock);
	if (mark != cnli->process_response.qos_tag) {
		cnli->process_response.qos_tag = mark;
		cnli->process_response.process_actions |=
			ECM_CLASSIFIER_PROCESS_ACTION_QOS_TAG;
		updated = true;
	}
	spin_unlock_bh(&ecm_classifier_nl_lock);

	if (updated) {
		/*
		 * we need to make sure to propagate the new mark to the
		 * NSS if the connection has been accelerated.  to do that,
		 * since there's no way to directly update an offload rule,
		 * we simply decelerate the connection which should result
		 * in a re-acceleration when the next packet is processed
		 * by the front end, thereby applying the new mark.
		 */
		feci = ecm_db_connection_front_end_get_and_ref(cnli->ci);
		feci->accel_state_get(feci,
				      &accel_mode,
				      &count,
				      &limit,
				      &can_accel);
		if (accel_mode == ECM_CLASSIFIER_ACCELERATION_MODE_ACCEL) {
			DEBUG_TRACE("%p: mark changed on offloaded connection, decelerate. new mark: 0x%08x\n",
				    cnli, mark);
			feci->decelerate(feci);
		} else {
			DEBUG_TRACE("%p: mark changed on non-offloaded connection. new mark: 0x%08x\n",
				    cnli, mark);
		}
		feci->deref(feci);
	}
}
EXPORT_SYMBOL(ecm_classifier_nl_process_mark);

/*
 * ecm_classifier_nl_process()
 *	Process new data for connection
 */
static void ecm_classifier_nl_process(struct ecm_classifier_instance *aci, ecm_tracker_sender_type_t sender,
						struct ecm_tracker_ip_header *ip_hdr, struct sk_buff *skb,
						struct ecm_classifier_process_response *process_response)
{
	struct ecm_classifier_nl_instance *cnli;
	ecm_classifier_relevence_t relevance;
	bool enabled;
	struct ecm_front_end_connection_instance *feci;
	ecm_classifier_acceleration_mode_t accel_mode;
	int count;
	int limit;
	bool can_accel;
	uint32_t became_relevant = 0;

	cnli = (struct ecm_classifier_nl_instance *)aci;
	DEBUG_CHECK_MAGIC(cnli, ECM_CLASSIFIER_NL_INSTANCE_MAGIC, "%p: magic failed\n", cnli);

	/*
	 * Have we decided our relevance?  If so return our state.
	 */
	spin_lock_bh(&ecm_classifier_nl_lock);
	relevance = cnli->process_response.relevance;
	if (relevance != ECM_CLASSIFIER_RELEVANCE_MAYBE) {
		*process_response = cnli->process_response;
		spin_unlock_bh(&ecm_classifier_nl_lock);
		return;
	}

	/*
	 * Decide upon relevance
	 */
	enabled = ecm_classifier_nl_enabled;
	spin_unlock_bh(&ecm_classifier_nl_lock);

	/*
	 * If classifier is enabled, the connection is routed and the front end says it can accel then we are "relevant".
	 * Any other condition and we are not and will stop analysing this connection.
	 */
	relevance = ECM_CLASSIFIER_RELEVANCE_NO;
	feci = ecm_db_connection_front_end_get_and_ref(cnli->ci);
	feci->accel_state_get(feci, &accel_mode, &count, &limit, &can_accel);
	feci->deref(feci);
	if (enabled && can_accel && ecm_db_connection_is_routed_get(cnli->ci)) {
		relevance = ECM_CLASSIFIER_RELEVANCE_YES;
		became_relevant = ecm_db_time_get();
	}

	/*
	 * Return process response
	 */
	spin_lock_bh(&ecm_classifier_nl_lock);
	cnli->process_response.relevance = relevance;
	cnli->process_response.became_relevant = became_relevant;
	*process_response = cnli->process_response;
	spin_unlock_bh(&ecm_classifier_nl_lock);
}

/*
 * ecm_classifier_nl_sync_to_v4()
 *	Front end is pushing NSS state to us
 */
static void
ecm_classifier_nl_sync_to_v4(struct ecm_classifier_instance *aci,
			     struct nss_ipv4_cb_params *params)
{
	int accel_ok;
	struct nss_ipv4_sync *sync;
	struct ecm_classifier_nl_instance *cnli;

	accel_ok = 0;

	DEBUG_ASSERT(params->reason == NSS_IPV4_CB_REASON_SYNC,
		     "sync_to_v4 callback issued for non-sync reason\n");

	sync = &params->params.sync;

	if (!(sync->flow_tx_packet_count || sync->return_tx_packet_count)) {
		/* nothing to update.  we only care about flows that
		   are actively being accelerated. */
		return;
	}

	cnli = (struct ecm_classifier_nl_instance *)aci;
	DEBUG_CHECK_MAGIC(cnli, ECM_CLASSIFIER_NL_INSTANCE_MAGIC,
			  "%p: magic failed", cnli);

	switch(sync->reason) {
	case NSS_IPV4_SYNC_REASON_FLUSH:
		/* do nothing */
		DEBUG_TRACE("%p: nl_sync_to_v4: SYNC_FLUSH\n", cnli);
		break;
	case NSS_IPV4_SYNC_REASON_EVICT:
		/* do nothing */
		DEBUG_TRACE("%p: nl_sync_to_v4: SYNC_EVICT\n", cnli);
		break;
	case NSS_IPV4_SYNC_REASON_DESTROY:
		DEBUG_TRACE("%p: nl_sync_to_v4: SYNC_DESTROY\n", cnli);
		break;
	case NSS_IPV4_SYNC_REASON_STATS:
		DEBUG_TRACE("%p: nl_sync_to_v4: SYNC_STATS\n", cnli);
		accel_ok = 1;
		break;
	default:
		DEBUG_TRACE("%p: nl_sync_to_v4: unsupported reason\n", cnli);
		break;
	}

	if (accel_ok) {
		ecm_classifier_nl_genl_msg_ACCEL_OK(cnli);
	}
}

/*
 * ecm_classifier_nl_sync_from_v4()
 *	Front end is retrieving NSS state from us
 */
static void ecm_classifier_nl_sync_from_v4(struct ecm_classifier_instance *aci, struct nss_ipv4_create *create)
{
	struct ecm_classifier_nl_instance *cnli;

	cnli = (struct ecm_classifier_nl_instance *)aci;
	DEBUG_CHECK_MAGIC(cnli, ECM_CLASSIFIER_NL_INSTANCE_MAGIC, "%p: magic failed", cnli);
}

/*
 * ecm_classifier_nl_sync_to_v6()
 *	Front end is pushing NSS state to us
 */
static void ecm_classifier_nl_sync_to_v6(struct ecm_classifier_instance *aci, struct nss_ipv6_cb_params *params)
{
	struct ecm_classifier_nl_instance *cnli;

	cnli = (struct ecm_classifier_nl_instance *)aci;
	DEBUG_CHECK_MAGIC(cnli, ECM_CLASSIFIER_NL_INSTANCE_MAGIC, "%p: magic failed", cnli);

}

/*
 * ecm_classifier_nl_sync_from_v6()
 *	Front end is retrieving NSS state from us
 */
static void ecm_classifier_nl_sync_from_v6(struct ecm_classifier_instance *aci, struct nss_ipv6_create *create)
{
	struct ecm_classifier_nl_instance *cnli;

	cnli = (struct ecm_classifier_nl_instance *)aci;
	DEBUG_CHECK_MAGIC(cnli, ECM_CLASSIFIER_NL_INSTANCE_MAGIC, "%p: magic failed", cnli);

}

/*
 * ecm_classifier_nl_type_get()
 *	Get type of classifier this is
 */
static ecm_classifier_type_t ecm_classifier_nl_type_get(struct ecm_classifier_instance *ci)
{
	struct ecm_classifier_nl_instance *cnli;
	cnli = (struct ecm_classifier_nl_instance *)ci;

	DEBUG_CHECK_MAGIC(cnli, ECM_CLASSIFIER_NL_INSTANCE_MAGIC, "%p: magic failed\n", cnli);
	return ECM_CLASSIFIER_TYPE_NL;
}

/*
 * ecm_classifier_nl_last_process_response_get()
 *	Get result code returned by the last process call
 */
static void ecm_classifier_nl_last_process_response_get(struct ecm_classifier_instance *ci,
							struct ecm_classifier_process_response *process_response)
{
	struct ecm_classifier_nl_instance *cnli;

	cnli = (struct ecm_classifier_nl_instance *)ci;
	DEBUG_CHECK_MAGIC(cnli, ECM_CLASSIFIER_NL_INSTANCE_MAGIC, "%p: magic failed\n", cnli);

	spin_lock_bh(&ecm_classifier_nl_lock);
	*process_response = cnli->process_response;
	spin_unlock_bh(&ecm_classifier_nl_lock);
}

/*
 * ecm_classifier_nl_reclassify_allowed()
 *	Indicate if reclassify is allowed
 */
static bool ecm_classifier_nl_reclassify_allowed(struct ecm_classifier_instance *ci)
{
	struct ecm_classifier_nl_instance *cnli;
	cnli = (struct ecm_classifier_nl_instance *)ci;
	DEBUG_CHECK_MAGIC(cnli, ECM_CLASSIFIER_NL_INSTANCE_MAGIC, "%p: magic failed\n", cnli);

	return true;
}

/*
 * ecm_classifier_nl_reclassify()
 *	Reclassify
 */
static void ecm_classifier_nl_reclassify(struct ecm_classifier_instance *ci)
{
	struct ecm_classifier_nl_instance *cnli;
	cnli = (struct ecm_classifier_nl_instance *)ci;
	DEBUG_CHECK_MAGIC(cnli, ECM_CLASSIFIER_NL_INSTANCE_MAGIC, "%p: magic failed\n", cnli);
}

/*
 * ecm_classifier_nl_xml_state_get()
 *	Return an XML state element
 */
static int ecm_classifier_nl_xml_state_get(struct ecm_classifier_instance *ci, char *buf, int buf_sz)
{
	struct ecm_classifier_nl_instance *cnli;
	struct ecm_classifier_process_response process_response;
	int count;
	int total;

	cnli = (struct ecm_classifier_nl_instance *)ci;
	DEBUG_CHECK_MAGIC(cnli, ECM_CLASSIFIER_NL_INSTANCE_MAGIC, "%p: magic failed", cnli);

	spin_lock_bh(&ecm_classifier_nl_lock);
	process_response = cnli->process_response;
	spin_unlock_bh(&ecm_classifier_nl_lock);

	count = snprintf(buf, buf_sz, "<ecm_classifier_nl>\n");
	if ((count <= 0) || (count == buf_sz)) {
		return -1;
	}
	total = count;
	buf_sz -= count;

	/*
	 * Output our last process response
	 */
	count = ecm_classifier_process_response_xml_state_get(buf + total, buf_sz, &process_response);
	if ((count <= 0) || (count == buf_sz)) {
		return -1;
	}
	total += count;
	buf_sz -= count;

	/*
	 * Output our terminal element
	 */
	count = snprintf(buf + total, buf_sz, "</ecm_classifier_nl>\n");
	if ((count <= 0) || (count == buf_sz)) {
		return -1;
	}
	total += count;
	return total;
}

/*
 * ecm_classifier_nl_instance_alloc()
 *	Allocate an instance of the Netlink classifier
 */
struct ecm_classifier_nl_instance *ecm_classifier_nl_instance_alloc(struct ecm_db_connection_instance *ci)
{
	struct ecm_classifier_nl_instance *cnli;

	/*
	 * Allocate the instance
	 */
	cnli = (struct ecm_classifier_nl_instance *)kzalloc(sizeof(struct ecm_classifier_nl_instance), GFP_ATOMIC | __GFP_NOWARN);
	if (!cnli) {
		DEBUG_WARN("Failed to allocate Netlink instance\n");
		return NULL;
	}

	DEBUG_SET_MAGIC(cnli, ECM_CLASSIFIER_NL_INSTANCE_MAGIC);
	cnli->refs = 1;
	cnli->base.process = ecm_classifier_nl_process;
	cnli->base.sync_from_v4 = ecm_classifier_nl_sync_from_v4;
	cnli->base.sync_to_v4 = ecm_classifier_nl_sync_to_v4;
	cnli->base.sync_from_v6 = ecm_classifier_nl_sync_from_v6;
	cnli->base.sync_to_v6 = ecm_classifier_nl_sync_to_v6;
	cnli->base.type_get = ecm_classifier_nl_type_get;
	cnli->base.last_process_response_get = ecm_classifier_nl_last_process_response_get;
	cnli->base.reclassify_allowed = ecm_classifier_nl_reclassify_allowed;
	cnli->base.reclassify = ecm_classifier_nl_reclassify;
	cnli->base.xml_state_get = ecm_classifier_nl_xml_state_get;
	cnli->base.ref = ecm_classifier_nl_ref;
	cnli->base.deref = ecm_classifier_nl_deref;
	cnli->ci = ci;

	/*
	 * Classifier initially denies acceleration.
	 */
	cnli->process_response.qos_tag = 0;
	cnli->process_response.relevance = ECM_CLASSIFIER_RELEVANCE_MAYBE;
	cnli->process_response.process_actions =
		ECM_CLASSIFIER_PROCESS_ACTION_ACCEL_MODE;
	cnli->process_response.accel_mode = ECM_CLASSIFIER_ACCELERATION_MODE_NO;

	spin_lock_bh(&ecm_classifier_nl_lock);

	/*
	 * Final check if we are pending termination
	 */
	if (ecm_classifier_nl_terminate_pending) {
		spin_unlock_bh(&ecm_classifier_nl_lock);
		DEBUG_INFO("%p: Terminating\n", ci);
		kfree(cnli);
		return NULL;
	}

	/*
	 * Link the new instance into our list at the head
	 */
	cnli->next = ecm_classifier_nl_instances;
	if (ecm_classifier_nl_instances) {
		ecm_classifier_nl_instances->prev = cnli;
	}
	ecm_classifier_nl_instances = cnli;

	/*
	 * Increment stats
	 */
	ecm_classifier_nl_count++;
	DEBUG_ASSERT(ecm_classifier_nl_count > 0, "%p: ecm_classifier_nl_count wrap\n", cnli);
	spin_unlock_bh(&ecm_classifier_nl_lock);

	DEBUG_INFO("Netlink instance alloc: %p\n", cnli);
	return cnli;
}
EXPORT_SYMBOL(ecm_classifier_nl_instance_alloc);

/*
 * ecm_classifier_nl_set_set_command()
 *	Set Netlink command to accel/decel connection.
 */
static ssize_t ecm_classifier_nl_set_command(struct sys_device *dev,
							  struct sysdev_attribute *attr,
							  const char *buf, size_t count)
{
#define ECM_CLASSIFIER_NL_SET_IP_COMMAND_FIELDS 7
	char *cmd_buf;
	int field_count;
	char *field_ptr;
	char *fields[ECM_CLASSIFIER_NL_SET_IP_COMMAND_FIELDS];
	char cmd;
	uint32_t serial;
	ip_addr_t src_ip;
	uint32_t src_port;
	int proto;
	ip_addr_t dest_ip;
	uint32_t dest_port;
	struct ecm_db_connection_instance *ci;
	struct ecm_classifier_nl_instance *cnli;
	struct ecm_front_end_connection_instance *feci;

	/*
	 * Check if we are enabled
	 */
	spin_lock_bh(&ecm_classifier_nl_lock);
	if (!ecm_classifier_nl_enabled) {
		spin_unlock_bh(&ecm_classifier_nl_lock);
		return 0;
	}
	spin_unlock_bh(&ecm_classifier_nl_lock);

	/*
	 * buf is formed as:
	 * [0]   [1]      [2]      [3]        [4]     [5]       [6]
	 * <CMD>/<SERIAL>/<src_ip>/<src_port>/<proto>/<dest_ip>/<dest_port>
	 * CMD:
	 *	F = Accelerate based on IP address, <SERIAL> unused
	 *	f = Decelerate based on IP address, <SERIAL> unused
	 *	S = Accelerate based on serial, <SERIAL> only becomes relevant
	 *	s = Decelerate based on serial, <SERIAL> only becomes relevant
	 */
	cmd_buf = (char *)kzalloc(count + 1, GFP_ATOMIC);
	if (!cmd_buf) {
		return 0;
	}
	memcpy(cmd_buf, buf, count);

	/*
	 * Split the buffer into its fields
	 */
	field_count = 0;
	field_ptr = cmd_buf;
	fields[field_count] = strsep(&field_ptr, "/");
	while (fields[field_count] != NULL) {
		DEBUG_TRACE("FIELD %d: %s\n", field_count, fields[field_count]);
		field_count++;
		if (field_count == ECM_CLASSIFIER_NL_SET_IP_COMMAND_FIELDS) {
			break;
		}
		fields[field_count] = strsep(&field_ptr, "/");
	}

	if (field_count != ECM_CLASSIFIER_NL_SET_IP_COMMAND_FIELDS) {
		DEBUG_WARN("invalid field count %d\n", field_count);
		kfree(cmd_buf);
		return 0;
	}

	sscanf(fields[0], "%c", &cmd);
	sscanf(fields[1], "%u", &serial);
	ecm_string_to_ip_addr(src_ip, fields[2]);
	sscanf(fields[3], "%u", &src_port);
	sscanf(fields[4], "%d", &proto);
	ecm_string_to_ip_addr(dest_ip, fields[5]);
	sscanf(fields[6], "%u", &dest_port);

	kfree(cmd_buf);

	/*
	 * Locate the connection using the serial or tuple given
	 */
	switch (cmd) {
	case 'F':
	case 'f':
		DEBUG_TRACE("Lookup connection " ECM_IP_ADDR_OCTAL_FMT ":%d <> " ECM_IP_ADDR_OCTAL_FMT ":%d protocol %d\n",
				ECM_IP_ADDR_TO_OCTAL(src_ip), src_port, ECM_IP_ADDR_TO_OCTAL(dest_ip), dest_port, proto);
		ci = ecm_db_connection_find_and_ref(src_ip, dest_ip, proto, src_port, dest_port);
		break;
	case 'S':
	case 's':
		DEBUG_TRACE("Lookup connection using serial: %u\n", serial);
		ci = ecm_db_connection_serial_find_and_ref(serial);
		break;
	default:
		DEBUG_WARN("invalid cmd %c\n", cmd);
		return 0;
	}

	if (!ci) {
		DEBUG_WARN("database connection not found\n");
		return 0;
	}
	DEBUG_TRACE("Connection found: %p\n", ci);

	/*
	 * Get the NL classifier
	 */
	cnli = (struct ecm_classifier_nl_instance *)ecm_db_connection_assigned_classifier_find_and_ref(ci, ECM_CLASSIFIER_TYPE_NL);
	DEBUG_ASSERT(cnli, "NL classifier should never have unassigned\n");

	/*
	 * Now action the command
	 */
	switch (cmd) {
	case 's':
	case 'f':
		/*
		 * Decelerate the connection, NL is denying further accel until it says so.
		 */
		DEBUG_TRACE("Force decel: %p\n", ci);
		spin_lock_bh(&ecm_classifier_nl_lock);
		cnli->process_response.accel_mode = ECM_CLASSIFIER_ACCELERATION_MODE_NO;
		spin_unlock_bh(&ecm_classifier_nl_lock);
		feci = ecm_db_connection_front_end_get_and_ref(ci);
		feci->decelerate(feci);
		feci->deref(feci);
		break;
	case 'S':
	case 'F':
		/*
		 * Allow acceleration of the connection.  This will be done as packets are processed in the usual way.
		 */
		DEBUG_TRACE("Permit accel: %p\n", ci);
		spin_lock_bh(&ecm_classifier_nl_lock);
		cnli->process_response.accel_mode = ECM_CLASSIFIER_ACCELERATION_MODE_ACCEL;
		cnli->flags |= ECM_CLASSIFIER_NL_F_ACCEL;
		spin_unlock_bh(&ecm_classifier_nl_lock);
		break;
	}

	cnli->base.deref((struct ecm_classifier_instance *)cnli);
	ecm_db_connection_deref(ci);

	return count;
}

/*
 * ecm_classifier_nl_rule_get_enabled()
 */
static ssize_t ecm_classifier_nl_rule_get_enabled(struct sys_device *dev,
				  struct sysdev_attribute *attr,
				  char *buf)
{
	ssize_t count;
	int num;

	/*
	 * Operate under our locks
	 */
	DEBUG_TRACE("get enabled\n");
	spin_lock_bh(&ecm_classifier_nl_lock);
	num = ecm_classifier_nl_enabled;
	spin_unlock_bh(&ecm_classifier_nl_lock);

	count = snprintf(buf, (ssize_t)PAGE_SIZE, "%d\n", num);
	return count;
}

/*
 * ecm_classifier_nl_rule_set_enabled()
 */
static ssize_t ecm_classifier_nl_rule_set_enabled(struct sys_device *dev,
				  struct sysdev_attribute *attr,
				  const char *buf, size_t count)
{
	char num_buf[12];
	int num;

	/*
	 * Get the number from buf into a properly z-termed number buffer
	 */
	if (count > 11) return 0;
	memcpy(num_buf, buf, count);
	num_buf[count] = '\0';
	sscanf(num_buf, "%d", &num);
	DEBUG_TRACE("ecm_classifier_nl_enabled = %d\n", num);

	/*
	 * Operate under our locks
	 */
	spin_lock_bh(&ecm_classifier_nl_lock);
	ecm_classifier_nl_enabled = num;
	spin_unlock_bh(&ecm_classifier_nl_lock);

	return count;
}

/*
 * SysFS attributes for the user_rule classifier itself.
 */
static SYSDEV_ATTR(enabled, 0644, ecm_classifier_nl_rule_get_enabled, ecm_classifier_nl_rule_set_enabled);
static SYSDEV_ATTR(cmd, 0200, NULL, ecm_classifier_nl_set_command);

/*
 * SysFS class of the ubicom user_rule classifier
 * SysFS control points can be found at /sys/devices/system/ecm_classifier_nl/ecm_classifier_nlX/
 */
static struct sysdev_class ecm_classifier_nl_sysclass = {
	.name = "ecm_classifier_nl",
};

/*
 * Generic Netlink attr checking policies
 */
static struct nla_policy
ecm_cl_nl_genl_policy[ECM_CL_NL_GENL_ATTR_COUNT] = {
	[ECM_CL_NL_GENL_ATTR_TUPLE] = {
		.type = NLA_UNSPEC,
		.len = sizeof(struct ecm_cl_nl_genl_attr_tuple), },
};

/*
 * Generic Netlink message-to-handler mapping
 */
static struct genl_ops ecm_cl_nl_genl_ops[] = {
	{
		.cmd = ECM_CL_NL_GENL_CMD_ACCEL,
		.flags = 0,
		.policy = ecm_cl_nl_genl_policy,
		.doit = ecm_classifier_nl_genl_msg_ACCEL,
		.dumpit = NULL,
	},
	{
		.cmd = ECM_CL_NL_GENL_CMD_ACCEL_OK,
		.flags = 0,
		.policy = ecm_cl_nl_genl_policy,
		.doit = NULL,
		.dumpit = NULL,
	},
	{
		.cmd = ECM_CL_NL_GENL_CMD_CONNECTION_CLOSED,
		.flags = 0,
		.policy = ecm_cl_nl_genl_policy,
		.doit = NULL,
		.dumpit = NULL,
	},
};

static int ecm_classifier_nl_register_genl(void)
{
	int result;

	result = genl_register_family(&ecm_cl_nl_genl_family);
	if (result != 0) {
		DEBUG_ERROR("failed to register genl family: %d\n", result);
		goto err1;
	}

	result = genl_register_ops(&ecm_cl_nl_genl_family,
				   ecm_cl_nl_genl_ops);
	if (result != 0) {
		DEBUG_ERROR("failed to register genl ops: %d\n", result);
		goto err2;
	}

	result = genl_register_mc_group(&ecm_cl_nl_genl_family,
					&ecm_cl_nl_genl_mcgrp);
	if (result != 0) {
		DEBUG_ERROR("failed to register genl multicast group: %d\n",
			    result);
		goto err3;
	}

	return 0;

err3:
	genl_unregister_ops(&ecm_cl_nl_genl_family, ecm_cl_nl_genl_ops);
err2:
	genl_unregister_family(&ecm_cl_nl_genl_family);
err1:
	return result;
}

static void ecm_classifier_nl_unregister_genl(void)
{
	genl_unregister_ops(&ecm_cl_nl_genl_family, ecm_cl_nl_genl_ops);
	genl_unregister_family(&ecm_cl_nl_genl_family);
}

/*
 * ecm_classifier_nl_rules_init()
 */
int ecm_classifier_nl_rules_init(void)
{
	int result;
	DEBUG_INFO("Netlink classifier Module init\n");

	/*
	 * Initialise our global lock
	 */
	spin_lock_init(&ecm_classifier_nl_lock);

	/*
	 * Register the sysfs class
	 */
	result = sysdev_class_register(&ecm_classifier_nl_sysclass);
	if (result) {
		DEBUG_WARN("Failed to register SysFS class\n");
		return result;
	}

	/*
	 * Register SYSFS device control
	 */
	memset(&ecm_classifier_nl_sys_dev, 0, sizeof(ecm_classifier_nl_sys_dev));
	ecm_classifier_nl_sys_dev.id = 0;
	ecm_classifier_nl_sys_dev.cls = &ecm_classifier_nl_sysclass;
	result = sysdev_register(&ecm_classifier_nl_sys_dev);
	if (result) {
		DEBUG_WARN("Failed to register SysFS device\n");
		goto classifier_task_cleanup_1;
	}

	result = sysdev_create_file(&ecm_classifier_nl_sys_dev, &attr_enabled);
	if (result) {
		DEBUG_TRACE("Failed to register enabled SysFS file\n");
		goto classifier_task_cleanup_2;
	}

	result = sysdev_create_file(&ecm_classifier_nl_sys_dev, &attr_cmd);
	if (result) {
		DEBUG_TRACE("Failed to register cmd SysFS file\n");
		goto classifier_task_cleanup_2;
	}

	result = ecm_classifier_nl_register_genl();
	if (result) {
		DEBUG_TRACE("Failed to register genl sockets\n");
		goto classifier_task_cleanup_2;
	}

	return 0;

classifier_task_cleanup_2:
	sysdev_unregister(&ecm_classifier_nl_sys_dev);
classifier_task_cleanup_1:
	sysdev_class_unregister(&ecm_classifier_nl_sysclass);

	return result;

}
EXPORT_SYMBOL(ecm_classifier_nl_rules_init);

/*
 * ecm_classifier_nl_rules_exit()
 */
void ecm_classifier_nl_rules_exit(void)
{
	DEBUG_INFO("Netlink classifier Module exit\n");

	spin_lock_bh(&ecm_classifier_nl_lock);
	ecm_classifier_nl_terminate_pending = true;
	spin_unlock_bh(&ecm_classifier_nl_lock);

	ecm_classifier_nl_unregister_genl();
	sysdev_unregister(&ecm_classifier_nl_sys_dev);
	sysdev_class_unregister(&ecm_classifier_nl_sysclass);
}
EXPORT_SYMBOL(ecm_classifier_nl_rules_exit);
