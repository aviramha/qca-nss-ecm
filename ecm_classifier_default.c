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
#include <linux/ctype.h>
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

/*
 * Debug output levels
 * 0 = OFF
 * 1 = ASSERTS / ERRORS
 * 2 = 1 + WARN
 * 3 = 2 + INFO
 * 4 = 3 + TRACE
 */
#define DEBUG_LEVEL ECM_CLASSIFIER_DEFAULT_DEBUG_LEVEL

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

/*
 * Magic numbers
 */
#define ECM_CLASSIFIER_DEFAULT_INTERNAL_INSTANCE_MAGIC 0x8761
#define ECM_CLASSIFIER_DEFAULT_STATE_FILE_INSTANCE_MAGIC 0x3321

/*
 * struct ecm_classifier_default_internal_instance
 * 	State to allow tracking of dynamic priority for a connection
 */
struct ecm_classifier_default_internal_instance {
	struct ecm_classifier_default_instance base;		/* Base type */

	struct ecm_db_connection_instance *ci;			/* RO: Connection pointer, note that this is a copy of the connection pointer not a ref to it as this instance is ref'd by the connection itself. */
	uint32_t serial;					/* RO: Linkage to the connection the cdii is associated with. */
	
	struct ecm_classifier_process_response process_response;
								/* Last process response computed */

	ecm_db_timer_group_t timer_group;			/* The timer group the connection should be in based on state */

	ecm_tracker_sender_type_t ingress_sender;		/* RO: Which sender is sending ingress data */
	ecm_tracker_sender_type_t egress_sender;		/* RO: Which sender is sending egress data */

	struct ecm_tracker_instance *ti;			/* RO: Tracker used while we detect MSS. Pointer will not change so safe to access outside of lock. */
	bool tracking;						/* Are we tracking? */

	int refs;						/* Integer to trap we never go negative */
#if (DEBUG_LEVEL > 0)
	uint16_t magic;
#endif
};

static spinlock_t ecm_classifier_default_lock;			/* Concurrency control SMP access */
static int ecm_classifier_default_count = 0;			/* Tracks number of instances allocated */

/*
 * Operational control
 */
static ecm_classifier_acceleration_mode_t ecm_classifier_default_accel_mode = ECM_CLASSIFIER_ACCELERATION_MODE_ACCEL;
								/* Cause connections whose hosts are both on-link to be accelerated */
static bool ecm_classifier_default_enabled = true;		/* When disabled the qos algorithm will not be applied to skb's */

/*
 * Management thread control
 */
static bool ecm_classifier_default_terminate_pending = false;	/* True when the user wants us to terminate */
static int ecm_classifier_default_thread_refs = 0;		/* Signal to tell the control thread to terminate */
static struct task_struct *ecm_classifier_default_thread = NULL;
								/* Control thread */

/*
 * Character device stuff - used to communicate status back to user space
 */
#define ECM_CLASSIFIER_DEFAULT_STATE_FILE_BUFFER_SIZE 1024
struct ecm_classifier_default_state_file_instance {
	struct ecm_classifier_default_internal_instance *cdii;
	bool doc_start_written;
	bool doc_end_written;
	char msg_buffer[ECM_CLASSIFIER_DEFAULT_STATE_FILE_BUFFER_SIZE];	/* Used to hold the current state message being output */
	char *msgp;							/* Points into the msg buffer as we output it piece by piece */
	int msg_len;							/* Length of the buffer still to be written out */
#if (DEBUG_LEVEL > 0)
	uint16_t magic;
#endif
};
static struct sys_device ecm_classifier_default_sys_dev;		/* SysFS linkage */

/*
 * _ecm_classifier_default_ref()
 *	Ref
 */
static void _ecm_classifier_default_ref(struct ecm_classifier_default_internal_instance *cdii)
{
	cdii->refs++;
	DEBUG_TRACE("%p: cdii ref %d\n", cdii, cdii->refs);
	DEBUG_ASSERT(cdii->refs > 0, "%p: ref wrap\n", cdii);
}

/*
 * ecm_classifier_default_ref()
 *	Ref
 */
static void ecm_classifier_default_ref(struct ecm_classifier_instance *ci)
{
	struct ecm_classifier_default_internal_instance *cdii;
	cdii = (struct ecm_classifier_default_internal_instance *)ci;

	DEBUG_CHECK_MAGIC(cdii, ECM_CLASSIFIER_DEFAULT_INTERNAL_INSTANCE_MAGIC, "%p: magic failed", cdii);
	spin_lock_bh(&ecm_classifier_default_lock);
	_ecm_classifier_default_ref(cdii);
	spin_unlock_bh(&ecm_classifier_default_lock);
}

/*
 * ecm_classifier_default_deref()
 *	Deref
 */
static int ecm_classifier_default_deref(struct ecm_classifier_instance *ci)
{
	struct ecm_classifier_default_internal_instance *cdii;
	cdii = (struct ecm_classifier_default_internal_instance *)ci;

	DEBUG_CHECK_MAGIC(cdii, ECM_CLASSIFIER_DEFAULT_INTERNAL_INSTANCE_MAGIC, "%p: magic failed", cdii);
	spin_lock_bh(&ecm_classifier_default_lock);
	cdii->refs--;
	DEBUG_ASSERT(cdii->refs >= 0, "%p: refs wrapped\n", cdii);
	DEBUG_TRACE("%p: Default classifier deref %d\n", cdii, cdii->refs);
	if (cdii->refs) {
		int refs = cdii->refs;
		spin_unlock_bh(&ecm_classifier_default_lock);
		return refs;
	}

	/*
	 * Object to be destroyed
	 */
	ecm_classifier_default_count--;
	DEBUG_ASSERT(ecm_classifier_default_count >= 0, "%p: ecm_classifier_default_count wrap\n", cdii);

	/*
	 * Release ref to thread
	 */
	ecm_classifier_default_thread_refs--;
	DEBUG_ASSERT(ecm_classifier_default_thread_refs >= 0, "Thread refs wrap %d\n", ecm_classifier_default_thread_refs);
	spin_unlock_bh(&ecm_classifier_default_lock);

	/*
	 * Release our tracker
	 */
	cdii->ti->deref(cdii->ti);

	/*
	 * Final
	 */
	DEBUG_INFO("%p: Final default classifier instance\n", cdii);
	kfree(cdii);
	wake_up_process(ecm_classifier_default_thread);

	return 0;
}

/*
 * ecm_classifier_default_process_callback()
 *	Process new data updating the priority
 *
 * NOTE: This function would only ever be called if all other classifiers have failed.
 */
static void ecm_classifier_default_process(struct ecm_classifier_instance *aci, ecm_tracker_sender_type_t sender,
									struct ecm_tracker_ip_header *ip_hdr, struct sk_buff *skb,
									struct ecm_classifier_process_response *process_response)
{
	struct ecm_tracker_instance *ti;
	ecm_tracker_sender_state_t from_state;
	ecm_tracker_sender_state_t to_state;
	ecm_tracker_connection_state_t prevailing_state;
	ecm_db_timer_group_t tg;
	struct ecm_tracker_tcp_instance *tti;
	bool tracking;
	struct ecm_classifier_default_internal_instance *cdii = (struct ecm_classifier_default_internal_instance *)aci;
	DEBUG_CHECK_MAGIC(cdii, ECM_CLASSIFIER_DEFAULT_INTERNAL_INSTANCE_MAGIC, "%p: invalid state magic\n", cdii);

	spin_lock_bh(&ecm_classifier_default_lock);

	/*
	 * Get qos result and accel mode
	 * Default classifier is rarely disabled.
	 */
	if (unlikely(!ecm_classifier_default_enabled)) {
		/*
		 * Still relevant but have no actions that need processing
		 */
		cdii->process_response.process_actions = 0;
		*process_response = cdii->process_response;
		spin_unlock_bh(&ecm_classifier_default_lock);
		return;
	}

	/*
	 * Accel?
	 */
	if (ecm_classifier_default_accel_mode != ECM_CLASSIFIER_ACCELERATION_MODE_DONT_CARE) {
		cdii->process_response.accel_mode = ecm_classifier_default_accel_mode;
		cdii->process_response.process_actions |= ECM_CLASSIFIER_PROCESS_ACTION_ACCEL_MODE;
	} else {
		cdii->process_response.process_actions &= ~ECM_CLASSIFIER_PROCESS_ACTION_ACCEL_MODE;
	}

	/*
	 * Compute the timer group this connection should be in.
	 * For this we need the tracker and the state to be updated.
	 * NOTE: Tracker does not need to be ref'd it will exist for as long as this default classifier instance does
	 * which is at least for the duration of this call.
	 */
	ti = cdii->ti;
	spin_unlock_bh(&ecm_classifier_default_lock);
	ti->state_update(ti, sender, ip_hdr, skb);
	ti->state_get(ti, &from_state, &to_state, &prevailing_state, &tg);
	spin_lock_bh(&ecm_classifier_default_lock);
	if (unlikely(cdii->timer_group != tg)) {
		/*
		 * Timer group has changed
		 */
		cdii->process_response.process_actions |= ECM_CLASSIFIER_PROCESS_ACTION_TIMER_GROUP;
		cdii->process_response.timer_group = tg;

		/*
		 * Record for future change comparisons
		 */
		cdii->timer_group = tg;
	}
	spin_unlock_bh(&ecm_classifier_default_lock);

	/*
	 * Handle non-TCP case
	 */
	if (ecm_db_connection_protocol_get(cdii->ci) != IPPROTO_TCP) {
		goto return_response;
	}

	/*
	 * Until the connection is established we track data, only to detect mss
	 */
	spin_lock_bh(&ecm_classifier_default_lock);
	tracking = cdii->tracking;
	spin_unlock_bh(&ecm_classifier_default_lock);
	if (tracking) {
		if (!ti->datagram_add(ti, sender, skb)) {
			spin_lock_bh(&ecm_classifier_default_lock);
			cdii->tracking = false;
			spin_unlock_bh(&ecm_classifier_default_lock);
		} else {
			/*
			 * Discard as we don't actually need it, we just wanted the tracker to detect MSS
			 */
			ti->discard_all(ti);
		}
	}

	/*
	 * TCP requires special handling due to MSS
	 */
	if (unlikely(prevailing_state != ECM_TRACKER_CONNECTION_STATE_ESTABLISHED)) {
		goto return_response;
	}

	/*
	 * Once established a TCP connection should have seen its MSS, there is no point in tracking further anyway
	 */
	spin_lock_bh(&ecm_classifier_default_lock);
	cdii->tracking = false;
	spin_unlock_bh(&ecm_classifier_default_lock);

	/*
	 * By implication the tracker is a TCP tracker
	 */
	tti = (struct ecm_tracker_tcp_instance *)ti;

return_response:
	;

	/*
	 * Return the process response
	 */
	spin_lock_bh(&ecm_classifier_default_lock);
	*process_response = cdii->process_response;
	spin_unlock_bh(&ecm_classifier_default_lock);
}

/*
 * ecm_classifier_default_type_get()
 *	Get type of classifier this is
 */
static ecm_classifier_type_t ecm_classifier_default_type_get(struct ecm_classifier_instance *aci)
{
	struct ecm_classifier_default_internal_instance *cdii;
	cdii = (struct ecm_classifier_default_internal_instance *)aci;

	DEBUG_CHECK_MAGIC(cdii, ECM_CLASSIFIER_DEFAULT_INTERNAL_INSTANCE_MAGIC, "%p: magic failed", cdii);
	return ECM_CLASSIFIER_TYPE_DEFAULT;
}

/*
 * ecm_classifier_default_reclassify_allowed()
 *	Get whether reclassification is allowed
 */
static bool ecm_classifier_default_reclassify_allowed(struct ecm_classifier_instance *aci)
{
	struct ecm_classifier_default_internal_instance *cdii;
	cdii = (struct ecm_classifier_default_internal_instance *)aci;

	DEBUG_CHECK_MAGIC(cdii, ECM_CLASSIFIER_DEFAULT_INTERNAL_INSTANCE_MAGIC, "%p: magic failed", cdii);
	return true;
}

/*
 * ecm_classifier_default_reclassify()
 *	Reclassify
 */
static void ecm_classifier_default_reclassify(struct ecm_classifier_instance *aci)
{
	struct ecm_classifier_default_internal_instance *cdii;
	cdii = (struct ecm_classifier_default_internal_instance *)aci;
	DEBUG_CHECK_MAGIC(cdii, ECM_CLASSIFIER_DEFAULT_INTERNAL_INSTANCE_MAGIC, "%p: magic failed", cdii);
}

/*
 * ecm_classifier_default_last_process_response_get()
 *	Get result code returned by the last process call
 */
static void ecm_classifier_default_last_process_response_get(struct ecm_classifier_instance *aci,
							struct ecm_classifier_process_response *process_response)
{
	struct ecm_classifier_default_internal_instance *cdii;
	cdii = (struct ecm_classifier_default_internal_instance *)aci;
	DEBUG_CHECK_MAGIC(cdii, ECM_CLASSIFIER_DEFAULT_INTERNAL_INSTANCE_MAGIC, "%p: magic failed", cdii);

	spin_lock_bh(&ecm_classifier_default_lock);
	*process_response = cdii->process_response;
	spin_unlock_bh(&ecm_classifier_default_lock);
}

/*
 * ecm_classifier_default_sync_to_v4()
 *	Front end is pushing NSS state to us
 */
static void ecm_classifier_default_sync_to_v4(struct ecm_classifier_instance *aci, struct nss_ipv4_cb_params *params)
{
	struct ecm_classifier_default_internal_instance *cdii __attribute__((unused));

	cdii = (struct ecm_classifier_default_internal_instance *)aci;
	DEBUG_CHECK_MAGIC(cdii, ECM_CLASSIFIER_DEFAULT_INTERNAL_INSTANCE_MAGIC, "%p: magic failed", cdii);
}

/*
 * ecm_classifier_default_sync_from_v4()
 *	Front end is retrieving NSS state from us
 */
static void ecm_classifier_default_sync_from_v4(struct ecm_classifier_instance *aci, struct nss_ipv4_create *create)
{
	struct ecm_classifier_default_internal_instance *cdii __attribute__((unused));

	cdii = (struct ecm_classifier_default_internal_instance *)aci;
	DEBUG_CHECK_MAGIC(cdii, ECM_CLASSIFIER_DEFAULT_INTERNAL_INSTANCE_MAGIC, "%p: magic failed", cdii);
}

/*
 * ecm_classifier_default_sync_to_v6()
 *	Front end is pushing NSS state to us
 */
static void ecm_classifier_default_sync_to_v6(struct ecm_classifier_instance *aci, struct nss_ipv6_cb_params *params)
{
	struct ecm_classifier_default_internal_instance *cdii __attribute__((unused));

	cdii = (struct ecm_classifier_default_internal_instance *)aci;
	DEBUG_CHECK_MAGIC(cdii, ECM_CLASSIFIER_DEFAULT_INTERNAL_INSTANCE_MAGIC, "%p: magic failed", cdii);
}

/*
 * ecm_classifier_default_sync_from_v6()
 *	Front end is retrieving NSS state from us
 */
static void ecm_classifier_default_sync_from_v6(struct ecm_classifier_instance *aci, struct nss_ipv6_create *create)
{
	struct ecm_classifier_default_internal_instance *cdii __attribute__((unused));

	cdii = (struct ecm_classifier_default_internal_instance *)aci;
	DEBUG_CHECK_MAGIC(cdii, ECM_CLASSIFIER_DEFAULT_INTERNAL_INSTANCE_MAGIC, "%p: magic failed", cdii);
}

/*
 * ecm_classifier_tracker_get_and_ref()
 *	Obtain default classifiers tracker (usually for state tracking for the connection as it always exists for the connection)
 */
static struct ecm_tracker_instance *ecm_classifier_tracker_get_and_ref(struct ecm_classifier_default_instance *dci)
{
	struct ecm_classifier_default_internal_instance *cdii;
	struct ecm_tracker_instance *ti;

	cdii = (struct ecm_classifier_default_internal_instance *)dci;
	DEBUG_CHECK_MAGIC(cdii, ECM_CLASSIFIER_DEFAULT_INTERNAL_INSTANCE_MAGIC, "%p: magic failed", cdii);

	ti = cdii->ti;
	ti->ref(ti);
	return ti;
}

/*
 * ecm_classifier_default_xml_state_get()
 *	Return an XML state element
 */
static int ecm_classifier_default_xml_state_get(struct ecm_classifier_instance *ci, char *buf, int buf_sz)
{
	struct ecm_classifier_default_internal_instance *cdii;
	struct ecm_classifier_process_response process_response;
	ecm_db_timer_group_t timer_group;
	ecm_tracker_sender_type_t ingress_sender;
	ecm_tracker_sender_type_t egress_sender;
	bool tracking;
	int count;
	int total;

	cdii = (struct ecm_classifier_default_internal_instance *)ci;
	DEBUG_CHECK_MAGIC(cdii, ECM_CLASSIFIER_DEFAULT_INTERNAL_INSTANCE_MAGIC, "%p: magic failed", cdii);

	spin_lock_bh(&ecm_classifier_default_lock);
	tracking = cdii->tracking;
	egress_sender = cdii->egress_sender;
	ingress_sender = cdii->ingress_sender;
	timer_group = cdii->timer_group;
	process_response = cdii->process_response;
	spin_unlock_bh(&ecm_classifier_default_lock);

	count = snprintf(buf, buf_sz, "<ecm_classifier_default ingress_sender=\"%d\" egress_sender=\"%d\" "
			"timer_group=\"%d\" tracking=\"%u\">\n",
			ingress_sender,
			egress_sender,
			timer_group,
			tracking);
	if ((count <= 0) || (count >= buf_sz)) {
		return -1;
	}
	total = count;
	buf_sz -= count;

	/*
	 * Output our last process response
	 */
	count = ecm_classifier_process_response_xml_state_get(buf + total, buf_sz, &process_response);
	if ((count <= 0) || (count >= buf_sz)) {
		return -1;
	}
	total += count;
	buf_sz -= count;

	/*
	 * Output our tracker state
	 */
	count = cdii->ti->xml_state_get(cdii->ti, buf + total, buf_sz);
	if ((count <= 0) || (count >= buf_sz)) {
		return -1;
	}
	total += count;
	buf_sz -= count;

	/*
	 * Output our terminal element
	 */
	count = snprintf(buf + total, buf_sz, "</ecm_classifier_default>\n");
	if ((count <= 0) || (count >= buf_sz)) {
		return -1;
	}
	total += count;
	return total;
}

/*
 * ecm_classifier_default_instance_alloc()
 *	Allocate an instance of the default classifier
 */
struct ecm_classifier_default_instance *ecm_classifier_default_instance_alloc(struct ecm_db_connection_instance *ci, int protocol, ecm_db_direction_t dir, int from_port, int to_port)
{
	struct ecm_classifier_default_internal_instance *cdii;
	struct ecm_classifier_default_instance *cdi;

	/*
	 * Allocate the instance
	 */
	cdii = (struct ecm_classifier_default_internal_instance *)kzalloc(sizeof(struct ecm_classifier_default_internal_instance), GFP_ATOMIC | __GFP_NOWARN);
	if (!cdii) {
		DEBUG_WARN("Failed to allocate default instance\n");
		return NULL;
	}

	/*
	 * Allocate a tracker for state etc.
	 */
	if (protocol == IPPROTO_TCP) {
		DEBUG_TRACE("%p: Alloc tracker for TCP connection: %p\n", cdii, ci);
		cdii->ti = (struct ecm_tracker_instance *)ecm_tracker_tcp_alloc();
		if (!cdii->ti) {
			DEBUG_WARN("%p: Failed to alloc tracker\n", cdii);
			kfree(cdii);
			return NULL;
		}
		ecm_tracker_tcp_init((struct ecm_tracker_tcp_instance *)cdii->ti, ECM_TRACKER_CONNECTION_TRACKING_LIMIT_DEFAULT, 1500, 1500);
		cdii->tracking = true;
	} else if (protocol == IPPROTO_UDP) {
		DEBUG_TRACE("%p: Alloc tracker for UDP connection: %p\n", cdii, ci);
		cdii->ti = (struct ecm_tracker_instance *)ecm_tracker_udp_alloc();
		if (!cdii->ti) {
			DEBUG_WARN("%p: Failed to alloc tracker\n", cdii);
			kfree(cdii);
			return NULL;
		}
		ecm_tracker_udp_init((struct ecm_tracker_udp_instance *)cdii->ti, ECM_TRACKER_CONNECTION_TRACKING_LIMIT_DEFAULT, from_port, to_port);
	} else {
		DEBUG_TRACE("%p: Alloc tracker for non-ported connection: %p\n", cdii, ci);
		cdii->ti = (struct ecm_tracker_instance *)ecm_tracker_datagram_alloc();
		if (!cdii->ti) {
			DEBUG_WARN("%p: Failed to alloc tracker\n", cdii);
			kfree(cdii);
			return NULL;
		}
		ecm_tracker_datagram_init((struct ecm_tracker_datagram_instance *)cdii->ti, ECM_TRACKER_CONNECTION_TRACKING_LIMIT_DEFAULT);
	}

	DEBUG_SET_MAGIC(cdii, ECM_CLASSIFIER_DEFAULT_INTERNAL_INSTANCE_MAGIC);
	cdii->refs = 1;
	cdii->ci = ci;
	cdii->serial = ecm_db_connection_serial_get(ci);

	/*
	 * We are always relevant to the connection
	 */
	cdii->process_response.relevance = ECM_CLASSIFIER_RELEVANCE_YES;

	/*
	 * Using the connection direction identify egress and ingress host addresses
	 */
	if (dir == ECM_DB_DIRECTION_INGRESS) {
		cdii->ingress_sender = ECM_TRACKER_SENDER_TYPE_SRC;
		cdii->egress_sender = ECM_TRACKER_SENDER_TYPE_DEST;
	} else {
		cdii->egress_sender = ECM_TRACKER_SENDER_TYPE_SRC;
		cdii->ingress_sender = ECM_TRACKER_SENDER_TYPE_DEST;
	}
	DEBUG_TRACE("%p: Ingress sender = %d egress sender = %d\n", cdii, cdii->ingress_sender, cdii->egress_sender);

	/*
	 * Methods specific to the default classifier
	 */
	cdi = (struct ecm_classifier_default_instance *)cdii;
	cdi->tracker_get_and_ref = ecm_classifier_tracker_get_and_ref;

	/*
	 * Methods generic to all classifiers.
	 */
	cdi->base.process = ecm_classifier_default_process;
	cdi->base.sync_from_v4 = ecm_classifier_default_sync_from_v4;
	cdi->base.sync_to_v4 = ecm_classifier_default_sync_to_v4;
	cdi->base.sync_from_v6 = ecm_classifier_default_sync_from_v6;
	cdi->base.sync_to_v6 = ecm_classifier_default_sync_to_v6;
	cdi->base.type_get = ecm_classifier_default_type_get;
	cdi->base.reclassify_allowed = ecm_classifier_default_reclassify_allowed;
	cdi->base.reclassify = ecm_classifier_default_reclassify;
	cdi->base.last_process_response_get = ecm_classifier_default_last_process_response_get;
	cdi->base.xml_state_get = ecm_classifier_default_xml_state_get;
	cdi->base.ref = ecm_classifier_default_ref;
	cdi->base.deref = ecm_classifier_default_deref;

	spin_lock_bh(&ecm_classifier_default_lock);

	/*
	 * Final check if we are pending termination
	 */
	if (ecm_classifier_default_terminate_pending) {
		spin_unlock_bh(&ecm_classifier_default_lock);
		DEBUG_INFO("%p: Terminating\n", ci);
		cdii->ti->deref(cdii->ti);
		kfree(cdii);
		return NULL;
	}

	/*
	 * Ensure our thread persists now
	 */
	ecm_classifier_default_thread_refs++;
	DEBUG_ASSERT(ecm_classifier_default_thread_refs > 0, "Thread refs wrap %d\n", ecm_classifier_default_thread_refs);

	/*
	 * Increment stats
	 */
	ecm_classifier_default_count++;
	DEBUG_ASSERT(ecm_classifier_default_count > 0, "%p: ecm_classifier_default_count wrap\n", cdii);
	spin_unlock_bh(&ecm_classifier_default_lock);

	DEBUG_INFO("Default classifier instance alloc: %p\n", cdii);
	return cdi;
}
EXPORT_SYMBOL(ecm_classifier_default_instance_alloc);

/*
 * SysFS class of the ubicom default classifier
 * SysFS control points can be found at /sys/devices/system/ecm_classifier_default/ecm_classifier_defaultX/
 */
static struct sysdev_class ecm_classifier_default_sysclass = {
	.name = "ecm_classifier_default",
};

/*
 * ecm_classifier_default_get_terminate()
 */
static ssize_t ecm_classifier_default_get_terminate(struct sys_device *dev,
				  struct sysdev_attribute *attr,
				  char *buf)
{
	unsigned int n;
	ssize_t count;

	DEBUG_INFO("ecm_classifier_default_get_terminate\n");
	spin_lock_bh(&ecm_classifier_default_lock);
	n = ecm_classifier_default_terminate_pending;
	spin_unlock_bh(&ecm_classifier_default_lock);
	count = snprintf(buf, (ssize_t)PAGE_SIZE, "%u\n", n);
	return count;
}

/*
 * ecm_classifier_default_set_terminate()
 *	Writing anything to this 'file' will cause the default classifier to terminate
 */
static ssize_t ecm_classifier_default_set_terminate(struct sys_device *dev,
				  struct sysdev_attribute *attr,
				  const char *buf, size_t count)
{
	DEBUG_INFO("Default classifier terminate\n");
	spin_lock_bh(&ecm_classifier_default_lock);

	/*
	 * Are we already signalled to terminate?
	 */
	if (ecm_classifier_default_terminate_pending) {
		spin_unlock_bh(&ecm_classifier_default_lock);
		return 0;
	}

	ecm_classifier_default_terminate_pending = true;
	ecm_classifier_default_thread_refs--;
	DEBUG_ASSERT(ecm_classifier_default_thread_refs >= 0, "Thread ref wrap %d\n", ecm_classifier_default_thread_refs);
	wake_up_process(ecm_classifier_default_thread);
	spin_unlock_bh(&ecm_classifier_default_lock);

	return count;
}

/*
 * ecm_classifier_default_get_accel_mode()
 *	Display accel_mode of classifier.
 */
static ssize_t ecm_classifier_default_get_accel_mode(struct sys_device *dev,
		  struct sysdev_attribute *attr,
		  char *buf)
{
	ssize_t count;
	uint32_t num;

	DEBUG_INFO("ecm_classifier_default_get_accel_mode\n");

	spin_lock_bh(&ecm_classifier_default_lock);
	num = (uint32_t)ecm_classifier_default_accel_mode;
	spin_unlock_bh(&ecm_classifier_default_lock);

	count = snprintf(buf, (ssize_t)PAGE_SIZE, "%u", num);
	return count;
}

/*
 * ecm_classifier_default_set_accel_mode()
 *	Set new accel mode value for default classifier.
 */
static ssize_t ecm_classifier_default_set_accel_mode(struct sys_device *dev,
		  struct sysdev_attribute *attr,
		  const char *buf, size_t count)
{
	char num_buf[12];
	uint32_t num;

	/*
	 * Get the number from buf into a properly z-termed number buffer
	 */
	if (count >= sizeof(num_buf)) return 0;
	memcpy(num_buf, buf, count);
	num_buf[count] = '\0';
	sscanf(num_buf, "%u", &num);

	DEBUG_TRACE("ecm_classifier_default_set_accel_mode = %u\n", num);

	spin_lock_bh(&ecm_classifier_default_lock);
	ecm_classifier_default_accel_mode = (ecm_classifier_acceleration_mode_t)num;
	spin_unlock_bh(&ecm_classifier_default_lock);
	return count;
}

/*
 * ecm_classifier_default_get_enabled()
 *	Display enabled of classifier.
 */
static ssize_t ecm_classifier_default_get_enabled(struct sys_device *dev,
		  struct sysdev_attribute *attr,
		  char *buf)
{
	ssize_t count;
	uint32_t num;

	DEBUG_INFO("ecm_classifier_default_get_enabled\n");

	spin_lock_bh(&ecm_classifier_default_lock);
	num = (uint32_t)ecm_classifier_default_enabled;
	spin_unlock_bh(&ecm_classifier_default_lock);

	count = snprintf(buf, (ssize_t)PAGE_SIZE, "%u", num);
	return count;
}

/*
 * ecm_classifier_default_set_enabled()
 *	Set new enabled value for default classifier.
 */
static ssize_t ecm_classifier_default_set_enabled(struct sys_device *dev,
		  struct sysdev_attribute *attr,
		  const char *buf, size_t count)
{
	char num_buf[12];
	uint32_t num;

	/*
	 * Get the number from buf into a properly z-termed number buffer
	 */
	if (count >= sizeof(num_buf)) return 0;
	memcpy(num_buf, buf, count);
	num_buf[count] = '\0';
	sscanf(num_buf, "%u", &num);

	DEBUG_TRACE("ecm_classifier_default_set_enabled = %u\n", num);

	spin_lock_bh(&ecm_classifier_default_lock);
	ecm_classifier_default_enabled = (bool)num;
	spin_unlock_bh(&ecm_classifier_default_lock);
	return count;
}

static SYSDEV_ATTR(terminate, 0644, ecm_classifier_default_get_terminate, ecm_classifier_default_set_terminate);
static SYSDEV_ATTR(accel_mode, 0644, ecm_classifier_default_get_accel_mode, ecm_classifier_default_set_accel_mode);
static SYSDEV_ATTR(enabled, 0644, ecm_classifier_default_get_enabled, ecm_classifier_default_set_enabled);

/*
 * ecm_classifier_default_thread_fn()
 *	A thread to handle tasks that can only be done in thread context.
 */
static int ecm_classifier_default_thread_fn(void *arg)
{
	int result;

	DEBUG_TRACE("Default classifier Thread START\n");

	/*
	 * Get reference to this module - release it when thread exits
	 */
	if (!try_module_get(THIS_MODULE)) {
		return -EINVAL;
	}

	/*
	 * Register the sysfs class
	 */
	result = sysdev_class_register(&ecm_classifier_default_sysclass);
	if (result) {
		DEBUG_TRACE("Failed to register SysFS class\n");
		goto classifier_thread_cleanup_1;
	}

	/*
	 * Register SYSFS device control
	 */
	memset(&ecm_classifier_default_sys_dev, 0, sizeof(ecm_classifier_default_sys_dev));
	ecm_classifier_default_sys_dev.id = 0;
	ecm_classifier_default_sys_dev.cls = &ecm_classifier_default_sysclass;
	result = sysdev_register(&ecm_classifier_default_sys_dev);
	if (result) {
		DEBUG_TRACE("Failed to register SysFS device\n");
		goto classifier_thread_cleanup_2;
	}

	/*
	 * Create files, one for each parameter supported by this module
	 */
	result = sysdev_create_file(&ecm_classifier_default_sys_dev, &attr_terminate);
	if (result) {
		DEBUG_TRACE("Failed to register terminate SysFS file\n");
		goto classifier_thread_cleanup_3;
	}

	result = sysdev_create_file(&ecm_classifier_default_sys_dev, &attr_accel_mode);
	if (result) {
		DEBUG_TRACE("Failed to register accel_mode SysFS file\n");
		goto classifier_thread_cleanup_4;
	}

	result = sysdev_create_file(&ecm_classifier_default_sys_dev, &attr_enabled);
	if (result) {
		DEBUG_TRACE("Failed to register enabled SysFS file\n");
		goto classifier_thread_cleanup_5;
	}

	/*
	 * Allow wakeup signals
	 */
	allow_signal(SIGCONT);
	set_current_state(TASK_INTERRUPTIBLE);

	spin_lock_bh(&ecm_classifier_default_lock);

	/*
	 * Set thread refs to 1 - user must terminate us now.
	 */
	ecm_classifier_default_thread_refs = 1;

	while (ecm_classifier_default_thread_refs) {
		/*
		 * Sleep and wait for an instruction 
		 */
		spin_unlock_bh(&ecm_classifier_default_lock);
		DEBUG_TRACE("Default classifier SLEEP\n");
		schedule();
		set_current_state(TASK_INTERRUPTIBLE);
		spin_lock_bh(&ecm_classifier_default_lock);
	}
	DEBUG_TRACE("Default classifier TERMINATE\n");
	DEBUG_ASSERT(ecm_classifier_default_terminate_pending, "User has not requested terminate\n");

	/*
	 * If we are terminating then there should be no state remaining - or our linkage into the database will be messed up.
	 */
	DEBUG_ASSERT(ecm_classifier_default_count == 0, "state is still active\n");

	spin_unlock_bh(&ecm_classifier_default_lock);

	result = 0;

	sysdev_remove_file(&ecm_classifier_default_sys_dev, &attr_enabled);
classifier_thread_cleanup_5:
	sysdev_remove_file(&ecm_classifier_default_sys_dev, &attr_accel_mode);
classifier_thread_cleanup_4:
	sysdev_remove_file(&ecm_classifier_default_sys_dev, &attr_terminate);
classifier_thread_cleanup_3:
	sysdev_unregister(&ecm_classifier_default_sys_dev);
classifier_thread_cleanup_2:
	sysdev_class_unregister(&ecm_classifier_default_sysclass);
classifier_thread_cleanup_1:

	module_put(THIS_MODULE);
	return result;
}

/*
 * ecm_classifier_default_init()
 */
static int __init ecm_classifier_default_init(void)
{
	DEBUG_INFO("Default classifier Module init\n");

	DEBUG_ASSERT(ECM_CLASSIFIER_TYPE_DEFAULT == 0, "DO NOT CHANGE DEFAULT PRIORITY");

	/*
	 * Initialise our global lock
	 */
	spin_lock_init(&ecm_classifier_default_lock);

	/*
	 * Create a thread to handle the start/stop of operation.
	 * NOTE: We use a thread as some things we need to do cannot be done in this context
	 */
	ecm_classifier_default_thread = kthread_create(ecm_classifier_default_thread_fn, NULL, "%s", "ecm_classifier_default");
	if (!ecm_classifier_default_thread) {
		return -EINVAL;
	}
	wake_up_process(ecm_classifier_default_thread);
	return 0;
}

/*
 * ecm_classifier_default_exit()
 */
static void __exit ecm_classifier_default_exit(void)
{
	DEBUG_INFO("Default classifier Module exit\n");
	DEBUG_ASSERT(!ecm_classifier_default_thread_refs, "Thread has refs %d\n", ecm_classifier_default_thread_refs);
}

module_init(ecm_classifier_default_init)
module_exit(ecm_classifier_default_exit)

MODULE_AUTHOR("Qualcomm Atheros, Inc.");
MODULE_DESCRIPTION("ECM Default classifier");
#ifdef MODULE_LICENSE
MODULE_LICENSE("Dual BSD/GPL");
#endif
