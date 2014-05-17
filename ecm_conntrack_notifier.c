/*
 **************************************************************************
 * Copyright (c) 2014, The Linux Foundation. All rights reserved.
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

/*
 * ecm_conntrack_notifier.c
 * 	Conntrack notifier functionality.
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

/*
 * Debug output levels
 * 0 = OFF
 * 1 = ASSERTS / ERRORS
 * 2 = 1 + WARN
 * 3 = 2 + INFO
 * 4 = 3 + TRACE
 */
#define DEBUG_LEVEL ECM_CONNTRACK_NOTIFIER_DEBUG_LEVEL

#include <nss_api_if.h>

#include "ecm_types.h"
#include "ecm_db_types.h"
#include "ecm_tracker.h"
#include "ecm_classifier.h"
#include "ecm_front_end_types.h"
#include "ecm_tracker_udp.h"
#include "ecm_tracker_tcp.h"
#include "ecm_tracker_datagram.h"
#include "ecm_db.h"
#include "ecm_classifier_default.h"
#include "ecm_front_end_ipv4.h"
// GGG #include "ecm_front_end_ipv6.h"

/*
 * Locking of the classifier - concurrency control
 */
static spinlock_t ecm_conntrack_notifier_lock;				/* Protect against SMP access between netfilter, events and private threaded function. */

/*
 * SysFS linkage
 */
static struct sys_device ecm_conntrack_notifier_sys_dev;		/* SysFS linkage */

/*
 * General operational control
 */
static int ecm_conntrack_notifier_stopped = 0;				/* When non-zero further traffic will not be processed */

/*
 * Management thread control
 */
static bool ecm_conntrack_notifier_terminate_pending = false;		/* True when the user has signalled we should quit */
static int ecm_conntrack_notifier_thread_refs = 0;			/* >0 when the thread must stay active */
static struct task_struct *ecm_conntrack_notifier_thread = NULL;	/* Control thread */

#ifdef CONFIG_NF_CONNTRACK_EVENTS
/*
 * ecm_conntrack_event()
 *	Callback event invoked when conntrack connection state changes, currently we handle destroy events to quickly release state
 */
#ifdef CONFIG_NF_CONNTRACK_CHAIN_EVENTS
static int ecm_conntrack_event(struct notifier_block *this, unsigned long events, void *ptr)
#else
static int ecm_conntrack_event(unsigned int events, struct nf_ct_event *item)
#endif
{
#ifdef CONFIG_NF_CONNTRACK_CHAIN_EVENTS
	struct nf_ct_event *item = (struct nf_ct_event *)ptr;
#endif
	struct nf_conn *ct = item->ct;

	/*
	 * If operations have stopped then do not process event
	 */
	spin_lock_bh(&ecm_conntrack_notifier_lock);
	if (unlikely(ecm_conntrack_notifier_stopped)) {
		DEBUG_WARN("Ignoring event - stopped\n");
		spin_unlock_bh(&ecm_conntrack_notifier_lock);
		return NOTIFY_DONE;
	}
	spin_unlock_bh(&ecm_conntrack_notifier_lock);

	if (!ct) {
		DEBUG_WARN("Error: no ct\n");
		return NOTIFY_DONE;
	}

	/*
	 * Special untracked connection is not monitored
	 */
	if (ct == &nf_conntrack_untracked) {
		DEBUG_TRACE("Fake connection event - ignoring\n");
		return NOTIFY_DONE;
	}

	/*
	 * Only interested if this is IPv4 or IPv6.
	 */
	if (nf_ct_l3num(ct) == AF_INET) {
		return ecm_front_end_ipv4_conntrack_event(events, ct);
	} else if (nf_ct_l3num(ct) == AF_INET6) {
//GGG TODO		return ecm_ipv6_front_end_conntrack_event(events, ct);
	}

	return NOTIFY_DONE;
}

#ifdef CONFIG_NF_CONNTRACK_CHAIN_EVENTS
/*
 * struct notifier_block ecm_conntrack_notifier
 *	Netfilter conntrack event system to monitor connection tracking changes
 */
static struct notifier_block ecm_conntrack_notifier = {
	.notifier_call	= ecm_conntrack_event,
};
#else
/*
 * struct nf_ct_event_notifier ecm_conntrack_notifier
 *	Netfilter conntrack event system to monitor connection tracking changes
 */
static struct nf_ct_event_notifier ecm_conntrack_notifier = {
	.fcn	= ecm_conntrack_event,
};
#endif
#endif

/*
 * ecm_conntrack_notifier_get_terminate()
 */
static ssize_t ecm_conntrack_notifier_get_terminate(struct sys_device *dev,
				  struct sysdev_attribute *attr,
				  char *buf)
{
	ssize_t count;
	unsigned int n;

	DEBUG_INFO("Conntrack notifier get terminate\n");

	spin_lock_bh(&ecm_conntrack_notifier_lock);
	n = ecm_conntrack_notifier_terminate_pending;
	spin_unlock_bh(&ecm_conntrack_notifier_lock);
	count = snprintf(buf, (ssize_t)PAGE_SIZE, "%u\n", n);
	return count;
}

/*
 * ecm_conntrack_notifier_set_terminate()
 *	Writing anything to this 'file' will cause the default classifier to terminate
 */
static ssize_t ecm_conntrack_notifier_set_terminate(struct sys_device *dev,
				  struct sysdev_attribute *attr,
				  const char *buf, size_t count)
{
	DEBUG_INFO("Conntrack notifier set terminate\n");

	/*
	 * Are we already signalled to terminate?
	 */
	spin_lock_bh(&ecm_conntrack_notifier_lock);
	if (ecm_conntrack_notifier_terminate_pending) {
		spin_unlock_bh(&ecm_conntrack_notifier_lock);
		return 0;
	}

	ecm_conntrack_notifier_terminate_pending = true;
	ecm_conntrack_notifier_thread_refs--;
	DEBUG_ASSERT(ecm_conntrack_notifier_thread_refs >= 0, "Thread ref wrap %d\n", ecm_conntrack_notifier_thread_refs);
	wake_up_process(ecm_conntrack_notifier_thread);
	spin_unlock_bh(&ecm_conntrack_notifier_lock);
	return count;
}

/*
 * ecm_conntrack_notifier_get_stop()
 */
static ssize_t ecm_conntrack_notifier_get_stop(struct sys_device *dev,
				  struct sysdev_attribute *attr,
				  char *buf)
{
	ssize_t count;
	int num;

	/*
	 * Operate under our locks
	 */
	spin_lock_bh(&ecm_conntrack_notifier_lock);
	num = ecm_conntrack_notifier_stopped;
	spin_unlock_bh(&ecm_conntrack_notifier_lock);

	count = snprintf(buf, (ssize_t)PAGE_SIZE, "%d\n", num);
	return count;
}

/*
 * ecm_conntrack_notifier_set_stop()
 */
static ssize_t ecm_conntrack_notifier_set_stop(struct sys_device *dev,
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
	DEBUG_TRACE("ecm_conntrack_notifier_stop = %d\n", num);

	/*
	 * Operate under our locks and stop further processing of packets
	 */
	spin_lock_bh(&ecm_conntrack_notifier_lock);
	ecm_conntrack_notifier_stopped = num;
	spin_unlock_bh(&ecm_conntrack_notifier_lock);

	return count;
}

/*
 * SysFS attributes.
 */
static SYSDEV_ATTR(terminate, 0644, ecm_conntrack_notifier_get_terminate, ecm_conntrack_notifier_set_terminate);
static SYSDEV_ATTR(stop, 0644, ecm_conntrack_notifier_get_stop, ecm_conntrack_notifier_set_stop);

/*
 * SysFS class
 * SysFS control points can be found at /sys/devices/system/ecm_conntrack_notifier/ecm_conntrack_notifierX/
 */
static struct sysdev_class ecm_conntrack_notifier_sysclass = {
	.name = "ecm_conntrack_notifier",
};

/*
 * ecm_conntrack_notifier_thread_fn()
 *	A thread to handle tasks that can only be done in thread context.
 */
static int ecm_conntrack_notifier_thread_fn(void *arg)
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
	result = sysdev_class_register(&ecm_conntrack_notifier_sysclass);
	if (result) {
		DEBUG_ERROR("Failed to register SysFS class %d\n", result);
		goto task_cleanup_1;
	}

	/*
	 * Register SYSFS device control
	 */
	memset(&ecm_conntrack_notifier_sys_dev, 0, sizeof(ecm_conntrack_notifier_sys_dev));
	ecm_conntrack_notifier_sys_dev.id = 0;
	ecm_conntrack_notifier_sys_dev.cls = &ecm_conntrack_notifier_sysclass;
	result = sysdev_register(&ecm_conntrack_notifier_sys_dev);
	if (result) {
		DEBUG_ERROR("Failed to register SysFS device %d\n", result);
		goto task_cleanup_2;
	}

	/*
	 * Create files, one for each parameter supported by this module
	 */
	result = sysdev_create_file(&ecm_conntrack_notifier_sys_dev, &attr_terminate);
	if (result) {
		DEBUG_ERROR("Failed to register terminate file %d\n", result);
		goto task_cleanup_3;
	}

	result = sysdev_create_file(&ecm_conntrack_notifier_sys_dev, &attr_stop);
	if (result) {
		DEBUG_ERROR("Failed to register stop file %d\n", result);
		goto task_cleanup_4;
	}

#ifdef CONFIG_NF_CONNTRACK_EVENTS
	/*
	 * Eventing subsystem is available so we register a notifier hook to get fast notifications of expired connections
	 */
	result = nf_conntrack_register_notifier(&init_net, &ecm_conntrack_notifier);
	if (result < 0) {
		DEBUG_ERROR("Can't register nf notifier hook.\n");
		goto task_cleanup_5;
	}
#endif

	/*
	 * Allow wakeup signals
	 */
	allow_signal(SIGCONT);
	set_current_state(TASK_INTERRUPTIBLE);

	spin_lock_bh(&ecm_conntrack_notifier_lock);

	/*
	 * Set thread refs to 1 - user must terminate us now.
	 */
	ecm_conntrack_notifier_thread_refs = 1;

	while (ecm_conntrack_notifier_thread_refs) {
		/*
		 * Sleep and wait for an instruction
		 */
		spin_unlock_bh(&ecm_conntrack_notifier_lock);
		DEBUG_TRACE("ecm_conntrack_notifier sleep\n");
		schedule();
		set_current_state(TASK_INTERRUPTIBLE);
		spin_lock_bh(&ecm_conntrack_notifier_lock);
	}
	DEBUG_INFO("ecm_conntrack_notifier terminate\n");
	DEBUG_ASSERT(ecm_conntrack_notifier_terminate_pending, "User has not requested terminate\n");
	spin_unlock_bh(&ecm_conntrack_notifier_lock);

	result = 0;

#ifdef CONFIG_NF_CONNTRACK_EVENTS
	nf_conntrack_unregister_notifier(&init_net, &ecm_conntrack_notifier);
#endif
task_cleanup_5:
	sysdev_remove_file(&ecm_conntrack_notifier_sys_dev, &attr_stop);
task_cleanup_4:
	sysdev_remove_file(&ecm_conntrack_notifier_sys_dev, &attr_terminate);
task_cleanup_3:
	sysdev_unregister(&ecm_conntrack_notifier_sys_dev);
task_cleanup_2:
	sysdev_class_unregister(&ecm_conntrack_notifier_sysclass);
task_cleanup_1:

	module_put(THIS_MODULE);
	return result;
}

/*
 * ecm_conntrack_notifier_init()
 */
static int __init ecm_conntrack_notifier_init(void)
{
	DEBUG_INFO("ECM Conntrack Notifier init\n");

	/*
	 * Initialise our global lock
	 */
	spin_lock_init(&ecm_conntrack_notifier_lock);

	/*
	 * Create a thread to handle the start/stop of the database.
	 * NOTE: We use a thread as some things we need to do cannot be done in this context
	 */
	ecm_conntrack_notifier_thread = kthread_create(ecm_conntrack_notifier_thread_fn, NULL, "%s", "ecm_conn_ntfr");
	if (!ecm_conntrack_notifier_thread) {
		return -EINVAL;
	}
	wake_up_process(ecm_conntrack_notifier_thread);
	return 0;
}

/*
 * ecm_conntrack_notifier_exit()
 */
static void __exit ecm_conntrack_notifier_exit(void)
{
	DEBUG_INFO("ECM Conntrack Notifier exit\n");
	DEBUG_ASSERT(!ecm_conntrack_notifier_thread_refs, "Thread has refs %d\n", ecm_conntrack_notifier_thread_refs);
}

module_init(ecm_conntrack_notifier_init)
module_exit(ecm_conntrack_notifier_exit)

MODULE_AUTHOR("Qualcomm Atheros Inc");
MODULE_DESCRIPTION("ECM Conntrack notifier");
#ifdef MODULE_LICENSE
MODULE_LICENSE("Dual BSD/GPL");
#endif

