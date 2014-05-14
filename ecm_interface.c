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
#include <net/ip6_route.h>
#include <net/ip6_fib.h>
#include <net/ipv6.h>
#include <net/route.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <asm/unaligned.h>
#include <asm/uaccess.h>	/* for put_user */
#include <linux/inet.h>
#include <linux/in6.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>


#include <linux/inetdevice.h>
#include <net/ipip.h>
#include <net/ip6_tunnel.h>
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

/*
 * Debug output levels
 * 0 = OFF
 * 1 = ASSERTS / ERRORS
 * 2 = 1 + WARN
 * 3 = 2 + INFO
 * 4 = 3 + TRACE
 */
#define DEBUG_LEVEL ECM_INTERFACE_DEBUG_LEVEL

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
#include "ecm_interface.h"

/*
 * Locking - concurrency control
 */
static spinlock_t ecm_interface_lock;			/* Protect against SMP access between netfilter, events and private threaded function. */

/*
 * SysFS linkage
 */
static struct sys_device ecm_interface_sys_dev;		/* SysFS linkage */

/*
 * General operational control
 */
static int ecm_interface_stopped = 0;			/* When non-zero further traffic will not be processed */

/*
 * Management thread control
 */
static bool ecm_interface_terminate_pending = false;		/* True when the user has signalled we should quit */
static int ecm_interface_thread_refs = 0;			/* >0 when the thread must stay active */
static struct task_struct *ecm_interface_thread = NULL;		/* Control thread */

/*
 * ecm_interface_mac_addr_get_ipv6()
 *	Return mac for an IPv6 address
 *
 * GGG TODO Need to make sure this also works for local IP addresses too.
 */
static bool ecm_interface_mac_addr_get_ipv6(ip_addr_t addr, uint8_t *mac_addr, bool *on_link, ip_addr_t gw_addr)
{
	struct in6_addr daddr;
	struct ecm_interface_route ecm_rt;
	struct neighbour *neigh;
	struct rt6_info *rt;
	struct dst_entry *dst;

	/*
	 * Get the MAC address that corresponds to IP address given.
	 * We look up the rt6_info entries and, from its neighbour structure, obtain the hardware address.
	 * This means we will also work if the neighbours are routers too.
	 */
	ECM_IP_ADDR_TO_NIN6_ADDR(daddr, addr);
	if (!ecm_interface_find_route_by_addr(addr, &ecm_rt)) {
		return false;
	}
	DEBUG_ASSERT(!ecm_rt.v4_route, "Did not locate a v6 route!\n");

	/*
	 * Is this destination on link or off-link via a gateway?
	 */
	rt = ecm_rt.rt.rtv6;
	if (!ECM_IP_ADDR_MATCH(rt->rt6i_dst.addr.in6_u.u6_addr32, rt->rt6i_gateway.in6_u.u6_addr32) || (rt->rt6i_flags & RTF_GATEWAY)) {
		*on_link = false;
		ECM_NIN6_ADDR_TO_IP_ADDR(gw_addr, rt->rt6i_gateway)
	} else {
		*on_link = true;
	}

	rcu_read_lock();
	dst = ecm_rt.dst;
	neigh = dst_get_neighbour_noref(dst);
	if (!neigh) {
		rcu_read_unlock();
		ecm_interface_route_release(&ecm_rt);
		return false;
	}
	if (!(neigh->nud_state & NUD_VALID)) {
		rcu_read_unlock();
		ecm_interface_route_release(&ecm_rt);
		return false;
	}
	if (!neigh->dev) {
		rcu_read_unlock();
		ecm_interface_route_release(&ecm_rt);
		return false;
	}

	/*
	 * If neigh->dev is a loopback then addr is a local address in which case we take the MAC from given device
	 */
	if (neigh->dev->flags & IFF_LOOPBACK) {
		// GGG TODO Create an equivalent logic to that for ipv4, maybe need to create an ip6_dev_find()?
		DEBUG_TRACE("local address " ECM_IP_ADDR_OCTAL_FMT " (found loopback)\n", ECM_IP_ADDR_TO_OCTAL(addr));
		memset(mac_addr, 0, 6);
	} else {
		memcpy(mac_addr, neigh->ha, 6);
	}
	rcu_read_unlock();
	ecm_interface_route_release(&ecm_rt);

	DEBUG_TRACE(ECM_IP_ADDR_OCTAL_FMT " maps to %pM\n", ECM_IP_ADDR_TO_OCTAL(addr), mac_addr);
	return true;
}

/*
 * ecm_interface_mac_addr_get_ipv4()
 *	Return mac for an IPv4 address
 */
static bool ecm_interface_mac_addr_get_ipv4(ip_addr_t addr, uint8_t *mac_addr, bool *on_link, ip_addr_t gw_addr)
{
	struct neighbour *neigh;
	struct ecm_interface_route ecm_rt;
	struct rtable *rt;
	struct dst_entry *dst;
	__be32 ipv4_addr;
	
	/*
	 * Get the MAC address that corresponds to IP address given.
	 * We look up the rtable entries and, from its neighbour structure, obtain the hardware address.
	 * This means we will also work if the neighbours are routers too.
	 * We also locate the MAC if the address is a local host address.
	 */
	ECM_IP_ADDR_TO_NIN4_ADDR(ipv4_addr, addr);
	if (!ecm_interface_find_route_by_addr(addr, &ecm_rt)) {
		return false;
	}
	DEBUG_ASSERT(ecm_rt.v4_route, "Did not locate a v4 route!\n");

	/*
	 * Is this destination on link or off-link via a gateway?
	 */
	rt = ecm_rt.rt.rtv4;
	if ((rt->rt_dst != rt->rt_gateway) || (rt->rt_flags & RTF_GATEWAY)) {
		*on_link = false;
		ECM_NIN4_ADDR_TO_IP_ADDR(gw_addr, rt->rt_gateway)
	} else {
		*on_link = true;
	}

	/*
	 * Get the neighbour entry for the address
	 */
	rcu_read_lock();
	dst = ecm_rt.dst;
	neigh = dst_get_neighbour_noref(dst);
	if (neigh) {
		neigh_hold(neigh);
	} else {
		neigh = neigh_lookup(&arp_tbl, &ipv4_addr, dst->dev);
	}
	if (!neigh) {
		rcu_read_unlock();
		ecm_interface_route_release(&ecm_rt);
		return false;
	}
	if (!(neigh->nud_state & NUD_VALID)) {
		rcu_read_unlock();
		neigh_release(neigh);
		ecm_interface_route_release(&ecm_rt);
		return false;
	}
	if (!neigh->dev) {
		rcu_read_unlock();
		neigh_release(neigh);
		ecm_interface_route_release(&ecm_rt);
		return false;
	}

	/*
	 * If the device is loopback this will be because the address is a local address
	 * In this case locate the device that has this local address and get its mac.
	 */
	if (neigh->dev->type == ARPHRD_LOOPBACK) {
		struct net_device *dev;

		DEBUG_TRACE("%pI4 finds loopback device, dev: %p (%s)\n", &ipv4_addr, neigh->dev, neigh->dev->name);
		rcu_read_unlock();
		neigh_release(neigh);
		ecm_interface_route_release(&ecm_rt);

		/*
		 * Lookup the device that has this IP address assigned
		 */
		dev = ip_dev_find(&init_net, ipv4_addr);
		if (!dev) {
			DEBUG_WARN("Unable to locate dev for: %pI4\n", &ipv4_addr);
			return false;
		}
		memcpy(mac_addr, dev->dev_addr, (size_t)dev->addr_len);
		DEBUG_TRACE("is local addr: %pI4, mac: %pM, dev ifindex: %d, dev: %p (%s), dev_type: %d\n",
				&ipv4_addr, mac_addr, dev->ifindex, dev, dev->name, dev->type);
		dev_put(dev);
		return true;
	}

	if (!(neigh->dev->flags & IFF_NOARP)) {
		memcpy(mac_addr, neigh->ha, (size_t)neigh->dev->addr_len);
	} else {
		DEBUG_TRACE("non-arp device: %p (%s, type: %d) to reach %pI4\n", neigh->dev, neigh->dev->name, neigh->dev->type, &ipv4_addr);
		memset(mac_addr, 0, 6);
	}
	DEBUG_TRACE("addr: %pI4, mac: %pM, iif: %d, neigh dev ifindex: %d, dev: %p (%s), dev_type: %d\n",
			&ipv4_addr, mac_addr, rt->rt_iif, neigh->dev->ifindex, neigh->dev, neigh->dev->name, neigh->dev->type);

	rcu_read_unlock();
	neigh_release(neigh);
	ecm_interface_route_release(&ecm_rt);
	return true;
}

/*
 * ecm_interface_mac_addr_get()
 *	Return the mac address for the given IP address.  Returns false on failure.
 *
 * dev is the device on which the addr was sent/received.  If addr is a local address then mac shall be the given dev mac.
 *
 * GGG TODO Make this function work for IPv6!!!!!!!!!!!!!!
 */
bool ecm_interface_mac_addr_get(ip_addr_t addr, uint8_t *mac_addr, bool *on_link, ip_addr_t gw_addr)
{
	if (ECM_IP_ADDR_IS_V4(addr)) {
		return ecm_interface_mac_addr_get_ipv4(addr, mac_addr, on_link, gw_addr);
	}

	return ecm_interface_mac_addr_get_ipv6(addr, mac_addr, on_link, gw_addr);
}
EXPORT_SYMBOL(ecm_interface_mac_addr_get);

/*
 * ecm_interface_addr_find_route_by_addr_ipv4()
 *	Return the route for the given IP address.  Returns NULL on failure.
 */
static bool ecm_interface_find_route_by_addr_ipv4(ip_addr_t addr, struct ecm_interface_route *ecm_rt)
{
	__be32 be_addr;

	/*
	 * Get a route to the given IP address, this will allow us to also find the interface
	 * it is using to communicate with that IP address.
	 */
	ECM_IP_ADDR_TO_NIN4_ADDR(be_addr, addr);
	ecm_rt->rt.rtv4 = ip_route_output(&init_net, be_addr, 0, 0, 0);
	if (IS_ERR(ecm_rt->rt.rtv4)) {
		DEBUG_TRACE("No output route to: %pI4n\n", &be_addr);
		return false;
	}
	DEBUG_TRACE("Output route to: %pI4n is: %p\n", &be_addr, ecm_rt->rt.rtv4);
	ecm_rt->dst = (struct dst_entry *)ecm_rt->rt.rtv4;
	ecm_rt->v4_route = true;
	return true;
}

/*
 * ecm_interface_addr_find_route_by_addr_ipv6()
 *	Return the route for the given IP address.  Returns NULL on failure.
 */
static bool ecm_interface_find_route_by_addr_ipv6(ip_addr_t addr, struct ecm_interface_route *ecm_rt)
{
	struct in6_addr naddr;

	ECM_IP_ADDR_TO_NIN6_ADDR(naddr, addr);

	/*
	 * Get a route to the given IP address, this will allow us to also find the interface
	 * it is using to communicate with that IP address.
	 */
	ecm_rt->rt.rtv6 = rt6_lookup(&init_net, &naddr, NULL, 0, 0);
	if (!ecm_rt->rt.rtv6) {
		DEBUG_TRACE("No output route to: " ECM_IP_ADDR_OCTAL_FMT "\n", ECM_IP_ADDR_TO_OCTAL(addr));
		return NULL;
	}
	DEBUG_TRACE("Output route to: " ECM_IP_ADDR_OCTAL_FMT " is: %p\n", ECM_IP_ADDR_TO_OCTAL(addr), ecm_rt->rt.rtv6);
	ecm_rt->dst = (struct dst_entry *)ecm_rt->rt.rtv6;
	ecm_rt->v4_route = false;
	return true;
}

/*
 * ecm_interface_addr_find_route_by_addr()
 *	Return the route (in the given parameter) for the given IP address.  Returns false on failure.
 *
 * Route is the device on which the addr is reachable, which may be loopback for local addresses.
 *
 * Returns true if the route was able to be located.  The route must be released using ecm_interface_route_release().
 */
bool ecm_interface_find_route_by_addr(ip_addr_t addr, struct ecm_interface_route *ecm_rt)
{
	char __attribute__((unused)) addr_str[40];
	
	ecm_ip_addr_to_string(addr_str, addr);
	DEBUG_TRACE("Locate route to: %s\n", addr_str);

	if (ECM_IP_ADDR_IS_V4(addr)) {
		return ecm_interface_find_route_by_addr_ipv4(addr, ecm_rt);
	}

	return ecm_interface_find_route_by_addr_ipv6(addr, ecm_rt);
}
EXPORT_SYMBOL(ecm_interface_find_route_by_addr);

/*
 * ecm_interface_route_release()
 *	Release an ecm route
 */
void ecm_interface_route_release(struct ecm_interface_route *rt)
{
	dst_release(rt->dst);
}
EXPORT_SYMBOL(ecm_interface_route_release);

/*
 * ecm_interface_bridge_iface_final()
 *	An interface object we created has been destroyed
 */
static void ecm_interface_bridge_iface_final(void *arg)
{
	DEBUG_INFO("Bridge interface final: %p\n", arg);

	/*
	 * No longer need the ref to the thread
	 */
	spin_lock_bh(&ecm_interface_lock);
	ecm_interface_thread_refs--;
	DEBUG_ASSERT(ecm_interface_thread_refs >= 0, "Thread refs wrap %d\n", ecm_interface_thread_refs);
	spin_unlock_bh(&ecm_interface_lock);
	wake_up_process(ecm_interface_thread);
}

/*
 * ecm_interface_vlan_iface_final()
 *	An interface object we created has been destroyed
 */
static void ecm_interface_vlan_iface_final(void *arg)
{
	DEBUG_INFO("VLAN interface final: %p\n", arg);

	/*
	 * No longer need the ref to the thread
	 */
	spin_lock_bh(&ecm_interface_lock);
	ecm_interface_thread_refs--;
	DEBUG_ASSERT(ecm_interface_thread_refs >= 0, "Thread refs wrap %d\n", ecm_interface_thread_refs);
	spin_unlock_bh(&ecm_interface_lock);
	wake_up_process(ecm_interface_thread);
}

/*
 * ecm_interface_lag_iface_final()
 *	An interface object we created has been destroyed
 */
static void ecm_interface_lag_iface_final(void *arg)
{
	DEBUG_INFO("LAG interface final: %p\n", arg);

	/*
	 * No longer need the ref to the thread
	 */
	spin_lock_bh(&ecm_interface_lock);
	ecm_interface_thread_refs--;
	DEBUG_ASSERT(ecm_interface_thread_refs >= 0, "Thread refs wrap %d\n", ecm_interface_thread_refs);
	spin_unlock_bh(&ecm_interface_lock);
	wake_up_process(ecm_interface_thread);
}

/*
 * ecm_interface_ethernet_iface_final()
 *	An interface object we created has been destroyed
 */
static void ecm_interface_ethernet_iface_final(void *arg)
{
	DEBUG_INFO("ETHERNET interface final: %p\n", arg);

	/*
	 * No longer need the ref to the thread
	 */
	spin_lock_bh(&ecm_interface_lock);
	ecm_interface_thread_refs--;
	DEBUG_ASSERT(ecm_interface_thread_refs >= 0, "Thread refs wrap %d\n", ecm_interface_thread_refs);
	spin_unlock_bh(&ecm_interface_lock);
	wake_up_process(ecm_interface_thread);
}

#ifdef ECM_INTERFACE_PPP_SUPPORT
/*
 * ecm_interface_pppoe_iface_final()
 *	An interface object we created has been destroyed
 */
static void ecm_interface_pppoe_iface_final(void *arg)
{
	DEBUG_INFO("PPPoE interface final: %p\n", arg);

	/*
	 * No longer need the ref to the thread
	 */
	spin_lock_bh(&ecm_interface_lock);
	ecm_interface_thread_refs--;
	DEBUG_ASSERT(ecm_interface_thread_refs >= 0, "Thread refs wrap %d\n", ecm_interface_thread_refs);
	spin_unlock_bh(&ecm_interface_lock);
	wake_up_process(ecm_interface_thread);
}
#endif

/*
 * ecm_interface_unknown_iface_final()
 *	An interface object we created has been destroyed
 */
static void ecm_interface_unknown_iface_final(void *arg)
{
	DEBUG_INFO("UNKNOWN type interface final: %p\n", arg);

	/*
	 * No longer need the ref to the thread
	 */
	spin_lock_bh(&ecm_interface_lock);
	ecm_interface_thread_refs--;
	DEBUG_ASSERT(ecm_interface_thread_refs >= 0, "Thread refs wrap %d\n", ecm_interface_thread_refs);
	spin_unlock_bh(&ecm_interface_lock);
	wake_up_process(ecm_interface_thread);
}

/*
 * ecm_interface_loopback_iface_final()
 *	An interface object we created has been destroyed
 */
static void ecm_interface_loopback_iface_final(void *arg)
{
	DEBUG_INFO("LOOPBACK type interface final: %p\n", arg);

	/*
	 * No longer need the ref to the thread
	 */
	spin_lock_bh(&ecm_interface_lock);
	ecm_interface_thread_refs--;
	DEBUG_ASSERT(ecm_interface_thread_refs >= 0, "Thread refs wrap %d\n", ecm_interface_thread_refs);
	spin_unlock_bh(&ecm_interface_lock);
	wake_up_process(ecm_interface_thread);
}

/*
 * ecm_interface_ipsec_tunnel_iface_final()
 *	An interface object we created has been destroyed
 */
static void ecm_interface_ipsec_tunnel_iface_final(void *arg)
{
	DEBUG_INFO("IPSEC TUNNEL type interface final: %p\n", arg);

	/*
	 * No longer need the ref to the thread
	 */
	spin_lock_bh(&ecm_interface_lock);
	ecm_interface_thread_refs--;
	DEBUG_ASSERT(ecm_interface_thread_refs >= 0, "Thread refs wrap %d\n", ecm_interface_thread_refs);
	spin_unlock_bh(&ecm_interface_lock);
	wake_up_process(ecm_interface_thread);
}

#ifdef CONFIG_IPV6_SIT_6RD
/*
 * ecm_interface_sit_iface_final()
 *	An interface object we created has been destroyed
 */
static void ecm_interface_sit_iface_final(void *arg)
{
	DEBUG_INFO("SIT (6-in-4) type interface final: %p\n", arg);

	/*
	 * No longer need the ref to the thread
	 */
	spin_lock_bh(&ecm_interface_lock);
	ecm_interface_thread_refs--;
	DEBUG_ASSERT(ecm_interface_thread_refs >= 0, "Thread refs wrap %d\n", ecm_interface_thread_refs);
	spin_unlock_bh(&ecm_interface_lock);
	wake_up_process(ecm_interface_thread);
}
#endif

/*
 * ecm_interface_tunipip6_iface_final()
 *	An interface object we created has been destroyed
 */
static void ecm_interface_tunipip6_iface_final(void *arg)
{
	DEBUG_INFO("TUNIPIP6 type interface final: %p\n", arg);

	/*
	 * No longer need the ref to the thread
	 */
	spin_lock_bh(&ecm_interface_lock);
	ecm_interface_thread_refs--;
	DEBUG_ASSERT(ecm_interface_thread_refs >= 0, "Thread refs wrap %d\n", ecm_interface_thread_refs);
	spin_unlock_bh(&ecm_interface_lock);
	wake_up_process(ecm_interface_thread);
}

/*
 * ecm_interface_vlan_interface_establish()
 *	Returns a reference to a iface of the VLAN type, possibly creating one if necessary.
 * Returns NULL on failure or a reference to interface.
 */
static struct ecm_db_iface_instance *ecm_interface_vlan_interface_establish(struct ecm_db_interface_info_vlan *type_info,
							char *dev_name, int32_t dev_interface_num, int32_t nss_interface_num, int32_t mtu)
{
	struct ecm_db_iface_instance *nii;
	struct ecm_db_iface_instance *ii;

	DEBUG_INFO("Establish VLAN iface: %s with address: %pM, vlan tag: %u, MTU: %d, if num: %d, nss if id: %d\n",
			dev_name, type_info->address, type_info->vlan_tag, mtu, dev_interface_num, nss_interface_num);

	/*
	 * Locate the iface
	 */
	ii = ecm_db_iface_find_and_ref_vlan(type_info->address, type_info->vlan_tag);
	if (ii) {
		DEBUG_TRACE("%p: iface established\n", ii);
		return ii;
	}

	/*
	 * No iface - create one
	 */
	nii = ecm_db_iface_alloc();
	if (!nii) {
		DEBUG_WARN("Failed to establish iface\n");
		return NULL;
	}

	/*
	 * Add iface into the database, atomically to avoid races creating the same thing
	 */
	spin_lock_bh(&ecm_interface_lock);
	ii = ecm_db_iface_find_and_ref_vlan(type_info->address, type_info->vlan_tag);
	if (ii) {
		spin_unlock_bh(&ecm_interface_lock);
		ecm_db_iface_deref(nii);
		return ii;
	}
	ecm_db_iface_add_vlan(nii, type_info->address, type_info->vlan_tag, dev_name,
			mtu, dev_interface_num, nss_interface_num, ecm_interface_vlan_iface_final, nii);

	/*
	 * Ensure our thread persists (and hence this module) for as long as the interface is referenced as we could get
	 * callbacks from the database at any time.
	 */
	ecm_interface_thread_refs++;
	DEBUG_ASSERT(ecm_interface_thread_refs > 0, "Thread refs wrap %d\n", ecm_interface_thread_refs);
	spin_unlock_bh(&ecm_interface_lock);

	DEBUG_TRACE("%p: vlan iface established\n", nii);
	return nii;
}

/*
 * ecm_interface_bridge_interface_establish()
 *	Returns a reference to a iface of the BRIDGE type, possibly creating one if necessary.
 * Returns NULL on failure or a reference to interface.
 */
static struct ecm_db_iface_instance *ecm_interface_bridge_interface_establish(struct ecm_db_interface_info_bridge *type_info,
							char *dev_name, int32_t dev_interface_num, int32_t nss_interface_num, int32_t mtu)
{
	struct ecm_db_iface_instance *nii;
	struct ecm_db_iface_instance *ii;

	DEBUG_INFO("Establish BRIDGE iface: %s with address: %pM, MTU: %d, if num: %d, nss if id: %d\n",
			dev_name, type_info->address, mtu, dev_interface_num, nss_interface_num);

	/*
	 * Locate the iface
	 */
	ii = ecm_db_iface_find_and_ref_bridge(type_info->address);
	if (ii) {
		DEBUG_TRACE("%p: iface established\n", ii);
		return ii;
	}

	/*
	 * No iface - create one
	 */
	nii = ecm_db_iface_alloc();
	if (!nii) {
		DEBUG_WARN("Failed to establish iface\n");
		return NULL;
	}

	/*
	 * Add iface into the database, atomically to avoid races creating the same thing
	 */
	spin_lock_bh(&ecm_interface_lock);
	ii = ecm_db_iface_find_and_ref_bridge(type_info->address);
	if (ii) {
		spin_unlock_bh(&ecm_interface_lock);
		ecm_db_iface_deref(nii);
		return ii;
	}
	ecm_db_iface_add_bridge(nii, type_info->address, dev_name,
			mtu, dev_interface_num, nss_interface_num, ecm_interface_bridge_iface_final, nii);

	/*
	 * Ensure our thread persists (and hence this module) for as long as the interface is referenced as we could get
	 * callbacks from the database at any time.
	 */
	ecm_interface_thread_refs++;
	DEBUG_ASSERT(ecm_interface_thread_refs > 0, "Thread refs wrap %d\n", ecm_interface_thread_refs);
	spin_unlock_bh(&ecm_interface_lock);

	DEBUG_TRACE("%p: bridge iface established\n", nii);
	return nii;
}

/*
 * ecm_interface_lag_interface_establish()
 *	Returns a reference to a iface of the LAG type, possibly creating one if necessary.
 * Returns NULL on failure or a reference to interface.
 */
static struct ecm_db_iface_instance *ecm_interface_lag_interface_establish(struct ecm_db_interface_info_lag *type_info,
							char *dev_name, int32_t dev_interface_num, int32_t nss_interface_num, int32_t mtu)
{
	struct ecm_db_iface_instance *nii;
	struct ecm_db_iface_instance *ii;

	DEBUG_INFO("Establish LAG iface: %s with address: %pM, MTU: %d, if num: %d, nss if id: %d\n",
			dev_name, type_info->address, mtu, dev_interface_num, nss_interface_num);

	/*
	 * Locate the iface
	 */
	ii = ecm_db_iface_find_and_ref_lag(type_info->address);
	if (ii) {
		DEBUG_TRACE("%p: iface established\n", ii);
		return ii;
	}

	/*
	 * No iface - create one
	 */
	nii = ecm_db_iface_alloc();
	if (!nii) {
		DEBUG_WARN("Failed to establish iface\n");
		return NULL;
	}

	/*
	 * Add iface into the database, atomically to avoid races creating the same thing
	 */
	spin_lock_bh(&ecm_interface_lock);
	ii = ecm_db_iface_find_and_ref_lag(type_info->address);
	if (ii) {
		spin_unlock_bh(&ecm_interface_lock);
		ecm_db_iface_deref(nii);
		return ii;
	}
	ecm_db_iface_add_lag(nii, type_info->address, dev_name,
			mtu, dev_interface_num, nss_interface_num, ecm_interface_lag_iface_final, nii);

	/*
	 * Ensure our thread persists (and hence this module) for as long as the interface is referenced as we could get
	 * callbacks from the database at any time.
	 */
	ecm_interface_thread_refs++;
	DEBUG_ASSERT(ecm_interface_thread_refs > 0, "Thread refs wrap %d\n", ecm_interface_thread_refs);
	spin_unlock_bh(&ecm_interface_lock);

	DEBUG_TRACE("%p: lag iface established\n", nii);
	return nii;
}

/*
 * ecm_interface_ethernet_interface_establish()
 *	Returns a reference to a iface of the ETHERNET type, possibly creating one if necessary.
 * Returns NULL on failure or a reference to interface.
 */
static struct ecm_db_iface_instance *ecm_interface_ethernet_interface_establish(struct ecm_db_interface_info_ethernet *type_info,
							char *dev_name, int32_t dev_interface_num, int32_t nss_interface_num, int32_t mtu)
{
	struct ecm_db_iface_instance *nii;
	struct ecm_db_iface_instance *ii;

	DEBUG_INFO("Establish ETHERNET iface: %s with address: %pM, MTU: %d, if num: %d, nss if id: %d\n",
			dev_name, type_info->address, mtu, dev_interface_num, nss_interface_num);

	/*
	 * Locate the iface
	 */
	ii = ecm_db_iface_find_and_ref_ethernet(type_info->address);
	if (ii) {
		DEBUG_TRACE("%p: iface established\n", ii);
		return ii;
	}

	/*
	 * No iface - create one
	 */
	nii = ecm_db_iface_alloc();
	if (!nii) {
		DEBUG_WARN("Failed to establish iface\n");
		return NULL;
	}

	/*
	 * Add iface into the database, atomically to avoid races creating the same thing
	 */
	spin_lock_bh(&ecm_interface_lock);
	ii = ecm_db_iface_find_and_ref_ethernet(type_info->address);
	if (ii) {
		spin_unlock_bh(&ecm_interface_lock);
		ecm_db_iface_deref(nii);
		return ii;
	}
	ecm_db_iface_add_ethernet(nii, type_info->address, dev_name,
			mtu, dev_interface_num, nss_interface_num, ecm_interface_ethernet_iface_final, nii);

	/*
	 * Ensure our thread persists (and hence this module) for as long as the interface is referenced as we could get
	 * callbacks from the database at any time.
	 */
	ecm_interface_thread_refs++;
	DEBUG_ASSERT(ecm_interface_thread_refs > 0, "Thread refs wrap %d\n", ecm_interface_thread_refs);
	spin_unlock_bh(&ecm_interface_lock);

	DEBUG_TRACE("%p: ethernet iface established\n", nii);
	return nii;
}

#ifdef ECM_INTERFACE_PPP_SUPPORT
/*
 * ecm_interface_pppoe_interface_establish()
 *	Returns a reference to a iface of the PPPoE type, possibly creating one if necessary.
 * Returns NULL on failure or a reference to interface.
 */
static struct ecm_db_iface_instance *ecm_interface_pppoe_interface_establish(struct ecm_db_interface_info_pppoe *type_info,
							char *dev_name, int32_t dev_interface_num, int32_t nss_interface_num, int32_t mtu)
{
	struct ecm_db_iface_instance *nii;
	struct ecm_db_iface_instance *ii;

	DEBUG_INFO("Establish PPPoE iface: %s with session id: %u, remote mac: %pM, MTU: %d, if num: %d, nss if id: %d\n",
			dev_name, type_info->pppoe_session_id, type_info->remote_mac, mtu, dev_interface_num, nss_interface_num);

	/*
	 * Locate the iface
	 */
	ii = ecm_db_iface_find_and_ref_pppoe(type_info->pppoe_session_id, type_info->remote_mac);
	if (ii) {
		DEBUG_TRACE("%p: iface established\n", ii);
		return ii;
	}

	/*
	 * No iface - create one
	 */
	nii = ecm_db_iface_alloc();
	if (!nii) {
		DEBUG_WARN("Failed to establish iface\n");
		return NULL;
	}

	/*
	 * Add iface into the database, atomically to avoid races creating the same thing
	 */
	spin_lock_bh(&ecm_interface_lock);
	ii = ecm_db_iface_find_and_ref_pppoe(type_info->pppoe_session_id, type_info->remote_mac);
	if (ii) {
		spin_unlock_bh(&ecm_interface_lock);
		ecm_db_iface_deref(nii);
		return ii;
	}
	ecm_db_iface_add_pppoe(nii, type_info->pppoe_session_id, type_info->remote_mac, dev_name,
			mtu, dev_interface_num, nss_interface_num, ecm_interface_pppoe_iface_final, nii);

	/*
	 * Ensure our thread persists (and hence this module) for as long as the interface is referenced as we could get
	 * callbacks from the database at any time.
	 */
	ecm_interface_thread_refs++;
	DEBUG_ASSERT(ecm_interface_thread_refs > 0, "Thread refs wrap %d\n", ecm_interface_thread_refs);
	spin_unlock_bh(&ecm_interface_lock);

	DEBUG_TRACE("%p: pppoe iface established\n", nii);
	return nii;
}
#endif

/*
 * ecm_interface_unknown_interface_establish()
 *	Returns a reference to a iface of the UNKNOWN type, possibly creating one if necessary.
 * Returns NULL on failure or a reference to interface.
 */
static struct ecm_db_iface_instance *ecm_interface_unknown_interface_establish(struct ecm_db_interface_info_unknown *type_info,
							char *dev_name, int32_t dev_interface_num, int32_t nss_interface_num, int32_t mtu)
{
	struct ecm_db_iface_instance *nii;
	struct ecm_db_iface_instance *ii;

	DEBUG_INFO("Establish UNKNOWN iface: %s with os_specific_ident: %u, MTU: %d, if num: %d, nss if id: %d\n",
			dev_name, type_info->os_specific_ident, mtu, dev_interface_num, nss_interface_num);

	/*
	 * Locate the iface
	 */
	ii = ecm_db_iface_find_and_ref_unknown(type_info->os_specific_ident);
	if (ii) {
		DEBUG_TRACE("%p: iface established\n", ii);
		return ii;
	}

	/*
	 * No iface - create one
	 */
	nii = ecm_db_iface_alloc();
	if (!nii) {
		DEBUG_WARN("Failed to establish iface\n");
		return NULL;
	}

	/*
	 * Add iface into the database, atomically to avoid races creating the same thing
	 */
	spin_lock_bh(&ecm_interface_lock);
	ii = ecm_db_iface_find_and_ref_unknown(type_info->os_specific_ident);
	if (ii) {
		spin_unlock_bh(&ecm_interface_lock);
		ecm_db_iface_deref(nii);
		return ii;
	}
	ecm_db_iface_add_unknown(nii, type_info->os_specific_ident, dev_name,
			mtu, dev_interface_num, nss_interface_num, ecm_interface_unknown_iface_final, nii);

	/*
	 * Ensure our thread persists (and hence this module) for as long as the interface is referenced as we could get
	 * callbacks from the database at any time.
	 */
	ecm_interface_thread_refs++;
	DEBUG_ASSERT(ecm_interface_thread_refs > 0, "Thread refs wrap %d\n", ecm_interface_thread_refs);
	spin_unlock_bh(&ecm_interface_lock);

	DEBUG_TRACE("%p: unknown iface established\n", nii);
	return nii;
}

/*
 * ecm_interface_loopback_interface_establish()
 *	Returns a reference to a iface of the LOOPBACK type, possibly creating one if necessary.
 * Returns NULL on failure or a reference to interface.
 */
static struct ecm_db_iface_instance *ecm_interface_loopback_interface_establish(struct ecm_db_interface_info_loopback *type_info,
							char *dev_name, int32_t dev_interface_num, int32_t nss_interface_num, int32_t mtu)
{
	struct ecm_db_iface_instance *nii;
	struct ecm_db_iface_instance *ii;

	DEBUG_INFO("Establish LOOPBACK iface: %s with os_specific_ident: %u, MTU: %d, if num: %d, nss if id: %d\n",
			dev_name, type_info->os_specific_ident, mtu, dev_interface_num, nss_interface_num);

	/*
	 * Locate the iface
	 */
	ii = ecm_db_iface_find_and_ref_loopback(type_info->os_specific_ident);
	if (ii) {
		DEBUG_TRACE("%p: iface established\n", ii);
		return ii;
	}

	/*
	 * No iface - create one
	 */
	nii = ecm_db_iface_alloc();
	if (!nii) {
		DEBUG_WARN("Failed to establish iface\n");
		return NULL;
	}

	/*
	 * Add iface into the database, atomically to avoid races creating the same thing
	 */
	spin_lock_bh(&ecm_interface_lock);
	ii = ecm_db_iface_find_and_ref_loopback(type_info->os_specific_ident);
	if (ii) {
		spin_unlock_bh(&ecm_interface_lock);
		ecm_db_iface_deref(nii);
		return ii;
	}
	ecm_db_iface_add_loopback(nii, type_info->os_specific_ident, dev_name,
			mtu, dev_interface_num, nss_interface_num, ecm_interface_loopback_iface_final, nii);

	/*
	 * Ensure our thread persists (and hence this module) for as long as the interface is referenced as we could get
	 * callbacks from the database at any time.
	 */
	ecm_interface_thread_refs++;
	DEBUG_ASSERT(ecm_interface_thread_refs > 0, "Thread refs wrap %d\n", ecm_interface_thread_refs);
	spin_unlock_bh(&ecm_interface_lock);

	DEBUG_TRACE("%p: loopback iface established\n", nii);
	return nii;
}

/*
 * ecm_interface_ipsec_tunnel_interface_establish()
 *	Returns a reference to a iface of the IPSEC_TUNNEL type, possibly creating one if necessary.
 * Returns NULL on failure or a reference to interface.
 *
 * NOTE: GGG TODO THIS NEEDS TO TAKE A PROPER APPROACH TO IPSEC TUNNELS USING ENDPOINT ADDRESSING AS THE TYPE INFO KEYS
 */
static struct ecm_db_iface_instance *ecm_interface_ipsec_tunnel_interface_establish(struct ecm_db_interface_info_ipsec_tunnel *type_info,
							char *dev_name, int32_t dev_interface_num, int32_t nss_interface_num, int32_t mtu)
{
	struct ecm_db_iface_instance *nii;
	struct ecm_db_iface_instance *ii;

	DEBUG_INFO("Establish IPSEC_TUNNEL iface: %s with os_specific_ident: %u, MTU: %d, if num: %d, nss if id: %d\n",
			dev_name, type_info->os_specific_ident, mtu, dev_interface_num, nss_interface_num);

	/*
	 * Locate the iface
	 */
	ii = ecm_db_iface_find_and_ref_ipsec_tunnel(type_info->os_specific_ident);
	if (ii) {
		DEBUG_TRACE("%p: iface established\n", ii);
		return ii;
	}

	/*
	 * No iface - create one
	 */
	nii = ecm_db_iface_alloc();
	if (!nii) {
		DEBUG_WARN("Failed to establish iface\n");
		return NULL;
	}

	/*
	 * Add iface into the database, atomically to avoid races creating the same thing
	 */
	spin_lock_bh(&ecm_interface_lock);
	ii = ecm_db_iface_find_and_ref_ipsec_tunnel(type_info->os_specific_ident);
	if (ii) {
		spin_unlock_bh(&ecm_interface_lock);
		ecm_db_iface_deref(nii);
		return ii;
	}
	ecm_db_iface_add_ipsec_tunnel(nii, type_info->os_specific_ident, dev_name,
			mtu, dev_interface_num, nss_interface_num, ecm_interface_ipsec_tunnel_iface_final, nii);

	/*
	 * Ensure our thread persists (and hence this module) for as long as the interface is referenced as we could get
	 * callbacks from the database at any time.
	 */
	ecm_interface_thread_refs++;
	DEBUG_ASSERT(ecm_interface_thread_refs > 0, "Thread refs wrap %d\n", ecm_interface_thread_refs);
	spin_unlock_bh(&ecm_interface_lock);

	DEBUG_TRACE("%p: ipsec_tunnel iface established\n", nii);
	return nii;
}

#ifdef CONFIG_IPV6_SIT_6RD
/*
 * ecm_interface_sit_interface_establish()
 *	Returns a reference to a iface of the SIT type, possibly creating one if necessary.
 * Returns NULL on failure or a reference to interface.
 */
static struct ecm_db_iface_instance *ecm_interface_sit_interface_establish(struct ecm_db_interface_info_sit *type_info,
							char *dev_name, int32_t dev_interface_num, int32_t nss_interface_num, int32_t mtu)
{
	struct ecm_db_iface_instance *nii;
	struct ecm_db_iface_instance *ii;

	DEBUG_INFO("Establish SIT iface: %s with saddr: " ECM_IP_ADDR_OCTAL_FMT ", daddr: " ECM_IP_ADDR_OCTAL_FMT ", MTU: %d, if num: %d, nss if id: %d\n",
			dev_name, ECM_IP_ADDR_TO_OCTAL(type_info->saddr), ECM_IP_ADDR_TO_OCTAL(type_info->daddr), mtu, dev_interface_num, nss_interface_num);

	/*
	 * Locate the iface
	 */
	ii = ecm_db_iface_find_and_ref_sit(type_info->saddr, type_info->daddr);
	if (ii) {
		DEBUG_TRACE("%p: iface established\n", ii);
		return ii;
	}

	/*
	 * No iface - create one
	 */
	nii = ecm_db_iface_alloc();
	if (!nii) {
		DEBUG_WARN("Failed to establish iface\n");
		return NULL;
	}

	/*
	 * Add iface into the database, atomically to avoid races creating the same thing
	 */
	spin_lock_bh(&ecm_interface_lock);
	ii = ecm_db_iface_find_and_ref_sit(type_info->saddr, type_info->daddr);
	if (ii) {
		spin_unlock_bh(&ecm_interface_lock);
		ecm_db_iface_deref(nii);
		return ii;
	}
	ecm_db_iface_add_sit(nii, type_info, dev_name, mtu, dev_interface_num,
			nss_interface_num, ecm_interface_sit_iface_final, nii);

	/*
	 * Ensure our thread persists (and hence this module) for as long as the interface is referenced as we could get
	 * callbacks from the database at any time.
	 */
	ecm_interface_thread_refs++;
	DEBUG_ASSERT(ecm_interface_thread_refs > 0, "Thread refs wrap %d\n", ecm_interface_thread_refs);
	spin_unlock_bh(&ecm_interface_lock);

	DEBUG_TRACE("%p: sit iface established\n", nii);
	return nii;
}
#endif

/*
 * ecm_interface_tunipip6_interface_establish()
 *	Returns a reference to a iface of the TUNIPIP6 type, possibly creating one if necessary.
 * Returns NULL on failure or a reference to interface.
 */
static struct ecm_db_iface_instance *ecm_interface_tunipip6_interface_establish(struct ecm_db_interface_info_tunipip6 *type_info,
							char *dev_name, int32_t dev_interface_num, int32_t nss_interface_num, int32_t mtu)
{
	struct ecm_db_iface_instance *nii;
	struct ecm_db_iface_instance *ii;

	DEBUG_INFO("Establish TUNIPIP6 iface: %s with saddr: " ECM_IP_ADDR_OCTAL_FMT ", daddr: " ECM_IP_ADDR_OCTAL_FMT ", MTU: %d, if num: %d, nss if id: %d\n",
			dev_name, ECM_IP_ADDR_TO_OCTAL(type_info->saddr), ECM_IP_ADDR_TO_OCTAL(type_info->daddr), mtu, dev_interface_num, nss_interface_num);

	/*
	 * Locate the iface
	 */
	ii = ecm_db_iface_find_and_ref_tunipip6(type_info->saddr, type_info->daddr);
	if (ii) {
		DEBUG_TRACE("%p: iface established\n", ii);
		return ii;
	}

	/*
	 * No iface - create one
	 */
	nii = ecm_db_iface_alloc();
	if (!nii) {
		DEBUG_WARN("Failed to establish iface\n");
		return NULL;
	}

	/*
	 * Add iface into the database, atomically to avoid races creating the same thing
	 */
	spin_lock_bh(&ecm_interface_lock);
	ii = ecm_db_iface_find_and_ref_tunipip6(type_info->saddr, type_info->daddr);
	if (ii) {
		spin_unlock_bh(&ecm_interface_lock);
		ecm_db_iface_deref(nii);
		return ii;
	}
	ecm_db_iface_add_tunipip6(nii, type_info, dev_name, mtu, dev_interface_num,
			nss_interface_num, ecm_interface_tunipip6_iface_final, nii);

	/*
	 * Ensure our thread persists (and hence this module) for as long as the interface is referenced as we could get
	 * callbacks from the database at any time.
	 */
	ecm_interface_thread_refs++;
	DEBUG_ASSERT(ecm_interface_thread_refs > 0, "Thread refs wrap %d\n", ecm_interface_thread_refs);
	spin_unlock_bh(&ecm_interface_lock);

	DEBUG_TRACE("%p: tunipip6 iface established\n", nii);
	return nii;
}

/*
 * ecm_interface_establish_and_ref()
 *	Establish an interface instance for the given interface detail.
 */
struct ecm_db_iface_instance *ecm_interface_establish_and_ref(struct net_device *dev)
{
	int32_t dev_interface_num;
	char *dev_name;
	int32_t dev_type;
	int32_t dev_mtu;
	int32_t nss_interface_num;
	struct ecm_db_iface_instance *ii;
	union {
		struct ecm_db_interface_info_ethernet ethernet;		/* type == ECM_DB_IFACE_TYPE_ETHERNET */
		struct ecm_db_interface_info_vlan vlan;			/* type == ECM_DB_IFACE_TYPE_VLAN */
		struct ecm_db_interface_info_lag lag;			/* type == ECM_DB_IFACE_TYPE_LAG */
		struct ecm_db_interface_info_bridge bridge;		/* type == ECM_DB_IFACE_TYPE_BRIDGE */
		struct ecm_db_interface_info_pppoe pppoe;		/* type == ECM_DB_IFACE_TYPE_PPPOE */
		struct ecm_db_interface_info_unknown unknown;		/* type == ECM_DB_IFACE_TYPE_UNKNOWN */
		struct ecm_db_interface_info_loopback loopback;		/* type == ECM_DB_IFACE_TYPE_LOOPBACK */
		struct ecm_db_interface_info_ipsec_tunnel ipsec_tunnel;	/* type == ECM_DB_IFACE_TYPE_IPSEC_TUNNEL */
		struct ecm_db_interface_info_sit sit;			/* type == ECM_DB_IFACE_TYPE_SIT */
		struct ecm_db_interface_info_tunipip6 tunipip6;		/* type == ECM_DB_IFACE_TYPE_TUNIPIP6 */
	} type_info;

#ifdef ECM_INTERFACE_PPP_SUPPORT
	int channel_count;
	struct ppp_channel *ppp_chan[1];
	const struct ppp_channel_ops *ppp_chan_ops;
	int channel_protocol;
	struct pppoe_channel_ops *pppoe_chan_ops;
	struct pppoe_opt addressing;
#endif

	/*
	 * Get basic information about the given device
	 */
	dev_interface_num = dev->ifindex;
	dev_name = dev->name;
	dev_type = dev->type;
	dev_mtu = dev->mtu;

	/*
	 * Does the NSS recognise this interface?
	 */
	nss_interface_num = nss_cmn_get_interface_number_by_dev(dev);

	DEBUG_TRACE("Establish interface instance for device: %p is type: %d, name: %s, ifindex: %d, nss_if: %d, mtu: %d\n",
			dev, dev_type, dev_name, dev_interface_num, nss_interface_num, dev_mtu);

	/*
	 * Extract from the device more type-specific information
	 */
	if (dev_type == ARPHRD_ETHER) {
		/*
		 * Ethernet - but what sub type?
		 */

		/*
		 * VLAN?
		 */
		if (is_vlan_dev(dev)) {
			/*
			 * VLAN master
			 * GGG No locking needed here, ASSUMPTION is that real_dev is held for as long as we have dev.
			 */
			memcpy(type_info.vlan.address, dev->dev_addr, 6);
			type_info.vlan.vlan_tag = vlan_dev_priv(dev)->vlan_id;
			DEBUG_TRACE("Net device: %p is VLAN, mac: %pM, vlan_id: %x\n",
					dev, type_info.vlan.address, type_info.vlan.vlan_tag);

			/*
			 * Establish this type of interface
			 */
			ii = ecm_interface_vlan_interface_establish(&type_info.vlan, dev_name, dev_interface_num, nss_interface_num, dev_mtu);
			return ii;
		}

		/*
		 * BRIDGE?
		 */
		if (ecm_front_end_is_bridge_device(dev)) {
			/*
			 * Bridge
			 */
			memcpy(type_info.bridge.address, dev->dev_addr, 6);

			DEBUG_TRACE("Net device: %p is BRIDGE, mac: %pM\n",
					dev, type_info.bridge.address);

			/*
			 * Establish this type of interface
			 */
			ii = ecm_interface_bridge_interface_establish(&type_info.bridge, dev_name, dev_interface_num, nss_interface_num, dev_mtu);
			return ii;
		}

		/*
		 * LAG?
		 */
		if (ecm_front_end_is_lag_master(dev)) {
			/*
			 * Link aggregation
			 */
			memcpy(type_info.lag.address, dev->dev_addr, 6);

			DEBUG_TRACE("Net device: %p is LAG, mac: %pM\n",
					dev, type_info.lag.address);

			/*
			 * Establish this type of interface
			 */
			ii = ecm_interface_lag_interface_establish(&type_info.lag, dev_name, dev_interface_num, nss_interface_num, dev_mtu);
			return ii;
		}

		/*
		 * ETHERNET!
		 * Just plain ethernet it seems
		 */
		memcpy(type_info.ethernet.address, dev->dev_addr, 6);
		DEBUG_TRACE("Net device: %p is ETHERNET, mac: %pM\n",
				dev, type_info.ethernet.address);

		/*
		 * Establish this type of interface
		 */
		ii = ecm_interface_ethernet_interface_establish(&type_info.ethernet, dev_name, dev_interface_num, nss_interface_num, dev_mtu);
		return ii;
	}

	/*
	 * LOOPBACK?
	 */
	if (dev_type == ARPHRD_LOOPBACK) {
		DEBUG_TRACE("Net device: %p is LOOPBACK type: %d\n", dev, dev_type);
		type_info.loopback.os_specific_ident = dev_interface_num;
		ii = ecm_interface_loopback_interface_establish(&type_info.loopback, dev_name, dev_interface_num, nss_interface_num, dev_mtu);
		return ii;
	}

	/*
	 * IPSEC?
	 */
	if (dev_type == ECM_ARPHRD_IPSEC_TUNNEL_TYPE) {
		DEBUG_TRACE("Net device: %p is IPSec tunnel type: %d\n", dev, dev_type);
		type_info.ipsec_tunnel.os_specific_ident = dev_interface_num;
		// GGG TODO Flesh this out with tunnel endpoint addressing detail
		ii = ecm_interface_ipsec_tunnel_interface_establish(&type_info.ipsec_tunnel, dev_name, dev_interface_num, nss_interface_num, dev_mtu);
		return ii;
	}

#ifdef CONFIG_IPV6_SIT_6RD
	/*
	 * SIT (6-in-4)?
	 */
	if (dev_type == ARPHRD_SIT) {
		struct ip_tunnel *tunnel;
		struct ip_tunnel_6rd_parm *ip6rd;
		const struct iphdr  *tiph;

		DEBUG_TRACE("Net device: %p is SIT (6-in-4) type: %d\n", dev, dev_type);

		tunnel = (struct ip_tunnel*)netdev_priv(dev);
		ip6rd =  &tunnel->ip6rd;

		/*
		 * Get the Tunnel device IP header info
		 */
		tiph = &tunnel->parms.iph ;

		type_info.sit.prefixlen = ip6rd->prefixlen;
		type_info.sit.relay_prefix = ip6rd->relay_prefix;
		type_info.sit.relay_prefixlen = ip6rd->relay_prefixlen;
		ECM_NIN4_ADDR_TO_IP_ADDR(type_info.sit.saddr, tiph->saddr);
		ECM_NIN4_ADDR_TO_IP_ADDR(type_info.sit.daddr, tiph->daddr);
		type_info.sit.prefix[0] = ntohl(ip6rd->prefix.s6_addr32[0]);
		type_info.sit.prefix[1] = ntohl(ip6rd->prefix.s6_addr32[1]);
		type_info.sit.prefix[2] = ntohl(ip6rd->prefix.s6_addr32[2]);
		type_info.sit.prefix[3] = ntohl(ip6rd->prefix.s6_addr32[3]);
		type_info.sit.ttl = tiph->ttl;
		type_info.sit.tos = tiph->tos;
		
		ii = ecm_interface_sit_interface_establish(&type_info.sit, dev_name, dev_interface_num, nss_interface_num, dev_mtu);
		return ii;
	}
#endif

	/*
	 * IPIP6 Tunnel?
	 */
	if (dev_type == ARPHRD_TUNNEL6) {
		struct ip6_tnl *tunnel;
		struct flowi6 *fl6;

		DEBUG_TRACE("Net device: %p is TUNIPIP6 type: %d\n", dev, dev_type);

		/*
		 * Get the tunnel device flow information (discover the output path of the tunnel)
		 */
		tunnel = (struct ip6_tnl *)netdev_priv(dev);
		fl6 = &tunnel->fl.u.ip6;

		ECM_NIN6_ADDR_TO_IP_ADDR(type_info.tunipip6.saddr, fl6->saddr);
		ECM_NIN6_ADDR_TO_IP_ADDR(type_info.tunipip6.daddr, fl6->daddr);
		type_info.tunipip6.hop_limit = tunnel->parms.hop_limit;
		type_info.tunipip6.flags = ntohl(tunnel->parms.flags);
		type_info.tunipip6.flowlabel = fl6->flowlabel;  /* flow Label In kernel is stored in big endian format */
		
		ii = ecm_interface_tunipip6_interface_establish(&type_info.tunipip6, dev_name, dev_interface_num, nss_interface_num, dev_mtu);
		return ii;
	}

	/*
	 * If this is NOT PPP then it is unknown to the ecm
	 */
	if (dev_type != ARPHRD_PPP) {
		DEBUG_TRACE("Net device: %p is UNKNOWN type: %d\n", dev, dev_type);
		type_info.unknown.os_specific_ident = dev_interface_num;

		/*
		 * Establish this type of interface
		 */
		ii = ecm_interface_unknown_interface_establish(&type_info.unknown, dev_name, dev_interface_num, nss_interface_num, dev_mtu);
		return ii;
	}

#ifndef ECM_INTERFACE_PPP_SUPPORT
	/*
	 * PPP support is NOT provided for.
	 * Interface is therefore unknown
	 */
	DEBUG_TRACE("Net device: %p is UNKNOWN (PPP Unsupported) type: %d\n", dev, dev_type);
	type_info.unknown.os_specific_ident = dev_interface_num;

	/*
	 * Establish this type of interface
	 */
	ii = ecm_interface_unknown_interface_establish(&type_info.unknown, dev_name, dev_interface_num, nss_interface_num, dev_mtu);
	return ii;
#else
	/*
	 * PPP - but what is the channel type?
	 * First: If this is multi-link then we do not support it
	 */
	if (ppp_is_multilink(dev) > 0) {
		DEBUG_TRACE("Net device: %p is MULTILINK PPP - Unknown to the ECM\n", dev);
		type_info.unknown.os_specific_ident = dev_interface_num;

		/*
		 * Establish this type of interface
		 */
		ii = ecm_interface_unknown_interface_establish(&type_info.unknown, dev_name, dev_interface_num, nss_interface_num, dev_mtu);
		return ii;
	}

	DEBUG_TRACE("Net device: %p is PPP\n", dev);

	/*
	 * Get the PPP channel and then enquire what kind of channel it is
	 * NOTE: Not multilink so only one channel to get.
	 */
	channel_count = ppp_hold_channels(dev, ppp_chan, 1);
	if (channel_count != 1) {
		DEBUG_TRACE("Net device: %p PPP has %d channels - Unknown to the ECM\n", dev, channel_count);
		type_info.unknown.os_specific_ident = dev_interface_num;

		/*
		 * Establish this type of interface
		 */
		ii = ecm_interface_unknown_interface_establish(&type_info.unknown, dev_name, dev_interface_num, nss_interface_num, dev_mtu);
		return ii;
	}

	/*
	 * Get channel protocol type
	 */
	ppp_chan_ops = ppp_chan[0]->ops;
	channel_protocol = ppp_chan_ops->get_channel_protocol(ppp_chan[0]);
	if (channel_protocol != PX_PROTO_OE) {
		DEBUG_TRACE("Net device: %p PPP channel protocol: %d - Unknown to the ECM\n", dev, channel_protocol);
		type_info.unknown.os_specific_ident = dev_interface_num;

		/*
		 * Release the channel
		 */
		ppp_release_channels(ppp_chan, 1);

		/*
		 * Establish this type of interface
		 */
		ii = ecm_interface_unknown_interface_establish(&type_info.unknown, dev_name, dev_interface_num, nss_interface_num, dev_mtu);
		return ii;
	}

	/*
	 * PPPoE channel
	 */
	DEBUG_TRACE("Net device: %p PPP channel is PPPoE\n", dev);

	/*
	 * Get PPPoE session information and the underlying device it is using.
	 * NOTE: We know this is PPPoE so we can cast the ppp_chan_ops to pppoe_chan_ops and
	 * use its channel specific methods.
	 */
	pppoe_chan_ops = (struct pppoe_channel_ops *)ppp_chan_ops;
	pppoe_chan_ops->get_addressing(ppp_chan[0], &addressing);

	type_info.pppoe.pppoe_session_id = (uint16_t)addressing.pa.sid;
	memcpy(type_info.pppoe.remote_mac, addressing.pa.remote, ETH_ALEN);

	/*
	 * Release the channel.  Note that next_dev is still (correctly) held.
	 */
	ppp_release_channels(ppp_chan, 1);

	DEBUG_TRACE("Net device: %p PPPoE session: %x, remote mac: %pM\n",
			dev, type_info.pppoe.pppoe_session_id, type_info.pppoe.remote_mac);

	/*
	 * Establish this type of interface
	 */
	ii = ecm_interface_pppoe_interface_establish(&type_info.pppoe, dev_name, dev_interface_num, nss_interface_num, dev_mtu);
	return ii;
#endif
}
EXPORT_SYMBOL(ecm_interface_establish_and_ref);

/*
 * ecm_interface_heirarchy_construct()
 *	Construct an interface heirarchy.
 *
 * Using the given addressing, locate the interface heirarchy used to emit packets to that destination.
 * This is the heirarchy of interfaces a packet would transit to emit from the device.
 * For example, with this network arrangement:
 *
 * PPPoE--VLAN--BRIDGE--BRIDGE_PORT(LAG_MASTER)--LAG_SLAVE_0--10.22.33.11
 *
 * Given the IP address 10.22.33.11 this will create an interface heirarchy (in interracfes[]) of:
 * LAG_SLAVE_0 @ [ECM_DB_IFACE_HEIRARCHY_MAX - 5]
 * LAG_MASTER @ [ECM_DB_IFACE_HEIRARCHY_MAX - 4]
 * BRIDGE @ [ECM_DB_IFACE_HEIRARCHY_MAX - 3]
 * VLAN @ [ECM_DB_IFACE_HEIRARCHY_MAX - 2]
 * PPPOE @ [ECM_DB_IFACE_HEIRARCHY_MAX - 1]
 * The value returned is (ECM_DB_IFACE_HEIRARCHY_MAX - 5)
 *
 * IMPORTANT: This function will return any known interfaces in the database, when interfaces do not exist in the database
 * they will be created and added automatically to the database.
 *
 * GGG TODO Make this function work for IPv6!!!!!!!!!!!!!!
 */
int32_t ecm_interface_heirarchy_construct(struct ecm_db_iface_instance *interfaces[], ip_addr_t packet_src_addr, ip_addr_t packet_dest_addr, int packet_protocol)
{
	char __attribute__((unused)) src_addr_str[40];
	char __attribute__((unused)) dest_addr_str[40];
	int protocol;
	ip_addr_t src_addr;
	ip_addr_t dest_addr;
	struct ecm_interface_route src_rt;
	struct ecm_interface_route dest_rt;
	struct dst_entry *src_dst;
	struct dst_entry *dest_dst;
	struct net_device *src_dev;
	struct net_device *dest_dev;
	char *src_dev_name;
	char *dest_dev_name;
	int32_t src_dev_type;
	int32_t dest_dev_type;
	int32_t current_interface_index;

	/*
	 * Get a big endian of the IPv4 address we have been given as our starting point.
	 */
	protocol = packet_protocol;
	ECM_IP_ADDR_COPY(src_addr, packet_src_addr);
	ECM_IP_ADDR_COPY(dest_addr, packet_dest_addr);
	ecm_ip_addr_to_string(src_addr_str, src_addr);
	ecm_ip_addr_to_string(dest_addr_str, dest_addr);
	DEBUG_TRACE("Construct interface heirarchy for from src_addr: %s to dest_addr: %s, protocol: %d\n", src_addr_str, dest_addr_str, protocol);

	/*
	 * Begin by finding the interface to which we reach the given addresses
	 */
	if (!ecm_interface_find_route_by_addr(src_addr, &src_rt)) {
		DEBUG_WARN("Construct interface heirarchy failed from src_addr: %s to dest_addr: %s, protocol: %d\n", src_addr_str, dest_addr_str, protocol);
		return ECM_DB_IFACE_HEIRARCHY_MAX;
	}
	if (!ecm_interface_find_route_by_addr(dest_addr, &dest_rt)) {
		ecm_interface_route_release(&src_rt);
		DEBUG_WARN("Construct interface heirarchy failed from src_addr: %s to dest_addr: %s, protocol: %d\n", src_addr_str, dest_addr_str, protocol);
		return ECM_DB_IFACE_HEIRARCHY_MAX;
	}

	/*
	 * Get the dst entries
	 */
	src_dst = src_rt.dst;
	dest_dst = dest_rt.dst;

	/*
	 * Get device from the destination entries
	 */
	src_dev = src_dst->dev;
	dev_hold(src_dev);
	src_dev_name = src_dev->name;
	src_dev_type = src_dev->type;

	dest_dev = dest_dst->dev;
	dev_hold(dest_dev);
	dest_dev_name = dest_dev->name;
	dest_dev_type = dest_dev->type;

	/*
	 * Release route (we hold devices for ourselves)
	 */
	ecm_interface_route_release(&src_rt);
	ecm_interface_route_release(&dest_rt);

	/*
	 * Iterate until we are done or get to the max number of interfaces we can record.
	 * NOTE: current_interface_index tracks the position of the first interface position in interfaces[]
	 * because we add from the end first_interface grows downwards.
	 */
	current_interface_index = ECM_DB_IFACE_HEIRARCHY_MAX;
	while (current_interface_index > 0) {
		struct ecm_db_iface_instance *ii;
		struct net_device *next_dev;

		/*
		 * Get the ecm db interface instance for the device at hand
		 */
		ii = ecm_interface_establish_and_ref(dest_dev);

		/*
		 * If the interface could not be established then we abort
		 */
		if (!ii) {
			DEBUG_WARN("Failed to establish interface: %p, name: %s\n", dest_dev, dest_dev_name);
			dev_put(src_dev);
			dev_put(dest_dev);

			/*
			 * Release the interfaces heirarchy we constructed to this point.
			 */
			ecm_db_connection_interfaces_deref(interfaces, current_interface_index);
			return ECM_DB_IFACE_HEIRARCHY_MAX;
		}

		/*
		 * Record the interface instance into the interfaces[]
		 */
		current_interface_index--;
		interfaces[current_interface_index] = ii;

		/*
		 * Now we have to figure out what the next device will be (in the transmission path) the skb
		 * will use to emit to the destination address.
		 */
		do {
#ifdef ECM_INTERFACE_PPP_SUPPORT
			int channel_count;
			struct ppp_channel *ppp_chan[1];
			const struct ppp_channel_ops *ppp_chan_ops;
			int channel_protocol;
			struct pppoe_channel_ops *pppoe_chan_ops;
			struct pppoe_opt addressing;
#endif

			DEBUG_TRACE("Net device: %p is type: %d, name: %s\n", dest_dev, dest_dev_type, dest_dev_name);
			next_dev = NULL;

			if (dest_dev_type == ARPHRD_ETHER) {
				/*
				 * Ethernet - but what sub type?
				 */

				/*
				 * VLAN?
				 */
				if (is_vlan_dev(dest_dev)) {
					/*
					 * VLAN master
					 * No locking needed here, ASSUMPTION is that real_dev is held for as long as we have dev.
					 */
					next_dev = vlan_dev_priv(dest_dev)->real_dev;
					dev_hold(next_dev);
					DEBUG_TRACE("Net device: %p is VLAN, slave dev: %p (%s)\n",
							dest_dev, next_dev, next_dev->name);
					break;
				}

				/*
				 * BRIDGE?
				 */
				if (ecm_front_end_is_bridge_device(dest_dev)) {
					/*
					 * Bridge
					 * Figure out which port device the skb will go to using the dest_addr.
					 */
					bool on_link;
					ip_addr_t gw_addr;
					uint8_t mac_addr[ETH_ALEN];
					if (!ecm_interface_mac_addr_get(dest_addr, mac_addr, &on_link, gw_addr)) {
						/*
						 * Possible ARP does not know the address yet
						 */
						DEBUG_WARN("Unable to obtain MAC address for " ECM_IP_ADDR_DOT_FMT "\n", ECM_IP_ADDR_TO_DOT(dest_addr));
						dev_put(src_dev);
						dev_put(dest_dev);

						/*
						 * Release the interfaces heirarchy we constructed to this point.
						 */
						ecm_db_connection_interfaces_deref(interfaces, current_interface_index);
						return ECM_DB_IFACE_HEIRARCHY_MAX;
					}
					next_dev = br_port_dev_get(dest_dev, mac_addr);
					if (!next_dev) {
						DEBUG_WARN("Unable to obtain output port for: %pM\n", mac_addr);
						dev_put(src_dev);
						dev_put(dest_dev);

						/*
						 * Release the interfaces heirarchy we constructed to this point.
						 */
						ecm_db_connection_interfaces_deref(interfaces, current_interface_index);
						return ECM_DB_IFACE_HEIRARCHY_MAX;
					}
					DEBUG_TRACE("Net device: %p is BRIDGE, next_dev: %p (%s)\n", dest_dev, next_dev, next_dev->name);
					break;
				}

				/*
				 * LAG?
				 */
				if (ecm_front_end_is_lag_master(dest_dev)) {
					/*
					 * Link aggregation
					 * Figure out which slave device of the link aggregation will be used to reach the destination.
					 */
					bool src_on_link;
					bool dest_on_link;
					ip_addr_t src_gw_addr;
					ip_addr_t dest_gw_addr;
					uint32_t src_addr_32;
					uint32_t dest_addr_32;
					uint8_t src_mac_addr[ETH_ALEN];
					uint8_t dest_mac_addr[ETH_ALEN];

					if (!ecm_interface_mac_addr_get(src_addr, src_mac_addr, &src_on_link, src_gw_addr)) {
						/*
						 * Possible ARP does not know the address yet
						 */
						DEBUG_WARN("Unable to obtain MAC address for " ECM_IP_ADDR_DOT_FMT "\n", ECM_IP_ADDR_TO_DOT(src_addr));
						dev_put(src_dev);
						dev_put(dest_dev);

						/*
						 * Release the interfaces heirarchy we constructed to this point.
						 */
						ecm_db_connection_interfaces_deref(interfaces, current_interface_index);
						return ECM_DB_IFACE_HEIRARCHY_MAX;
					}
					if (!ecm_interface_mac_addr_get(dest_addr, dest_mac_addr, &dest_on_link, dest_gw_addr)) {
						/*
						 * Possible ARP does not know the address yet
						 */
						DEBUG_WARN("Unable to obtain MAC address for " ECM_IP_ADDR_DOT_FMT "\n", ECM_IP_ADDR_TO_DOT(dest_addr));
						dev_put(src_dev);
						dev_put(dest_dev);

						/*
						 * Release the interfaces heirarchy we constructed to this point.
						 */
						ecm_db_connection_interfaces_deref(interfaces, current_interface_index);
						return ECM_DB_IFACE_HEIRARCHY_MAX;
					}

					ECM_IP_ADDR_TO_HIN4_ADDR(src_addr_32, src_addr);
					ECM_IP_ADDR_TO_HIN4_ADDR(dest_addr_32, dest_addr);

					next_dev = bond_get_tx_dev(NULL, src_mac_addr, dest_mac_addr, &src_addr_32, &dest_addr_32, (uint16_t)protocol, dest_dev);
					if (next_dev) {
						dev_hold(next_dev);
					} else {
						DEBUG_WARN("Unable to obtain LAG output slave device\n");
						dev_put(src_dev);
						dev_put(dest_dev);

						/*
						 * Release the interfaces heirarchy we constructed to this point.
						 */
						ecm_db_connection_interfaces_deref(interfaces, current_interface_index);
						return ECM_DB_IFACE_HEIRARCHY_MAX;
					}

					DEBUG_TRACE("Net device: %p is LAG, slave dev: %p (%s)\n", dest_dev, next_dev, next_dev->name);

					break;
				}

				/*
				 * ETHERNET!
				 * Just plain ethernet it seems.
				 */
				DEBUG_TRACE("Net device: %p is ETHERNET\n", dest_dev);
				break;
			} 

			/*
			 * LOOPBACK?
			 */
			if (dest_dev_type == ARPHRD_LOOPBACK) {
				DEBUG_TRACE("Net device: %p is LOOPBACK type: %d\n", dest_dev, dest_dev_type);
				break;
			}

			/*
			 * IPSEC?
			 */
			if (dest_dev_type == ECM_ARPHRD_IPSEC_TUNNEL_TYPE) {
				DEBUG_TRACE("Net device: %p is IPSec tunnel type: %d\n", dest_dev, dest_dev_type);
				// GGG TODO Figure out the next device the tunnel is using...
				break;
			}

			/*
			 * SIT (6-in-4)?
			 */
			if (dest_dev_type == ARPHRD_SIT) {
				DEBUG_TRACE("Net device: %p is SIT (6-in-4) type: %d\n", dest_dev, dest_dev_type);
				break;
			}

			/*
			 * IPIP6 Tunnel?
			 */
			if (dest_dev_type == ARPHRD_TUNNEL6) {
				DEBUG_TRACE("Net device: %p is TUNIPIP6 type: %d\n", dest_dev, dest_dev_type);
				break;
			}

			/*
			 * If this is NOT PPP then it is unknown to the ecm and we cannot figure out it's next device.
			 */
			if (dest_dev_type != ARPHRD_PPP) {
				DEBUG_TRACE("Net device: %p is UNKNOWN type: %d\n", dest_dev, dest_dev_type);
				break;
			}

#ifndef ECM_INTERFACE_PPP_SUPPORT
			DEBUG_TRACE("Net device: %p is UNKNOWN (PPP Unsupported) type: %d\n", dest_dev, dest_dev_type);
#else
			/*
			 * PPP - but what is the channel type?
			 * First: If this is multi-link then we do not support it
			 */
			if (ppp_is_multilink(dest_dev) > 0) {
				DEBUG_TRACE("Net device: %p is MULTILINK PPP - Unknown to the ECM\n", dest_dev);
				break;
			}

			DEBUG_TRACE("Net device: %p is PPP\n", dest_dev);

			/*
			 * Get the PPP channel and then enquire what kind of channel it is
			 * NOTE: Not multilink so only one channel to get.
			 */
			channel_count = ppp_hold_channels(dest_dev, ppp_chan, 1);
			if (channel_count != 1) {
				DEBUG_TRACE("Net device: %p PPP has %d channels - Unknown to the ECM\n",
						dest_dev, channel_count);
				break;
			}

			/*
			 * Get channel protocol type
			 */
			ppp_chan_ops = ppp_chan[0]->ops;
			channel_protocol = ppp_chan_ops->get_channel_protocol(ppp_chan[0]);
			if (channel_protocol != PX_PROTO_OE) {
				DEBUG_TRACE("Net device: %p PPP channel protocol: %d - Unknown to the ECM\n",
						dest_dev, channel_protocol);
				
				/*
				 * Release the channel
				 */
				ppp_release_channels(ppp_chan, 1);

				break;
			}

			/*
			 * PPPoE channel
			 */
			DEBUG_TRACE("Net device: %p PPP channel is PPPoE\n", dest_dev);
	
			/*
			 * Get PPPoE session information and the underlying device it is using.
			 * NOTE: We know this is PPPoE so we can cast the ppp_chan_ops to pppoe_chan_ops and
			 * use its channel specific methods.
			 */
			pppoe_chan_ops = (struct pppoe_channel_ops *)ppp_chan_ops;
			pppoe_chan_ops->get_addressing(ppp_chan[0], &addressing);

			/*
			 * Copy the dev hold into this, we will release the hold later
			 */
			next_dev = addressing.dev;

			DEBUG_TRACE("Net device: %p, next device: %p (%s)\n", dest_dev, next_dev, next_dev->name);

			/*
			 * Release the channel.  Note that next_dev is still (correctly) held.
			 */
			ppp_release_channels(ppp_chan, 1);
#endif
		} while (false);

		/*
		 * No longer need dest_dev as it may become next_dev
		 */
		dev_put(dest_dev);

		/*
		 * Check out the next_dev, if any
		 */
		if (!next_dev) {
			int32_t i __attribute__((unused));
			DEBUG_INFO("Completed interface heirarchy construct with first interface @: %d\n", current_interface_index);
#if DEBUG_LEVEL > 1
			for (i = current_interface_index; i < ECM_DB_IFACE_HEIRARCHY_MAX; ++i) {
				DEBUG_TRACE("\tInterface @ %d: %p, type: %d, name: %s\n",
						i, interfaces[i], ecm_db_connection_iface_type_get(interfaces[i]), ecm_db_interface_type_to_string(ecm_db_connection_iface_type_get(interfaces[i])));
			}
#endif

			/*
			 * Release src_dev now
			 */
			dev_put(src_dev);

			return current_interface_index;
		}

		/*
		 * dest_dev becomes next_dev
		 */
		dest_dev = next_dev;
		dest_dev_name = dest_dev->name;
		dest_dev_type = dest_dev->type;
	}

	DEBUG_WARN("Too many interfaces: %d\n", current_interface_index);
	DEBUG_ASSERT(current_interface_index == 0, "Bad logic handling current_interface_index: %d\n", current_interface_index);
	dev_put(src_dev);
	dev_put(dest_dev);

	/*
	 * Release the interfaces heirarchy we constructed to this point.
	 */
	ecm_db_connection_interfaces_deref(interfaces, current_interface_index);
	return ECM_DB_IFACE_HEIRARCHY_MAX;
}
EXPORT_SYMBOL(ecm_interface_heirarchy_construct);

/*
 * ecm_interface_regenerate_connections()
 *	Cause regeneration of all connections that are using the specified interface.
 */
static void ecm_interface_regenerate_connections(struct ecm_db_iface_instance *ii)
{
	struct ecm_db_connection_instance *ci;

	DEBUG_TRACE("Regenerate connections using interface: %p\n", ii);

	/*
	 * Iterate the connections of this interface and cause each one to be re-generated.
	 * GGG TODO NOTE: If this proves slow (need metrics here) we could just regenerate the "lot" with one very simple call.
	 * But this would cause re-gen of every connection which may not be appropriate, this here at least keeps things in scope of the interface
	 * but at the cost of performance.
	 */
	DEBUG_TRACE("%p: Regenerate 'from' connections\n", ii);
	ci = ecm_db_iface_connections_from_get_and_ref_first(ii);
	while (ci) {
		struct ecm_db_connection_instance *cin;
		cin = ecm_db_connection_iface_from_get_and_ref_next(ci);

		DEBUG_TRACE("%p: Regenerate: %p", ii, ci);
		ecm_db_connection_classifier_generation_change(ci);
		ecm_db_connection_deref(ci);
		ci = cin;
	}

	DEBUG_TRACE("%p: Regenerate 'to' connections\n", ii);
	ci = ecm_db_iface_connections_to_get_and_ref_first(ii);
	while (ci) {
		struct ecm_db_connection_instance *cin;
		cin = ecm_db_connection_iface_to_get_and_ref_next(ci);

		DEBUG_TRACE("%p: Regenerate: %p", ii, ci);
		ecm_db_connection_classifier_generation_change(ci);
		ecm_db_connection_deref(ci);
		ci = cin;
	}

	DEBUG_TRACE("%p: Regenerate 'from_nat' connections\n", ii);
	ci = ecm_db_iface_connections_nat_from_get_and_ref_first(ii);
	while (ci) {
		struct ecm_db_connection_instance *cin;
		cin = ecm_db_connection_iface_nat_from_get_and_ref_next(ci);

		DEBUG_TRACE("%p: Regenerate: %p", ii, ci);
		ecm_db_connection_classifier_generation_change(ci);
		ecm_db_connection_deref(ci);
		ci = cin;
	}

	DEBUG_TRACE("%p: Regenerate 'to_nat' connections\n", ii);
	ci = ecm_db_iface_connections_nat_to_get_and_ref_first(ii);
	while (ci) {
		struct ecm_db_connection_instance *cin;
		cin = ecm_db_connection_iface_nat_to_get_and_ref_next(ci);

		DEBUG_TRACE("%p: Regenerate: %p", ii, ci);
		ecm_db_connection_classifier_generation_change(ci);
		ecm_db_connection_deref(ci);
		ci = cin;
	}

	DEBUG_TRACE("%p: Regenerate COMPLETE\n", ii);
}

/*
 * ecm_interface_dev_regenerate_connections()
 *	Cause regeneration of all connections that are using the specified interface.
 */
static void ecm_interface_dev_regenerate_connections(struct net_device *dev)
{
	struct ecm_db_iface_instance *ii;

	DEBUG_INFO("Regenerate connections for: %p (%s)\n", dev, dev->name);

	/*
	 * Establish the interface for the given device.
	 * NOTE: The cute thing here is even if dev is previously unknown to us this will create an interface instance
	 * but it will have no connections to regen and will be destroyed at the end of the function when we deref - so no harm done.
	 * However if the interface is known to us then we will get it returned by this function and process it accordingly.
	 */
	ii = ecm_interface_establish_and_ref(dev);
	if (!ii) {
		DEBUG_WARN("%p: No interface instance could be established for this dev\n", dev);
		return;
	}
	ecm_interface_regenerate_connections(ii);
	DEBUG_TRACE("%p: Regenerate for %p: COMPLETE\n", dev, ii);
	ecm_db_iface_deref(ii);
}

/*
 * ecm_interface_mtu_change()
 *	MTU of interface has changed
 */
static void ecm_interface_mtu_change(struct net_device *dev)
{
	int mtu;
	struct ecm_db_iface_instance *ii;

	mtu = dev->mtu;
	DEBUG_INFO("%p (%s): MTU Change to: %d\n", dev, dev->name, mtu);

	/*
	 * Establish the interface for the given device.
	 */
	ii = ecm_interface_establish_and_ref(dev);
	if (!ii) {
		DEBUG_WARN("%p: No interface instance could be established for this dev\n", dev);
		return;
	}

	/*
	 * Change the mtu
	 */
	ecm_db_iface_mtu_reset(ii, mtu);
	DEBUG_TRACE("%p (%s): MTU Changed to: %d\n", dev, dev->name, mtu);
	ecm_interface_regenerate_connections(ii);
	DEBUG_TRACE("%p: Regenerate for %p: COMPLETE\n", dev, ii);
	ecm_db_iface_deref(ii);
}

/*
 * ecm_interface_netdev_notifier_callback()
 * 	Netdevice notifier callback to inform us of change of state of a netdevice
 */
static int ecm_interface_netdev_notifier_callback(struct notifier_block *this, unsigned long event, void *ptr)
{
	struct net_device *dev __attribute__ ((unused)) = (struct net_device *)ptr;

	DEBUG_INFO("Net device notifier for: %p, name: %s, event: %lx\n", dev, dev->name, event);

	switch (event) {
	case NETDEV_DOWN:
		DEBUG_INFO("Net device: %p, DOWN\n", dev);
		ecm_interface_dev_regenerate_connections(dev);
		break;

	case NETDEV_CHANGE:
		DEBUG_INFO("Net device: %p, CHANGE\n", dev);
		if (!netif_carrier_ok(dev)) {
			DEBUG_INFO("Net device: %p, CARRIER BAD\n", dev);
			ecm_interface_dev_regenerate_connections(dev);
		}
		break;

	case NETDEV_CHANGEMTU:
		DEBUG_INFO("Net device: %p, MTU CHANGE\n", dev);
		ecm_interface_mtu_change(dev);
		break;

	default:
		DEBUG_TRACE("Net device: %p, UNHANDLED: %lx\n", dev, event);
		break;
	}

	return NOTIFY_DONE;
}

/*
 * struct notifier_block ecm_interface_netdev_notifier
 *	Registration for net device changes of state.
 */
static struct notifier_block ecm_interface_netdev_notifier __read_mostly = {
	.notifier_call		= ecm_interface_netdev_notifier_callback,
};

/*
 * ecm_interface_get_terminate()
 */
static ssize_t ecm_interface_get_terminate(struct sys_device *dev,
				  struct sysdev_attribute *attr,
				  char *buf)
{
	ssize_t count;
	unsigned int n;

	spin_lock_bh(&ecm_interface_lock);
	n = ecm_interface_terminate_pending;
	spin_unlock_bh(&ecm_interface_lock);
	count = snprintf(buf, (ssize_t)PAGE_SIZE, "%u\n", n);
	return count;
}

/*
 * ecm_interface_set_terminate()
 *	Writing anything to this 'file' will cause the default classifier to terminate
 */
static ssize_t ecm_interface_set_terminate(struct sys_device *dev,
				  struct sysdev_attribute *attr,
				  const char *buf, size_t count)
{
	DEBUG_INFO("Terminate\n");

	/*
	 * Are we already signalled to terminate?
	 */
	spin_lock_bh(&ecm_interface_lock);
	if (ecm_interface_terminate_pending) {
		spin_unlock_bh(&ecm_interface_lock);
		return 0;
	}

	ecm_interface_terminate_pending = true;
	ecm_interface_thread_refs--;
	DEBUG_ASSERT(ecm_interface_thread_refs >= 0, "Thread ref wrap %d\n", ecm_interface_thread_refs);
	wake_up_process(ecm_interface_thread);
	spin_unlock_bh(&ecm_interface_lock);
	return count;
}

/*
 * ecm_interface_get_stop()
 */
static ssize_t ecm_interface_get_stop(struct sys_device *dev,
				  struct sysdev_attribute *attr,
				  char *buf)
{
	ssize_t count;
	int num;

	/*
	 * Operate under our locks
	 */
	spin_lock_bh(&ecm_interface_lock);
	num = ecm_interface_stopped;
	spin_unlock_bh(&ecm_interface_lock);

	count = snprintf(buf, (ssize_t)PAGE_SIZE, "%d\n", num);
	return count;
}

/*
 * ecm_interface_set_stop()
 */
static ssize_t ecm_interface_set_stop(struct sys_device *dev,
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
	DEBUG_TRACE("ecm_interface_stop = %d\n", num);

	/*
	 * Operate under our locks and stop further processing of packets
	 */
	spin_lock_bh(&ecm_interface_lock);
	ecm_interface_stopped = num;
	spin_unlock_bh(&ecm_interface_lock);

	return count;
}

/*
 * SysFS attributes for the default classifier itself.
 */
static SYSDEV_ATTR(terminate, 0644, ecm_interface_get_terminate, ecm_interface_set_terminate);
static SYSDEV_ATTR(stop, 0644, ecm_interface_get_stop, ecm_interface_set_stop);

/*
 * SysFS class of the ubicom default classifier
 * SysFS control points can be found at /sys/devices/system/ecm_front_end/ecm_front_endX/
 */
static struct sysdev_class ecm_interface_sysclass = {
	.name = "ecm_interface",
};

/*
 * ecm_interface_thread_fn()
 *	A thread to handle tasks that can only be done in thread context.
 */
static int ecm_interface_thread_fn(void *arg)
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
	result = sysdev_class_register(&ecm_interface_sysclass);
	if (result) {
		DEBUG_ERROR("Failed to register SysFS class %d\n", result);
		goto task_cleanup_1;
	}

	/*
	 * Register SYSFS device control
	 */
	memset(&ecm_interface_sys_dev, 0, sizeof(ecm_interface_sys_dev));
	ecm_interface_sys_dev.id = 0;
	ecm_interface_sys_dev.cls = &ecm_interface_sysclass;
	result = sysdev_register(&ecm_interface_sys_dev);
	if (result) {
		DEBUG_ERROR("Failed to register SysFS device %d\n", result);
		goto task_cleanup_2;
	}

	/*
	 * Create files, one for each parameter supported by this module
	 */
	result = sysdev_create_file(&ecm_interface_sys_dev, &attr_terminate);
	if (result) {
		DEBUG_ERROR("Failed to register terminate file %d\n", result);
		goto task_cleanup_3;
	}

	result = sysdev_create_file(&ecm_interface_sys_dev, &attr_stop);
	if (result) {
		DEBUG_ERROR("Failed to register stop file %d\n", result);
		goto task_cleanup_4;
	}

	result = register_netdevice_notifier(&ecm_interface_netdev_notifier);
	if (result != 0) {
		DEBUG_ERROR("Failed to register netdevice notifier %d\n", result);
		goto task_cleanup_5;
	}

	/*
	 * Allow wakeup signals
	 */
	allow_signal(SIGCONT);
	set_current_state(TASK_INTERRUPTIBLE);

	spin_lock_bh(&ecm_interface_lock);

	/*
	 * Set thread refs to 1 - user must terminate us now.
	 */
	ecm_interface_thread_refs = 1;

	while (ecm_interface_thread_refs) {
		/*
		 * Sleep and wait for an instruction
		 */
		spin_unlock_bh(&ecm_interface_lock);
		DEBUG_TRACE("ecm_interface sleep\n");
		schedule();
		set_current_state(TASK_INTERRUPTIBLE);
		spin_lock_bh(&ecm_interface_lock);
	}
	DEBUG_INFO("ecm_interface terminate\n");
	DEBUG_ASSERT(ecm_interface_terminate_pending, "User has not requested terminate\n");
	spin_unlock_bh(&ecm_interface_lock);

	result = 0;

	unregister_netdevice_notifier(&ecm_interface_netdev_notifier);
task_cleanup_5:
	sysdev_remove_file(&ecm_interface_sys_dev, &attr_stop);
task_cleanup_4:
	sysdev_remove_file(&ecm_interface_sys_dev, &attr_terminate);
task_cleanup_3:
	sysdev_unregister(&ecm_interface_sys_dev);
task_cleanup_2:
	sysdev_class_unregister(&ecm_interface_sysclass);
task_cleanup_1:

	module_put(THIS_MODULE);
	return result;
}

/*
 * ecm_interface_init()
 */
static int __init ecm_interface_init(void)
{
	DEBUG_INFO("ECM Interface init\n");

	/*
	 * Initialise our global lock
	 */
	spin_lock_init(&ecm_interface_lock);

	/*
	 * Create a thread to handle the start/stop of the database.
	 * NOTE: We use a thread as some things we need to do cannot be done in this context
	 */
	ecm_interface_thread = kthread_create(ecm_interface_thread_fn, NULL, "%s", "ecm_interface");
	if (!ecm_interface_thread) {
		return -EINVAL;
	}
	wake_up_process(ecm_interface_thread);
	return 0;
}

/*
 * ecm_interface_exit()
 */
static void __exit ecm_interface_exit(void)
{
	DEBUG_INFO("ECM Interface exit\n");
	DEBUG_ASSERT(!ecm_interface_thread_refs, "Thread has refs %d\n", ecm_interface_thread_refs);
}

module_init(ecm_interface_init)
module_exit(ecm_interface_exit)

MODULE_AUTHOR("Qualcomm Atheros, Inc.");
MODULE_DESCRIPTION("ECM Interface");
#ifdef MODULE_LICENSE
MODULE_LICENSE("Dual BSD/GPL");
#endif
