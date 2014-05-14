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

/*
 * Debug output levels
 * 0 = OFF
 * 1 = ASSERTS / ERRORS
 * 2 = 1 + WARN
 * 3 = 2 + INFO
 * 4 = 3 + TRACE
 */
#define DEBUG_LEVEL ECM_DB_DEBUG_LEVEL

#include <nss_api_if.h>

#include "ecm_types.h"
#include "ecm_db_types.h"
#include "ecm_tracker.h"
#include "ecm_classifier.h"
#include "ecm_front_end_types.h"
#include "ecm_classifier_default.h"
#include "ecm_db.h"

/*
 * Magic numbers
 */
#define ECM_DB_CONNECTION_INSTANCE_MAGIC 0xff23
#define ECM_DB_HOST_INSTANCE_MAGIC 0x2873
#define ECM_DB_MAPPING_INSTANCE_MAGIC 0x8765
#define ECM_DB_LISTENER_INSTANCE_MAGIC 0x9876
#define ECM_DB_NODE_INSTANCE_MAGIC 0x3312
#define ECM_DB_IFACE_INSTANCE_MAGIC 0xAEF1
#define ECM_DB_STATE_FILE_INSTANCE_MAGIC 0xB3FE

/*
 * Global lists.
 * All instances are inserted into global list - this allows easy iteration of all instances of a particular type.
 * The list is doubly linked for fast removal.  The list is in no particular order.
 */
struct ecm_db_connection_instance *ecm_db_connections = NULL;
struct ecm_db_mapping_instance *ecm_db_mappings = NULL;
struct ecm_db_host_instance *ecm_db_hosts = NULL;
struct ecm_db_node_instance *ecm_db_nodes = NULL;
struct ecm_db_iface_instance *ecm_db_interfaces = NULL;

/*
 * Connection hash table
 */
#define ECM_DB_CONNECTION_HASH_SLOTS 32768
static struct ecm_db_connection_instance *ecm_db_connection_table[ECM_DB_CONNECTION_HASH_SLOTS];
						/* Slots of the connection hash table */
static int ecm_db_connection_table_lengths[ECM_DB_CONNECTION_HASH_SLOTS];
						/* Tracks how long each chain is */
static int ecm_db_connection_count = 0;		/* Number of connections allocated */
static int ecm_db_connection_serial = 0;		/* Serial number - ensures each connection has a unique serial number.
						 * Serial numbers are used mainly by classifiers that keep their own state
						 * and can 'link' their state to the right connection using a serial number.
						 * In the XML state files a key can be set up on serial for fast association between
						 * state data.
						 * The serial number is also used as a soft linkage to other subsystems such as NA.
						 */
typedef uint32_t ecm_db_connection_hash_t;

/*
 * Connection serial number hash table
 */
#define ECM_DB_CONNECTION_SERIAL_HASH_SLOTS 32768
static struct ecm_db_connection_instance *ecm_db_connection_serial_table[ECM_DB_CONNECTION_SERIAL_HASH_SLOTS];
						/* Slots of the connection serial hash table */
static int ecm_db_connection_serial_table_lengths[ECM_DB_CONNECTION_SERIAL_HASH_SLOTS];
						/* Tracks how long each chain is */
typedef uint32_t ecm_db_connection_serial_hash_t;

/*
 * Mapping hash table
 */
#define ECM_DB_MAPPING_HASH_SLOTS 32768
static struct ecm_db_mapping_instance *ecm_db_mapping_table[ECM_DB_MAPPING_HASH_SLOTS];
							/* Slots of the mapping hash table */
static int ecm_db_mapping_table_lengths[ECM_DB_MAPPING_HASH_SLOTS];
							/* Tracks how long each chain is */
static int ecm_db_mapping_count = 0;			/* Number of mappings allocated */
typedef uint32_t ecm_db_mapping_hash_t;

/*
 * Host hash table
 */
#define ECM_DB_HOST_HASH_SLOTS 32768
static struct ecm_db_host_instance *ecm_db_host_table[ECM_DB_HOST_HASH_SLOTS];
							/* Slots of the host hash table */
static int ecm_db_host_table_lengths[ECM_DB_HOST_HASH_SLOTS];
							/* Tracks how long each chain is */
static int ecm_db_host_count = 0;			/* Number of hosts allocated */
typedef uint32_t ecm_db_host_hash_t;

/*
 * Node hash table
 */
#define ECM_DB_NODE_HASH_SLOTS 32768
static struct ecm_db_node_instance *ecm_db_node_table[ECM_DB_NODE_HASH_SLOTS];
							/* Slots of the node hash table */
static int ecm_db_node_table_lengths[ECM_DB_NODE_HASH_SLOTS];
							/* Tracks how long each chain is */
static int ecm_db_node_count = 0;			/* Number of nodes allocated */
typedef uint32_t ecm_db_node_hash_t;

/*
 * Interface hash table
 */
#define ECM_DB_IFACE_HASH_SLOTS 8
static struct ecm_db_iface_instance *ecm_db_iface_table[ECM_DB_IFACE_HASH_SLOTS];
							/* Slots of the interface hash table */
static int ecm_db_iface_table_lengths[ECM_DB_IFACE_HASH_SLOTS];
							/* Tracks how long each chain is */
static int ecm_db_iface_count = 0;			/* Number of interfaces allocated */
typedef uint32_t ecm_db_iface_hash_t;

/*
 * Listeners
 */
static int ecm_db_listeners_count = 0;			/* Number of listeners allocated */
static struct ecm_db_listener_instance *ecm_db_listeners = NULL;
							/* Event listeners */

/*
 * ecm_db_iface_xml_state_get_method_t
 *	Used to obtain interface XML state
 */
typedef int (*ecm_db_iface_xml_state_get_method_t)(struct ecm_db_iface_instance *ii, char *buf, int buf_sz);

/*
 * struct ecm_db_iface_instance
 */
struct ecm_db_iface_instance {
	struct ecm_db_iface_instance *next;		/* Next instance in global list */
	struct ecm_db_iface_instance *prev;		/* Previous instance in global list */
	struct ecm_db_iface_instance *hash_next;	/* Next Interface in the chain of Interfaces */
	struct ecm_db_iface_instance *hash_prev;	/* previous Interface in the chain of Interfaces */
	ecm_db_iface_type_t type;			/* RO: Type of interface */
	struct ecm_db_node_instance *nodes;		/* Nodes associated with this Interface */
	int node_count;					/* Number of Nodes in the nodes list */
	uint32_t time_added;				/* RO: DB time stamp when the Interface was added into the database */

	int32_t interface_identifier;			/* RO: The operating system dependent identifier of this interface */
	int32_t nss_interface_identifier;		/* RO: The NSS identifier of this interface */
	char name[IFNAMSIZ];				/* Name of interface */
	int32_t mtu;					/* Interface MTU */

	uint64_t from_data_total;			/* Total of data sent by this Interface */
	uint64_t to_data_total;				/* Total of data sent to this Interface */
	uint64_t from_packet_total;			/* Total of packets sent by this Interface */
	uint64_t to_packet_total;			/* Total of packets sent to this Interface */
	uint64_t from_data_total_dropped;
	uint64_t to_data_total_dropped;
	uint64_t from_packet_total_dropped;
	uint64_t to_packet_total_dropped;

	/*
	 * For convenience interfaces keep lists of connections that have been established
	 * from them and to them.
	 * In fact the same connection could be listed as from & to on the same interface (think: WLAN<>WLAN AP function)
	 * Interfaces keep this information for rapid iteration of connections e.g. when an interface 'goes down' we
	 * can defunct all associated connections or destroy any NSS rules.
	 */
	struct ecm_db_connection_instance *from_connections;		/* list of connections made from this interface */
	struct ecm_db_connection_instance *to_connections;		/* list of connections made to this interface */

	struct ecm_db_connection_instance *from_nat_connections;	/* list of NAT connections made from this interface */
	struct ecm_db_connection_instance *to_nat_connections;		/* list of NAT connections made to this interface */

	/*
	 * Interface specific information.
	 * type identifies which information is applicable.
	 */
	union {
		struct ecm_db_interface_info_ethernet ethernet;		/* type == ECM_DB_IFACE_TYPE_ETHERNET */
		struct ecm_db_interface_info_vlan vlan;			/* type == ECM_DB_IFACE_TYPE_VLAN */
		struct ecm_db_interface_info_lag lag;			/* type == ECM_DB_IFACE_TYPE_LAG */
		struct ecm_db_interface_info_bridge bridge;		/* type == ECM_DB_IFACE_TYPE_BRIDGE */
		struct ecm_db_interface_info_pppoe pppoe;		/* type == ECM_DB_IFACE_TYPE_PPPOE */
		struct ecm_db_interface_info_unknown unknown;		/* type == ECM_DB_IFACE_TYPE_UNKNOWN */
		struct ecm_db_interface_info_loopback loopback;		/* type == ECM_DB_IFACE_TYPE_LOOPBACK */
		struct ecm_db_interface_info_ipsec_tunnel ipsec_tunnel;	/* type == ECM_DB_IFACE_TYPE_IPSEC_TUNNEL */
		struct ecm_db_interface_info_sit sit;			/* type == ECM_DB_IFACE_TYPE_SIT (6-in-4) */
		struct ecm_db_interface_info_tunipip6 tunipip6;		/* type == ECM_DB_IFACE_TYPE_TUNIPIP6 (IPIP v6 Tunnel i.e. TUNNEL6) */
	} type_info;

	ecm_db_iface_xml_state_get_method_t xml_state_get;		/* Type specific state method to return XML state for it */

	ecm_db_iface_final_callback_t final;		/* Callback to owner when object is destroyed */
	void *arg;					/* Argument returned to owner in callbacks */
	uint32_t flags;
	int refs;					/* Integer to trap we never go negative */
	ecm_db_iface_hash_t hash_index;
#if (DEBUG_LEVEL > 0)
	uint16_t magic;
#endif
};

/*
 * Interface flags
 */
#define ECM_DB_IFACE_FLAGS_INSERTED 1			/* Interface is inserted into connection database tables */

/*
 * struct ecm_db_node_instance
 */
struct ecm_db_node_instance {
	struct ecm_db_node_instance *next;		/* Next instance in global list */
	struct ecm_db_node_instance *prev;		/* Previous instance in global list */
	struct ecm_db_node_instance *hash_next;		/* Next host in the chain of nodes */
	struct ecm_db_node_instance *hash_prev;		/* previous host in the chain of nodes */
	uint8_t address[ETH_ALEN];			/* RO: MAC Address of this node */
	struct ecm_db_host_instance *hosts;		/* Hosts associated with this node */
	int host_count;					/* Number of hosts in the hosts list */
	uint32_t time_added;				/* RO: DB time stamp when the node was added into the database */

	uint64_t from_data_total;			/* Total of data sent by this node */
	uint64_t to_data_total;				/* Total of data sent to this node */
	uint64_t from_packet_total;			/* Total of packets sent by this node */
	uint64_t to_packet_total;			/* Total of packets sent to this node */
	uint64_t from_data_total_dropped;
	uint64_t to_data_total_dropped;
	uint64_t from_packet_total_dropped;
	uint64_t to_packet_total_dropped;

	struct ecm_db_iface_instance *iface;		/* The interface to which this node relates */
	struct ecm_db_node_instance *node_next;		/* The next node within the same iface nodes list */
	struct ecm_db_node_instance *node_prev;		/* The previous node within the same iface nodes list */

	ecm_db_node_final_callback_t final;		/* Callback to owner when object is destroyed */
	void *arg;					/* Argument returned to owner in callbacks */
	uint8_t flags;
	int refs;					/* Integer to trap we never go negative */
	ecm_db_node_hash_t hash_index;
#if (DEBUG_LEVEL > 0)
	uint16_t magic;
#endif
};

/*
 * Node flags
 */
#define ECM_DB_NODE_FLAGS_INSERTED 1			/* Node is inserted into connection database tables */

/*
 * struct ecm_db_host_instance
 */
struct ecm_db_host_instance {
	struct ecm_db_host_instance *next;		/* Next instance in global list */
	struct ecm_db_host_instance *prev;		/* Previous instance in global list */
	struct ecm_db_host_instance *hash_next;		/* Next host in the chain of hosts */
	struct ecm_db_host_instance *hash_prev;		/* previous host in the chain of hosts */
	ip_addr_t address;				/* RO: IPv4/v6 Address of this host */
	bool on_link;					/* RO: false when this host is reached via a gateway */
	struct ecm_db_mapping_instance *mappings;	/* Mappings made on this host */
	int mapping_count;				/* Number of mappings in the mapping list */
	uint32_t time_added;				/* RO: DB time stamp when the host was added into the database */
	struct ecm_db_node_instance *node;		/* The node to which this host relates */
	struct ecm_db_host_instance *host_next;		/* The next host within the nodes hosts list */
	struct ecm_db_host_instance *host_prev;		/* The previous host within the nodes hosts list */
	
	uint64_t from_data_total;			/* Total of data sent by this host */
	uint64_t to_data_total;				/* Total of data sent to this host */
	uint64_t from_packet_total;			/* Total of packets sent by this host */
	uint64_t to_packet_total;			/* Total of packets sent to this host */
	uint64_t from_data_total_dropped;
	uint64_t to_data_total_dropped;
	uint64_t from_packet_total_dropped;
	uint64_t to_packet_total_dropped;

	ecm_db_host_final_callback_t final;		/* Callback to owner when object is destroyed */
	void *arg;					/* Argument returned to owner in callbacks */
	uint32_t flags;
	int refs;					/* Integer to trap we never go negative */
	ecm_db_host_hash_t hash_index;
#if (DEBUG_LEVEL > 0)
	uint16_t magic;
#endif
};

/*
 * Host flags
 */
#define ECM_DB_HOST_FLAGS_INSERTED 1			/* Host is inserted into connection database tables */

/*
 * struct ecm_db_mapping_instance
 */
struct ecm_db_mapping_instance {
	struct ecm_db_mapping_instance *next;				/* Next instance in global list */
	struct ecm_db_mapping_instance *prev;				/* Previous instance in global list */

	struct ecm_db_mapping_instance *hash_next;			/* Next mapping in the chain of mappings */
	struct ecm_db_mapping_instance *hash_prev;			/* previous mapping in the chain of mappings */

	uint32_t time_added;						/* RO: DB time stamp when the connection was added into the database */
	struct ecm_db_host_instance *host;				/* The host to which this mapping relates */
	int port;							/* RO: The port number on the host - only applicable for mapping protocols that are port based */
	struct ecm_db_mapping_instance *mapping_next;			/* Next mapping in the list of mappings for the host */
	struct ecm_db_mapping_instance *mapping_prev;			/* previous mapping in the list of mappings for the host */

	struct ecm_db_connection_instance *from_connections;		/* list of connections made from this host mapping */
	struct ecm_db_connection_instance *to_connections;		/* list of connections made to this host mapping */

	struct ecm_db_connection_instance *from_nat_connections;	/* list of NAT connections made from this host mapping */
	struct ecm_db_connection_instance *to_nat_connections;		/* list of NAT connections made to this host mapping */

	/*
	 * Connection counts
	 */
	int tcp_from;
	int tcp_to;
	int udp_from;
	int udp_to;
	int tcp_nat_from;
	int tcp_nat_to;
	int udp_nat_from;
	int udp_nat_to;

	/*
	 * Total counts
	 */
	int from;
	int to;
	int nat_from;
	int nat_to;

	/*
	 * Data totals
	 */
	uint64_t from_data_total;					/* Total of data sent by this mapping */
	uint64_t to_data_total;						/* Total of data sent to this mapping */
	uint64_t from_packet_total;					/* Total of packets sent by this mapping */
	uint64_t to_packet_total;					/* Total of packets sent to this mapping */
	uint64_t from_data_total_dropped;
	uint64_t to_data_total_dropped;
	uint64_t from_packet_total_dropped;
	uint64_t to_packet_total_dropped;

	ecm_db_mapping_final_callback_t final;				/* Callback to owner when object is destroyed */
	void *arg;							/* Argument returned to owner in callbacks */
	uint32_t flags;
	int refs;							/* Integer to trap we never go negative */
	ecm_db_mapping_hash_t hash_index;
#if (DEBUG_LEVEL > 0)
	uint16_t magic;
#endif
};

/*
 * Mapping flags
 */
#define ECM_DB_MAPPING_FLAGS_INSERTED 1	/* Mapping is inserted into connection database tables */

/*
 * struct ecm_db_timer_group
 *	A timer group - all group members within the same group have the same TTL reset value.
 *
 * Expiry of entries occurs from tail to head.
 */
struct ecm_db_timer_group {
	struct ecm_db_timer_group_entry *head;		/* Most recently used entry in this timer group */
	struct ecm_db_timer_group_entry *tail;		/* Least recently used entry in this timer group. */
	uint32_t time;					/* Time in seconds a group entry will be given to live when 'touched' */
	ecm_db_timer_group_t tg;			/* RO: The group id */
#if (DEBUG_LEVEL > 0)
	uint16_t magic;
#endif
};

/*
 * Timers and cleanup
 */
static uint32_t ecm_db_time = 0;					/* Time in seconds since start */
static struct ecm_db_timer_group ecm_db_timer_groups[ECM_DB_TIMER_GROUPS_MAX];
								/* Timer groups */
static struct timer_list ecm_db_timer;				/* Timer to drive timer groups */

/*
 * struct ecm_db_connection_instance
 */
struct ecm_db_connection_instance {
	struct ecm_db_connection_instance *next;		/* Next instance in global list */
	struct ecm_db_connection_instance *prev;		/* Previous instance in global list */

	struct ecm_db_connection_instance *hash_next;		/* Next connection in chain */
	struct ecm_db_connection_instance *hash_prev;		/* Previous connection in chain */
	ecm_db_connection_hash_t hash_index;			/* The hash table slot whose chain of connections this is inserted into */
	
	struct ecm_db_connection_instance *serial_hash_next;	/* Next connection in serial hash chain */
	struct ecm_db_connection_instance *serial_hash_prev;	/* Previous connection in serial hash chain */
	ecm_db_connection_hash_t serial_hash_index;		/* The hash table slot whose chain of connections this is inserted into */

	uint32_t time_added;					/* RO: DB time stamp when the connection was added into the database */

	int protocol;						/* RO: Protocol of the connection */
	ecm_db_direction_t direction;				/* RO: 'Direction' of connection establishment. */
	bool is_routed;						/* RO: True when connection is routed, false when not */

	/*
	 * Connection endpoint mapping
	 */
	struct ecm_db_mapping_instance *mapping_from;		/* The connection was established from this mapping */
	struct ecm_db_mapping_instance *mapping_to;		/* The connection was established to this mapping */
	struct ecm_db_connection_instance *from_next;		/* Next connection made from the same mapping */
	struct ecm_db_connection_instance *from_prev;		/* Previous connection made from the same mapping */
	struct ecm_db_connection_instance *to_next;		/* Next connection made to the same mapping */
	struct ecm_db_connection_instance *to_prev;		/* Previous connection made to the same mapping */

	/*
	 * Connection endpoint mapping for NAT purposes
	 * NOTE: For non-NAT connections these would be identical to the endpoint mappings.
	 */
	struct ecm_db_mapping_instance *mapping_nat_from;	/* The connection was established from this mapping */
	struct ecm_db_mapping_instance *mapping_nat_to;		/* The connection was established to this mapping */
	struct ecm_db_connection_instance *from_nat_next;	/* Next connection made from the same mapping */
	struct ecm_db_connection_instance *from_nat_prev;	/* Previous connection made from the same mapping */
	struct ecm_db_connection_instance *to_nat_next;		/* Next connection made to the same mapping */
	struct ecm_db_connection_instance *to_nat_prev;		/* Previous connection made to the same mapping */

	/*
	 * Connection endpoint interface
	 */
	struct ecm_db_connection_instance *iface_from_next;	/* Next connection made from the same interface */
	struct ecm_db_connection_instance *iface_from_prev;	/* Previous connection made from the same interface */
	struct ecm_db_connection_instance *iface_to_next;	/* Next connection made to the same interface */
	struct ecm_db_connection_instance *iface_to_prev;	/* Previous connection made to the same interface */

	/*
	 * Connection endpoint interface for NAT purposes
	 * NOTE: For non-NAT connections these would be identical to the endpoint interface.
	 */
	struct ecm_db_connection_instance *iface_from_nat_next;	/* Next connection made from the same interface */
	struct ecm_db_connection_instance *iface_from_nat_prev;	/* Previous connection made from the same interface */
	struct ecm_db_connection_instance *iface_to_nat_next;	/* Next connection made to the same interface */
	struct ecm_db_connection_instance *iface_to_nat_prev;	/* Previous connection made to the same interface */

	/*
	 * From / To interfaces list
	 */
	struct ecm_db_iface_instance *from_interfaces[ECM_DB_IFACE_HEIRARCHY_MAX];
								/* The outermost to innnermost interface this connection is using in the from path.
								 * Relationships are recorded from [ECM_DB_IFACE_HEIRARCHY_MAX - 1] to [0]
								 */
	int32_t from_interface_first;				/* The index of the first interface in the list */
	bool from_interface_set;				/* True when a list has been set - even if there is NO list, it's still deliberately set that way. */
	struct ecm_db_iface_instance *to_interfaces[ECM_DB_IFACE_HEIRARCHY_MAX];
								/* The outermost to innnermost interface this connection is using in the to path */
	int32_t to_interface_first;				/* The index of the first interface in the list */
	bool to_interface_set;					/* True when a list has been set - even if there is NO list, it's still deliberately set that way. */

	/*
	 * From / To NAT interfaces list
	 */
	struct ecm_db_iface_instance *from_nat_interfaces[ECM_DB_IFACE_HEIRARCHY_MAX];
								/* The outermost to innnermost interface this connection is using in the from path.
								 * Relationships are recorded from [ECM_DB_IFACE_HEIRARCHY_MAX - 1] to [0]
								 */
	int32_t from_nat_interface_first;			/* The index of the first interface in the list */
	bool from_nat_interface_set;				/* True when a list has been set - even if there is NO list, it's still deliberately set that way. */
	struct ecm_db_iface_instance *to_nat_interfaces[ECM_DB_IFACE_HEIRARCHY_MAX];
								/* The outermost to innnermost interface this connection is using in the to path */
	int32_t to_nat_interface_first;				/* The index of the first interface in the list */
	bool to_nat_interface_set;				/* True when a list has been set - even if there is NO list, it's still deliberately set that way. */

	/*
	 * Time values in seconds
	 */
	struct ecm_db_timer_group_entry defunct_timer;		/* Used to defunct the connection on inactivity */

	/*
	 * Byte and packet counts
	 */
	uint64_t from_data_total;				/* Totals of data as sent by the 'from' side of this connection */
	uint64_t to_data_total;					/* Totals of data as sent by the 'to' side of this connection */
	uint64_t from_packet_total;				/* Totals of packets as sent by the 'from' side of this connection */
	uint64_t to_packet_total;				/* Totals of packets as sent by the 'to' side of this connection */
	uint64_t from_data_total_dropped;			/* Total data sent by the 'from' side that we purposely dropped - the 'to' side has not seen this data */
	uint64_t to_data_total_dropped;				/* Total data sent by the 'to' side that we purposely dropped - the 'from' side has not seen this data */
	uint64_t from_packet_total_dropped;			/* Total packets sent by the 'from' side that we purposely dropped - the 'to' side has not seen this data */
	uint64_t to_packet_total_dropped;			/* Total packets sent by the 'to' side that we purposely dropped - the 'from' side has not seen this data */

	/*
	 * Classifiers attached to this connection
	 */
	struct ecm_classifier_default_instance *dci;		/* The default classifier */
	struct ecm_classifier_instance *assignments;		/* A list of all classifiers that are still assigned to this connection.
								 * When a connection is created, instances of every type of classifier are assigned to the connection.
								 * Classifiers are added in ascending order of priority - so the most important processes a packet last.
								 * Classifiers may drop out of this list (become unassigned) at any time.
								 */
	struct ecm_classifier_instance *assignments_by_type[ECM_CLASSIFIER_TYPES];
								/* All assignments are also recorded in this array, since there can be only one of each type, this array allows
								 * rapid retrieval of a classifier type, saving having to iterate the assignments list.
								 */
	uint16_t classifier_generation;				/* Used to detect when a re-evaluation of this connection is necessary */
	struct ecm_front_end_connection_instance *feci;		/* Front end instance specific to this connection */

	ecm_db_connection_final_callback_t final;		/* Callback to owner when object is destroyed */
	void *arg;						/* Argument returned to owner in callbacks */

	uint32_t serial;					/* Serial number for the connection - unique for run lifetime */
	uint32_t flags;
	int refs;						/* Integer to trap we never go negative */
#if (DEBUG_LEVEL > 0)
	uint16_t magic;
#endif
};

/*
 * Connection flags
 */
#define ECM_DB_CONNECTION_FLAGS_INSERTED 1			/* Connection is inserted into connection database tables */

/*
 * struct ecm_db_listener_instance 
 *	listener instances
 */
struct ecm_db_listener_instance {
	struct ecm_db_listener_instance *next;
	struct ecm_db_listener_instance *event_next;
	uint32_t flags;
	void *arg;
	int refs;							/* Integer to trap we never go negative */
	ecm_db_mapping_final_callback_t final;				/* Final callback for this instance */

	ecm_db_iface_listener_added_callback_t iface_added;
	ecm_db_iface_listener_removed_callback_t iface_removed;
	ecm_db_node_listener_added_callback_t node_added;
	ecm_db_node_listener_removed_callback_t node_removed;
	ecm_db_host_listener_added_callback_t host_added;
	ecm_db_host_listener_removed_callback_t host_removed;
	ecm_db_mapping_listener_added_callback_t mapping_added;
	ecm_db_mapping_listener_removed_callback_t mapping_removed;
	ecm_db_connection_listener_added_callback_t connection_added;
	ecm_db_connection_listener_removed_callback_t connection_removed;
#if (DEBUG_LEVEL > 0)
	uint16_t magic;
#endif
};

/*
 * Listener flags
 */
#define ECM_DB_LISTENER_FLAGS_INSERTED 1				/* Is inserted into database */

/*
 * Simple stats
 */
static int ecm_db_connection_count_by_protocol[256];		/* Each IP protocol has its own count */

/*
 * Locking of the database - concurrency control
 */
static spinlock_t ecm_db_lock;					/* Protect the table from SMP access. */

/*
 * Connection validity
 */
static uint16_t ecm_db_classifier_generation = 0;		/* Generation counter to detect out of date connections that should be reclassified */

/*
 * SysFS linkage
 */
static struct sys_device ecm_db_sys_dev;				/* SysFS linkage */

/*
 * Management thread control
 */
static bool ecm_db_terminate_pending = false;			/* When true the user has requested termination */
static int ecm_db_thread_refs = 0;				/* Counts the number of entities that rely on the thread staying functional. When 0 the thread may terminate */
static struct task_struct *ecm_db_thread = NULL;			/* Control thread */

/*
 * Character device stuff - used to communicate status back to user space
 */
#define ECM_DB_STATE_FILE_BUFFER_SIZE 8192
static int ecm_db_dev_major_id = 0;			/* Major ID of registered char dev from which we can dump out state to userspace */

#define ECM_DB_STATE_FILE_OUTPUT_CONNECTIONS 1
#define ECM_DB_STATE_FILE_OUTPUT_MAPPINGS 2
#define ECM_DB_STATE_FILE_OUTPUT_HOSTS 4
#define ECM_DB_STATE_FILE_OUTPUT_NODES 8
#define ECM_DB_STATE_FILE_OUTPUT_INTERFACES 16
#define ECM_DB_STATE_FILE_OUTPUT_CONNECTIONS_CHAIN 32
#define ECM_DB_STATE_FILE_OUTPUT_MAPPINGS_CHAIN 64
#define ECM_DB_STATE_FILE_OUTPUT_HOSTS_CHAIN 128
#define ECM_DB_STATE_FILE_OUTPUT_NODES_CHAIN 256
#define ECM_DB_STATE_FILE_OUTPUT_INTERFACES_CHAIN 512
#define ECM_DB_STATE_FILE_OUTPUT_PROTOCOL_COUNTS 1024

/*
 * struct ecm_db_state_file_instance
 *	Structure used as state per open instance of our db state file
 */
struct ecm_db_state_file_instance {
	int output_mask;
	struct ecm_db_connection_instance *ci;
	struct ecm_db_mapping_instance *mi;
	struct ecm_db_host_instance *hi;
	struct ecm_db_node_instance *ni;
	struct ecm_db_iface_instance *ii;
	int connection_hash_index;
	int mapping_hash_index;
	int host_hash_index;
	int node_hash_index;
	int iface_hash_index;
	int protocol;
	bool doc_start_written;
	bool doc_end_written;
	char msg_buffer[ECM_DB_STATE_FILE_BUFFER_SIZE];	/* Used to hold the current state message being output */
	char *msgp;					/* Points into the msg buffer as we output it piece by piece */
	int msg_len;					/* Length of the buffer still to be written out */
#if (DEBUG_LEVEL > 0)
	uint16_t magic;
#endif
};
static int ecm_db_state_file_output_mask = ECM_DB_STATE_FILE_OUTPUT_CONNECTIONS;
							/* Bit mask specifies which data to output in the state file */

/*
 * ecm_db_interface_type_names[]
 *	Array that maps the interface type to a string
 */
static char *ecm_db_interface_type_names[ECM_DB_IFACE_TYPE_COUNT] = {
	"ETHERNET",
	"PPPoE",
	"LINK-AGGREGATION",
	"VLAN",
	"BRIDGE",
	"LOOPBACK",
	"IPSEC_TUNNEL",
	"UNKNOWN",		
};

/*
 * ecm_db_interface_type_to_string()
 *	Return a string buffer containing the type name of the interface
 */
char *ecm_db_interface_type_to_string(ecm_db_iface_type_t type)
{
	DEBUG_ASSERT((type >= 0) && (type < ECM_DB_IFACE_TYPE_COUNT), "Invalid type: %d\n", type);
	return ecm_db_interface_type_names[(int)type];
}
EXPORT_SYMBOL(ecm_db_interface_type_to_string);

/*
 * ecm_db_iface_nss_interface_identifier_get()
 *	Return the NSS interface number of this ecm interface
 */
int32_t ecm_db_iface_nss_interface_identifier_get(struct ecm_db_iface_instance *ii)
{
	DEBUG_CHECK_MAGIC(ii, ECM_DB_IFACE_INSTANCE_MAGIC, "%p: magic failed", ii);
	return ii->nss_interface_identifier;
}
EXPORT_SYMBOL(ecm_db_iface_nss_interface_identifier_get);

/*
 * ecm_db_iface_mtu_reset()
 *	Reset the mtu
 */
int32_t ecm_db_iface_mtu_reset(struct ecm_db_iface_instance *ii, int32_t mtu)
{
	int32_t mtu_old;
	DEBUG_CHECK_MAGIC(ii, ECM_DB_IFACE_INSTANCE_MAGIC, "%p: magic failed", ii);
	spin_lock_bh(&ecm_db_lock);
	mtu_old = ii->mtu;
	ii->mtu = mtu;
	spin_unlock_bh(&ecm_db_lock);
	DEBUG_INFO("%p: Mtu change from %d to %d\n", ii, mtu_old, mtu);
	
	return mtu_old;
}
EXPORT_SYMBOL(ecm_db_iface_mtu_reset);

/*
 * ecm_db_connection_front_end_get_and_ref()
 *	Return ref to the front end instance of the connection
 */
struct ecm_front_end_connection_instance *ecm_db_connection_front_end_get_and_ref(struct ecm_db_connection_instance *ci)
{
	DEBUG_CHECK_MAGIC(ci, ECM_DB_CONNECTION_INSTANCE_MAGIC, "%p: magic failed", ci);
	ci->feci->ref(ci->feci);
	return ci->feci;
}
EXPORT_SYMBOL(ecm_db_connection_front_end_get_and_ref);

/*
 * ecm_db_connection_defunct_callback()
 *	Invoked by the expiration of the defunct_timer contained in a connection instance
 */
static void ecm_db_connection_defunct_callback(void *arg)
{
	struct ecm_db_connection_instance *ci = (struct ecm_db_connection_instance *)arg;
	DEBUG_CHECK_MAGIC(ci, ECM_DB_CONNECTION_INSTANCE_MAGIC, "%p: magic failed", ci);

	DEBUG_INFO("%p: defunct timer expired\n", ci);
	ecm_db_connection_deref(ci);
}

/*
 * ecm_db_connection_defunct_timer_reset()
 *	Set/change the timer group associated with a connection.  Returns false if the connection has become defunct and the new group cannot be set for that reason.
 */
bool ecm_db_connection_defunct_timer_reset(struct ecm_db_connection_instance *ci, ecm_db_timer_group_t tg)
{
	DEBUG_CHECK_MAGIC(ci, ECM_DB_CONNECTION_INSTANCE_MAGIC, "%p: magic failed", ci);
	return ecm_db_timer_group_entry_reset(&ci->defunct_timer, tg);
}
EXPORT_SYMBOL(ecm_db_connection_defunct_timer_reset);

/*
 * ecm_db_connection_defunct_timer_touch()
 *	Update the connections defunct timer to stop it timing out.  Returns false if the connection defunct timer has expired.
 */
bool ecm_db_connection_defunct_timer_touch(struct ecm_db_connection_instance *ci)
{
	DEBUG_CHECK_MAGIC(ci, ECM_DB_CONNECTION_INSTANCE_MAGIC, "%p: magic failed", ci);
	return ecm_db_timer_group_entry_touch(&ci->defunct_timer);
}
EXPORT_SYMBOL(ecm_db_connection_defunct_timer_touch);

/*
 * ecm_db_connection_timer_group_get()
 *	Return the timer group id
 */
ecm_db_timer_group_t ecm_db_connection_timer_group_get(struct ecm_db_connection_instance *ci)
{
	ecm_db_timer_group_t tg;
	DEBUG_CHECK_MAGIC(ci, ECM_DB_CONNECTION_INSTANCE_MAGIC, "%p: magic failed", ci);

	spin_lock_bh(&ecm_db_lock);
	tg = ci->defunct_timer.group;
	spin_unlock_bh(&ecm_db_lock);
	return tg;
}
EXPORT_SYMBOL(ecm_db_connection_timer_group_get);

/*
 * ecm_db_connection_make_defunct()
 *	Make connection defunct.
 */
void ecm_db_connection_make_defunct(struct ecm_db_connection_instance *ci)
{
	DEBUG_CHECK_MAGIC(ci, ECM_DB_CONNECTION_INSTANCE_MAGIC, "%p: magic failed", ci);
	if (ecm_db_timer_group_entry_remove(&ci->defunct_timer)) {
		ecm_db_connection_deref(ci);
	}
}
EXPORT_SYMBOL(ecm_db_connection_make_defunct);

/*
 * ecm_db_connection_data_totals_update()
 *	Update the total data (and packets) sent/received by the given host
 */
void ecm_db_connection_data_totals_update(struct ecm_db_connection_instance *ci, bool is_from, uint64_t size, uint64_t packets)
{
	DEBUG_CHECK_MAGIC(ci, ECM_DB_CONNECTION_INSTANCE_MAGIC, "%p: magic failed\n", ci);

	spin_lock_bh(&ecm_db_lock);

	if (is_from) {
		/*
		 * Update totals sent by the FROM side of connection
		 */
		ci->from_data_total += size;
		ci->mapping_from->from_data_total += size;
		ci->mapping_from->host->from_data_total += size;
		ci->mapping_from->host->node->from_data_total += size;
		ci->from_packet_total += packets;
		ci->mapping_from->from_packet_total += packets;
		ci->mapping_from->host->from_packet_total += packets;
		ci->mapping_from->host->node->from_packet_total += packets;

		/*
		 * Data from the host is essentially TO the interface on which the host is reachable
		 */
		ci->mapping_from->host->node->iface->to_data_total += size;
		ci->mapping_from->host->node->iface->to_packet_total += packets;

		/*
		 * Update totals sent TO the other side of the connection
		 */
		ci->mapping_to->to_data_total += size;
		ci->mapping_to->host->to_data_total += size;
		ci->mapping_to->host->node->to_data_total += size;
		ci->mapping_to->to_packet_total += packets;
		ci->mapping_to->host->to_packet_total += packets;
		ci->mapping_to->host->node->to_packet_total += packets;

		/*
		 * Sending to the other side means FROM the interface we reach that host
		 */
		ci->mapping_to->host->node->iface->from_data_total += size;
		ci->mapping_to->host->node->iface->from_packet_total += packets;
		spin_unlock_bh(&ecm_db_lock);
		return;
	}

	/*
	 * Update totals sent by the TO side of this connection
	 */
	ci->to_data_total += size;
	ci->mapping_to->from_data_total += size;
	ci->mapping_to->host->from_data_total += size;
	ci->mapping_to->host->node->from_data_total += size;
	ci->to_packet_total += packets;
	ci->mapping_to->from_packet_total += packets;
	ci->mapping_to->host->from_packet_total += packets;
	ci->mapping_to->host->node->from_packet_total += packets;

	/*
	 * Data from the host is essentially TO the interface on which the host is reachable
	 */
	ci->mapping_to->host->node->iface->to_data_total += size;
	ci->mapping_to->host->node->iface->to_packet_total += packets;

	/*
	 * Update totals sent TO the other side of the connection
	 */
	ci->mapping_from->to_data_total += size;
	ci->mapping_from->host->to_data_total += size;
	ci->mapping_from->host->node->to_data_total += size;
	ci->mapping_from->to_packet_total += packets;
	ci->mapping_from->host->to_packet_total += packets;
	ci->mapping_from->host->node->to_packet_total += packets;

	/*
	 * Sending to the other side means FROM the interface we reach that host
	 */
	ci->mapping_from->host->node->iface->from_data_total += size;
	ci->mapping_from->host->node->iface->from_packet_total += packets;
	spin_unlock_bh(&ecm_db_lock);
}
EXPORT_SYMBOL(ecm_db_connection_data_totals_update);

/*
 * ecm_db_connection_data_totals_update_dropped()
 *	Update the total data (and packets) sent by the given host but which we dropped
 */
void ecm_db_connection_data_totals_update_dropped(struct ecm_db_connection_instance *ci, bool is_from, uint64_t size, uint64_t packets)
{
	DEBUG_CHECK_MAGIC(ci, ECM_DB_CONNECTION_INSTANCE_MAGIC, "%p: magic failed\n", ci);

	if (is_from) {
		/*
		 * Update dropped totals sent by the FROM side
		 */
		spin_lock_bh(&ecm_db_lock);
		ci->from_data_total_dropped += size;
		ci->mapping_from->from_data_total_dropped += size;
		ci->mapping_from->host->from_data_total_dropped += size;
		ci->mapping_from->host->node->from_data_total_dropped += size;
		ci->from_packet_total_dropped += packets;
		ci->mapping_from->from_packet_total_dropped += packets;
		ci->mapping_from->host->from_packet_total_dropped += packets;
		ci->mapping_from->host->node->from_packet_total_dropped += packets;

		/*
		 * Data from the host is essentially TO the interface on which the host is reachable
		 */
		ci->mapping_from->host->node->iface->to_data_total_dropped += size;
		ci->mapping_from->host->node->iface->to_packet_total_dropped += packets;
		spin_unlock_bh(&ecm_db_lock);
		return;
	}

	/*
	 * Update dropped totals sent by the TO side of this connection
	 */
	spin_lock_bh(&ecm_db_lock);
	ci->to_data_total_dropped += size;
	ci->mapping_to->from_data_total_dropped += size;
	ci->mapping_to->host->from_data_total_dropped += size;
	ci->mapping_to->host->node->from_data_total_dropped += size;
	ci->to_packet_total_dropped += packets;
	ci->mapping_to->from_packet_total_dropped += packets;
	ci->mapping_to->host->from_packet_total_dropped += packets;
	ci->mapping_to->host->node->from_packet_total_dropped += packets;

	/*
	 * Data from the host is essentially TO the interface on which the host is reachable
	 */
	ci->mapping_to->host->node->iface->to_data_total_dropped += size;
	ci->mapping_to->host->node->iface->to_packet_total_dropped += packets;
	spin_unlock_bh(&ecm_db_lock);
}
EXPORT_SYMBOL(ecm_db_connection_data_totals_update_dropped);

/*
 * ecm_db_connection_data_stats_get()
 *	Return data stats for the instance
 */
void ecm_db_connection_data_stats_get(struct ecm_db_connection_instance *ci, uint64_t *from_data_total, uint64_t *to_data_total,
						uint64_t *from_packet_total, uint64_t *to_packet_total,
						uint64_t *from_data_total_dropped, uint64_t *to_data_total_dropped,
						uint64_t *from_packet_total_dropped, uint64_t *to_packet_total_dropped)
{
	DEBUG_CHECK_MAGIC(ci, ECM_DB_CONNECTION_INSTANCE_MAGIC, "%p: magic failed", ci);

	spin_lock_bh(&ecm_db_lock);
	if (from_data_total) {
		*from_data_total = ci->from_data_total;
	}
	if (to_data_total) {
		*to_data_total = ci->to_data_total;
	}
	if (from_packet_total) {
		*from_packet_total = ci->from_packet_total;
	}
	if (to_packet_total) {
		*to_packet_total = ci->to_packet_total;
	}
	if (from_data_total_dropped) {
		*from_data_total_dropped = ci->from_data_total_dropped;
	}
	if (to_data_total_dropped) {
		*to_data_total_dropped = ci->to_data_total_dropped;
	}
	if (from_packet_total_dropped) {
		*from_packet_total_dropped = ci->from_packet_total_dropped;
	}
	if (to_packet_total_dropped) {
		*to_packet_total_dropped = ci->to_packet_total_dropped;
	}
	spin_unlock_bh(&ecm_db_lock);
}
EXPORT_SYMBOL(ecm_db_connection_data_stats_get);

/*
 * ecm_db_mapping_data_stats_get()
 *	Return data stats for the instance
 */
void ecm_db_mapping_data_stats_get(struct ecm_db_mapping_instance *mi, uint64_t *from_data_total, uint64_t *to_data_total,
						uint64_t *from_packet_total, uint64_t *to_packet_total,
						uint64_t *from_data_total_dropped, uint64_t *to_data_total_dropped,
						uint64_t *from_packet_total_dropped, uint64_t *to_packet_total_dropped)
{
	DEBUG_CHECK_MAGIC(mi, ECM_DB_MAPPING_INSTANCE_MAGIC, "%p: magic failed", mi);
	spin_lock_bh(&ecm_db_lock);
	if (from_data_total) {
		*from_data_total = mi->from_data_total;
	}
	if (to_data_total) {
		*to_data_total = mi->to_data_total;
	}
	if (from_packet_total) {
		*from_packet_total = mi->from_packet_total;
	}
	if (to_packet_total) {
		*to_packet_total = mi->to_packet_total;
	}
	if (from_data_total_dropped) {
		*from_data_total_dropped = mi->from_data_total_dropped;
	}
	if (to_data_total_dropped) {
		*to_data_total_dropped = mi->to_data_total_dropped;
	}
	if (from_packet_total_dropped) {
		*from_packet_total_dropped = mi->from_packet_total_dropped;
	}
	if (to_packet_total_dropped) {
		*to_packet_total_dropped = mi->to_packet_total_dropped;
	}
	spin_unlock_bh(&ecm_db_lock);
}
EXPORT_SYMBOL(ecm_db_mapping_data_stats_get);

/*
 * ecm_db_host_data_stats_get()
 *	Return data stats for the instance
 */
void ecm_db_host_data_stats_get(struct ecm_db_host_instance *hi, uint64_t *from_data_total, uint64_t *to_data_total,
						uint64_t *from_packet_total, uint64_t *to_packet_total,
						uint64_t *from_data_total_dropped, uint64_t *to_data_total_dropped,
						uint64_t *from_packet_total_dropped, uint64_t *to_packet_total_dropped)
{
	DEBUG_CHECK_MAGIC(hi, ECM_DB_HOST_INSTANCE_MAGIC, "%p: magic failed", hi);
	spin_lock_bh(&ecm_db_lock);
	if (from_data_total) {
		*from_data_total = hi->from_data_total;
	}
	if (to_data_total) {
		*to_data_total = hi->to_data_total;
	}
	if (from_packet_total) {
		*from_packet_total = hi->from_packet_total;
	}
	if (to_packet_total) {
		*to_packet_total = hi->to_packet_total;
	}
	if (from_data_total_dropped) {
		*from_data_total_dropped = hi->from_data_total_dropped;
	}
	if (to_data_total_dropped) {
		*to_data_total_dropped = hi->to_data_total_dropped;
	}
	if (from_packet_total_dropped) {
		*from_packet_total_dropped = hi->from_packet_total_dropped;
	}
	if (to_packet_total_dropped) {
		*to_packet_total_dropped = hi->to_packet_total_dropped;
	}
	spin_unlock_bh(&ecm_db_lock);
}
EXPORT_SYMBOL(ecm_db_host_data_stats_get);

/*
 * ecm_db_node_data_stats_get()
 *	Return data stats for the instance
 */
void ecm_db_node_data_stats_get(struct ecm_db_node_instance *ni, uint64_t *from_data_total, uint64_t *to_data_total,
						uint64_t *from_packet_total, uint64_t *to_packet_total,
						uint64_t *from_data_total_dropped, uint64_t *to_data_total_dropped,
						uint64_t *from_packet_total_dropped, uint64_t *to_packet_total_dropped)
{
	DEBUG_CHECK_MAGIC(ni, ECM_DB_NODE_INSTANCE_MAGIC, "%p: magic failed", ni);
	spin_lock_bh(&ecm_db_lock);
	if (from_data_total) {
		*from_data_total = ni->from_data_total;
	}
	if (to_data_total) {
		*to_data_total = ni->to_data_total;
	}
	if (from_packet_total) {
		*from_packet_total = ni->from_packet_total;
	}
	if (to_packet_total) {
		*to_packet_total = ni->to_packet_total;
	}
	if (from_data_total_dropped) {
		*from_data_total_dropped = ni->from_data_total_dropped;
	}
	if (to_data_total_dropped) {
		*to_data_total_dropped = ni->to_data_total_dropped;
	}
	if (from_packet_total_dropped) {
		*from_packet_total_dropped = ni->from_packet_total_dropped;
	}
	if (to_packet_total_dropped) {
		*to_packet_total_dropped = ni->to_packet_total_dropped;
	}
	spin_unlock_bh(&ecm_db_lock);
}
EXPORT_SYMBOL(ecm_db_node_data_stats_get);

/*
 * ecm_db_iface_data_stats_get()
 *	Return data stats for the instance
 */
void ecm_db_iface_data_stats_get(struct ecm_db_iface_instance *ii, uint64_t *from_data_total, uint64_t *to_data_total,
						uint64_t *from_packet_total, uint64_t *to_packet_total,
						uint64_t *from_data_total_dropped, uint64_t *to_data_total_dropped,
						uint64_t *from_packet_total_dropped, uint64_t *to_packet_total_dropped)
{
	DEBUG_CHECK_MAGIC(ii, ECM_DB_IFACE_INSTANCE_MAGIC, "%p: magic failed", ii);
	spin_lock_bh(&ecm_db_lock);
	if (from_data_total) {
		*from_data_total = ii->from_data_total;
	}
	if (to_data_total) {
		*to_data_total = ii->to_data_total;
	}
	if (from_packet_total) {
		*from_packet_total = ii->from_packet_total;
	}
	if (to_packet_total) {
		*to_packet_total = ii->to_packet_total;
	}
	if (from_data_total_dropped) {
		*from_data_total_dropped = ii->from_data_total_dropped;
	}
	if (to_data_total_dropped) {
		*to_data_total_dropped = ii->to_data_total_dropped;
	}
	if (from_packet_total_dropped) {
		*from_packet_total_dropped = ii->from_packet_total_dropped;
	}
	if (to_packet_total_dropped) {
		*to_packet_total_dropped = ii->to_packet_total_dropped;
	}
	spin_unlock_bh(&ecm_db_lock);
}
EXPORT_SYMBOL(ecm_db_iface_data_stats_get);

/*
 * ecm_db_connection_serial_get()
 *	Return serial
 */
uint32_t ecm_db_connection_serial_get(struct ecm_db_connection_instance *ci)
{
	DEBUG_CHECK_MAGIC(ci, ECM_DB_CONNECTION_INSTANCE_MAGIC, "%p: magic failed", ci);
	return ci->serial;
}
EXPORT_SYMBOL(ecm_db_connection_serial_get);

/*
 * ecm_db_connection_from_address_get()
 *	Return ip address address
 */
void ecm_db_connection_from_address_get(struct ecm_db_connection_instance *ci, ip_addr_t addr)
{
	DEBUG_CHECK_MAGIC(ci, ECM_DB_CONNECTION_INSTANCE_MAGIC, "%p: magic failed", ci);
	DEBUG_CHECK_MAGIC(ci->mapping_from, ECM_DB_MAPPING_INSTANCE_MAGIC, "%p: magic failed", ci->mapping_from);
	DEBUG_CHECK_MAGIC(ci->mapping_from->host, ECM_DB_HOST_INSTANCE_MAGIC, "%p: magic failed", ci->mapping_from->host);
	ECM_IP_ADDR_COPY(addr, ci->mapping_from->host->address);
}
EXPORT_SYMBOL(ecm_db_connection_from_address_get);

/*
 * ecm_db_connection_from_address_nat_get()
 *	Return NAT ip address address
 */
void ecm_db_connection_from_address_nat_get(struct ecm_db_connection_instance *ci, ip_addr_t addr)
{
	DEBUG_CHECK_MAGIC(ci, ECM_DB_CONNECTION_INSTANCE_MAGIC, "%p: magic failed", ci);
	DEBUG_CHECK_MAGIC(ci->mapping_from, ECM_DB_MAPPING_INSTANCE_MAGIC, "%p: magic failed", ci->mapping_from);
	DEBUG_CHECK_MAGIC(ci->mapping_from->host, ECM_DB_HOST_INSTANCE_MAGIC, "%p: magic failed", ci->mapping_from->host);
	ECM_IP_ADDR_COPY(addr, ci->mapping_nat_from->host->address);
}
EXPORT_SYMBOL(ecm_db_connection_from_address_nat_get);

/*
 * ecm_db_connection_to_address_get()
 *	Return ip address address
 */
void ecm_db_connection_to_address_get(struct ecm_db_connection_instance *ci, ip_addr_t addr)
{
	DEBUG_CHECK_MAGIC(ci, ECM_DB_CONNECTION_INSTANCE_MAGIC, "%p: magic failed", ci);
	DEBUG_CHECK_MAGIC(ci->mapping_to, ECM_DB_MAPPING_INSTANCE_MAGIC, "%p: magic failed", ci->mapping_to);
	DEBUG_CHECK_MAGIC(ci->mapping_to->host, ECM_DB_HOST_INSTANCE_MAGIC, "%p: magic failed", ci->mapping_to->host);
	ECM_IP_ADDR_COPY(addr, ci->mapping_to->host->address);
}
EXPORT_SYMBOL(ecm_db_connection_to_address_get);

/*
 * ecm_db_connection_to_address_nat_get()
 *	Return NAT ip address address
 */
void ecm_db_connection_to_address_nat_get(struct ecm_db_connection_instance *ci, ip_addr_t addr)
{
	DEBUG_CHECK_MAGIC(ci, ECM_DB_CONNECTION_INSTANCE_MAGIC, "%p: magic failed", ci);
	DEBUG_CHECK_MAGIC(ci->mapping_to, ECM_DB_MAPPING_INSTANCE_MAGIC, "%p: magic failed", ci->mapping_to);
	DEBUG_CHECK_MAGIC(ci->mapping_to->host, ECM_DB_HOST_INSTANCE_MAGIC, "%p: magic failed", ci->mapping_to->host);
	ECM_IP_ADDR_COPY(addr, ci->mapping_nat_to->host->address);
}
EXPORT_SYMBOL(ecm_db_connection_to_address_nat_get);

/*
 * ecm_db_connection_to_port_get()
 *	Return port
 */
int ecm_db_connection_to_port_get(struct ecm_db_connection_instance *ci)
{
	DEBUG_CHECK_MAGIC(ci, ECM_DB_CONNECTION_INSTANCE_MAGIC, "%p: magic failed", ci);
	DEBUG_CHECK_MAGIC(ci->mapping_to, ECM_DB_MAPPING_INSTANCE_MAGIC, "%p: magic failed", ci->mapping_to);
	return ci->mapping_to->port;
}
EXPORT_SYMBOL(ecm_db_connection_to_port_get);

/*
 * ecm_db_connection_to_port_nat_get()
 *	Return port
 */
int ecm_db_connection_to_port_nat_get(struct ecm_db_connection_instance *ci)
{
	DEBUG_CHECK_MAGIC(ci, ECM_DB_CONNECTION_INSTANCE_MAGIC, "%p: magic failed", ci);
	DEBUG_CHECK_MAGIC(ci->mapping_to, ECM_DB_MAPPING_INSTANCE_MAGIC, "%p: magic failed", ci->mapping_to);
	return ci->mapping_nat_to->port;
}
EXPORT_SYMBOL(ecm_db_connection_to_port_nat_get);

/*
 * ecm_db_connection_from_port_get()
 *	Return port
 */
int ecm_db_connection_from_port_get(struct ecm_db_connection_instance *ci)
{
	DEBUG_CHECK_MAGIC(ci, ECM_DB_CONNECTION_INSTANCE_MAGIC, "%p: magic failed", ci);
	DEBUG_CHECK_MAGIC(ci->mapping_from, ECM_DB_MAPPING_INSTANCE_MAGIC, "%p: magic failed", ci->mapping_from);
	return ci->mapping_from->port;
}
EXPORT_SYMBOL(ecm_db_connection_from_port_get);

/*
 * ecm_db_connection_from_port_nat_get()
 *	Return port
 */
int ecm_db_connection_from_port_nat_get(struct ecm_db_connection_instance *ci)
{
	DEBUG_CHECK_MAGIC(ci, ECM_DB_CONNECTION_INSTANCE_MAGIC, "%p: magic failed", ci);
	DEBUG_CHECK_MAGIC(ci->mapping_from, ECM_DB_MAPPING_INSTANCE_MAGIC, "%p: magic failed", ci->mapping_from);
	return ci->mapping_nat_from->port;
}
EXPORT_SYMBOL(ecm_db_connection_from_port_nat_get);

/*
 * ecm_db_connection_to_node_address_get()
 *	Return address of the node used when sending packets to the 'to' side.
 */
void ecm_db_connection_to_node_address_get(struct ecm_db_connection_instance *ci, uint8_t *address_buffer)
{
	DEBUG_CHECK_MAGIC(ci, ECM_DB_CONNECTION_INSTANCE_MAGIC, "%p: magic failed", ci);
	memcpy(address_buffer, ci->mapping_to->host->node->address, ETH_ALEN);
}
EXPORT_SYMBOL(ecm_db_connection_to_node_address_get);

/*
 * ecm_db_connection_from_node_address_get()
 *	Return address of the node used when sending packets to the 'from' side.
 */
void ecm_db_connection_from_node_address_get(struct ecm_db_connection_instance *ci, uint8_t *address_buffer)
{
	DEBUG_CHECK_MAGIC(ci, ECM_DB_CONNECTION_INSTANCE_MAGIC, "%p: magic failed", ci);
	memcpy(address_buffer, ci->mapping_from->host->node->address, ETH_ALEN);
}
EXPORT_SYMBOL(ecm_db_connection_from_node_address_get);

/*
 * ecm_db_connection_to_nat_node_address_get()
 *	Return address of the node used when sending packets to the 'to' NAT side.
 */
void ecm_db_connection_to_nat_node_address_get(struct ecm_db_connection_instance *ci, uint8_t *address_buffer)
{
	DEBUG_CHECK_MAGIC(ci, ECM_DB_CONNECTION_INSTANCE_MAGIC, "%p: magic failed", ci);
	memcpy(address_buffer, ci->mapping_nat_to->host->node->address, ETH_ALEN);
}
EXPORT_SYMBOL(ecm_db_connection_to_nat_node_address_get);

/*
 * ecm_db_connection_from_nat_node_address_get()
 *	Return address of the node used when sending packets to the 'from' NAT side.
 */
void ecm_db_connection_from_nat_node_address_get(struct ecm_db_connection_instance *ci, uint8_t *address_buffer)
{
	DEBUG_CHECK_MAGIC(ci, ECM_DB_CONNECTION_INSTANCE_MAGIC, "%p: magic failed", ci);
	memcpy(address_buffer, ci->mapping_nat_from->host->node->address, ETH_ALEN);
}
EXPORT_SYMBOL(ecm_db_connection_from_nat_node_address_get);

/*
 * ecm_db_connection_to_iface_name_get()
 *	Return name of interface on which the 'to' side may be reached
 */
void ecm_db_connection_to_iface_name_get(struct ecm_db_connection_instance *ci, char *name_buffer)
{
	DEBUG_CHECK_MAGIC(ci, ECM_DB_CONNECTION_INSTANCE_MAGIC, "%p: magic failed", ci);
	strcpy(name_buffer, ci->mapping_to->host->node->iface->name);
}
EXPORT_SYMBOL(ecm_db_connection_to_iface_name_get);

/*
 * ecm_db_connection_from_iface_name_get()
 *	Return name of interface on which the 'from' side may be reached
 */
void ecm_db_connection_from_iface_name_get(struct ecm_db_connection_instance *ci, char *name_buffer)
{
	DEBUG_CHECK_MAGIC(ci, ECM_DB_CONNECTION_INSTANCE_MAGIC, "%p: magic failed", ci);
	strcpy(name_buffer, ci->mapping_from->host->node->iface->name);
}
EXPORT_SYMBOL(ecm_db_connection_from_iface_name_get);

/*
 * ecm_db_connection_to_iface_mtu_get()
 *	Return MTU of interface on which the 'to' side may be reached
 */
int ecm_db_connection_to_iface_mtu_get(struct ecm_db_connection_instance *ci)
{
	int mtu;
	DEBUG_CHECK_MAGIC(ci, ECM_DB_CONNECTION_INSTANCE_MAGIC, "%p: magic failed", ci);
	spin_lock_bh(&ecm_db_lock);
	mtu = ci->mapping_to->host->node->iface->mtu;
	spin_unlock_bh(&ecm_db_lock);
	return mtu;
}
EXPORT_SYMBOL(ecm_db_connection_to_iface_mtu_get);

/*
 * ecm_db_connection_to_iface_type_get()
 *	Return type of interface on which the 'to' side may be reached
 */
ecm_db_iface_type_t ecm_db_connection_to_iface_type_get(struct ecm_db_connection_instance *ci)
{
	ecm_db_iface_type_t type;

	DEBUG_CHECK_MAGIC(ci, ECM_DB_CONNECTION_INSTANCE_MAGIC, "%p: magic failed", ci);
	spin_lock_bh(&ecm_db_lock);
	type = ci->mapping_to->host->node->iface->type;
	spin_unlock_bh(&ecm_db_lock);
	return type;
}
EXPORT_SYMBOL(ecm_db_connection_to_iface_type_get);

/*
 * ecm_db_connection_from_iface_mtu_get()
 *	Return MTU of interface on which the 'from' side may be reached
 */
int ecm_db_connection_from_iface_mtu_get(struct ecm_db_connection_instance *ci)
{
	int mtu;
	DEBUG_CHECK_MAGIC(ci, ECM_DB_CONNECTION_INSTANCE_MAGIC, "%p: magic failed", ci);
	spin_lock_bh(&ecm_db_lock);
	mtu = ci->mapping_from->host->node->iface->mtu;
	spin_unlock_bh(&ecm_db_lock);
	return mtu;
}
EXPORT_SYMBOL(ecm_db_connection_from_iface_mtu_get);

/*
 * ecm_db_connection_from_iface_type_get()
 *	Return type of interface on which the 'from' side may be reached
 */
ecm_db_iface_type_t ecm_db_connection_from_iface_type_get(struct ecm_db_connection_instance *ci)
{
	ecm_db_iface_type_t type;

	DEBUG_CHECK_MAGIC(ci, ECM_DB_CONNECTION_INSTANCE_MAGIC, "%p: magic failed", ci);
	spin_lock_bh(&ecm_db_lock);
	type = ci->mapping_from->host->node->iface->type;
	spin_unlock_bh(&ecm_db_lock);
	return type;
}
EXPORT_SYMBOL(ecm_db_connection_from_iface_type_get);

/*
 * ecm_db_connection_iface_type_get()
 *	Return type of interface
 */
ecm_db_iface_type_t ecm_db_connection_iface_type_get(struct ecm_db_iface_instance *ii)
{
	DEBUG_CHECK_MAGIC(ii, ECM_DB_IFACE_INSTANCE_MAGIC, "%p: magic failed", ii);
	return ii->type;
}
EXPORT_SYMBOL(ecm_db_connection_iface_type_get);

/*
 * ecm_db_connection_classifier_generation_changed()
 *	Returns true if the classifier generation has changed for this connection.
 *
 * NOTE: The generation index will be reset on return from this call so action any true result immediately.
 */
bool ecm_db_connection_classifier_generation_changed(struct ecm_db_connection_instance *ci)
{
	DEBUG_CHECK_MAGIC(ci, ECM_DB_CONNECTION_INSTANCE_MAGIC, "%p: magic failed", ci);

	spin_lock_bh(&ecm_db_lock);
	if (ci->classifier_generation == ecm_db_classifier_generation) {
		spin_unlock_bh(&ecm_db_lock);
		return false;
	}
	ci->classifier_generation = ecm_db_classifier_generation;
	spin_unlock_bh(&ecm_db_lock);
	return true;
}
EXPORT_SYMBOL(ecm_db_connection_classifier_generation_changed);

/*
 * ecm_db_connection_classifier_peek_generation_changed()
 *	Returns true if the classifier generation has changed for this connection.
 *
 * NOTE: The generation index will NOT be reset on return from this call.
 */
bool ecm_db_connection_classifier_peek_generation_changed(struct ecm_db_connection_instance *ci)
{
	DEBUG_CHECK_MAGIC(ci, ECM_DB_CONNECTION_INSTANCE_MAGIC, "%p: magic failed", ci);

	spin_lock_bh(&ecm_db_lock);
	if (ci->classifier_generation == ecm_db_classifier_generation) {
		spin_unlock_bh(&ecm_db_lock);
		return false;
	}
	spin_unlock_bh(&ecm_db_lock);
	return true;
}
EXPORT_SYMBOL(ecm_db_connection_classifier_peek_generation_changed);

/*
 * ecm_db_connection_classifier_generation_change()
 *	Cause a specific connection to be re-generated
 */
void ecm_db_connection_classifier_generation_change(struct ecm_db_connection_instance *ci)
{
	DEBUG_CHECK_MAGIC(ci, ECM_DB_CONNECTION_INSTANCE_MAGIC, "%p: magic failed", ci);

	spin_lock_bh(&ecm_db_lock);
	ci->classifier_generation = ecm_db_classifier_generation - 1;
	spin_unlock_bh(&ecm_db_lock);
}
EXPORT_SYMBOL(ecm_db_connection_classifier_generation_change);

/*
 * ecm_db_classifier_generation_change()
 *	Bump the generation index to cause a re-classification of connections
 *
 * NOTE: Any connections that see activity after a call to this could be put back to undetermined qos state
 * and driven back through the classifiers.
 */
void ecm_db_classifier_generation_change(void)
{
	spin_lock_bh(&ecm_db_lock);
	ecm_db_classifier_generation++;
	spin_unlock_bh(&ecm_db_lock);
}
EXPORT_SYMBOL(ecm_db_classifier_generation_change);

/*
 * ecm_db_connection_direction_get()
 *	Return direction of the connection.
 *
 * NOTE: an EGRESS connection means that packets being sent to mapping_to should have qos applied.
 * INGRESS means that packets being sent to mapping_from should have qos applied.
 */
ecm_db_direction_t ecm_db_connection_direction_get(struct ecm_db_connection_instance *ci)
{
	DEBUG_CHECK_MAGIC(ci, ECM_DB_CONNECTION_INSTANCE_MAGIC, "%p: magic failed", ci);
	return ci->direction;
}
EXPORT_SYMBOL(ecm_db_connection_direction_get);

/*
 * ecm_db_mapping_port_count_get()
 *	Return port count stats for a mapping.
 */
void ecm_db_mapping_port_count_get(struct ecm_db_mapping_instance *mi,
						int *tcp_from, int *tcp_to, int *udp_from, int *udp_to, int *from, int *to,
						int *tcp_nat_from, int *tcp_nat_to, int *udp_nat_from, int *udp_nat_to, int *nat_from, int *nat_to)
{
	DEBUG_CHECK_MAGIC(mi, ECM_DB_MAPPING_INSTANCE_MAGIC, "%p: magic failed", mi);

	spin_lock_bh(&ecm_db_lock);

	*tcp_from = mi->tcp_from;
	*tcp_to = mi->tcp_to;
	*udp_from = mi->udp_from;
	*udp_to = mi->udp_to;
	*from = mi->from;
	*to = mi->to;

	*tcp_nat_from = mi->tcp_nat_from;
	*tcp_nat_to = mi->tcp_nat_to;
	*udp_nat_from = mi->udp_nat_from;
	*udp_nat_to = mi->udp_nat_to;
	*nat_from = mi->nat_from;
	*nat_to = mi->nat_to;

	spin_unlock_bh(&ecm_db_lock);
}
EXPORT_SYMBOL(ecm_db_mapping_port_count_get);

/*
 * ecm_db_connection_is_routed_get()
 *	Return whether connection is a routed path or not
 */
bool ecm_db_connection_is_routed_get(struct ecm_db_connection_instance *ci)
{
	DEBUG_CHECK_MAGIC(ci, ECM_DB_CONNECTION_INSTANCE_MAGIC, "%p: magic failed", ci);
	return ci->is_routed;
}
EXPORT_SYMBOL(ecm_db_connection_is_routed_get);

/*
 * ecm_db_connection_protocol_get()
 *	Return protocol of connection
 */
int ecm_db_connection_protocol_get(struct ecm_db_connection_instance *ci)
{
	DEBUG_CHECK_MAGIC(ci, ECM_DB_CONNECTION_INSTANCE_MAGIC, "%p: magic failed", ci);
	return ci->protocol;
}
EXPORT_SYMBOL(ecm_db_connection_protocol_get);

/*
 * ecm_db_host_address_get()
 *	Return address of host
 */
void ecm_db_host_address_get(struct ecm_db_host_instance *hi, ip_addr_t addr)
{
	DEBUG_CHECK_MAGIC(hi, ECM_DB_HOST_INSTANCE_MAGIC, "%p: magic failed", hi);
	ECM_IP_ADDR_COPY(addr, hi->address);
}
EXPORT_SYMBOL(ecm_db_host_address_get);

/*
 * ecm_db_host_node_address_get()
 *	Return node address of the host
 */
void ecm_db_host_node_address_get(struct ecm_db_host_instance *hi, uint8_t *address_buffer)
{
	DEBUG_CHECK_MAGIC(hi, ECM_DB_HOST_INSTANCE_MAGIC, "%p: magic failed", hi);
	memcpy(address_buffer, hi->node->address, ETH_ALEN);
}
EXPORT_SYMBOL(ecm_db_host_node_address_get);

/*
 * ecm_db_host_on_link_get()
 *	Return on link status of host
 */
bool ecm_db_host_on_link_get(struct ecm_db_host_instance *hi)
{
	DEBUG_CHECK_MAGIC(hi, ECM_DB_HOST_INSTANCE_MAGIC, "%p: magic failed", hi);
	return hi->on_link;
}
EXPORT_SYMBOL(ecm_db_host_on_link_get);

/*
 * ecm_db_mapping_adress_get()
 *	Return address
 */
void ecm_db_mapping_adress_get(struct ecm_db_mapping_instance *mi, ip_addr_t addr)
{
	DEBUG_CHECK_MAGIC(mi, ECM_DB_MAPPING_INSTANCE_MAGIC, "%p: magic failed", mi);
	ECM_IP_ADDR_COPY(addr, mi->host->address);
}
EXPORT_SYMBOL(ecm_db_mapping_adress_get);

/*
 * ecm_db_mapping_port_get()
 *	Return port
 */
int ecm_db_mapping_port_get(struct ecm_db_mapping_instance *mi)
{
	DEBUG_CHECK_MAGIC(mi, ECM_DB_MAPPING_INSTANCE_MAGIC, "%p: magic failed", mi);
	return mi->port;
}
EXPORT_SYMBOL(ecm_db_mapping_port_get);

/*
 * ecm_db_node_adress_get()
 *	Return address
 */
void ecm_db_node_adress_get(struct ecm_db_node_instance *ni, uint8_t *address_buffer)
{
	DEBUG_CHECK_MAGIC(ni, ECM_DB_NODE_INSTANCE_MAGIC, "%p: magic failed", ni);
	memcpy(address_buffer, ni->address, ETH_ALEN);
}
EXPORT_SYMBOL(ecm_db_node_adress_get);

/*
 * _ecm_db_timer_group_entry_remove()
 *	Remove the entry from its timer group, returns false if the entry has already expired.
 */
static bool _ecm_db_timer_group_entry_remove(struct ecm_db_timer_group_entry *tge)
{
	struct ecm_db_timer_group *timer_group;

	/*
	 * If not in a timer group then it is already removed
	 */
	if (tge->group == ECM_DB_TIMER_GROUPS_MAX) {
		return false;
	}

	/*
	 * Remove the connection from its current group
	 */
	timer_group = &ecm_db_timer_groups[tge->group];

	/*
	 * Somewhere in the list?
	 */
	if (tge->prev) {
		tge->prev->next = tge->next;
	} else {
		/*
		 * First in the group
		 */
		DEBUG_ASSERT(timer_group->head == tge, "%p: bad head, expecting %p, got %p\n", timer_group, tge, timer_group->head);
		timer_group->head = tge->next;
	}	

	if (tge->next) {
		tge->next->prev = tge->prev;
	} else {
		/*
		 * No next so this must be the last item - we need to adjust the tail pointer
		 */
		DEBUG_ASSERT(timer_group->tail == tge, "%p: bad tail, expecting %p got %p\n", timer_group, tge, timer_group->tail);
		timer_group->tail = tge->prev;
	}

	/*
	 * No longer a part of a timer group
	 */
	tge->group = ECM_DB_TIMER_GROUPS_MAX;
	return true;
}

/*
 * ecm_db_timer_group_entry_remove()
 *	Remove the connection from its timer group, returns false if the entry has already expired.
 */
bool ecm_db_timer_group_entry_remove(struct ecm_db_timer_group_entry *tge)
{
	bool res;
	spin_lock_bh(&ecm_db_lock);
	res = _ecm_db_timer_group_entry_remove(tge);
	spin_unlock_bh(&ecm_db_lock);
	return res;
}
EXPORT_SYMBOL(ecm_db_timer_group_entry_remove);

/*
 * _ecm_db_timer_group_entry_set()
 *	Set the timer group to which this entry will be a member
 */
void _ecm_db_timer_group_entry_set(struct ecm_db_timer_group_entry *tge, ecm_db_timer_group_t tg)
{
	struct ecm_db_timer_group *timer_group;

	DEBUG_ASSERT(tge->group == ECM_DB_TIMER_GROUPS_MAX, "%p: already set\n", tge);

	/*
	 * Set group
	 */
	tge->group = tg;
	timer_group = &ecm_db_timer_groups[tge->group];
	tge->timeout = timer_group->time + ecm_db_time;

	/*
	 * Insert into a timer group at the head (as this is now touched)
	 */
	tge->prev = NULL;
	tge->next = timer_group->head;
	if (!timer_group->head) {
		/*
		 * As there is no head there is also no tail so we need to set that
		 */
		timer_group->tail = tge;
	} else {
		/*
		 * As there is a head already there must be a tail.  Since we insert before
		 * the current head we don't adjust the tail.
		 */
		timer_group->head->prev = tge;
	}
	timer_group->head = tge;
}

/*
 * ecm_db_timer_group_entry_reset()
 *	Re-set the timer group to which this entry will be a member.
 *
 * Returns false if the timer cannot be reset because it has expired
 */
bool ecm_db_timer_group_entry_reset(struct ecm_db_timer_group_entry *tge, ecm_db_timer_group_t tg)
{
	spin_lock_bh(&ecm_db_lock);

	/*
	 * Remove it from its current group, if any
	 */
	if (!_ecm_db_timer_group_entry_remove(tge)) {
		spin_unlock_bh(&ecm_db_lock);
		return false;
	}

	/*
	 * Set new group
	 */
	_ecm_db_timer_group_entry_set(tge, tg);
	spin_unlock_bh(&ecm_db_lock);
	return true;
}
EXPORT_SYMBOL(ecm_db_timer_group_entry_reset);

/*
 * ecm_db_timer_group_entry_set()
 *	Set the timer group to which this entry will be a member
 */
void ecm_db_timer_group_entry_set(struct ecm_db_timer_group_entry *tge, ecm_db_timer_group_t tg)
{
	spin_lock_bh(&ecm_db_lock);
	_ecm_db_timer_group_entry_set(tge, tg);
	spin_unlock_bh(&ecm_db_lock);
}
EXPORT_SYMBOL(ecm_db_timer_group_entry_set);

/*
 * ecm_db_timer_group_entry_init()
 *	Initialise a timer entry ready for setting
 */
void ecm_db_timer_group_entry_init(struct ecm_db_timer_group_entry *tge, ecm_db_timer_group_entry_callback_t fn, void *arg)
{
	memset(tge, 0, sizeof(struct ecm_db_timer_group_entry));
	tge->group = ECM_DB_TIMER_GROUPS_MAX;
	tge->arg = arg;
	tge->fn = fn;
}
EXPORT_SYMBOL(ecm_db_timer_group_entry_init);

/*
 * ecm_db_timer_group_entry_touch()
 *	Update the timeout, if the timer is not running this has no effect.
 * It returns false if the timer is not running.
 */
bool ecm_db_timer_group_entry_touch(struct ecm_db_timer_group_entry *tge)
{
	struct ecm_db_timer_group *timer_group;

	spin_lock_bh(&ecm_db_lock);

	/*
	 * If not in a timer group then do nothing
	 */
	if (tge->group == ECM_DB_TIMER_GROUPS_MAX) {
		spin_unlock_bh(&ecm_db_lock);
		return false;
	}

	/*
	 * Update time to live
	 */
	timer_group = &ecm_db_timer_groups[tge->group];

	/*
	 * Link out of its current position.
	 */
	if (!tge->prev) {
		/*
		 * Already at the head, just update the time
		 */
		tge->timeout = timer_group->time + ecm_db_time;
		spin_unlock_bh(&ecm_db_lock);
		return true;
	}

	/*
	 * tge->prev is not null, so:
	 * 1) it is in a timer list
	 * 2) is not at the head of the list
	 * 3) there is a head already (so more than one item on the list)
	 * 4) there is a prev pointer.
	 * Somewhere in the group list - unlink it.
	 */
	tge->prev->next = tge->next;

	if (tge->next) {
		tge->next->prev = tge->prev;
	} else {
		/*
		 * Since there is no next this must be the tail
		 */
		DEBUG_ASSERT(timer_group->tail == tge, "%p: bad tail, expecting %p got %p\n", timer_group, tge, timer_group->tail);
		timer_group->tail = tge->prev;
	}

	/*
	 * Link in to head.
	 */
	tge->prev = NULL;
	tge->next = timer_group->head;
	timer_group->head->prev = tge;
	timer_group->head = tge;
	spin_unlock_bh(&ecm_db_lock);
	return true;
}
EXPORT_SYMBOL(ecm_db_timer_group_entry_touch);

/*
 * _ecm_db_connection_ref()
 */
static void _ecm_db_connection_ref(struct ecm_db_connection_instance *ci)
{
	DEBUG_CHECK_MAGIC(ci, ECM_DB_CONNECTION_INSTANCE_MAGIC, "%p: magic failed", ci);
	ci->refs++;
	DEBUG_TRACE("%p: connection ref %d\n", ci, ci->refs);
	DEBUG_ASSERT(ci->refs > 0, "%p: ref wrap\n", ci);
}

/*
 * ecm_db_connection_ref()
 */
void ecm_db_connection_ref(struct ecm_db_connection_instance *ci)
{
	spin_lock_bh(&ecm_db_lock);
	_ecm_db_connection_ref(ci);
	spin_unlock_bh(&ecm_db_lock);
}
EXPORT_SYMBOL(ecm_db_connection_ref);

/*
 * _ecm_db_mapping_ref()
 */
static void _ecm_db_mapping_ref(struct ecm_db_mapping_instance *mi)
{
	DEBUG_CHECK_MAGIC(mi, ECM_DB_MAPPING_INSTANCE_MAGIC, "%p: magic failed\n", mi);
	mi->refs++;
	DEBUG_TRACE("%p: mapping ref %d\n", mi, mi->refs);
	DEBUG_ASSERT(mi->refs > 0, "%p: ref wrap\n", mi);
}

/*
 * ecm_db_mapping_ref()
 */
void ecm_db_mapping_ref(struct ecm_db_mapping_instance *mi)
{
	spin_lock_bh(&ecm_db_lock);
	_ecm_db_mapping_ref(mi);
	spin_unlock_bh(&ecm_db_lock);
}
EXPORT_SYMBOL(ecm_db_mapping_ref);

/*
 * _ecm_db_host_ref()
 */
static void _ecm_db_host_ref(struct ecm_db_host_instance *hi)
{
	DEBUG_CHECK_MAGIC(hi, ECM_DB_HOST_INSTANCE_MAGIC, "%p: magic failed\n", hi);
	hi->refs++;
	DEBUG_TRACE("%p: host ref %d\n", hi, hi->refs);
	DEBUG_ASSERT(hi->refs > 0, "%p: ref wrap\n", hi);
}

/*
 * ecm_db_host_ref()
 */
void ecm_db_host_ref(struct ecm_db_host_instance *hi)
{
	spin_lock_bh(&ecm_db_lock);
	_ecm_db_host_ref(hi);
	spin_unlock_bh(&ecm_db_lock);
}
EXPORT_SYMBOL(ecm_db_host_ref);

/*
 * _ecm_db_node_ref()
 */
static void _ecm_db_node_ref(struct ecm_db_node_instance *ni)
{
	DEBUG_CHECK_MAGIC(ni, ECM_DB_NODE_INSTANCE_MAGIC, "%p: magic failed\n", ni);
	ni->refs++;
	DEBUG_TRACE("%p: node ref %d\n", ni, ni->refs);
	DEBUG_ASSERT(ni->refs > 0, "%p: ref wrap\n", ni);
}

/*
 * ecm_db_node_ref()
 */
void ecm_db_node_ref(struct ecm_db_node_instance *ni)
{
	spin_lock_bh(&ecm_db_lock);
	_ecm_db_node_ref(ni);
	spin_unlock_bh(&ecm_db_lock);
}
EXPORT_SYMBOL(ecm_db_node_ref);

/*
 * _ecm_db_iface_ref()
 */
static void _ecm_db_iface_ref(struct ecm_db_iface_instance *ii)
{
	DEBUG_CHECK_MAGIC(ii, ECM_DB_IFACE_INSTANCE_MAGIC, "%p: magic failed\n", ii);
	ii->refs++;
	DEBUG_TRACE("%p: iface ref %d\n", ii, ii->refs);
	DEBUG_ASSERT(ii->refs > 0, "%p: ref wrap\n", ii);
}

/*
 * ecm_db_iface_ref()
 */
void ecm_db_iface_ref(struct ecm_db_iface_instance *ii)
{
	spin_lock_bh(&ecm_db_lock);
	_ecm_db_iface_ref(ii);
	spin_unlock_bh(&ecm_db_lock);
}
EXPORT_SYMBOL(ecm_db_iface_ref);

/*
 * _ecm_db_listener_ref()
 */
static void _ecm_db_listener_ref(struct ecm_db_listener_instance *li)
{
	DEBUG_CHECK_MAGIC(li, ECM_DB_LISTENER_INSTANCE_MAGIC, "%p: magic failed", li);
	li->refs++;
	DEBUG_ASSERT(li->refs > 0, "%p: ref wrap\n", li);
}

/*
 * ecm_db_listener_ref()
 */
void ecm_db_listener_ref(struct ecm_db_listener_instance *li)
{
	spin_lock_bh(&ecm_db_lock);
	_ecm_db_listener_ref(li);
	spin_unlock_bh(&ecm_db_lock);
}
EXPORT_SYMBOL(ecm_db_listener_ref);

/*
 * ecm_db_connections_get_and_ref_first()
 *	Obtain a ref to the first connection instance, if any
 */
static struct ecm_db_connection_instance *ecm_db_connections_get_and_ref_first(void)
{
	struct ecm_db_connection_instance *ci;
	spin_lock_bh(&ecm_db_lock);
	ci = ecm_db_connections;
	if (ci) {
		_ecm_db_connection_ref(ci);
	}	
	spin_unlock_bh(&ecm_db_lock);
	return ci;
}
EXPORT_SYMBOL(ecm_db_connections_get_and_ref_first);

/*
 * ecm_db_connection_get_and_ref_next()
 *	Return the next connection in the list given a connection
 */
struct ecm_db_connection_instance *ecm_db_connection_get_and_ref_next(struct ecm_db_connection_instance *ci)
{
	struct ecm_db_connection_instance *cin;
	DEBUG_CHECK_MAGIC(ci, ECM_DB_CONNECTION_INSTANCE_MAGIC, "%p: magic failed", ci);
	spin_lock_bh(&ecm_db_lock);
	cin = ci->next;
	if (cin) {
		_ecm_db_connection_ref(cin);
	}	
	spin_unlock_bh(&ecm_db_lock);
	return cin;
}
EXPORT_SYMBOL(ecm_db_connection_get_and_ref_next);

/*
 * ecm_db_mappings_get_and_ref_first()
 *	Obtain a ref to the first mapping instance, if any
 */
struct ecm_db_mapping_instance *ecm_db_mappings_get_and_ref_first(void)
{
	struct ecm_db_mapping_instance *mi;
	spin_lock_bh(&ecm_db_lock);
	mi = ecm_db_mappings;
	if (mi) {
		_ecm_db_mapping_ref(mi);
	}	
	spin_unlock_bh(&ecm_db_lock);
	return mi;
}
EXPORT_SYMBOL(ecm_db_mappings_get_and_ref_first);

/*
 * ecm_db_mapping_get_and_ref_next()
 *	Return the next mapping in the list given a mapping
 */
struct ecm_db_mapping_instance *ecm_db_mapping_get_and_ref_next(struct ecm_db_mapping_instance *mi)
{
	struct ecm_db_mapping_instance *min;
	DEBUG_CHECK_MAGIC(mi, ECM_DB_MAPPING_INSTANCE_MAGIC, "%p: magic failed", mi);
	spin_lock_bh(&ecm_db_lock);
	min = mi->next;
	if (min) {
		_ecm_db_mapping_ref(min);
	}	
	spin_unlock_bh(&ecm_db_lock);
	return min;
}
EXPORT_SYMBOL(ecm_db_mapping_get_and_ref_next);

/*
 * ecm_db_hosts_get_and_ref_first()
 *	Obtain a ref to the first host instance, if any
 */
struct ecm_db_host_instance *ecm_db_hosts_get_and_ref_first(void)
{
	struct ecm_db_host_instance *hi;
	spin_lock_bh(&ecm_db_lock);
	hi = ecm_db_hosts;
	if (hi) {
		_ecm_db_host_ref(hi);
	}	
	spin_unlock_bh(&ecm_db_lock);
	return hi;
}
EXPORT_SYMBOL(ecm_db_hosts_get_and_ref_first);

/*
 * ecm_db_host_get_and_ref_next()
 *	Return the next host in the list given a host
 */
struct ecm_db_host_instance *ecm_db_host_get_and_ref_next(struct ecm_db_host_instance *hi)
{
	struct ecm_db_host_instance *hin;
	DEBUG_CHECK_MAGIC(hi, ECM_DB_HOST_INSTANCE_MAGIC, "%p: magic failed", hi);
	spin_lock_bh(&ecm_db_lock);
	hin = hi->next;
	if (hin) {
		_ecm_db_host_ref(hin);
	}	
	spin_unlock_bh(&ecm_db_lock);
	return hin;
}
EXPORT_SYMBOL(ecm_db_host_get_and_ref_next);

/*
 * ecm_db_listeners_get_and_ref_first()
 *	Obtain a ref to the first listener instance, if any
 */
static struct ecm_db_listener_instance *ecm_db_listeners_get_and_ref_first(void)
{
	struct ecm_db_listener_instance *li;
	spin_lock_bh(&ecm_db_lock);
	li = ecm_db_listeners;
	if (li) {
		_ecm_db_listener_ref(li);
	}	
	spin_unlock_bh(&ecm_db_lock);
	return li;
}

/*
 * ecm_db_listener_get_and_ref_next()
 *	Return the next listener in the list given a listener
 */
static struct ecm_db_listener_instance *ecm_db_listener_get_and_ref_next(struct ecm_db_listener_instance *li)
{
	struct ecm_db_listener_instance *lin;
	DEBUG_CHECK_MAGIC(li, ECM_DB_LISTENER_INSTANCE_MAGIC, "%p: magic failed", li);
	spin_lock_bh(&ecm_db_lock);
	lin = li->next;
	if (lin) {
		_ecm_db_listener_ref(lin);
	}	
	spin_unlock_bh(&ecm_db_lock);
	return lin;
}

/*
 * ecm_db_nodes_get_and_ref_first()
 *	Obtain a ref to the first node instance, if any
 */
struct ecm_db_node_instance *ecm_db_nodes_get_and_ref_first(void)
{
	struct ecm_db_node_instance *ni;
	spin_lock_bh(&ecm_db_lock);
	ni = ecm_db_nodes;
	if (ni) {
		_ecm_db_node_ref(ni);
	}	
	spin_unlock_bh(&ecm_db_lock);
	return ni;
}
EXPORT_SYMBOL(ecm_db_nodes_get_and_ref_first);

/*
 * ecm_db_node_get_and_ref_next()
 *	Return the next node in the list given a node
 */
struct ecm_db_node_instance *ecm_db_node_get_and_ref_next(struct ecm_db_node_instance *ni)
{
	struct ecm_db_node_instance *nin;
	DEBUG_CHECK_MAGIC(ni, ECM_DB_NODE_INSTANCE_MAGIC, "%p: magic failed", ni);
	spin_lock_bh(&ecm_db_lock);
	nin = ni->next;
	if (nin) {
		_ecm_db_node_ref(nin);
	}	
	spin_unlock_bh(&ecm_db_lock);
	return nin;
}
EXPORT_SYMBOL(ecm_db_node_get_and_ref_next);

/*
 * ecm_db_interfaces_get_and_ref_first()
 *	Obtain a ref to the first iface instance, if any
 */
struct ecm_db_iface_instance *ecm_db_interfaces_get_and_ref_first(void)
{
	struct ecm_db_iface_instance *ii;
	spin_lock_bh(&ecm_db_lock);
	ii = ecm_db_interfaces;
	if (ii) {
		_ecm_db_iface_ref(ii);
	}	
	spin_unlock_bh(&ecm_db_lock);
	return ii;
}
EXPORT_SYMBOL(ecm_db_interfaces_get_and_ref_first);

/*
 * ecm_db_interface_get_and_ref_next()
 *	Return the next iface in the list given a iface
 */
struct ecm_db_iface_instance *ecm_db_interface_get_and_ref_next(struct ecm_db_iface_instance *ii)
{
	struct ecm_db_iface_instance *iin;
	DEBUG_CHECK_MAGIC(ii, ECM_DB_IFACE_INSTANCE_MAGIC, "%p: magic failed", ii);
	spin_lock_bh(&ecm_db_lock);
	iin = ii->next;
	if (iin) {
		_ecm_db_iface_ref(iin);
	}	
	spin_unlock_bh(&ecm_db_lock);
	return iin;
}
EXPORT_SYMBOL(ecm_db_interface_get_and_ref_next);

/*
 * ecm_db_connection_deref()
 *	Release reference to connection.  Connection is removed from database on final deref and destroyed.
 */
int ecm_db_connection_deref(struct ecm_db_connection_instance *ci)
{
	int32_t i;

	DEBUG_CHECK_MAGIC(ci, ECM_DB_CONNECTION_INSTANCE_MAGIC, "%p: magic failed", ci);

	spin_lock_bh(&ecm_db_lock);
	ci->refs--;
	DEBUG_TRACE("%p: connection deref %d\n", ci, ci->refs);
	DEBUG_ASSERT(ci->refs >= 0, "%p: ref wrap\n", ci);

	if (ci->refs > 0) {
		int refs = ci->refs;
		spin_unlock_bh(&ecm_db_lock);
		return refs;
	}

	/*
	 * Remove from database if inserted
	 */
	if (!ci->flags & ECM_DB_CONNECTION_FLAGS_INSERTED) {
		spin_unlock_bh(&ecm_db_lock);
	} else {
		struct ecm_db_listener_instance *li;
		struct ecm_db_iface_instance *iface_from;
		struct ecm_db_iface_instance *iface_to;
		struct ecm_db_iface_instance *iface_nat_from;
		struct ecm_db_iface_instance *iface_nat_to;

		/*
		 * Remove it from the connection hash table
		 */
		if (!ci->hash_prev) {
			DEBUG_ASSERT(ecm_db_connection_table[ci->hash_index] == ci, "%p: hash table bad\n", ci);
			ecm_db_connection_table[ci->hash_index] = ci->hash_next;
		} else {
			ci->hash_prev->hash_next = ci->hash_next;
		}
		if (ci->hash_next) {
			ci->hash_next->hash_prev = ci->hash_prev;
		}
		ecm_db_connection_table_lengths[ci->hash_index]--;
		DEBUG_ASSERT(ecm_db_connection_table_lengths[ci->hash_index] >= 0, "%p: invalid table len %d\n", ci, ecm_db_connection_table_lengths[ci->hash_index]);

		/*
		 * Remove it from the connection serial hash table
		 */
		if (!ci->serial_hash_prev) {
			DEBUG_ASSERT(ecm_db_connection_serial_table[ci->serial_hash_index] == ci, "%p: hash table bad\n", ci);
			ecm_db_connection_serial_table[ci->serial_hash_index] = ci->serial_hash_next;
		} else {
			ci->serial_hash_prev->serial_hash_next = ci->serial_hash_next;
		}
		if (ci->serial_hash_next) {
			ci->serial_hash_next->serial_hash_prev = ci->serial_hash_prev;
		}
		ecm_db_connection_serial_table_lengths[ci->serial_hash_index]--;
		DEBUG_ASSERT(ecm_db_connection_serial_table_lengths[ci->serial_hash_index] >= 0, "%p: invalid table len %d\n", ci, ecm_db_connection_serial_table_lengths[ci->serial_hash_index]);

		/*
		 * Remove from the global list
		 */
		if (!ci->prev) {
			DEBUG_ASSERT(ecm_db_connections == ci, "%p: conn table bad\n", ci);
			ecm_db_connections = ci->next;
		} else {
			ci->prev->next = ci->next;
		}
		if (ci->next) {
			ci->next->prev = ci->prev;
		}

		/*
		 * Remove connection from the "from" mapping connection list
		 */
		if (!ci->from_prev) {
			DEBUG_ASSERT(ci->mapping_from->from_connections == ci, "%p: from conn table bad\n", ci);
			ci->mapping_from->from_connections = ci->from_next;
		} else {
			ci->from_prev->from_next = ci->from_next;
		}
		if (ci->from_next) {
			ci->from_next->from_prev = ci->from_prev;
		}

		/*
		 * Remove connection from the "to" mapping connection list
		 */
		if (!ci->to_prev) {
			DEBUG_ASSERT(ci->mapping_to->to_connections == ci, "%p: to conn table bad\n", ci);
			ci->mapping_to->to_connections = ci->to_next;
		} else {
			ci->to_prev->to_next = ci->to_next;
		}
		if (ci->to_next) {
			ci->to_next->to_prev = ci->to_prev;
		}

		/*
		 * Remove connection from the "from" NAT mapping connection list
		 */
		if (!ci->from_nat_prev) {
			DEBUG_ASSERT(ci->mapping_nat_from->from_nat_connections == ci, "%p: nat from conn table bad\n", ci);
			ci->mapping_nat_from->from_nat_connections = ci->from_nat_next;
		} else {
			ci->from_nat_prev->from_nat_next = ci->from_nat_next;
		}
		if (ci->from_nat_next) {
			ci->from_nat_next->from_nat_prev = ci->from_nat_prev;
		}

		/*
		 * Remove connection from the "to" NAT mapping connection list
		 */
		if (!ci->to_nat_prev) {
			DEBUG_ASSERT(ci->mapping_nat_to->to_nat_connections == ci, "%p: nat to conn table bad\n", ci);
			ci->mapping_nat_to->to_nat_connections = ci->to_nat_next;
		} else {
			ci->to_nat_prev->to_nat_next = ci->to_nat_next;
		}
		if (ci->to_nat_next) {
			ci->to_nat_next->to_nat_prev = ci->to_nat_prev;
		}

		/*
		 * Remove connection from the "from" iface connection list
		 */
		iface_from = ci->mapping_from->host->node->iface;
		if (!ci->iface_from_prev) {
			DEBUG_ASSERT(iface_from->from_connections == ci, "%p: iface from conn table bad\n", ci);
			iface_from->from_connections = ci->iface_from_next;
		} else {
			ci->iface_from_prev->iface_from_next = ci->iface_from_next;
		}
		if (ci->iface_from_next) {
			ci->iface_from_next->iface_from_prev = ci->iface_from_prev;
		}

		/*
		 * Remove connection from the "to" iface connection list
		 */
		iface_to = ci->mapping_to->host->node->iface;
		if (!ci->iface_to_prev) {
			DEBUG_ASSERT(iface_to->to_connections == ci, "%p: to conn table bad\n", ci);
			iface_to->to_connections = ci->iface_to_next;
		} else {
			ci->iface_to_prev->iface_to_next = ci->iface_to_next;
		}
		if (ci->iface_to_next) {
			ci->iface_to_next->iface_to_prev = ci->iface_to_prev;
		}

		/*
		 * Remove connection from the "from" NAT iface connection list
		 */
		iface_nat_from = ci->mapping_nat_from->host->node->iface;
		if (!ci->iface_from_nat_prev) {
			DEBUG_ASSERT(iface_nat_from->from_nat_connections == ci, "%p: nat from conn table bad\n", ci);
			iface_nat_from->from_nat_connections = ci->iface_from_nat_next;
		} else {
			ci->iface_from_nat_prev->iface_from_nat_next = ci->iface_from_nat_next;
		}
		if (ci->iface_from_nat_next) {
			ci->iface_from_nat_next->iface_from_nat_prev = ci->iface_from_nat_prev;
		}

		/*
		 * Remove connection from the "to" NAT iface connection list
		 */
		iface_nat_to = ci->mapping_nat_to->host->node->iface;
		if (!ci->iface_to_nat_prev) {
			DEBUG_ASSERT(iface_nat_to->to_nat_connections == ci, "%p: nat to conn table bad\n", ci);
			iface_nat_to->to_nat_connections = ci->iface_to_nat_next;
		} else {
			ci->iface_to_nat_prev->iface_to_nat_next = ci->iface_to_nat_next;
		}
		if (ci->iface_to_nat_next) {
			ci->iface_to_nat_next->iface_to_nat_prev = ci->iface_to_nat_prev;
		}

		/*
		 * Update the counters in the mappings
		 */
		if (ci->protocol == IPPROTO_UDP) {
			ci->mapping_from->udp_from--;
			ci->mapping_to->udp_to--;
			ci->mapping_nat_from->udp_nat_from--;
			ci->mapping_nat_to->udp_nat_to--;
		} else if (ci->protocol == IPPROTO_TCP) {
			ci->mapping_from->tcp_from--;
			ci->mapping_to->tcp_to--;
			ci->mapping_nat_from->tcp_nat_from--;
			ci->mapping_nat_to->tcp_nat_to--;
		}

		ci->mapping_from->from--;
		ci->mapping_to->to--;
		ci->mapping_nat_from->nat_from--;
		ci->mapping_nat_to->nat_to--;

		/*
		 * Assert that the defunt timer has been detached
		 */
		DEBUG_ASSERT(ci->defunct_timer.group == ECM_DB_TIMER_GROUPS_MAX, "%p: unexpected timer group %d\n", ci, ci->defunct_timer.group);

		/*
		 * Decrement protocol counter stats
		 */
		ecm_db_connection_count_by_protocol[ci->protocol]--;
		DEBUG_ASSERT(ecm_db_connection_count_by_protocol[ci->protocol] >= 0, "%p: Invalid protocol count %d\n", ci, ecm_db_connection_count_by_protocol[ci->protocol]);
		spin_unlock_bh(&ecm_db_lock);

		/*
		 * Throw removed event to listeners
		 */
		DEBUG_TRACE("%p: Throw connection removed event\n", ci);
		li = ecm_db_listeners_get_and_ref_first();
		while (li) {
			struct ecm_db_listener_instance *lin;
			if (li->connection_removed) {
				li->connection_removed(li->arg, ci);
			}

			/*
			 * Get next listener
			 */
			lin = ecm_db_listener_get_and_ref_next(li);
			ecm_db_listener_deref(li);
			li = lin;
		}
	}

	/*
	 * Throw final event
	 */
	if (ci->final) {
		ci->final(ci->arg);
	}

	/*
	 * Release instances to the objects referenced by the connection
	 */
	while (ci->assignments) {
		struct ecm_classifier_instance *classi = ci->assignments;
		ci->assignments = classi->ca_next;
		classi->deref(classi);
	}

	if (ci->dci) {
		ci->dci->base.deref((struct ecm_classifier_instance *)ci->dci);
	}
	if (ci->mapping_from) {
		ecm_db_mapping_deref(ci->mapping_from);
	}
	if (ci->mapping_to) {
		ecm_db_mapping_deref(ci->mapping_to);
	}
	if (ci->mapping_nat_from) {
		ecm_db_mapping_deref(ci->mapping_nat_from);
	}
	if (ci->mapping_nat_to) {
		ecm_db_mapping_deref(ci->mapping_nat_to);
	}
	if (ci->feci) {
		ci->feci->deref(ci->feci);
	}

	/*
	 * Remove references to the interfaces in our heirarchy lists
	 */
	for (i = ci->from_interface_first; i < ECM_DB_IFACE_HEIRARCHY_MAX; ++i) {
		DEBUG_TRACE("%p: from interface %d remove: %p\n", ci, i, ci->from_interfaces[i]);
		ecm_db_iface_deref(ci->from_interfaces[i]);
	}
	for (i = ci->to_interface_first; i < ECM_DB_IFACE_HEIRARCHY_MAX; ++i) {
		DEBUG_TRACE("%p: to interface %d remove: %p\n", ci, i, ci->to_interfaces[i]);
		ecm_db_iface_deref(ci->to_interfaces[i]);
	}
	for (i = ci->from_nat_interface_first; i < ECM_DB_IFACE_HEIRARCHY_MAX; ++i) {
		DEBUG_TRACE("%p: from nat interface %d remove: %p\n", ci, i, ci->from_nat_interfaces[i]);
		ecm_db_iface_deref(ci->from_nat_interfaces[i]);
	}
	for (i = ci->to_nat_interface_first; i < ECM_DB_IFACE_HEIRARCHY_MAX; ++i) {
		DEBUG_TRACE("%p: to nat interface %d remove: %p\n", ci, i, ci->to_nat_interfaces[i]);
		ecm_db_iface_deref(ci->to_nat_interfaces[i]);
	}

	/*
	 * We can now destroy the instance
	 */
	DEBUG_CLEAR_MAGIC(ci);
	kfree(ci);

	/*
	 * Decrease global connection count
	 */
	spin_lock_bh(&ecm_db_lock);
	ecm_db_connection_count--;
	DEBUG_ASSERT(ecm_db_connection_count >= 0, "%p: connection count wrap\n", ci);

	/*
	 * No longer need ref to thread for this object
	 */
	ecm_db_thread_refs--;
	DEBUG_ASSERT(ecm_db_thread_refs >= 0, "thread ref wrap: %d\n", ecm_db_thread_refs);
	spin_unlock_bh(&ecm_db_lock);

	/*
	 * Thread may be able to exit on object destruction
	 */
	wake_up_process(ecm_db_thread);

	return 0;
}
EXPORT_SYMBOL(ecm_db_connection_deref);

/*
 * ecm_db_mapping_deref()
 *	Release ref to mapping, possibly removing it from the database and destroying it.
 */
int ecm_db_mapping_deref(struct ecm_db_mapping_instance *mi)
{
	DEBUG_CHECK_MAGIC(mi, ECM_DB_MAPPING_INSTANCE_MAGIC, "%p: magic failed\n", mi);

	spin_lock_bh(&ecm_db_lock);
	mi->refs--;
	DEBUG_TRACE("%p: mapping deref %d\n", mi, mi->refs);
	DEBUG_ASSERT(mi->refs >= 0, "%p: ref wrap\n", mi);

	if (mi->refs > 0) {
		int refs = mi->refs;
		spin_unlock_bh(&ecm_db_lock);
		return refs;
	}

	DEBUG_ASSERT(!mi->from_connections && !mi->tcp_from && !mi->udp_from && !mi->from, "%p: from not null: %p, %d, %d, %d\n",
			mi, mi->from_connections, mi->tcp_from, mi->udp_from, mi->from);
	DEBUG_ASSERT(!mi->to_connections && !mi->tcp_to && !mi->udp_to && !mi->to, "%p: to not null: %p, %d, %d, %d\n",
			mi, mi->to_connections, mi->tcp_to, mi->udp_to, mi->to);
	DEBUG_ASSERT(!mi->from_nat_connections && !mi->tcp_nat_from && !mi->udp_nat_from && !mi->nat_from, "%p: nat_from not null: %p, %d, %d, %d\n",
			mi, mi->from_nat_connections, mi->tcp_nat_from, mi->udp_nat_from, mi->nat_from);
	DEBUG_ASSERT(!mi->to_nat_connections && !mi->tcp_nat_to && !mi->udp_nat_to && !mi->nat_to, "%p: nat_to not null: %p, %d, %d, %d\n",
			mi, mi->to_nat_connections, mi->tcp_nat_to, mi->udp_nat_to, mi->nat_to);

	/*
	 * Remove from database if inserted
	 */
	if (!mi->flags & ECM_DB_MAPPING_FLAGS_INSERTED) {
		spin_unlock_bh(&ecm_db_lock);
	} else {
		struct ecm_db_listener_instance *li;

		/*
		 * Remove from the global list
		 */
		if (!mi->prev) {
			DEBUG_ASSERT(ecm_db_mappings == mi, "%p: mapping table bad\n", mi);
			ecm_db_mappings = mi->next;
		} else {
			mi->prev->next = mi->next;
		}
		if (mi->next) {
			mi->next->prev = mi->prev;
		}

		/*
		 * Unlink it from the mapping hash table
		 */
		if (!mi->hash_prev) {
			DEBUG_ASSERT(ecm_db_mapping_table[mi->hash_index] == mi, "%p: hash table bad\n", mi);
			ecm_db_mapping_table[mi->hash_index] = mi->hash_next;
		} else {
			mi->hash_prev->hash_next = mi->hash_next;
		}
		if (mi->hash_next) {
			mi->hash_next->hash_prev = mi->hash_prev;
		}
		mi->hash_next = NULL;
		mi->hash_prev = NULL;
		ecm_db_mapping_table_lengths[mi->hash_index]--;
		DEBUG_ASSERT(ecm_db_mapping_table_lengths[mi->hash_index] >= 0, "%p: invalid table len %d\n", mi, ecm_db_mapping_table_lengths[mi->hash_index]);

		/*
		 * Unlink it from the host mapping list
		 */
		if (!mi->mapping_prev) {
			DEBUG_ASSERT(mi->host->mappings == mi, "%p: mapping table bad\n", mi);
			mi->host->mappings = mi->mapping_next;
		} else {
			mi->mapping_prev->mapping_next = mi->mapping_next;
		}
		if (mi->mapping_next) {
			mi->mapping_next->mapping_prev = mi->mapping_prev;
		}
		mi->mapping_next = NULL;
		mi->mapping_prev = NULL;

		mi->host->mapping_count--;
		spin_unlock_bh(&ecm_db_lock);

		/*
		 * Throw removed event to listeners
		 */
		DEBUG_TRACE("%p: Throw mapping removed event\n", mi);
		li = ecm_db_listeners_get_and_ref_first();
		while (li) {
			struct ecm_db_listener_instance *lin;
			if (li->mapping_removed) {
				li->mapping_removed(li->arg, mi);
			}

			/*
			 * Get next listener
			 */
			lin = ecm_db_listener_get_and_ref_next(li);
			ecm_db_listener_deref(li);
			li = lin;
		}
	}

	/*
	 * Throw final event
	 */
	if (mi->final) {
		mi->final(mi->arg);
	}

	/*
	 * Now release the host instance if the mapping had one
	 */
	if (mi->host) {
		ecm_db_host_deref(mi->host);
	}

	/*
	 * We can now destroy the instance
	 */
	DEBUG_CLEAR_MAGIC(mi);
	kfree(mi);

	/*
	 * Decrease global mapping count
	 */
	spin_lock_bh(&ecm_db_lock);
	ecm_db_mapping_count--;
	DEBUG_ASSERT(ecm_db_mapping_count >= 0, "%p: mapping count wrap\n", mi);

	/*
	 * No longer need ref to thread for this object
	 */
	ecm_db_thread_refs--;
	DEBUG_ASSERT(ecm_db_thread_refs >= 0, "thread ref wrap: %d\n", ecm_db_thread_refs);
	spin_unlock_bh(&ecm_db_lock);

	/*
	 * Thread may be able to exit on object destruction
	 */
	wake_up_process(ecm_db_thread);

	return 0;
}
EXPORT_SYMBOL(ecm_db_mapping_deref);

/*
 * ecm_db_host_deref()
 *	Release a ref to a host instance, possibly causing removal from the database and destruction of the instance
 */
int ecm_db_host_deref(struct ecm_db_host_instance *hi)
{
	DEBUG_CHECK_MAGIC(hi, ECM_DB_HOST_INSTANCE_MAGIC, "%p: magic failed\n", hi);

	spin_lock_bh(&ecm_db_lock);
	hi->refs--;
	DEBUG_TRACE("%p: host deref %d\n", hi, hi->refs);
	DEBUG_ASSERT(hi->refs >= 0, "%p: ref wrap\n", hi);

	if (hi->refs > 0) {
		int refs = hi->refs;
		spin_unlock_bh(&ecm_db_lock);
		return refs;
	}

	DEBUG_ASSERT((hi->mappings == NULL) && (hi->mapping_count == 0), "%p: mappings not null\n", hi);

	/*
	 * Remove from database if inserted
	 */
	if (!hi->flags & ECM_DB_HOST_FLAGS_INSERTED) {
		spin_unlock_bh(&ecm_db_lock);
	} else {
		struct ecm_db_listener_instance *li;

		/*
		 * Remove from the global list
		 */
		if (!hi->prev) {
			DEBUG_ASSERT(ecm_db_hosts == hi, "%p: host table bad\n", hi);
			ecm_db_hosts = hi->next;
		} else {
			hi->prev->next = hi->next;
		}
		if (hi->next) {
			hi->next->prev = hi->prev;
		}

		/*
		 * Unlink it from the host hash table
		 */
		if (!hi->hash_prev) {
			DEBUG_ASSERT(ecm_db_host_table[hi->hash_index] == hi, "%p: hash table bad\n", hi);
			ecm_db_host_table[hi->hash_index] = hi->hash_next;
		} else {
			hi->hash_prev->hash_next = hi->hash_next;
		}
		if (hi->hash_next) {
			hi->hash_next->hash_prev = hi->hash_prev;
		}
		hi->hash_next = NULL;
		hi->hash_prev = NULL;
		ecm_db_host_table_lengths[hi->hash_index]--;
		DEBUG_ASSERT(ecm_db_host_table_lengths[hi->hash_index] >= 0, "%p: invalid table len %d\n", hi, ecm_db_host_table_lengths[hi->hash_index]);

		/*
		 * Unlink it from the node host list
		 */
		if (!hi->host_prev) {
			DEBUG_ASSERT(hi->node->hosts == hi, "%p: hosts table bad\n", hi);
			hi->node->hosts = hi->host_next;
		} else {
			hi->host_prev->host_next = hi->host_next;
		}
		if (hi->host_next) {
			hi->host_next->host_prev = hi->host_prev;
		}
		hi->host_next = NULL;
		hi->host_prev = NULL;

		hi->node->host_count--;
		spin_unlock_bh(&ecm_db_lock);

		/*
		 * Throw removed event to listeners
		 */
		DEBUG_TRACE("%p: Throw host removed event\n", hi);
		li = ecm_db_listeners_get_and_ref_first();
		while (li) {
			struct ecm_db_listener_instance *lin;
			if (li->host_removed) {
				li->host_removed(li->arg, hi);
			}

			/*
			 * Get next listener
			 */
			lin = ecm_db_listener_get_and_ref_next(li);
			ecm_db_listener_deref(li);
			li = lin;
		}
	}

	/*
	 * Throw final event
	 */
	if (hi->final) {
		hi->final(hi->arg);
	}

	/*
	 * Now release the node instance if the host had one
	 */
	if (hi->node) {
		ecm_db_node_deref(hi->node);
	}

	/*
	 * We can now destroy the instance
	 */
	DEBUG_CLEAR_MAGIC(hi);
	kfree(hi);

	/*
	 * Decrease global host count
	 */
	spin_lock_bh(&ecm_db_lock);
	ecm_db_host_count--;
	DEBUG_ASSERT(ecm_db_host_count >= 0, "%p: host count wrap\n", hi);

	/*
	 * No longer need ref to thread for this object
	 */
	ecm_db_thread_refs--;
	DEBUG_ASSERT(ecm_db_thread_refs >= 0, "thread ref wrap: %d\n", ecm_db_thread_refs);
	spin_unlock_bh(&ecm_db_lock);

	/*
	 * Thread may be able to exit on object destruction
	 */
	wake_up_process(ecm_db_thread);
	return 0;
}
EXPORT_SYMBOL(ecm_db_host_deref);

/*
 * ecm_db_node_deref()
 *	Deref a node.  Removing it on the last ref and destroying it.
 */
int ecm_db_node_deref(struct ecm_db_node_instance *ni)
{
	DEBUG_CHECK_MAGIC(ni, ECM_DB_NODE_INSTANCE_MAGIC, "%p: magic failed\n", ni);

	spin_lock_bh(&ecm_db_lock);
	ni->refs--;
	DEBUG_TRACE("%p: node deref %d\n", ni, ni->refs);
	DEBUG_ASSERT(ni->refs >= 0, "%p: ref wrap\n", ni);

	if (ni->refs > 0) {
		int refs = ni->refs;
		spin_unlock_bh(&ecm_db_lock);
		return refs;
	}

	DEBUG_ASSERT((ni->hosts == NULL) && (ni->host_count == 0), "%p: hosts not null\n", ni);

	/*
	 * Remove from database if inserted
	 */
	if (!ni->flags & ECM_DB_NODE_FLAGS_INSERTED) {
		spin_unlock_bh(&ecm_db_lock);
	} else {
		struct ecm_db_listener_instance *li;

		/*
		 * Remove from the global list
		 */
		if (!ni->prev) {
			DEBUG_ASSERT(ecm_db_nodes == ni, "%p: node table bad\n", ni);
			ecm_db_nodes = ni->next;
		} else {
			ni->prev->next = ni->next;
		}
		if (ni->next) {
			ni->next->prev = ni->prev;
		}

		/*
		 * Link out of hash table
		 */
		if (!ni->hash_prev) {
			DEBUG_ASSERT(ecm_db_node_table[ni->hash_index] == ni, "%p: hash table bad\n", ni);
			ecm_db_node_table[ni->hash_index] = ni->hash_next;
		} else {
			ni->hash_prev->hash_next = ni->hash_next;
		}
		if (ni->hash_next) {
			ni->hash_next->hash_prev = ni->hash_prev;
		}
		ni->hash_next = NULL;
		ni->hash_prev = NULL;
		ecm_db_node_table_lengths[ni->hash_index]--;
		DEBUG_ASSERT(ecm_db_node_table_lengths[ni->hash_index] >= 0, "%p: invalid table len %d\n", ni, ecm_db_node_table_lengths[ni->hash_index]);

		/*
		 * Unlink it from the iface node list
		 */
		if (!ni->node_prev) {
			DEBUG_ASSERT(ni->iface->nodes == ni, "%p: nodes table bad\n", ni);
			ni->iface->nodes = ni->node_next;
		} else {
			ni->node_prev->node_next = ni->node_next;
		}
		if (ni->node_next) {
			ni->node_next->node_prev = ni->node_prev;
		}
		ni->node_next = NULL;
		ni->node_prev = NULL;
		ni->iface->node_count--;
		spin_unlock_bh(&ecm_db_lock);

		/*
		 * Throw removed event to listeners
		 */
		DEBUG_TRACE("%p: Throw node removed event\n", ni);
		li = ecm_db_listeners_get_and_ref_first();
		while (li) {
			struct ecm_db_listener_instance *lin;
			if (li->node_removed) {
				li->node_removed(li->arg, ni);
			}

			/*
			 * Get next listener
			 */
			lin = ecm_db_listener_get_and_ref_next(li);
			ecm_db_listener_deref(li);
			li = lin;
		}
	}

	/*
	 * Throw final event
	 */
	if (ni->final) {
		ni->final(ni->arg);
	}

	/*
	 * Now release the iface instance if the node had one
	 */
	if (ni->iface) {
		ecm_db_iface_deref(ni->iface);
	}

	/*
	 * We can now destroy the instance
	 */
	DEBUG_CLEAR_MAGIC(ni);
	kfree(ni);

	/*
	 * Decrease global node count
	 */
	spin_lock_bh(&ecm_db_lock);
	ecm_db_node_count--;
	DEBUG_ASSERT(ecm_db_node_count >= 0, "%p: node count wrap\n", ni);

	/*
	 * No longer need ref to thread for this object
	 */
	ecm_db_thread_refs--;
	DEBUG_ASSERT(ecm_db_thread_refs >= 0, "thread ref wrap: %d\n", ecm_db_thread_refs);
	spin_unlock_bh(&ecm_db_lock);

	/*
	 * Thread may be able to exit on object destruction
	 */
	wake_up_process(ecm_db_thread);

	return 0;
}
EXPORT_SYMBOL(ecm_db_node_deref);

/*
 * ecm_db_iface_deref()
 *	Deref a interface instance, removing it from the database on the last ref release
 */
int ecm_db_iface_deref(struct ecm_db_iface_instance *ii)
{
	DEBUG_CHECK_MAGIC(ii, ECM_DB_IFACE_INSTANCE_MAGIC, "%p: magic failed\n", ii);

	/*
	 * Decrement reference count
	 */
	spin_lock_bh(&ecm_db_lock);
	ii->refs--;
	DEBUG_TRACE("%p: iface deref %d\n", ii, ii->refs);
	DEBUG_ASSERT(ii->refs >= 0, "%p: ref wrap\n", ii);

	if (ii->refs > 0) {
		int refs = ii->refs;
		spin_unlock_bh(&ecm_db_lock);
		return refs;
	}

	DEBUG_ASSERT((ii->nodes == NULL) && (ii->node_count == 0), "%p: nodes not null\n", ii);

	/*
	 * Remove from database if inserted
	 */
	if (!ii->flags & ECM_DB_IFACE_FLAGS_INSERTED) {
		spin_unlock_bh(&ecm_db_lock);
	} else {
		struct ecm_db_listener_instance *li;

		/*
		 * Remove from the global list
		 */
		if (!ii->prev) {
			DEBUG_ASSERT(ecm_db_interfaces == ii, "%p: interface table bad\n", ii);
			ecm_db_interfaces = ii->next;
		} else {
			ii->prev->next = ii->next;
		}
		if (ii->next) {
			ii->next->prev = ii->prev;
		}

		/*
		 * Link out of hash table
		 */
		if (!ii->hash_prev) {
			DEBUG_ASSERT(ecm_db_iface_table[ii->hash_index] == ii, "%p: hash table bad got %p for hash index %u\n", ii, ecm_db_iface_table[ii->hash_index], ii->hash_index);
			ecm_db_iface_table[ii->hash_index] = ii->hash_next;
		} else {
			ii->hash_prev->hash_next = ii->hash_next;
		}
		if (ii->hash_next) {
			ii->hash_next->hash_prev = ii->hash_prev;
		}
		ii->hash_next = NULL;
		ii->hash_prev = NULL;
		ecm_db_iface_table_lengths[ii->hash_index]--;
		DEBUG_ASSERT(ecm_db_iface_table_lengths[ii->hash_index] >= 0, "%p: invalid table len %d\n", ii, ecm_db_iface_table_lengths[ii->hash_index]);
		spin_unlock_bh(&ecm_db_lock);

		/*
		 * Throw removed event to listeners
		 */
		DEBUG_TRACE("%p: Throw iface removed event\n", ii);
		li = ecm_db_listeners_get_and_ref_first();
		while (li) {
			struct ecm_db_listener_instance *lin;
			if (li->iface_removed) {
				li->iface_removed(li->arg, ii);
			}

			/*
			 * Get next listener
			 */
			lin = ecm_db_listener_get_and_ref_next(li);
			ecm_db_listener_deref(li);
			li = lin;
		}
	}

	/*
	 * Throw final event
	 */
	if (ii->final) {
		ii->final(ii->arg);
	}

	/*
	 * We can now destroy the instance
	 */
	DEBUG_CLEAR_MAGIC(ii);
	kfree(ii);

	/*
	 * Decrease global interface count
	 */
	spin_lock_bh(&ecm_db_lock);
	ecm_db_iface_count--;
	DEBUG_ASSERT(ecm_db_iface_count >= 0, "%p: iface count wrap\n", ii);

	/*
	 * No longer need ref to thread for this object
	 */
	ecm_db_thread_refs--;
	DEBUG_ASSERT(ecm_db_thread_refs >= 0, "thread ref wrap: %d\n", ecm_db_thread_refs);
	spin_unlock_bh(&ecm_db_lock);

	/*
	 * Thread may be able to exit on object destruction
	 */
	wake_up_process(ecm_db_thread);

	return 0;
}
EXPORT_SYMBOL(ecm_db_iface_deref);

/*
 * ecm_db_listener_deref()
 *	Release reference to listener.
 *
 * On final reference release listener shall be removed from the database.
 */
int ecm_db_listener_deref(struct ecm_db_listener_instance *li)
{
	struct ecm_db_listener_instance *cli;
	struct ecm_db_listener_instance **cli_prev;

	DEBUG_CHECK_MAGIC(li, ECM_DB_LISTENER_INSTANCE_MAGIC, "%p: magic failed", li);

	spin_lock_bh(&ecm_db_lock);
	li->refs--;
	DEBUG_ASSERT(li->refs >= 0, "%p: ref wrap\n", li);
	if (li->refs > 0) {
		int refs;
		refs = li->refs;
		spin_unlock_bh(&ecm_db_lock);
		return refs;
	}

	/*
	 * Instance is to be removed and destroyed.
	 * Link the listener out of the listener list.
	 */
	cli = ecm_db_listeners;
	cli_prev = &ecm_db_listeners;
	while (cli) {
		if (cli == li) {
			*cli_prev = cli->next;
			break;
		}
		cli_prev = &cli->next;
		cli = cli->next;
	}
	DEBUG_ASSERT(cli, "%p: not found\n", li);
	spin_unlock_bh(&ecm_db_lock);

	/*
	 * Invoke final callback
	 */
	if (li->final) {
		li->final(li->arg);
	}
	DEBUG_CLEAR_MAGIC(li);
	kfree(li);

	/*
	 * Decrease global listener count
	 */
	spin_lock_bh(&ecm_db_lock);
	ecm_db_listeners_count--;
	DEBUG_ASSERT(ecm_db_listeners_count >= 0, "%p: listener count wrap\n", li);

	/*
	 * No longer need ref to thread for this object
	 */
	ecm_db_thread_refs--;
	DEBUG_ASSERT(ecm_db_thread_refs >= 0, "thread ref wrap: %d\n", ecm_db_thread_refs);
	spin_unlock_bh(&ecm_db_lock);

	/*
	 * Thread may be able to exit on object destruction
	 */
	wake_up_process(ecm_db_thread);
	return 0;
}
EXPORT_SYMBOL(ecm_db_listener_deref);

/*
 * ecm_db_connection_defunct_all()
 *	Make defunct ALL connections.
 *
 * This API is typically used in shutdown situations commanded by the user.
 * NOTE: Ensure all front ends are stopped to avoid further connections being created while this is running.
 */
void ecm_db_connection_defunct_all(void)
{
	struct ecm_db_connection_instance *ci;

	DEBUG_INFO("Defuncting all\n");

	/*
	 * Iterate all connections
	 */
	ci = ecm_db_connections_get_and_ref_first();
	while (ci) {
		struct ecm_db_connection_instance *cin;

		DEBUG_TRACE("%p: defunct\n", ci);
		ecm_db_connection_make_defunct(ci);
		
		cin = ecm_db_connection_get_and_ref_next(ci);
		ecm_db_connection_deref(ci);
		ci = cin;
	}
	DEBUG_INFO("Defuncting complete\n");
}
EXPORT_SYMBOL(ecm_db_connection_defunct_all);

/*
 * ecm_db_connection_generate_hash_index()
 * 	Calculate the hash index.
 *
 * Note: The hash we produce is symmetric - i.e. we can swap the "from" and "to"
 * details without generating a different hash index!
 */
static inline ecm_db_connection_hash_t ecm_db_connection_generate_hash_index(ip_addr_t host1_addr, uint32_t host1_port, ip_addr_t host2_addr, uint32_t host2_port, int protocol)
{
	uint32_t temp;
	uint32_t hash_val;

	/*
	 * The hash function only uses both host 1 address/port, host 2 address/port
	 * and protocol fields.
	 */
	temp = (u32)host1_addr[0] + host1_port + (u32)host2_addr[0] + host2_port + (uint32_t)protocol;
	hash_val = (temp >> 24) ^ (temp >> 16) ^ (temp >> 8) ^ temp;

	return (ecm_db_connection_hash_t)(hash_val & (ECM_DB_CONNECTION_HASH_SLOTS - 1));
}

/*
 * ecm_db_connection_generate_serial_hash_index()
 * 	Calculate the serial hash index.
 */
static inline ecm_db_connection_serial_hash_t ecm_db_connection_generate_serial_hash_index(uint32_t serial)
{
	return (ecm_db_connection_serial_hash_t)(serial & (ECM_DB_CONNECTION_SERIAL_HASH_SLOTS - 1));
}

/*
 * ecm_db_mapping_generate_hash_index()
 * 	Calculate the hash index.
 */
static inline ecm_db_mapping_hash_t ecm_db_mapping_generate_hash_index(ip_addr_t address, uint32_t port)
{
	uint32_t temp;
	uint32_t hash_val;

	temp = (u32)address[0] + port;
	hash_val = (temp >> 24) ^ (temp >> 16) ^ (temp >> 8) ^ temp;

	return (ecm_db_mapping_hash_t)(hash_val & (ECM_DB_MAPPING_HASH_SLOTS - 1));
}

/*
 * ecm_db_host_generate_hash_index()
 * 	Calculate the hash index.
 */
static inline ecm_db_host_hash_t ecm_db_host_generate_hash_index(ip_addr_t address)
{
	uint32_t temp;
	uint32_t hash_val;

	temp = (uint32_t)address[0];
	hash_val = (temp >> 24) ^ (temp >> 16) ^ (temp >> 8) ^ temp;

	return (ecm_db_host_hash_t)(hash_val & (ECM_DB_HOST_HASH_SLOTS - 1));
}

/*
 * ecm_db_node_generate_hash_index()
 * 	Calculate the hash index.
 */
static inline ecm_db_node_hash_t ecm_db_node_generate_hash_index(uint8_t *address)
{
	uint32_t hash_val;

	hash_val = (((uint32_t)(address[2] ^ address[4])) << 8) | (address[3] ^ address[5]);
	hash_val &= (ECM_DB_NODE_HASH_SLOTS - 1);

	return (ecm_db_node_hash_t)hash_val;
}

/*
 * ecm_db_iface_generate_hash_index_sit()
 * 	Calculate the hash index.
 */
static inline ecm_db_iface_hash_t ecm_db_iface_generate_hash_index_sit(ip_addr_t saddr, ip_addr_t daddr)
{
	uint32_t temp;
	uint32_t hash_val;

	temp = (uint32_t )(saddr[0] ^ daddr[0]);
	hash_val = (temp >> 24) ^ (temp >> 16) ^ (temp >> 8) ^ temp;
	return (ecm_db_iface_hash_t)(hash_val & (ECM_DB_IFACE_HASH_SLOTS - 1));
}

/*
 * ecm_db_iface_generate_hash_index_tunipip6()
 * 	Calculate the hash index.
 */
static inline ecm_db_iface_hash_t ecm_db_iface_generate_hash_index_tunipip6(ip_addr_t saddr, ip_addr_t daddr)
{
	uint32_t temp;
	uint32_t hash_val;

	temp = (uint32_t )(saddr[0] ^ daddr[0]);
	hash_val = (temp >> 24) ^ (temp >> 16) ^ (temp >> 8) ^ temp;
	return (ecm_db_iface_hash_t)(hash_val & (ECM_DB_IFACE_HASH_SLOTS - 1));
}

/*
 * ecm_db_iface_generate_hash_index_ethernet()
 * 	Calculate the hash index.
 */
static inline ecm_db_iface_hash_t ecm_db_iface_generate_hash_index_ethernet(uint8_t *address)
{
	return (ecm_db_iface_hash_t)(address[5] & (ECM_DB_IFACE_HASH_SLOTS - 1));
}

/*
 * ecm_db_iface_generate_hash_index_pppoe()
 * 	Calculate the hash index.
 */
static inline ecm_db_iface_hash_t ecm_db_iface_generate_hash_index_pppoe(uint16_t pppoe_session_id)
{
	return (ecm_db_iface_hash_t)(pppoe_session_id & (ECM_DB_IFACE_HASH_SLOTS - 1));
}

/*
 * ecm_db_iface_generate_hash_index_unknown()
 * 	Calculate the hash index.
 */
static inline ecm_db_iface_hash_t ecm_db_iface_generate_hash_index_unknown(uint32_t os_specific_ident)
{
	return (ecm_db_iface_hash_t)(os_specific_ident & (ECM_DB_IFACE_HASH_SLOTS - 1));
}

/*
 * ecm_db_iface_generate_hash_index_loopback()
 * 	Calculate the hash index.
 */
static inline ecm_db_iface_hash_t ecm_db_iface_generate_hash_index_loopback(uint32_t os_specific_ident)
{
	return (ecm_db_iface_hash_t)(os_specific_ident & (ECM_DB_IFACE_HASH_SLOTS - 1));
}

/*
 * ecm_db_iface_generate_hash_index_ipsec_tunnel()
 * 	Calculate the hash index.
 * GGG TODO Flesh this out using actual tunnel endpoint keys
 */
static inline ecm_db_iface_hash_t ecm_db_iface_generate_hash_index_ipsec_tunnel(uint32_t os_specific_ident)
{
	return (ecm_db_iface_hash_t)(os_specific_ident & (ECM_DB_IFACE_HASH_SLOTS - 1));
}

/*
 * ecm_db_host_find_and_ref()
 *	Lookup and return a host reference if any
 */
struct ecm_db_host_instance *ecm_db_host_find_and_ref(ip_addr_t address)
{
	ecm_db_host_hash_t hash_index;
	struct ecm_db_host_instance *hi;

	DEBUG_TRACE("Lookup host with addr " ECM_IP_ADDR_OCTAL_FMT "\n", ECM_IP_ADDR_TO_OCTAL(address));

	/*
	 * Compute the hash chain index and prepare to walk the chain
	 */
	hash_index = ecm_db_host_generate_hash_index(address);

	/*
	 * Iterate the chain looking for a host with matching details
	 */
	spin_lock_bh(&ecm_db_lock);
	hi = ecm_db_host_table[hash_index];
	while (hi) {
		if (!ECM_IP_ADDR_MATCH(hi->address, address)) {
			hi = hi->hash_next;
			continue;
		}

		_ecm_db_host_ref(hi);
		spin_unlock_bh(&ecm_db_lock);
		DEBUG_TRACE("host found %p\n", hi);
		return hi;
	}
	spin_unlock_bh(&ecm_db_lock);
	DEBUG_TRACE("Host not found\n");
	return NULL;
}
EXPORT_SYMBOL(ecm_db_host_find_and_ref);

/*
 * ecm_db_node_find_and_ref()
 *	Lookup and return a node reference if any
 */
struct ecm_db_node_instance *ecm_db_node_find_and_ref(uint8_t *address)
{
	ecm_db_node_hash_t hash_index;
	struct ecm_db_node_instance *ni;

	DEBUG_TRACE("Lookup node with addr %pM\n", address);

	/*
	 * Compute the hash chain index and prepare to walk the chain
	 */
	hash_index = ecm_db_node_generate_hash_index(address);

	/*
	 * Iterate the chain looking for a host with matching details
	 */
	spin_lock_bh(&ecm_db_lock);
	ni = ecm_db_node_table[hash_index];
	while (ni) {
		if (memcmp(ni->address, address, ETH_ALEN)) {
			ni = ni->hash_next;
			continue;
		}

		_ecm_db_node_ref(ni);
		spin_unlock_bh(&ecm_db_lock);
		DEBUG_TRACE("node found %p\n", ni);
		return ni;
	}
	spin_unlock_bh(&ecm_db_lock);
	DEBUG_TRACE("Node not found\n");
	return NULL;
}
EXPORT_SYMBOL(ecm_db_node_find_and_ref);

/*
 * ecm_db_iface_ethernet_address_get()
 *	Obtain the ethernet address for an ethernet interface
 */
void ecm_db_iface_ethernet_address_get(struct ecm_db_iface_instance *ii, uint8_t *address)
{
	DEBUG_CHECK_MAGIC(ii, ECM_DB_IFACE_INSTANCE_MAGIC, "%p: magic failed", ii);
	DEBUG_ASSERT(ii->type == ECM_DB_IFACE_TYPE_ETHERNET, "%p: Bad type, expected ethernet, actual: %d\n", ii, ii->type);
	spin_lock_bh(&ecm_db_lock);
	memcpy(address, ii->type_info.ethernet.address, sizeof(ii->type_info.ethernet.address));
	spin_unlock_bh(&ecm_db_lock);
}
EXPORT_SYMBOL(ecm_db_iface_ethernet_address_get);

/*
 * ecm_db_iface_find_and_ref_ethernet()
 *	Lookup and return a iface reference if any
 */
struct ecm_db_iface_instance *ecm_db_iface_find_and_ref_ethernet(uint8_t *address)
{
	ecm_db_iface_hash_t hash_index;
	struct ecm_db_iface_instance *ii;

	DEBUG_TRACE("Lookup ethernet iface with addr %pM\n", address);

	/*
	 * Compute the hash chain index and prepare to walk the chain
	 */
	hash_index = ecm_db_iface_generate_hash_index_ethernet(address);

	/*
	 * Iterate the chain looking for a host with matching details
	 */
	spin_lock_bh(&ecm_db_lock);
	ii = ecm_db_iface_table[hash_index];
	while (ii) {
		if ((ii->type != ECM_DB_IFACE_TYPE_ETHERNET) || memcmp(ii->type_info.ethernet.address, address, ETH_ALEN)) {
			ii = ii->hash_next;
			continue;
		}

		_ecm_db_iface_ref(ii);
		spin_unlock_bh(&ecm_db_lock);
		DEBUG_TRACE("iface found %p\n", ii);
		return ii;
	}
	spin_unlock_bh(&ecm_db_lock);
	DEBUG_TRACE("Iface not found\n");
	return NULL;
}
EXPORT_SYMBOL(ecm_db_iface_find_and_ref_ethernet);

/*
 * ecm_db_iface_vlan_info_get()
 *	Get vlan interface specific information
 */
void ecm_db_iface_vlan_info_get(struct ecm_db_iface_instance *ii, struct ecm_db_interface_info_vlan *vlan_info)
{
	DEBUG_CHECK_MAGIC(ii, ECM_DB_IFACE_INSTANCE_MAGIC, "%p: magic failed", ii);
	DEBUG_ASSERT(ii->type == ECM_DB_IFACE_TYPE_VLAN, "%p: Bad type, expected vlan, actual: %d\n", ii, ii->type);
	spin_lock_bh(&ecm_db_lock);
	memcpy(vlan_info->address, ii->type_info.vlan.address, sizeof(ii->type_info.vlan.address));
	vlan_info->vlan_tag = ii->type_info.vlan.vlan_tag;
	spin_unlock_bh(&ecm_db_lock);
}
EXPORT_SYMBOL(ecm_db_iface_vlan_info_get);

/*
 * ecm_db_iface_find_and_ref_vlan()
 *	Lookup and return a iface reference if any
 */
struct ecm_db_iface_instance *ecm_db_iface_find_and_ref_vlan(uint8_t *address, uint16_t vlan_tag)
{
	ecm_db_iface_hash_t hash_index;
	struct ecm_db_iface_instance *ii;

	DEBUG_TRACE("Lookup vlan iface with addr %pM, vlan tag: %x\n", address, vlan_tag);

	/*
	 * Compute the hash chain index and prepare to walk the chain
	 */
	hash_index = ecm_db_iface_generate_hash_index_ethernet(address);

	/*
	 * Iterate the chain looking for a host with matching details
	 */
	spin_lock_bh(&ecm_db_lock);
	ii = ecm_db_iface_table[hash_index];
	while (ii) {
		if ((ii->type != ECM_DB_IFACE_TYPE_VLAN) || (ii->type_info.vlan.vlan_tag != vlan_tag)
				|| memcmp(ii->type_info.vlan.address, address, ETH_ALEN)) {
			ii = ii->hash_next;
			continue;
		}

		_ecm_db_iface_ref(ii);
		spin_unlock_bh(&ecm_db_lock);
		DEBUG_TRACE("iface found %p\n", ii);
		return ii;
	}
	spin_unlock_bh(&ecm_db_lock);
	DEBUG_TRACE("Iface not found\n");
	return NULL;
}
EXPORT_SYMBOL(ecm_db_iface_find_and_ref_vlan);

/*
 * ecm_db_iface_find_and_ref_bridge()
 *	Lookup and return a iface reference if any
 */
struct ecm_db_iface_instance *ecm_db_iface_find_and_ref_bridge(uint8_t *address)
{
	ecm_db_iface_hash_t hash_index;
	struct ecm_db_iface_instance *ii;

	DEBUG_TRACE("Lookup bridge iface with addr %pM\n", address);

	/*
	 * Compute the hash chain index and prepare to walk the chain
	 */
	hash_index = ecm_db_iface_generate_hash_index_ethernet(address);

	/*
	 * Iterate the chain looking for a host with matching details
	 */
	spin_lock_bh(&ecm_db_lock);
	ii = ecm_db_iface_table[hash_index];
	while (ii) {
		if ((ii->type != ECM_DB_IFACE_TYPE_BRIDGE) || memcmp(ii->type_info.bridge.address, address, ETH_ALEN)) {
			ii = ii->hash_next;
			continue;
		}

		_ecm_db_iface_ref(ii);
		spin_unlock_bh(&ecm_db_lock);
		DEBUG_TRACE("iface found %p\n", ii);
		return ii;
	}
	spin_unlock_bh(&ecm_db_lock);
	DEBUG_TRACE("Iface not found\n");
	return NULL;
}
EXPORT_SYMBOL(ecm_db_iface_find_and_ref_bridge);

/*
 * ecm_db_iface_find_and_ref_lag()
 *	Lookup and return a iface reference if any
 */
struct ecm_db_iface_instance *ecm_db_iface_find_and_ref_lag(uint8_t *address)
{
	ecm_db_iface_hash_t hash_index;
	struct ecm_db_iface_instance *ii;

	DEBUG_TRACE("Lookup lag iface with addr %pM\n", address);

	/*
	 * Compute the hash chain index and prepare to walk the chain
	 */
	hash_index = ecm_db_iface_generate_hash_index_ethernet(address);

	/*
	 * Iterate the chain looking for a host with matching details
	 */
	spin_lock_bh(&ecm_db_lock);
	ii = ecm_db_iface_table[hash_index];
	while (ii) {
		if ((ii->type != ECM_DB_IFACE_TYPE_LAG) || memcmp(ii->type_info.lag.address, address, ETH_ALEN)) {
			ii = ii->hash_next;
			continue;
		}

		_ecm_db_iface_ref(ii);
		spin_unlock_bh(&ecm_db_lock);
		DEBUG_TRACE("iface found %p\n", ii);
		return ii;
	}
	spin_unlock_bh(&ecm_db_lock);
	DEBUG_TRACE("Iface not found\n");
	return NULL;
}
EXPORT_SYMBOL(ecm_db_iface_find_and_ref_lag);

/*
 * ecm_db_iface_pppoe_session_info_get()
 *	Get vlan interface specific information
 */
void ecm_db_iface_pppoe_session_info_get(struct ecm_db_iface_instance *ii, struct ecm_db_interface_info_pppoe *pppoe_info)
{
	DEBUG_CHECK_MAGIC(ii, ECM_DB_IFACE_INSTANCE_MAGIC, "%p: magic failed", ii);
	DEBUG_ASSERT(ii->type == ECM_DB_IFACE_TYPE_PPPOE, "%p: Bad type, expected pppoe, actual: %d\n", ii, ii->type);
	spin_lock_bh(&ecm_db_lock);
	memcpy(pppoe_info->remote_mac, ii->type_info.pppoe.remote_mac, sizeof(ii->type_info.pppoe.remote_mac));
	pppoe_info->pppoe_session_id = ii->type_info.pppoe.pppoe_session_id;
	spin_unlock_bh(&ecm_db_lock);
}
EXPORT_SYMBOL(ecm_db_iface_pppoe_session_info_get);

/*
 * ecm_db_iface_find_and_ref_pppoe()
 *	Lookup and return a iface reference if any
 */
struct ecm_db_iface_instance *ecm_db_iface_find_and_ref_pppoe(uint16_t pppoe_session_id, uint8_t *remote_mac)
{
	ecm_db_iface_hash_t hash_index;
	struct ecm_db_iface_instance *ii;

	DEBUG_TRACE("Lookup pppoe iface with addr %x\n", pppoe_session_id);

	/*
	 * Compute the hash chain index and prepare to walk the chain
	 */
	hash_index = ecm_db_iface_generate_hash_index_pppoe(pppoe_session_id);

	/*
	 * Iterate the chain looking for a host with matching details
	 */
	spin_lock_bh(&ecm_db_lock);
	ii = ecm_db_iface_table[hash_index];
	while (ii) {
		if ((ii->type != ECM_DB_IFACE_TYPE_PPPOE)
				|| (ii->type_info.pppoe.pppoe_session_id != pppoe_session_id)
				|| memcmp(ii->type_info.pppoe.remote_mac, remote_mac, ETH_ALEN)) {
			ii = ii->hash_next;
			continue;
		}

		_ecm_db_iface_ref(ii);
		spin_unlock_bh(&ecm_db_lock);
		DEBUG_TRACE("iface found %p\n", ii);
		return ii;
	}
	spin_unlock_bh(&ecm_db_lock);
	DEBUG_TRACE("Iface not found\n");
	return NULL;
}
EXPORT_SYMBOL(ecm_db_iface_find_and_ref_pppoe);

/*
 * ecm_db_iface_find_and_ref_unknown()
 *	Lookup and return a iface reference if any
 */
struct ecm_db_iface_instance *ecm_db_iface_find_and_ref_unknown(uint32_t os_specific_ident)
{
	ecm_db_iface_hash_t hash_index;
	struct ecm_db_iface_instance *ii;

	DEBUG_TRACE("Lookup unknown iface with addr %x (%u)\n", os_specific_ident, os_specific_ident);

	/*
	 * Compute the hash chain index and prepare to walk the chain
	 */
	hash_index = ecm_db_iface_generate_hash_index_unknown(os_specific_ident);

	/*
	 * Iterate the chain looking for a host with matching details
	 */
	spin_lock_bh(&ecm_db_lock);
	ii = ecm_db_iface_table[hash_index];
	while (ii) {
		if ((ii->type != ECM_DB_IFACE_TYPE_UNKNOWN) || (ii->type_info.unknown.os_specific_ident != os_specific_ident)) {
			ii = ii->hash_next;
			continue;
		}

		_ecm_db_iface_ref(ii);
		spin_unlock_bh(&ecm_db_lock);
		DEBUG_TRACE("iface found %p\n", ii);
		return ii;
	}
	spin_unlock_bh(&ecm_db_lock);
	DEBUG_TRACE("Iface not found\n");
	return NULL;
}
EXPORT_SYMBOL(ecm_db_iface_find_and_ref_unknown);

/*
 * ecm_db_iface_find_and_ref_loopback()
 *	Lookup and return a iface reference if any
 */
struct ecm_db_iface_instance *ecm_db_iface_find_and_ref_loopback(uint32_t os_specific_ident)
{
	ecm_db_iface_hash_t hash_index;
	struct ecm_db_iface_instance *ii;

	DEBUG_TRACE("Lookup loopback iface with addr %x (%u)\n", os_specific_ident, os_specific_ident);

	/*
	 * Compute the hash chain index and prepare to walk the chain
	 */
	hash_index = ecm_db_iface_generate_hash_index_loopback(os_specific_ident);

	/*
	 * Iterate the chain looking for a host with matching details
	 */
	spin_lock_bh(&ecm_db_lock);
	ii = ecm_db_iface_table[hash_index];
	while (ii) {
		if ((ii->type != ECM_DB_IFACE_TYPE_LOOPBACK) || (ii->type_info.loopback.os_specific_ident != os_specific_ident)) {
			ii = ii->hash_next;
			continue;
		}

		_ecm_db_iface_ref(ii);
		spin_unlock_bh(&ecm_db_lock);
		DEBUG_TRACE("iface found %p\n", ii);
		return ii;
	}
	spin_unlock_bh(&ecm_db_lock);
	DEBUG_TRACE("Iface not found\n");
	return NULL;
}
EXPORT_SYMBOL(ecm_db_iface_find_and_ref_loopback);

/*
 * ecm_db_iface_find_and_ref_ipsec_tunnel()
 *	Lookup and return a iface reference if any.
 * GGG TODO Flesh this out using tunnel endpoint keys
 */
struct ecm_db_iface_instance *ecm_db_iface_find_and_ref_ipsec_tunnel(uint32_t os_specific_ident)
{
	ecm_db_iface_hash_t hash_index;
	struct ecm_db_iface_instance *ii;

	DEBUG_TRACE("Lookup ipsec_tunnel iface with addr %x (%u)\n", os_specific_ident, os_specific_ident);

	/*
	 * Compute the hash chain index and prepare to walk the chain
	 */
	hash_index = ecm_db_iface_generate_hash_index_ipsec_tunnel(os_specific_ident);

	/*
	 * Iterate the chain looking for a host with matching details
	 */
	spin_lock_bh(&ecm_db_lock);
	ii = ecm_db_iface_table[hash_index];
	while (ii) {
		if ((ii->type != ECM_DB_IFACE_TYPE_IPSEC_TUNNEL) || (ii->type_info.ipsec_tunnel.os_specific_ident != os_specific_ident)) {
			ii = ii->hash_next;
			continue;
		}

		_ecm_db_iface_ref(ii);
		spin_unlock_bh(&ecm_db_lock);
		DEBUG_TRACE("iface found %p\n", ii);
		return ii;
	}
	spin_unlock_bh(&ecm_db_lock);
	DEBUG_TRACE("Iface not found\n");
	return NULL;
}
EXPORT_SYMBOL(ecm_db_iface_find_and_ref_ipsec_tunnel);

/*
 * ecm_db_iface_find_and_ref_sit()
 *	Lookup and return a iface reference if any
 */
struct ecm_db_iface_instance *ecm_db_iface_find_and_ref_sit(ip_addr_t saddr, ip_addr_t daddr)
{
	ecm_db_iface_hash_t hash_index;
	struct ecm_db_iface_instance *ii;

	DEBUG_TRACE("Lookup sit (6-in-4) iface with saddr: " ECM_IP_ADDR_OCTAL_FMT ", daddr: " ECM_IP_ADDR_OCTAL_FMT "\n",
			ECM_IP_ADDR_TO_OCTAL(saddr), ECM_IP_ADDR_TO_OCTAL(daddr));

	/*
	 * Compute the hash chain index and prepare to walk the chain
	 */
	hash_index = ecm_db_iface_generate_hash_index_sit(saddr, daddr);

	/*
	 * Iterate the chain looking for a host with matching details
	 */
	spin_lock_bh(&ecm_db_lock);
	ii = ecm_db_iface_table[hash_index];
	while (ii) {
		if ((ii->type != ECM_DB_IFACE_TYPE_SIT)
				|| !ECM_IP_ADDR_MATCH(ii->type_info.sit.saddr, saddr)
				|| !ECM_IP_ADDR_MATCH(ii->type_info.sit.daddr, daddr)) {
			ii = ii->hash_next;
			continue;
		}

		_ecm_db_iface_ref(ii);
		spin_unlock_bh(&ecm_db_lock);
		DEBUG_TRACE("iface found %p\n", ii);
		return ii;
	}
	spin_unlock_bh(&ecm_db_lock);
	DEBUG_TRACE("Iface not found\n");
	return NULL;
}
EXPORT_SYMBOL(ecm_db_iface_find_and_ref_sit);

/*
 * ecm_db_iface_find_and_ref_tunipip6()
 *	Lookup and return a iface reference if any
 */
struct ecm_db_iface_instance *ecm_db_iface_find_and_ref_tunipip6(ip_addr_t saddr, ip_addr_t daddr)
{
	ecm_db_iface_hash_t hash_index;
	struct ecm_db_iface_instance *ii;

	DEBUG_TRACE("Lookup TUNIPIP6 iface with saddr: " ECM_IP_ADDR_OCTAL_FMT ", daddr: " ECM_IP_ADDR_OCTAL_FMT "\n",
			ECM_IP_ADDR_TO_OCTAL(saddr), ECM_IP_ADDR_TO_OCTAL(daddr));

	/*
	 * Compute the hash chain index and prepare to walk the chain
	 */
	hash_index = ecm_db_iface_generate_hash_index_tunipip6(saddr, daddr);

	/*
	 * Iterate the chain looking for a host with matching details
	 */
	spin_lock_bh(&ecm_db_lock);
	ii = ecm_db_iface_table[hash_index];
	while (ii) {
		if ((ii->type != ECM_DB_IFACE_TYPE_TUNIPIP6)
				|| !ECM_IP_ADDR_MATCH(ii->type_info.tunipip6.saddr, saddr)
				|| !ECM_IP_ADDR_MATCH(ii->type_info.tunipip6.daddr, daddr)) {
			ii = ii->hash_next;
			continue;
		}

		_ecm_db_iface_ref(ii);
		spin_unlock_bh(&ecm_db_lock);
		DEBUG_TRACE("iface found %p\n", ii);
		return ii;
	}
	spin_unlock_bh(&ecm_db_lock);
	DEBUG_TRACE("Iface not found\n");
	return NULL;
}
EXPORT_SYMBOL(ecm_db_iface_find_and_ref_tunipip6);

/*
 * ecm_db_mapping_find_and_ref()
 *	Lookup and return a mapping reference if any.
 *
 * NOTE: For non-port based protocols the ports are expected to be -(protocol)
 */
struct ecm_db_mapping_instance *ecm_db_mapping_find_and_ref(ip_addr_t address, int port)
{
	ecm_db_mapping_hash_t hash_index;
	struct ecm_db_mapping_instance *mi;

	DEBUG_TRACE("Lookup mapping with addr " ECM_IP_ADDR_OCTAL_FMT " and port %d\n", ECM_IP_ADDR_TO_OCTAL(address), port);

	/*
	 * Compute the hash chain index and prepare to walk the chain
	 */
	hash_index = ecm_db_mapping_generate_hash_index(address, port);

	/*
	 * Iterate the chain looking for a mapping with matching details
	 */
	spin_lock_bh(&ecm_db_lock);
	mi = ecm_db_mapping_table[hash_index];
	while (mi) {
		if (mi->port != port) {
			mi = mi->hash_next;
			continue;
		}

		if (!ECM_IP_ADDR_MATCH(mi->host->address, address)) {
			mi = mi->hash_next;
			continue;
		}

		_ecm_db_mapping_ref(mi);
		spin_unlock_bh(&ecm_db_lock);
		DEBUG_TRACE("Mapping found %p\n", mi);
		return mi;
	}
	spin_unlock_bh(&ecm_db_lock);
	DEBUG_TRACE("Mapping not found\n");
	return NULL;
}
EXPORT_SYMBOL(ecm_db_mapping_find_and_ref);

/*
 * ecm_db_connection_find_and_ref()
 *	Locate a connection instance based on addressing, protocol and optional port information.
 *
 * NOTE: For non-port based protocols then ports are expected to be -(protocol).
 */
struct ecm_db_connection_instance *ecm_db_connection_find_and_ref(ip_addr_t host1_addr, ip_addr_t host2_addr, int protocol, int host1_port, int host2_port)
{
	ecm_db_connection_hash_t hash_index;
	struct ecm_db_connection_instance *ci;

	DEBUG_TRACE("Lookup connection " ECM_IP_ADDR_OCTAL_FMT ":%d <> " ECM_IP_ADDR_OCTAL_FMT ":%d protocol %d\n", ECM_IP_ADDR_TO_OCTAL(host1_addr), host1_port, ECM_IP_ADDR_TO_OCTAL(host2_addr), host2_port, protocol);

	/*
	 * Compute the hash chain index and prepare to walk the chain
	 */
	hash_index = ecm_db_connection_generate_hash_index(host1_addr, host1_port, host2_addr, host2_port, protocol);

	/*
	 * Iterate the chain looking for a connection with matching details
	 */
	spin_lock_bh(&ecm_db_lock);
	ci = ecm_db_connection_table[hash_index];
	if (ci) {
		_ecm_db_connection_ref(ci);
	}
	spin_unlock_bh(&ecm_db_lock);
	while (ci) {
		struct ecm_db_connection_instance *cin;

		/*
		 * The use of unlikely() is liberally used because under fast-hit scenarios the connection would always be at the start of a chain
		 */
		if (unlikely(ci->protocol != protocol)) {
			goto try_next;
		}

		if (unlikely(!ECM_IP_ADDR_MATCH(host1_addr, ci->mapping_from->host->address))) {
			goto try_reverse;
		}

		if (unlikely(host1_port != ci->mapping_from->port)) {
			goto try_reverse;
		}

		if (unlikely(!ECM_IP_ADDR_MATCH(host2_addr, ci->mapping_to->host->address))) {
			goto try_reverse;
		}

		if (unlikely(host2_port != ci->mapping_to->port)) {
			goto try_reverse;
		}

		goto connection_found;

try_reverse:
		if (unlikely(!ECM_IP_ADDR_MATCH(host1_addr, ci->mapping_to->host->address))) {
			goto try_next;
		}

		if (unlikely(host1_port != ci->mapping_to->port)) {
			goto try_next;
		}

		if (unlikely(!ECM_IP_ADDR_MATCH(host2_addr, ci->mapping_from->host->address))) {
			goto try_next;
		}

		if (unlikely(host2_port != ci->mapping_from->port)) {
			goto try_next;
		}

		goto connection_found;

try_next:
		spin_lock_bh(&ecm_db_lock);
		cin = ci->hash_next;
		if (cin) {
			_ecm_db_connection_ref(cin);
		}
		spin_unlock_bh(&ecm_db_lock);
		ecm_db_connection_deref(ci);
		ci = cin;
	}
	DEBUG_TRACE("Connection not found\n");
	return NULL;

connection_found:
	DEBUG_TRACE("Connection found %p\n", ci);

	/*
	 * Move this connection to the head of the hash chain.
	 * This will win for us with heavy hit connections - we bubble MRU to the front of the list to
	 * avoid too much chain walking.
	 */
	spin_lock_bh(&ecm_db_lock);
	if (!ci->hash_prev) {
		/*
		 * No prev pointer - ci is at the head of the list already
		 */
		DEBUG_ASSERT(ecm_db_connection_table[hash_index] == ci, "%p: hash table bad\n", ci);
		spin_unlock_bh(&ecm_db_lock);
		return ci;
	}

	/*
	 * Link out
	 */
	ci->hash_prev->hash_next = ci->hash_next;
	if (ci->hash_next) {
		ci->hash_next->hash_prev = ci->hash_prev;
	}

	/*
	 * Re-insert at the head.
	 * NOTE: We know that there is a head already that is different to ci.
	 */
	ci->hash_next = ecm_db_connection_table[hash_index];
	ecm_db_connection_table[hash_index]->hash_prev = ci;
	ecm_db_connection_table[hash_index] = ci;
	ci->hash_prev = NULL;
	spin_unlock_bh(&ecm_db_lock);
	return ci;
}
EXPORT_SYMBOL(ecm_db_connection_find_and_ref);

/*
 * ecm_db_connection_serial_find_and_ref()
 *	Locate a connection instance based on serial if it still exists
 */
struct ecm_db_connection_instance *ecm_db_connection_serial_find_and_ref(uint32_t serial)
{
	ecm_db_connection_serial_hash_t serial_hash_index;
	struct ecm_db_connection_instance *ci;

	DEBUG_TRACE("Lookup connection serial: %u\n", serial);

	/*
	 * Compute the hash chain index and prepare to walk the chain
	 */
	serial_hash_index = ecm_db_connection_generate_serial_hash_index(serial);

	/*
	 * Iterate the chain looking for a connection with matching serial
	 */
	spin_lock_bh(&ecm_db_lock);
	ci = ecm_db_connection_serial_table[serial_hash_index];
	if (ci) {
		_ecm_db_connection_ref(ci);
	}
	spin_unlock_bh(&ecm_db_lock);
	while (ci) {
		struct ecm_db_connection_instance *cin;

		/*
		 * The use of likely() is used because under fast-hit scenarios the connection would always be at the start of a chain
		 */
		if (likely(ci->serial == serial)) {
			goto connection_found;
		}

		/*
		 * Try next
		 */
		spin_lock_bh(&ecm_db_lock);
		cin = ci->serial_hash_next;
		if (cin) {
			_ecm_db_connection_ref(cin);
		}
		spin_unlock_bh(&ecm_db_lock);
		ecm_db_connection_deref(ci);
		ci = cin;
	}
	DEBUG_TRACE("Connection not found\n");
	return NULL;

connection_found:
	DEBUG_TRACE("Connection found %p\n", ci);

	/*
	 * Move this connection to the head of the hash chain.
	 * This will win for us with heavy hit connections - we bubble MRU to the front of the list to
	 * avoid too much chain walking.
	 */
	spin_lock_bh(&ecm_db_lock);
	if (!ci->serial_hash_prev) {
		/*
		 * No prev pointer - ci is at the head of the list already
		 */
		DEBUG_ASSERT(ecm_db_connection_serial_table[serial_hash_index] == ci, "%p: hash table bad\n", ci);
		spin_unlock_bh(&ecm_db_lock);
		return ci;
	}

	/*
	 * Link out
	 */
	ci->serial_hash_prev->serial_hash_next = ci->serial_hash_next;
	if (ci->serial_hash_next) {
		ci->serial_hash_next->serial_hash_prev = ci->serial_hash_prev;
	}

	/*
	 * Re-insert at the head.
	 * NOTE: We know that there is a head already that is different to ci.
	 */
	ci->serial_hash_next = ecm_db_connection_serial_table[serial_hash_index];
	ecm_db_connection_serial_table[serial_hash_index]->serial_hash_prev = ci;
	ecm_db_connection_serial_table[serial_hash_index] = ci;
	ci->serial_hash_prev = NULL;
	spin_unlock_bh(&ecm_db_lock);
	return ci;
}
EXPORT_SYMBOL(ecm_db_connection_serial_find_and_ref);

/*
 * ecm_db_mapping_connections_from_get_and_ref_first()
 *	Return a reference to the first connection made from this mapping
 */
struct ecm_db_connection_instance *ecm_db_mapping_connections_from_get_and_ref_first(struct ecm_db_mapping_instance *mi)
{
	struct ecm_db_connection_instance *ci;

	DEBUG_CHECK_MAGIC(mi, ECM_DB_MAPPING_INSTANCE_MAGIC, "%p: magic failed", mi);

	spin_lock_bh(&ecm_db_lock);
	ci = mi->from_connections;
	if (ci) {
		_ecm_db_connection_ref(ci);
	}
	spin_unlock_bh(&ecm_db_lock);

	return ci;
}
EXPORT_SYMBOL(ecm_db_mapping_connections_from_get_and_ref_first);

/*
 * ecm_db_mapping_connections_to_get_and_ref_first()
 *	Return a reference to the first connection made to this mapping
 */
struct ecm_db_connection_instance *ecm_db_mapping_connections_to_get_and_ref_first(struct ecm_db_mapping_instance *mi)
{
	struct ecm_db_connection_instance *ci;

	DEBUG_CHECK_MAGIC(mi, ECM_DB_MAPPING_INSTANCE_MAGIC, "%p: magic failed", mi);

	spin_lock_bh(&ecm_db_lock);
	ci = mi->to_connections;
	if (ci) {
		_ecm_db_connection_ref(ci);
	}
	spin_unlock_bh(&ecm_db_lock);

	return ci;
}
EXPORT_SYMBOL(ecm_db_mapping_connections_to_get_and_ref_first);

/*
 * ecm_db_mapping_connections_nat_from_get_and_ref_first()
 *	Return a reference to the first NAT connection made from this mapping
 */
struct ecm_db_connection_instance *ecm_db_mapping_connections_nat_from_get_and_ref_first(struct ecm_db_mapping_instance *mi)
{
	struct ecm_db_connection_instance *ci;

	DEBUG_CHECK_MAGIC(mi, ECM_DB_MAPPING_INSTANCE_MAGIC, "%p: magic failed", mi);

	spin_lock_bh(&ecm_db_lock);
	ci = mi->from_nat_connections;
	if (ci) {
		_ecm_db_connection_ref(ci);
	}
	spin_unlock_bh(&ecm_db_lock);

	return ci;
}
EXPORT_SYMBOL(ecm_db_mapping_connections_nat_from_get_and_ref_first);

/*
 * ecm_db_mapping_connections_nat_to_get_and_ref_first()
 *	Return a reference to the first NAT connection made to this mapping
 */
struct ecm_db_connection_instance *ecm_db_mapping_connections_nat_to_get_and_ref_first(struct ecm_db_mapping_instance *mi)
{
	struct ecm_db_connection_instance *ci;

	DEBUG_CHECK_MAGIC(mi, ECM_DB_MAPPING_INSTANCE_MAGIC, "%p: magic failed", mi);

	spin_lock_bh(&ecm_db_lock);
	ci = mi->to_nat_connections;
	if (ci) {
		_ecm_db_connection_ref(ci);
	}
	spin_unlock_bh(&ecm_db_lock);

	return ci;
}
EXPORT_SYMBOL(ecm_db_mapping_connections_nat_to_get_and_ref_first);

/*
 * ecm_db_connection_node_from_get_and_ref()
 *	Return node reference
 */
struct ecm_db_node_instance *ecm_db_connection_node_to_get_and_ref(struct ecm_db_connection_instance *ci)
{
	struct ecm_db_node_instance *ni;

	DEBUG_CHECK_MAGIC(ci, ECM_DB_CONNECTION_INSTANCE_MAGIC, "%p: magic failed\n", ci);
	
	spin_lock_bh(&ecm_db_lock);
	ni = ci->mapping_to->host->node;
	DEBUG_CHECK_MAGIC(ni, ECM_DB_NODE_INSTANCE_MAGIC, "%p: magic failed\n", ni);
	_ecm_db_node_ref(ni);
	spin_unlock_bh(&ecm_db_lock);
	return ni;
}
EXPORT_SYMBOL(ecm_db_connection_node_to_get_and_ref);

/*
 * ecm_db_connection_mapping_from_get_and_ref_next()
 *	Return reference to next connection in from mapping chain
 */
struct ecm_db_connection_instance *ecm_db_connection_mapping_from_get_and_ref_next(struct ecm_db_connection_instance *ci)
{
	struct ecm_db_connection_instance *nci;

	DEBUG_CHECK_MAGIC(ci, ECM_DB_CONNECTION_INSTANCE_MAGIC, "%p: magic failed\n", ci);

	spin_lock_bh(&ecm_db_lock);
	nci = ci->from_next;
	if (nci) {
		_ecm_db_connection_ref(nci);
	}
	spin_unlock_bh(&ecm_db_lock);

	return nci;
}
EXPORT_SYMBOL(ecm_db_connection_mapping_from_get_and_ref_next);

/*
 * ecm_db_connection_mapping_to_get_and_ref_next()
 *	Return reference to next connection in to mapping chain
 */
struct ecm_db_connection_instance *ecm_db_connection_mapping_to_get_and_ref_next(struct ecm_db_connection_instance *ci)
{
	struct ecm_db_connection_instance *nci;

	DEBUG_CHECK_MAGIC(ci, ECM_DB_CONNECTION_INSTANCE_MAGIC, "%p: magic failed\n", ci);

	spin_lock_bh(&ecm_db_lock);
	nci = ci->to_next;
	if (nci) {
		_ecm_db_connection_ref(nci);
	}
	spin_unlock_bh(&ecm_db_lock);

	return nci;
}
EXPORT_SYMBOL(ecm_db_connection_mapping_to_get_and_ref_next);

/*
 * ecm_db_connection_mapping_nat_from_get_and_ref_next()
 *	Return reference to next connection in from NAT mapping chain
 */
struct ecm_db_connection_instance *ecm_db_connection_mapping_nat_from_get_and_ref_next(struct ecm_db_connection_instance *ci)
{
	struct ecm_db_connection_instance *nci;

	DEBUG_CHECK_MAGIC(ci, ECM_DB_CONNECTION_INSTANCE_MAGIC, "%p: magic failed\n", ci);

	spin_lock_bh(&ecm_db_lock);
	nci = ci->from_nat_next;
	if (nci) {
		_ecm_db_connection_ref(nci);
	}
	spin_unlock_bh(&ecm_db_lock);

	return nci;
}
EXPORT_SYMBOL(ecm_db_connection_mapping_nat_from_get_and_ref_next);

/*
 * ecm_db_connection_mapping_nat_to_get_and_ref_next()
 *	Return reference to next connection in to NAT mapping chain
 */
struct ecm_db_connection_instance *ecm_db_connection_mapping_nat_to_get_and_ref_next(struct ecm_db_connection_instance *ci)
{
	struct ecm_db_connection_instance *nci;

	DEBUG_CHECK_MAGIC(ci, ECM_DB_CONNECTION_INSTANCE_MAGIC, "%p: magic failed\n", ci);

	spin_lock_bh(&ecm_db_lock);
	nci = ci->to_nat_next;
	if (nci) {
		_ecm_db_connection_ref(nci);
	}
	spin_unlock_bh(&ecm_db_lock);

	return nci;
}
EXPORT_SYMBOL(ecm_db_connection_mapping_nat_to_get_and_ref_next);

/*
 * ecm_db_iface_connections_from_get_and_ref_first()
 *	Return a reference to the first connection made from this iface
 */
struct ecm_db_connection_instance *ecm_db_iface_connections_from_get_and_ref_first(struct ecm_db_iface_instance *ii)
{
	struct ecm_db_connection_instance *ci;

	DEBUG_CHECK_MAGIC(ii, ECM_DB_IFACE_INSTANCE_MAGIC, "%p: magic failed", ii);

	spin_lock_bh(&ecm_db_lock);
	ci = ii->from_connections;
	if (ci) {
		_ecm_db_connection_ref(ci);
	}
	spin_unlock_bh(&ecm_db_lock);

	return ci;
}
EXPORT_SYMBOL(ecm_db_iface_connections_from_get_and_ref_first);

/*
 * ecm_db_iface_connections_to_get_and_ref_first()
 *	Return a reference to the first connection made to this iface
 */
struct ecm_db_connection_instance *ecm_db_iface_connections_to_get_and_ref_first(struct ecm_db_iface_instance *ii)
{
	struct ecm_db_connection_instance *ci;

	DEBUG_CHECK_MAGIC(ii, ECM_DB_IFACE_INSTANCE_MAGIC, "%p: magic failed", ii);

	spin_lock_bh(&ecm_db_lock);
	ci = ii->to_connections;
	if (ci) {
		_ecm_db_connection_ref(ci);
	}
	spin_unlock_bh(&ecm_db_lock);

	return ci;
}
EXPORT_SYMBOL(ecm_db_iface_connections_to_get_and_ref_first);

/*
 * ecm_db_iface_connections_nat_from_get_and_ref_first()
 *	Return a reference to the first NAT connection made from this iface
 */
struct ecm_db_connection_instance *ecm_db_iface_connections_nat_from_get_and_ref_first(struct ecm_db_iface_instance *ii)
{
	struct ecm_db_connection_instance *ci;

	DEBUG_CHECK_MAGIC(ii, ECM_DB_IFACE_INSTANCE_MAGIC, "%p: magic failed", ii);

	spin_lock_bh(&ecm_db_lock);
	ci = ii->from_nat_connections;
	if (ci) {
		_ecm_db_connection_ref(ci);
	}
	spin_unlock_bh(&ecm_db_lock);

	return ci;
}
EXPORT_SYMBOL(ecm_db_iface_connections_nat_from_get_and_ref_first);

/*
 * ecm_db_iface_connections_nat_to_get_and_ref_first()
 *	Return a reference to the first NAT connection made to this iface
 */
struct ecm_db_connection_instance *ecm_db_iface_connections_nat_to_get_and_ref_first(struct ecm_db_iface_instance *ii)
{
	struct ecm_db_connection_instance *ci;

	DEBUG_CHECK_MAGIC(ii, ECM_DB_IFACE_INSTANCE_MAGIC, "%p: magic failed", ii);

	spin_lock_bh(&ecm_db_lock);
	ci = ii->to_nat_connections;
	if (ci) {
		_ecm_db_connection_ref(ci);
	}
	spin_unlock_bh(&ecm_db_lock);

	return ci;
}
EXPORT_SYMBOL(ecm_db_iface_connections_nat_to_get_and_ref_first);

/*
 * ecm_db_connection_iface_from_get_and_ref_next()
 *	Return reference to next connection in from iface chain
 */
struct ecm_db_connection_instance *ecm_db_connection_iface_from_get_and_ref_next(struct ecm_db_connection_instance *ci)
{
	struct ecm_db_connection_instance *nci;

	DEBUG_CHECK_MAGIC(ci, ECM_DB_CONNECTION_INSTANCE_MAGIC, "%p: magic failed\n", ci);

	spin_lock_bh(&ecm_db_lock);
	nci = ci->iface_from_next;
	if (nci) {
		_ecm_db_connection_ref(nci);
	}
	spin_unlock_bh(&ecm_db_lock);

	return nci;
}
EXPORT_SYMBOL(ecm_db_connection_iface_from_get_and_ref_next);

/*
 * ecm_db_connection_iface_to_get_and_ref_next()
 *	Return reference to next connection in to iface chain
 */
struct ecm_db_connection_instance *ecm_db_connection_iface_to_get_and_ref_next(struct ecm_db_connection_instance *ci)
{
	struct ecm_db_connection_instance *nci;

	DEBUG_CHECK_MAGIC(ci, ECM_DB_CONNECTION_INSTANCE_MAGIC, "%p: magic failed\n", ci);

	spin_lock_bh(&ecm_db_lock);
	nci = ci->iface_to_next;
	if (nci) {
		_ecm_db_connection_ref(nci);
	}
	spin_unlock_bh(&ecm_db_lock);

	return nci;
}
EXPORT_SYMBOL(ecm_db_connection_iface_to_get_and_ref_next);

/*
 * ecm_db_connection_iface_nat_from_get_and_ref_next()
 *	Return reference to next connection in from NAT iface chain
 */
struct ecm_db_connection_instance *ecm_db_connection_iface_nat_from_get_and_ref_next(struct ecm_db_connection_instance *ci)
{
	struct ecm_db_connection_instance *nci;

	DEBUG_CHECK_MAGIC(ci, ECM_DB_CONNECTION_INSTANCE_MAGIC, "%p: magic failed\n", ci);

	spin_lock_bh(&ecm_db_lock);
	nci = ci->iface_from_nat_next;
	if (nci) {
		_ecm_db_connection_ref(nci);
	}
	spin_unlock_bh(&ecm_db_lock);

	return nci;
}
EXPORT_SYMBOL(ecm_db_connection_iface_nat_from_get_and_ref_next);

/*
 * ecm_db_connection_iface_nat_to_get_and_ref_next()
 *	Return reference to next connection in to NAT iface chain
 */
struct ecm_db_connection_instance *ecm_db_connection_iface_nat_to_get_and_ref_next(struct ecm_db_connection_instance *ci)
{
	struct ecm_db_connection_instance *nci;

	DEBUG_CHECK_MAGIC(ci, ECM_DB_CONNECTION_INSTANCE_MAGIC, "%p: magic failed\n", ci);

	spin_lock_bh(&ecm_db_lock);
	nci = ci->iface_to_nat_next;
	if (nci) {
		_ecm_db_connection_ref(nci);
	}
	spin_unlock_bh(&ecm_db_lock);

	return nci;
}
EXPORT_SYMBOL(ecm_db_connection_iface_nat_to_get_and_ref_next);

/*
 * ecm_db_node_hosts_get_and_ref_first()
 *	Return a reference to the first host associated with this node
 */
struct ecm_db_host_instance *ecm_db_node_hosts_get_and_ref_first(struct ecm_db_node_instance *ni)
{
	struct ecm_db_host_instance *hi;

	DEBUG_CHECK_MAGIC(ni, ECM_DB_NODE_INSTANCE_MAGIC, "%p: magic failed", ni);

	spin_lock_bh(&ecm_db_lock);
	hi = ni->hosts;
	if (hi) {
		_ecm_db_host_ref(hi);
	}
	spin_unlock_bh(&ecm_db_lock);

	return hi;
}
EXPORT_SYMBOL(ecm_db_node_hosts_get_and_ref_first);

/*
 * ecm_db_iface_nodes_get_and_ref_first()
 *	Return a reference to the first node made from this iface
 */
struct ecm_db_node_instance *ecm_db_iface_nodes_get_and_ref_first(struct ecm_db_iface_instance *ii)
{
	struct ecm_db_node_instance *ni;

	DEBUG_CHECK_MAGIC(ii, ECM_DB_IFACE_INSTANCE_MAGIC, "%p: magic failed", ii);

	spin_lock_bh(&ecm_db_lock);
	ni = ii->nodes;
	if (ni) {
		_ecm_db_node_ref(ni);
	}
	spin_unlock_bh(&ecm_db_lock);

	return ni;
}
EXPORT_SYMBOL(ecm_db_iface_nodes_get_and_ref_first);

/*
 * ecm_db_mapping_node_get_and_ref()
 */
struct ecm_db_node_instance *ecm_db_mapping_node_get_and_ref(struct ecm_db_mapping_instance *mi)
{
	struct ecm_db_node_instance *ni;

	DEBUG_CHECK_MAGIC(mi, ECM_DB_MAPPING_INSTANCE_MAGIC, "%p: magic failed\n", mi);

	spin_lock_bh(&ecm_db_lock);
	ni = mi->host->node;
	DEBUG_CHECK_MAGIC(ni, ECM_DB_NODE_INSTANCE_MAGIC, "%p: magic failed\n", ni);
	_ecm_db_node_ref(ni);
	spin_unlock_bh(&ecm_db_lock);
	return ni;
}
EXPORT_SYMBOL(ecm_db_mapping_node_get_and_ref);

/*
 * ecm_db_mapping_iface_get_and_ref()
 *	Return a reference to the interface on which this mapping resides
 */
struct ecm_db_iface_instance *ecm_db_mapping_iface_get_and_ref(struct ecm_db_mapping_instance *mi)
{
	struct ecm_db_iface_instance *ii;

	DEBUG_CHECK_MAGIC(mi, ECM_DB_MAPPING_INSTANCE_MAGIC, "%p: magic failed\n", mi);

	spin_lock_bh(&ecm_db_lock);
	ii = mi->host->node->iface;
	DEBUG_CHECK_MAGIC(ii, ECM_DB_IFACE_INSTANCE_MAGIC, "%p: magic failed\n", ii);
	_ecm_db_iface_ref(ii);
	spin_unlock_bh(&ecm_db_lock);
	return ii;
}
EXPORT_SYMBOL(ecm_db_mapping_iface_get_and_ref);

/*
 * ecm_db_mapping_host_get_and_ref()
 */
struct ecm_db_host_instance *ecm_db_mapping_host_get_and_ref(struct ecm_db_mapping_instance *mi)
{
	DEBUG_CHECK_MAGIC(mi, ECM_DB_MAPPING_INSTANCE_MAGIC, "%p: magic failed\n", mi);

	spin_lock_bh(&ecm_db_lock);
	_ecm_db_host_ref(mi->host);
	spin_unlock_bh(&ecm_db_lock);
	return mi->host;
}
EXPORT_SYMBOL(ecm_db_mapping_host_get_and_ref);

/*
 * ecm_db_host_node_get_and_ref()
 */
struct ecm_db_node_instance *ecm_db_host_node_get_and_ref(struct ecm_db_host_instance *hi)
{
	DEBUG_CHECK_MAGIC(hi, ECM_DB_HOST_INSTANCE_MAGIC, "%p: magic failed\n", hi);

	spin_lock_bh(&ecm_db_lock);
	_ecm_db_node_ref(hi->node);
	spin_unlock_bh(&ecm_db_lock);
	return hi->node;
}
EXPORT_SYMBOL(ecm_db_host_node_get_and_ref);

/*
 * ecm_db_node_iface_get_and_ref()
 */
struct ecm_db_iface_instance *ecm_db_node_iface_get_and_ref(struct ecm_db_node_instance *ni)
{
	DEBUG_CHECK_MAGIC(ni, ECM_DB_NODE_INSTANCE_MAGIC, "%p: magic failed\n", ni);

	spin_lock_bh(&ecm_db_lock);
	_ecm_db_iface_ref(ni->iface);
	spin_unlock_bh(&ecm_db_lock);
	return ni->iface;
}
EXPORT_SYMBOL(ecm_db_node_iface_get_and_ref);

/*
 * ecm_db_node_host_count_get()
 *	Return the number of hosts to this node
 */
int ecm_db_node_host_count_get(struct ecm_db_node_instance *ni)
{
	int count;

	DEBUG_CHECK_MAGIC(ni, ECM_DB_NODE_INSTANCE_MAGIC, "%p: magic failed\n", ni);
	
	spin_lock_bh(&ecm_db_lock);
	count = ni->host_count;
	spin_unlock_bh(&ecm_db_lock);
	return count;
}
EXPORT_SYMBOL(ecm_db_node_host_count_get);

/*
 * ecm_db_iface_node_count_get()
 *	Return the number of nodes to this iface
 */
int ecm_db_iface_node_count_get(struct ecm_db_iface_instance *ii)
{
	int count;

	DEBUG_CHECK_MAGIC(ii, ECM_DB_IFACE_INSTANCE_MAGIC, "%p: magic failed\n", ii);
	
	spin_lock_bh(&ecm_db_lock);
	count = ii->node_count;
	spin_unlock_bh(&ecm_db_lock);
	return count;
}
EXPORT_SYMBOL(ecm_db_iface_node_count_get);

/*
 * ecm_db_host_mapping_count_get()
 *	Return the number of mappings to this host
 */
int ecm_db_host_mapping_count_get(struct ecm_db_host_instance *hi)
{
	int count;

	DEBUG_CHECK_MAGIC(hi, ECM_DB_HOST_INSTANCE_MAGIC, "%p: magic failed\n", hi);
	
	spin_lock_bh(&ecm_db_lock);
	count = hi->mapping_count;
	spin_unlock_bh(&ecm_db_lock);
	return count;
}
EXPORT_SYMBOL(ecm_db_host_mapping_count_get);

/*
 * ecm_db_mapping_connections_total_count_get()
 *	Return the total number of connections (NAT and non-NAT) this mapping has
 */
int ecm_db_mapping_connections_total_count_get(struct ecm_db_mapping_instance *mi)
{
	int count;

	DEBUG_CHECK_MAGIC(mi, ECM_DB_MAPPING_INSTANCE_MAGIC, "%p: magic failed\n", mi);
	
	spin_lock_bh(&ecm_db_lock);
	count = mi->from + mi->to + mi->nat_from + mi->nat_to;
	DEBUG_ASSERT(count >= 0, "%p: Count overflow from: %d, to: %d, nat_from: %d, nat_to: %d\n", mi, mi->from, mi->to, mi->nat_from, mi->nat_to);
	spin_unlock_bh(&ecm_db_lock);
	return count;
}
EXPORT_SYMBOL(ecm_db_mapping_connections_total_count_get);

/*
 * ecm_db_connection_mapping_from_get_and_ref()
 * 	Return a reference to the from mapping of the connection
 */
struct ecm_db_mapping_instance *ecm_db_connection_mapping_from_get_and_ref(struct ecm_db_connection_instance *ci)
{
	struct ecm_db_mapping_instance *mi;

	DEBUG_CHECK_MAGIC(ci, ECM_DB_CONNECTION_INSTANCE_MAGIC, "%p: magic failed\n", ci);
	
	spin_lock_bh(&ecm_db_lock);
	mi = ci->mapping_from;
	_ecm_db_mapping_ref(mi);
	spin_unlock_bh(&ecm_db_lock);
	return mi;
}
EXPORT_SYMBOL(ecm_db_connection_mapping_from_get_and_ref);

/*
 * ecm_db_connection_mapping_nat_from_get_and_ref()
 * 	Return a reference to the from NAT mapping of the connection
 */
struct ecm_db_mapping_instance *ecm_db_connection_mapping_nat_from_get_and_ref(struct ecm_db_connection_instance *ci)
{
	struct ecm_db_mapping_instance *mi;

	DEBUG_CHECK_MAGIC(ci, ECM_DB_CONNECTION_INSTANCE_MAGIC, "%p: magic failed\n", ci);
	
	spin_lock_bh(&ecm_db_lock);
	mi = ci->mapping_nat_from;
	_ecm_db_mapping_ref(mi);
	spin_unlock_bh(&ecm_db_lock);
	return mi;
}
EXPORT_SYMBOL(ecm_db_connection_mapping_nat_from_get_and_ref);

/*
 * ecm_db_connection_mapping_to_get_and_ref()
 * 	Return a reference to the from mapping of the connection
 */
struct ecm_db_mapping_instance *ecm_db_connection_mapping_to_get_and_ref(struct ecm_db_connection_instance *ci)
{
	struct ecm_db_mapping_instance *mi;

	DEBUG_CHECK_MAGIC(ci, ECM_DB_CONNECTION_INSTANCE_MAGIC, "%p: magic failed\n", ci);
	
	spin_lock_bh(&ecm_db_lock);
	mi = ci->mapping_to;
	_ecm_db_mapping_ref(mi);
	spin_unlock_bh(&ecm_db_lock);
	return mi;
}
EXPORT_SYMBOL(ecm_db_connection_mapping_to_get_and_ref);

/*
 * ecm_db_connection_mapping_to_nat_get_and_ref()
 * 	Return a reference to the from NAT mapping of the connection
 */
struct ecm_db_mapping_instance *ecm_db_connection_mapping_nat_to_get_and_ref(struct ecm_db_connection_instance *ci)
{
	struct ecm_db_mapping_instance *mi;

	DEBUG_CHECK_MAGIC(ci, ECM_DB_CONNECTION_INSTANCE_MAGIC, "%p: magic failed\n", ci);
	
	spin_lock_bh(&ecm_db_lock);
	mi = ci->mapping_nat_to;
	_ecm_db_mapping_ref(mi);
	spin_unlock_bh(&ecm_db_lock);
	return mi;
}
EXPORT_SYMBOL(ecm_db_connection_mapping_nat_to_get_and_ref);

/*
 * ecm_db_connection_node_from_get_and_ref()
 *	Return node reference
 */
struct ecm_db_node_instance *ecm_db_connection_node_from_get_and_ref(struct ecm_db_connection_instance *ci)
{
	struct ecm_db_node_instance *ni;

	DEBUG_CHECK_MAGIC(ci, ECM_DB_CONNECTION_INSTANCE_MAGIC, "%p: magic failed\n", ci);
	
	spin_lock_bh(&ecm_db_lock);
	ni = ci->mapping_from->host->node;
	_ecm_db_node_ref(ni);
	spin_unlock_bh(&ecm_db_lock);
	return ni;
}
EXPORT_SYMBOL(ecm_db_connection_node_from_get_and_ref);

/*
 * ecm_db_timer_groups_check()
 *	Check for expired group entries, returns the number that have expired
 */
static uint32_t ecm_db_timer_groups_check(uint32_t time_now)
{
	ecm_db_timer_group_t i;
	uint32_t expired = 0;

	DEBUG_TRACE("Timer groups check start %u\n", time_now);

	/*
	 * Examine all timer groups for expired entries.
	 */
	for (i = 0; i < ECM_DB_TIMER_GROUPS_MAX; ++i) {
		struct ecm_db_timer_group *timer_group;

		/*
		 * The group tail tracks the oldest entry so that is what we examine.
		 */
		timer_group = &ecm_db_timer_groups[i];
		spin_lock_bh(&ecm_db_lock);
		while (timer_group->tail) {
			struct ecm_db_timer_group_entry *tge;

			tge = timer_group->tail;
			if (tge->timeout > time_now) {
				/*
				 * Not expired - and no further will be as they are in order
				 */
				break;
			}

			/*
			 * Has expired - remove the entry from the list and invoke the callback
			 * NOTE: We know the entry is at the tail of the group
			 */
			if (tge->prev) {
				tge->prev->next = NULL;
			} else {
				/*
				 * First in the group
				 */
				DEBUG_ASSERT(timer_group->head == tge, "%p: bad head, expecting %p got %p\n", timer_group, tge, timer_group->head);
				timer_group->head = NULL;
			}	
			timer_group->tail = tge->prev;
			tge->group = ECM_DB_TIMER_GROUPS_MAX;
			spin_unlock_bh(&ecm_db_lock);
			expired++;
			DEBUG_TRACE("%p: Expired\n", tge);
			tge->fn(tge->arg);
			spin_lock_bh(&ecm_db_lock);
		}
		spin_unlock_bh(&ecm_db_lock);
	}

	spin_lock_bh(&ecm_db_lock);
	time_now = ecm_db_time;
	spin_unlock_bh(&ecm_db_lock);
	DEBUG_TRACE("Timer groups check end %u, expired count %u\n", time_now, expired);
	return expired;
}

/*
 * ecm_db_connection_classifier_assign()
 *	Assign a classifier to the connection assigned classifier list.
 *
 * This adds the classifier in the ci->assignments list in priority order according to the classifier type.
 * Only assigned classifiers are in this list, allowing fast retrival of in-order current assignments, avoiding the need to skip over unassigned classifiers.
 * Because there is only one of each type of classifier the classifier is also recorded in an array, the position in which is its type value.
 * This allows fast lookup based on type too.
 */
void ecm_db_connection_classifier_assign(struct ecm_db_connection_instance *ci, struct ecm_classifier_instance *new_ca)
{
	struct ecm_classifier_instance *ca;
	struct ecm_classifier_instance *ca_prev;
	ecm_classifier_type_t new_ca_type;
	DEBUG_CHECK_MAGIC(ci, ECM_DB_CONNECTION_INSTANCE_MAGIC, "%p: magic failed\n", ci);

	/*
	 * Get the type (which is also used as the priority)
	 */
	new_ca_type = new_ca->type_get(new_ca);

	/*
	 * Connection holds ref to the classifier
	 */
	new_ca->ref(new_ca);

	/*
	 * Find place to insert the classifier
	 */
	spin_lock_bh(&ecm_db_lock);
	ca = ci->assignments;
	ca_prev = NULL;
	while (ca) {
		ecm_classifier_type_t ca_type;
		ca_type = ca->type_get(ca);

		/*
		 * If new ca is less important that the current assigned classifier insert here
		 */
		if (new_ca_type < ca_type) {
			break;
		}
		ca_prev = ca;
		ca = ca->ca_next;
	}

	/*
	 * Insert new_ca before ca and after ca_prev.
	 */
	new_ca->ca_prev = ca_prev;
	if (ca_prev) {
		ca_prev->ca_next = new_ca;
	} else {
		DEBUG_ASSERT(ci->assignments == ca, "%p: Bad assigmnment list, expecting: %p, got: %p\n", ci, ca, ci->assignments);
		ci->assignments = new_ca;
	}

	new_ca->ca_next = ca;
	if (ca) {
		ca->ca_prev = new_ca;
	}

	/*
	 * Insert based on type too
	 */
	DEBUG_ASSERT(ci->assignments_by_type[new_ca_type] == NULL, "%p: Only one of each type: %d may be registered, new: %p, existing, %p\n",
			ci, new_ca_type, new_ca, ci->assignments_by_type[new_ca_type]);
	ci->assignments_by_type[new_ca_type] = new_ca;

	spin_unlock_bh(&ecm_db_lock);
}
EXPORT_SYMBOL(ecm_db_connection_classifier_assign);

/*
 * ecm_db_connection_classifier_assignments_get_and_ref()
 *	Populate the given array with references to the currently assigned classifiers.
 *
 * This function returns the number of assignments starting from [0].
 * [0] is the lowest priority classifier, [return_val - 1] is the highest priority.
 * Release each classifier when you are done, for convenience use ecm_db_connection_assignments_release().
 *
 * NOTE: The array also contains the default classifier too which of course will always be at [0]
 *
 * WARNING: The array MUST be of size ECM_CLASSIFIER_TYPES.
 */
int ecm_db_connection_classifier_assignments_get_and_ref(struct ecm_db_connection_instance *ci, struct ecm_classifier_instance *assignments[])
{
	int aci_count;
	struct ecm_classifier_instance *aci;
	DEBUG_CHECK_MAGIC(ci, ECM_DB_CONNECTION_INSTANCE_MAGIC, "%p: magic failed\n", ci);

	aci_count = 1;
	assignments[0] = (struct ecm_classifier_instance *)ci->dci;
	ci->dci->base.ref((struct ecm_classifier_instance *)ci->dci);
	spin_lock_bh(&ecm_db_lock);
	aci = ci->assignments;
	while (aci) {
		aci->ref(aci);
		assignments[aci_count++] = aci;
		aci = aci->ca_next;
	}
	spin_unlock_bh(&ecm_db_lock);
	return aci_count;
}
EXPORT_SYMBOL(ecm_db_connection_classifier_assignments_get_and_ref);

/*
 * ecm_db_connection_assignments_release()
 * 	Release references to classifiers in the assignments array
 */
void ecm_db_connection_assignments_release(int assignment_count, struct ecm_classifier_instance *assignments[])
{
	int i;
	for (i = 0; i < assignment_count; ++i) {
		struct ecm_classifier_instance *aci = assignments[i];
		if (aci) {
			aci->deref(aci);
		}
	}
}
EXPORT_SYMBOL(ecm_db_connection_assignments_release);

/*
 * ecm_db_connection_assigned_classifier_find_and_ref()
 *	Return a ref to classifier of the requested type, if found
 */
struct ecm_classifier_instance *ecm_db_connection_assigned_classifier_find_and_ref(struct ecm_db_connection_instance *ci, ecm_classifier_type_t type)
{
	struct ecm_classifier_instance *ca;
	DEBUG_CHECK_MAGIC(ci, ECM_DB_CONNECTION_INSTANCE_MAGIC, "%p: magic failed\n", ci);
	spin_lock_bh(&ecm_db_lock);
	ca = ci->assignments_by_type[type];
	if (ca) {
		ca->ref(ca);
	}
	spin_unlock_bh(&ecm_db_lock);
	return ca;
}
EXPORT_SYMBOL(ecm_db_connection_assigned_classifier_find_and_ref);

/*
 * ecm_db_connection_classifier_unassign()
 *	Unassign a classifier
 */
void ecm_db_connection_classifier_unassign(struct ecm_db_connection_instance *ci, struct ecm_classifier_instance *cci)
{
	ecm_classifier_type_t ca_type;
	DEBUG_CHECK_MAGIC(ci, ECM_DB_CONNECTION_INSTANCE_MAGIC, "%p: magic failed\n", ci);

	DEBUG_ASSERT(cci->type_get(cci) != ECM_CLASSIFIER_TYPE_DEFAULT, "%p: Cannot unassign default", ci);

	DEBUG_CHECK_MAGIC(ci, ECM_DB_CONNECTION_INSTANCE_MAGIC, "%p: magic failed\n", ci);

	/*
	 * Get the type
	 */
	ca_type = cci->type_get(cci);

	DEBUG_TRACE("%p: Unassign type: %d, classifier: %p\n", ci, ca_type, cci);

	spin_lock_bh(&ecm_db_lock);

	/*
	 * Remove from assignments_by_type
	 */
	DEBUG_ASSERT(ci->assignments_by_type[ca_type] == cci, "%p: Invalid unassign, type: %d, expecting: %p, existing: %p\n",
			ci, ca_type, cci, ci->assignments_by_type[ca_type]);
	ci->assignments_by_type[ca_type] = NULL;

	/*
	 * Link out of assignments list
	 */
	if (cci->ca_prev) {
		cci->ca_prev->ca_next = cci->ca_next;
	} else {
		DEBUG_ASSERT(ci->assignments == cci, "%p: Bad assigmnment list, expecting: %p, got: %p", ci, cci, ci->assignments);
		ci->assignments = cci->ca_next;
	}
	if (cci->ca_next) {
		cci->ca_next->ca_prev = cci->ca_prev;
	}
	spin_unlock_bh(&ecm_db_lock);
	cci->deref(cci);
}
EXPORT_SYMBOL(ecm_db_connection_classifier_unassign);

/*
 * ecm_db_connection_classifier_default_get_and_ref()
 *	Get a reference to default classifier associated with this connection
 */
struct ecm_classifier_default_instance *ecm_db_connection_classifier_default_get_and_ref(struct ecm_db_connection_instance *ci)
{
	DEBUG_CHECK_MAGIC(ci, ECM_DB_CONNECTION_INSTANCE_MAGIC, "%p: magic failed\n", ci);

	/*
	 * No need to lock this object - it cannot change
	 */
	ci->dci->base.ref((struct ecm_classifier_instance *)ci->dci);
	return ci->dci;
}
EXPORT_SYMBOL(ecm_db_connection_classifier_default_get_and_ref);

/*
 * ecm_db_connection_from_interfaces_get_and_ref()
 *	Return the interface heirarchy from which this connection is established.
 *
 * 'interfaces' MUST be an array as large as ECM_DB_IFACE_HEIRARCHY_MAX.
 * Returns either ECM_DB_IFACE_HEIRARCHY_MAX if there are no interfaces / error.
 * Returns the index into the interfaces[] of the first interface (so "for (i = <ret val>, i < ECM_DB_IFACE_HEIRARCHY_MAX; ++i)" works)
 *
 * Each interface is referenced on return, be sure to release them individually or use ecm_db_connection_interfaces_deref() instead.
 */
int32_t ecm_db_connection_from_interfaces_get_and_ref(struct ecm_db_connection_instance *ci, struct ecm_db_iface_instance *interfaces[])
{
	int32_t n;
	int32_t i;
	DEBUG_CHECK_MAGIC(ci, ECM_DB_CONNECTION_INSTANCE_MAGIC, "%p: magic failed\n", ci);

	spin_lock_bh(&ecm_db_lock);
	n = ci->from_interface_first;
	for (i = n; i < ECM_DB_IFACE_HEIRARCHY_MAX; ++i) {
		interfaces[i] = ci->from_interfaces[i];
		_ecm_db_iface_ref(interfaces[i]);
	}
	spin_unlock_bh(&ecm_db_lock);
	return n;
}
EXPORT_SYMBOL(ecm_db_connection_from_interfaces_get_and_ref);

/*
 * ecm_db_connection_to_interfaces_get_and_ref()
 *	Return the interface heirarchy to which this connection is established.
 *
 * 'interfaces' MUST be an array as large as ECM_DB_IFACE_HEIRARCHY_MAX.
 * Returns either ECM_DB_IFACE_HEIRARCHY_MAX if there are no interfaces / error.
 * Returns the index into the interfaces[] of the first interface (so "for (i = <ret val>, i < ECM_DB_IFACE_HEIRARCHY_MAX; ++i)" works)
 *
 * Each interface is referenced on return, be sure to release them individually or use ecm_db_connection_interfaces_deref() instead.
 */
int32_t ecm_db_connection_to_interfaces_get_and_ref(struct ecm_db_connection_instance *ci, struct ecm_db_iface_instance *interfaces[])
{
	int32_t n;
	int32_t i;
	DEBUG_CHECK_MAGIC(ci, ECM_DB_CONNECTION_INSTANCE_MAGIC, "%p: magic failed\n", ci);

	spin_lock_bh(&ecm_db_lock);
	n = ci->to_interface_first;
	for (i = n; i < ECM_DB_IFACE_HEIRARCHY_MAX; ++i) {
		interfaces[i] = ci->to_interfaces[i];
		_ecm_db_iface_ref(interfaces[i]);
	}
	spin_unlock_bh(&ecm_db_lock);
	return n;
}
EXPORT_SYMBOL(ecm_db_connection_to_interfaces_get_and_ref);

/*
 * ecm_db_connection_from_nat_interfaces_get_and_ref()
 *	Return the interface heirarchy from (nat) which this connection is established.
 *
 * 'interfaces' MUST be an array as large as ECM_DB_IFACE_HEIRARCHY_MAX.
 * Returns either ECM_DB_IFACE_HEIRARCHY_MAX if there are no interfaces / error.
 * Returns the index into the interfaces[] of the first interface (so "for (i = <ret val>, i < ECM_DB_IFACE_HEIRARCHY_MAX; ++i)" works)
 *
 * Each interface is referenced on return, be sure to release them individually or use ecm_db_connection_interfaces_deref() instead.
 */
int32_t ecm_db_connection_from_nat_interfaces_get_and_ref(struct ecm_db_connection_instance *ci, struct ecm_db_iface_instance *interfaces[])
{
	int32_t n;
	int32_t i;
	DEBUG_CHECK_MAGIC(ci, ECM_DB_CONNECTION_INSTANCE_MAGIC, "%p: magic failed\n", ci);

	spin_lock_bh(&ecm_db_lock);
	n = ci->from_nat_interface_first;
	for (i = n; i < ECM_DB_IFACE_HEIRARCHY_MAX; ++i) {
		interfaces[i] = ci->from_nat_interfaces[i];
		_ecm_db_iface_ref(interfaces[i]);
	}
	spin_unlock_bh(&ecm_db_lock);
	return n;
}
EXPORT_SYMBOL(ecm_db_connection_from_nat_interfaces_get_and_ref);

/*
 * ecm_db_connection_to_nat_interfaces_get_and_ref()
 *	Return the interface heirarchy to (nat) which this connection is established.
 *
 * 'interfaces' MUST be an array as large as ECM_DB_IFACE_HEIRARCHY_MAX.
 * Returns either ECM_DB_IFACE_HEIRARCHY_MAX if there are no interfaces / error.
 * Returns the index into the interfaces[] of the first interface (so "for (i = <ret val>, i < ECM_DB_IFACE_HEIRARCHY_MAX; ++i)" works)
 *
 * Each interface is referenced on return, be sure to release them individually or use ecm_db_connection_interfaces_deref() instead.
 */
int32_t ecm_db_connection_to_nat_interfaces_get_and_ref(struct ecm_db_connection_instance *ci, struct ecm_db_iface_instance *interfaces[])
{
	int32_t n;
	int32_t i;
	DEBUG_CHECK_MAGIC(ci, ECM_DB_CONNECTION_INSTANCE_MAGIC, "%p: magic failed\n", ci);

	spin_lock_bh(&ecm_db_lock);
	n = ci->to_nat_interface_first;
	for (i = n; i < ECM_DB_IFACE_HEIRARCHY_MAX; ++i) {
		interfaces[i] = ci->to_nat_interfaces[i];
		_ecm_db_iface_ref(interfaces[i]);
	}
	spin_unlock_bh(&ecm_db_lock);
	return n;
}
EXPORT_SYMBOL(ecm_db_connection_to_nat_interfaces_get_and_ref);

/*
 * ecm_db_connection_interfaces_deref()
 *	Release all interfaces in the given interfaces heirarchy array.
 *
 * 'first' is the number returned by one of the ecm_db_connection_xx_interfaces_get_and_ref().
 * You should NOT have released any references to any of the interfaces in the array youself, this releases them all.
 */
void ecm_db_connection_interfaces_deref(struct ecm_db_iface_instance *interfaces[], int32_t first)
{
	int32_t i;
	DEBUG_ASSERT((first >= 0) && (first <= ECM_DB_IFACE_HEIRARCHY_MAX), "Bad first: %d\n", first);

	for (i = first; i < ECM_DB_IFACE_HEIRARCHY_MAX; ++i) {
		ecm_db_iface_deref(interfaces[i]);
	}
}
EXPORT_SYMBOL(ecm_db_connection_interfaces_deref);

/*
 * ecm_db_connection_from_interfaces_reset()
 *	Reset the from interfaces heirarchy with a new set of interfaces
 *
 * NOTE: This will mark the list as set even if you specify no list as a replacement.
 * This is deliberate - it's stating that there is no list :-)
 */
void ecm_db_connection_from_interfaces_reset(struct ecm_db_connection_instance *ci, struct ecm_db_iface_instance *interfaces[], int32_t new_first)
{
	struct ecm_db_iface_instance *old[ECM_DB_IFACE_HEIRARCHY_MAX];
	int32_t old_first;
	int32_t i;
	DEBUG_CHECK_MAGIC(ci, ECM_DB_CONNECTION_INSTANCE_MAGIC, "%p: magic failed\n", ci);

	/*
	 * Iterate the from interface list, removing the old and adding in the new
	 */
	spin_lock_bh(&ecm_db_lock);
	for (i = 0; i < ECM_DB_IFACE_HEIRARCHY_MAX; ++i) {
		/*
		 * Put any previous interface into the old list
		 */
		old[i] = ci->from_interfaces[i];
		ci->from_interfaces[i] = NULL;
		if (i < new_first) {
			continue;
		}
		ci->from_interfaces[i] = interfaces[i];
		_ecm_db_iface_ref(ci->from_interfaces[i]);
	}

	/*
	 * Get old first and update to new first
	 */
	old_first = ci->from_interface_first;
	ci->from_interface_first = new_first;
	ci->from_interface_set = true;
	spin_unlock_bh(&ecm_db_lock);

	/*
	 * Release old
	 */
	ecm_db_connection_interfaces_deref(old, old_first);
}
EXPORT_SYMBOL(ecm_db_connection_from_interfaces_reset);

/*
 * ecm_db_connection_to_interfaces_reset()
 *	Reset the to interfaces heirarchy with a new set of interfaces
 *
 * NOTE: This will mark the list as set even if you specify no list as a replacement.
 * This is deliberate - it's stating that there is no list :-)
 */
void ecm_db_connection_to_interfaces_reset(struct ecm_db_connection_instance *ci, struct ecm_db_iface_instance *interfaces[], int32_t new_first)
{
	struct ecm_db_iface_instance *old[ECM_DB_IFACE_HEIRARCHY_MAX];
	int32_t old_first;
	int32_t i;
	DEBUG_CHECK_MAGIC(ci, ECM_DB_CONNECTION_INSTANCE_MAGIC, "%p: magic failed\n", ci);

	/*
	 * Iterate the to interface list, removing the old and adding in the new
	 */
	spin_lock_bh(&ecm_db_lock);
	for (i = 0; i < ECM_DB_IFACE_HEIRARCHY_MAX; ++i) {
		/*
		 * Put any previous interface into the old list
		 */
		old[i] = ci->to_interfaces[i];
		ci->to_interfaces[i] = NULL;
		if (i < new_first) {
			continue;
		}
		ci->to_interfaces[i] = interfaces[i];
		_ecm_db_iface_ref(ci->to_interfaces[i]);
	}

	/*
	 * Get old first and update to new first
	 */
	old_first = ci->to_interface_first;
	ci->to_interface_first = new_first;
	ci->to_interface_set = true;
	spin_unlock_bh(&ecm_db_lock);

	/*
	 * Release old
	 */
	ecm_db_connection_interfaces_deref(old, old_first);
}
EXPORT_SYMBOL(ecm_db_connection_to_interfaces_reset);

/*
 * ecm_db_connection_from_nat_interfaces_reset()
 *	Reset the from NAT interfaces heirarchy with a new set of interfaces
 *
 * NOTE: This will mark the list as set even if you specify no list as a replacement.
 * This is deliberate - it's stating that there is no list :-)
 */
void ecm_db_connection_from_nat_interfaces_reset(struct ecm_db_connection_instance *ci, struct ecm_db_iface_instance *interfaces[], int32_t new_first)
{
	struct ecm_db_iface_instance *old[ECM_DB_IFACE_HEIRARCHY_MAX];
	int32_t old_first;
	int32_t i;
	DEBUG_CHECK_MAGIC(ci, ECM_DB_CONNECTION_INSTANCE_MAGIC, "%p: magic failed\n", ci);

	/*
	 * Iterate the from nat interface list, removing the old and adding in the new
	 */
	spin_lock_bh(&ecm_db_lock);
	for (i = 0; i < ECM_DB_IFACE_HEIRARCHY_MAX; ++i) {
		/*
		 * Put any previous interface into the old list
		 */
		old[i] = ci->from_nat_interfaces[i];
		ci->from_nat_interfaces[i] = NULL;
		if (i < new_first) {
			continue;
		}
		ci->from_nat_interfaces[i] = interfaces[i];
		_ecm_db_iface_ref(ci->from_nat_interfaces[i]);
	}

	/*
	 * Get old first and update to new first
	 */
	old_first = ci->from_nat_interface_first;
	ci->from_nat_interface_first = new_first;
	ci->from_nat_interface_set = true;
	spin_unlock_bh(&ecm_db_lock);

	/*
	 * Release old
	 */
	ecm_db_connection_interfaces_deref(old, old_first);
}
EXPORT_SYMBOL(ecm_db_connection_from_nat_interfaces_reset);

/*
 * ecm_db_connection_to_nat_interfaces_reset()
 *	Reset the to NAT interfaces heirarchy with a new set of interfaces.
 *
 * NOTE: This will mark the list as set even if you specify no list as a replacement.
 * This is deliberate - it's stating that there is no list :-)
 */
void ecm_db_connection_to_nat_interfaces_reset(struct ecm_db_connection_instance *ci, struct ecm_db_iface_instance *interfaces[], int32_t new_first)
{
	struct ecm_db_iface_instance *old[ECM_DB_IFACE_HEIRARCHY_MAX];
	int32_t old_first;
	int32_t i;
	DEBUG_CHECK_MAGIC(ci, ECM_DB_CONNECTION_INSTANCE_MAGIC, "%p: magic failed\n", ci);

	/*
	 * Iterate the to nat interface list, removing the old and adding in the new
	 */
	spin_lock_bh(&ecm_db_lock);
	for (i = 0; i < ECM_DB_IFACE_HEIRARCHY_MAX; ++i) {
		/*
		 * Put any previous interface into the old list
		 */
		old[i] = ci->to_nat_interfaces[i];
		ci->to_nat_interfaces[i] = NULL;
		if (i < new_first) {
			continue;
		}
		ci->to_nat_interfaces[i] = interfaces[i];
		_ecm_db_iface_ref(ci->to_nat_interfaces[i]);
	}

	/*
	 * Get old first and update to new first
	 */
	old_first = ci->to_nat_interface_first;
	ci->to_nat_interface_first = new_first;
	ci->to_nat_interface_set = true;
	spin_unlock_bh(&ecm_db_lock);

	/*
	 * Release old
	 */
	ecm_db_connection_interfaces_deref(old, old_first);
}
EXPORT_SYMBOL(ecm_db_connection_to_nat_interfaces_reset);

/*
 * ecm_db_connection_to_nat_interfaces_get_count()
 *	Return the number of interfaces in the list
 */
int32_t ecm_db_connection_to_nat_interfaces_get_count(struct ecm_db_connection_instance *ci)
{
	int32_t first;
	DEBUG_CHECK_MAGIC(ci, ECM_DB_CONNECTION_INSTANCE_MAGIC, "%p: magic failed\n", ci);
	spin_lock_bh(&ecm_db_lock);
	first = ci->to_nat_interface_first;
	spin_unlock_bh(&ecm_db_lock);
	return ECM_DB_IFACE_HEIRARCHY_MAX - first;
}
EXPORT_SYMBOL(ecm_db_connection_to_nat_interfaces_get_count);

/*
 * ecm_db_connection_from_nat_interfaces_get_count()
 *	Return the number of interfaces in the list
 */
int32_t ecm_db_connection_from_nat_interfaces_get_count(struct ecm_db_connection_instance *ci)
{
	int32_t first;
	DEBUG_CHECK_MAGIC(ci, ECM_DB_CONNECTION_INSTANCE_MAGIC, "%p: magic failed\n", ci);
	spin_lock_bh(&ecm_db_lock);
	first = ci->from_nat_interface_first;
	spin_unlock_bh(&ecm_db_lock);
	return ECM_DB_IFACE_HEIRARCHY_MAX - first;
}
EXPORT_SYMBOL(ecm_db_connection_from_nat_interfaces_get_count);

/*
 * ecm_db_connection_to_interfaces_get_count()
 *	Return the number of interfaces in the list
 */
int32_t ecm_db_connection_to_interfaces_get_count(struct ecm_db_connection_instance *ci)
{
	int32_t first;
	DEBUG_CHECK_MAGIC(ci, ECM_DB_CONNECTION_INSTANCE_MAGIC, "%p: magic failed\n", ci);
	spin_lock_bh(&ecm_db_lock);
	first = ci->to_interface_first;
	spin_unlock_bh(&ecm_db_lock);
	return ECM_DB_IFACE_HEIRARCHY_MAX - first;
}
EXPORT_SYMBOL(ecm_db_connection_to_interfaces_get_count);

/*
 * ecm_db_connection_from_interfaces_get_count()
 *	Return the number of interfaces in the list
 */
int32_t ecm_db_connection_from_interfaces_get_count(struct ecm_db_connection_instance *ci)
{
	int32_t first;
	DEBUG_CHECK_MAGIC(ci, ECM_DB_CONNECTION_INSTANCE_MAGIC, "%p: magic failed\n", ci);
	spin_lock_bh(&ecm_db_lock);
	first = ci->from_interface_first;
	spin_unlock_bh(&ecm_db_lock);
	return ECM_DB_IFACE_HEIRARCHY_MAX - first;
}
EXPORT_SYMBOL(ecm_db_connection_from_interfaces_get_count);

/*
 * ecm_db_connection_to_interfaces_set_check()
 *	Returns true if the interface list has been set - even if set to an empty list!
 */
bool ecm_db_connection_to_interfaces_set_check(struct ecm_db_connection_instance *ci)
{
	bool set;

	DEBUG_CHECK_MAGIC(ci, ECM_DB_CONNECTION_INSTANCE_MAGIC, "%p: magic failed\n", ci);
	spin_lock_bh(&ecm_db_lock);
	set = ci->to_interface_set;
	spin_unlock_bh(&ecm_db_lock);
	return set;
}
EXPORT_SYMBOL(ecm_db_connection_to_interfaces_set_check);

/*
 * ecm_db_connection_from_interfaces_set_check()
 *	Returns true if the interface list has been set - even if set to an empty list!
 */
bool ecm_db_connection_from_interfaces_set_check(struct ecm_db_connection_instance *ci)
{
	bool set;

	DEBUG_CHECK_MAGIC(ci, ECM_DB_CONNECTION_INSTANCE_MAGIC, "%p: magic failed\n", ci);
	spin_lock_bh(&ecm_db_lock);
	set = ci->from_interface_set;
	spin_unlock_bh(&ecm_db_lock);
	return set;
}
EXPORT_SYMBOL(ecm_db_connection_from_interfaces_set_check);

/*
 * ecm_db_connection_to_nat_interfaces_set_check()
 *	Returns true if the interface list has been set - even if set to an empty list!
 */
bool ecm_db_connection_to_nat_interfaces_set_check(struct ecm_db_connection_instance *ci)
{
	bool set;

	DEBUG_CHECK_MAGIC(ci, ECM_DB_CONNECTION_INSTANCE_MAGIC, "%p: magic failed\n", ci);
	spin_lock_bh(&ecm_db_lock);
	set = ci->to_nat_interface_set;
	spin_unlock_bh(&ecm_db_lock);
	return set;
}
EXPORT_SYMBOL(ecm_db_connection_to_nat_interfaces_set_check);

/*
 * ecm_db_connection_from_nat_interfaces_set_check()
 *	Returns true if the interface list has been set - even if set to an empty list!
 */
bool ecm_db_connection_from_nat_interfaces_set_check(struct ecm_db_connection_instance *ci)
{
	bool set;

	DEBUG_CHECK_MAGIC(ci, ECM_DB_CONNECTION_INSTANCE_MAGIC, "%p: magic failed\n", ci);
	spin_lock_bh(&ecm_db_lock);
	set = ci->from_nat_interface_set;
	spin_unlock_bh(&ecm_db_lock);
	return set;
}
EXPORT_SYMBOL(ecm_db_connection_from_nat_interfaces_set_check);

/*
 * ecm_db_connection_from_interfaces_clear()
 *	Clear down the interfaces list, marking the list as not set
 */
void ecm_db_connection_from_interfaces_clear(struct ecm_db_connection_instance *ci)
{
	struct ecm_db_iface_instance *discard[ECM_DB_IFACE_HEIRARCHY_MAX];
	int32_t discard_first;
	int32_t i;

	DEBUG_CHECK_MAGIC(ci, ECM_DB_CONNECTION_INSTANCE_MAGIC, "%p: magic failed\n", ci);

	spin_lock_bh(&ecm_db_lock);
	for (i = ci->from_interface_first; i < ECM_DB_IFACE_HEIRARCHY_MAX; ++i) {
		discard[i] = ci->from_interfaces[i];
	}

	discard_first = ci->from_interface_first;
	ci->from_interface_set = false;
	ci->from_interface_first = ECM_DB_IFACE_HEIRARCHY_MAX;
	spin_unlock_bh(&ecm_db_lock);

	/*
	 * Release previous
	 */
	ecm_db_connection_interfaces_deref(discard, discard_first);
}
EXPORT_SYMBOL(ecm_db_connection_from_interfaces_clear);

/*
 * ecm_db_connection_from_nat_interfaces_clear()
 *	Clear down the interfaces list, marking the list as not set
 */
void ecm_db_connection_from_nat_interfaces_clear(struct ecm_db_connection_instance *ci)
{
	struct ecm_db_iface_instance *discard[ECM_DB_IFACE_HEIRARCHY_MAX];
	int32_t discard_first;
	int32_t i;

	DEBUG_CHECK_MAGIC(ci, ECM_DB_CONNECTION_INSTANCE_MAGIC, "%p: magic failed\n", ci);

	spin_lock_bh(&ecm_db_lock);
	for (i = ci->from_nat_interface_first; i < ECM_DB_IFACE_HEIRARCHY_MAX; ++i) {
		discard[i] = ci->from_nat_interfaces[i];
	}

	discard_first = ci->from_nat_interface_first;
	ci->from_nat_interface_set = false;
	ci->from_nat_interface_first = ECM_DB_IFACE_HEIRARCHY_MAX;
	spin_unlock_bh(&ecm_db_lock);

	/*
	 * Release previous
	 */
	ecm_db_connection_interfaces_deref(discard, discard_first);
}
EXPORT_SYMBOL(ecm_db_connection_from_nat_interfaces_clear);

/*
 * ecm_db_connection_to_interfaces_clear()
 *	Clear down the interfaces list, marking the list as not set
 */
void ecm_db_connection_to_interfaces_clear(struct ecm_db_connection_instance *ci)
{
	struct ecm_db_iface_instance *discard[ECM_DB_IFACE_HEIRARCHY_MAX];
	int32_t discard_first;
	int32_t i;

	DEBUG_CHECK_MAGIC(ci, ECM_DB_CONNECTION_INSTANCE_MAGIC, "%p: magic failed\n", ci);

	spin_lock_bh(&ecm_db_lock);
	for (i = ci->to_interface_first; i < ECM_DB_IFACE_HEIRARCHY_MAX; ++i) {
		discard[i] = ci->to_interfaces[i];
	}

	discard_first = ci->to_interface_first;
	ci->to_interface_set = false;
	ci->to_interface_first = ECM_DB_IFACE_HEIRARCHY_MAX;
	spin_unlock_bh(&ecm_db_lock);

	/*
	 * Release previous
	 */
	ecm_db_connection_interfaces_deref(discard, discard_first);
}
EXPORT_SYMBOL(ecm_db_connection_to_interfaces_clear);

/*
 * ecm_db_connection_to_nat_interfaces_clear()
 *	Clear down the interfaces list, marking the list as not set
 */
void ecm_db_connection_to_nat_interfaces_clear(struct ecm_db_connection_instance *ci)
{
	struct ecm_db_iface_instance *discard[ECM_DB_IFACE_HEIRARCHY_MAX];
	int32_t discard_first;
	int32_t i;

	DEBUG_CHECK_MAGIC(ci, ECM_DB_CONNECTION_INSTANCE_MAGIC, "%p: magic failed\n", ci);

	spin_lock_bh(&ecm_db_lock);
	for (i = ci->to_nat_interface_first; i < ECM_DB_IFACE_HEIRARCHY_MAX; ++i) {
		discard[i] = ci->to_nat_interfaces[i];
	}

	discard_first = ci->to_nat_interface_first;
	ci->to_nat_interface_set = false;
	ci->to_nat_interface_first = ECM_DB_IFACE_HEIRARCHY_MAX;
	spin_unlock_bh(&ecm_db_lock);

	/*
	 * Release previous
	 */
	ecm_db_connection_interfaces_deref(discard, discard_first);
}
EXPORT_SYMBOL(ecm_db_connection_to_nat_interfaces_clear);

/*
 * ecm_db_connection_add()
 *	Add the connection into the database.
 *
 * NOTE: The parameters are DIRECTIONAL in terms of which mapping established the connection.
 * NOTE: Dir confirms if this is an egressing or ingressing connection.  This applies to firewalling front ends mostly. If INGRESS then mapping_from is the WAN side.  If EGRESS then mapping_to is the WAN side.
 */
void ecm_db_connection_add(struct ecm_db_connection_instance *ci,
							struct ecm_front_end_connection_instance *feci,
							struct ecm_classifier_default_instance *dci,
							struct ecm_db_mapping_instance *mapping_from, struct ecm_db_mapping_instance *mapping_to,
							struct ecm_db_mapping_instance *mapping_nat_from, struct ecm_db_mapping_instance *mapping_nat_to,
							int protocol, ecm_db_direction_t dir,
							ecm_db_connection_final_callback_t final,
							ecm_db_timer_group_t tg, bool is_routed,
							void *arg)
{
	ecm_db_connection_hash_t hash_index;
	ecm_db_connection_serial_hash_t serial_hash_index;
	struct ecm_db_listener_instance *li;
	struct ecm_db_iface_instance *iface_from;
	struct ecm_db_iface_instance *iface_to;
	struct ecm_db_iface_instance *iface_nat_from;
	struct ecm_db_iface_instance *iface_nat_to;

	DEBUG_CHECK_MAGIC(ci, ECM_DB_CONNECTION_INSTANCE_MAGIC, "%p: magic failed\n", ci);
	DEBUG_CHECK_MAGIC(mapping_from, ECM_DB_MAPPING_INSTANCE_MAGIC, "%p: magic failed\n", mapping_from);
	DEBUG_CHECK_MAGIC(mapping_to, ECM_DB_MAPPING_INSTANCE_MAGIC, "%p: magic failed\n", mapping_to);
	DEBUG_CHECK_MAGIC(mapping_nat_from, ECM_DB_MAPPING_INSTANCE_MAGIC, "%p: magic failed\n", mapping_nat_from);
	DEBUG_CHECK_MAGIC(mapping_nat_to, ECM_DB_MAPPING_INSTANCE_MAGIC, "%p: magic failed\n", mapping_nat_to);
	DEBUG_ASSERT((protocol >= 0) && (protocol <= 255), "%p: invalid protocol number %d\n", ci, protocol);

	spin_lock_bh(&ecm_db_lock);
	DEBUG_ASSERT(!(ci->flags & ECM_DB_CONNECTION_FLAGS_INSERTED), "%p: inserted\n", ci);
	spin_unlock_bh(&ecm_db_lock);

	/*
	 * Record owner arg and callbacks
	 */
	ci->final = final;
	ci->arg = arg;

	/*
	 * Take reference to the front end
	 */
	feci->ref(feci);
	ci->feci = feci;

	/*
	 * Take reference to the default classifier
	 */
	dci->base.ref((struct ecm_classifier_instance *)dci);
	ci->dci = dci;
	ci->assignments_by_type[ECM_CLASSIFIER_TYPE_DEFAULT] = (struct ecm_classifier_instance *)dci;

	/*
	 * Connection takes references to the mappings
	 */
	ecm_db_mapping_ref(mapping_from);
	ecm_db_mapping_ref(mapping_to);
	ci->mapping_from = mapping_from;
	ci->mapping_to = mapping_to;

	ecm_db_mapping_ref(mapping_nat_from);
	ecm_db_mapping_ref(mapping_nat_to);
	ci->mapping_nat_from = mapping_nat_from;
	ci->mapping_nat_to = mapping_nat_to;

	/*
	 * Set the protocol and routed flag
	 */
	ci->protocol = protocol;
	ci->is_routed = is_routed;

	/*
	 * Set direction of connection
	 */
	ci->direction = dir;

	/*
	 * Identify which hash chain this connection will go into
	 */
       	hash_index = ecm_db_connection_generate_hash_index(mapping_from->host->address, mapping_from->port, mapping_to->host->address, mapping_to->port, protocol);
	ci->hash_index = hash_index;

	/*
	 * Identify which serial hash chain this connection will go into
	 */
       	serial_hash_index = ecm_db_connection_generate_serial_hash_index(ci->serial);
	ci->serial_hash_index = serial_hash_index;

	/*
	 * Now we need to lock
	 */
	spin_lock_bh(&ecm_db_lock);

	/*
	 * Increment protocol counter stats
	 */
	ecm_db_connection_count_by_protocol[protocol]++;
	DEBUG_ASSERT(ecm_db_connection_count_by_protocol[protocol] > 0, "%p: Invalid protocol count %d\n", ci, ecm_db_connection_count_by_protocol[protocol]);

	DEBUG_TRACE("c\n");

	/*
	 * Set time
	 */
	ci->time_added = ecm_db_time;

	/*
	 * Add connection into the global list
	 */
	ci->prev = NULL;
	ci->next = ecm_db_connections;
	if (ecm_db_connections) {
		ecm_db_connections->prev = ci;
	}
	ecm_db_connections = ci;

	/*
	 * Add this connection into the connections hash table
	 */
	ci->flags |= ECM_DB_CONNECTION_FLAGS_INSERTED;

	/*
	 * Insert mapping into the connections hash table
	 */
	ci->hash_next = ecm_db_connection_table[hash_index];
	if (ecm_db_connection_table[hash_index]) {
		ecm_db_connection_table[hash_index]->hash_prev = ci;
	}
	ecm_db_connection_table[hash_index] = ci;
	ecm_db_connection_table_lengths[hash_index]++;
	DEBUG_ASSERT(ecm_db_connection_table_lengths[hash_index] > 0, "%p: invalid table len %d\n", ci, ecm_db_connection_table_lengths[hash_index]);

	/*
	 * Insert connection into the connections serial hash table
	 */
	ci->serial_hash_next = ecm_db_connection_serial_table[serial_hash_index];
	if (ecm_db_connection_serial_table[serial_hash_index]) {
		ecm_db_connection_serial_table[serial_hash_index]->serial_hash_prev = ci;
	}
	ecm_db_connection_serial_table[serial_hash_index] = ci;
	ecm_db_connection_serial_table_lengths[serial_hash_index]++;
	DEBUG_ASSERT(ecm_db_connection_serial_table_lengths[serial_hash_index] > 0, "%p: invalid table len %d\n", ci, ecm_db_connection_serial_table_lengths[serial_hash_index]);

	/*
	 * Add this connection into the FROM mapping
	 */
	ci->from_prev = NULL;
	ci->from_next = mapping_from->from_connections;
	if (mapping_from->from_connections) {
		mapping_from->from_connections->from_prev = ci;
	}
	mapping_from->from_connections = ci;

	/*
	 * Add this connection into the TO mapping
	 */
	ci->to_prev = NULL;
	ci->to_next = mapping_to->to_connections;
	if (mapping_to->to_connections) {
		mapping_to->to_connections->to_prev = ci;
	}
	mapping_to->to_connections = ci;

	/*
	 * Add this connection into the FROM NAT mapping
	 */
	ci->from_nat_prev = NULL;
	ci->from_nat_next = mapping_nat_from->from_nat_connections;
	if (mapping_nat_from->from_nat_connections) {
		mapping_nat_from->from_nat_connections->from_nat_prev = ci;
	}
	mapping_nat_from->from_nat_connections = ci;

	/*
	 * Add this connection into the TO NAT mapping
	 */
	ci->to_nat_prev = NULL;
	ci->to_nat_next = mapping_nat_to->to_nat_connections;
	if (mapping_nat_to->to_nat_connections) {
		mapping_nat_to->to_nat_connections->to_nat_prev = ci;
	}
	mapping_nat_to->to_nat_connections = ci;

	/*
	 * Add this connection into the FROM iface list of connections
	 * NOTE: There is no need to ref the iface because it will exist for as long as this connection exists
	 * due to the heirarchy of dependencies being kept by the database.
	 */
	iface_from = mapping_from->host->node->iface;
	ci->iface_from_prev = NULL;
	ci->iface_from_next = iface_from->from_connections;
	if (iface_from->from_connections) {
		iface_from->from_connections->iface_from_prev = ci;
	}
	iface_from->from_connections = ci;

	/*
	 * Add this connection into the TO iface list of connections
	 * NOTE: There is no need to ref the iface because it will exist for as long as this connection exists
	 * due to the heirarchy of dependencies being kept by the database.
	 */
	iface_to = mapping_to->host->node->iface;
	ci->iface_to_prev = NULL;
	ci->iface_to_next = iface_to->to_connections;
	if (iface_to->to_connections) {
		iface_to->to_connections->iface_to_prev = ci;
	}
	iface_to->to_connections = ci;

	/*
	 * Add this connection into the FROM NAT iface list of connections
	 * NOTE: There is no need to ref the iface because it will exist for as long as this connection exists
	 * due to the heirarchy of dependencies being kept by the database.
	 */
	iface_nat_from = mapping_nat_from->host->node->iface;
	ci->iface_from_nat_prev = NULL;
	ci->iface_from_nat_next = iface_nat_from->from_nat_connections;
	if (iface_nat_from->from_nat_connections) {
		iface_nat_from->from_nat_connections->iface_from_nat_prev = ci;
	}
	iface_nat_from->from_nat_connections = ci;

	/*
	 * Add this connection into the TO NAT iface list of connections
	 * NOTE: There is no need to ref the iface because it will exist for as long as this connection exists
	 * due to the heirarchy of dependencies being kept by the database.
	 */
	iface_nat_to = mapping_nat_to->host->node->iface;
	ci->iface_to_nat_prev = NULL;
	ci->iface_to_nat_next = iface_nat_to->to_nat_connections;
	if (iface_nat_to->to_nat_connections) {
		iface_nat_to->to_nat_connections->iface_to_nat_prev = ci;
	}
	iface_nat_to->to_nat_connections = ci;

	/*
	 * NOTE: The interface heirarchy lists are deliberately left empty - these are completed
	 * by the front end if it is appropriate to do so.
	 */

	/*
	 * Update the counters in the mapping
	 */
	if (protocol == IPPROTO_UDP) {
		mapping_from->udp_from++;
		mapping_to->udp_to++;
		mapping_nat_from->udp_nat_from++;
		mapping_nat_to->udp_nat_to++;
	} else if (protocol == IPPROTO_TCP) {
		mapping_from->tcp_from++;
		mapping_to->tcp_to++;
		mapping_nat_from->tcp_nat_from++;
		mapping_nat_to->tcp_nat_to++;
	}

	mapping_from->from++;
	mapping_to->to++;
	mapping_nat_from->nat_from++;
	mapping_nat_to->nat_to++;

	/*
	 * Set the generation number
	 */
	ci->classifier_generation = ecm_db_classifier_generation;

	spin_unlock_bh(&ecm_db_lock);

	/*
	 * Throw add event to the listeners
 	 */
	DEBUG_TRACE("%p: Throw connection added event\n", ci);
	li = ecm_db_listeners_get_and_ref_first();
	while (li) {
		struct ecm_db_listener_instance *lin;
		if (li->connection_added) {
			li->connection_added(li->arg, ci);
		}

		/*
		 * Get next listener
		 */
		lin = ecm_db_listener_get_and_ref_next(li);
		ecm_db_listener_deref(li);
		li = lin;
	}

	/*
	 * Set timer group. 'ref' the connection to ensure it persists for the timer.
	 */
	ecm_db_connection_ref(ci);
	ecm_db_timer_group_entry_set(&ci->defunct_timer, tg);
}
EXPORT_SYMBOL(ecm_db_connection_add);

/*
 * ecm_db_mapping_add()
 *	Add a mapping instance into the database
 *
 * NOTE: The mapping will take a reference to the host instance.
 */
void ecm_db_mapping_add(struct ecm_db_mapping_instance *mi, struct ecm_db_host_instance *hi, int port,
						ecm_db_mapping_final_callback_t final, void *arg)
{
	ecm_db_mapping_hash_t hash_index;
	struct ecm_db_listener_instance *li;

	spin_lock_bh(&ecm_db_lock);
	DEBUG_CHECK_MAGIC(mi, ECM_DB_MAPPING_INSTANCE_MAGIC, "%p: magic failed\n", mi);
	DEBUG_CHECK_MAGIC(hi, ECM_DB_HOST_INSTANCE_MAGIC, "%p: magic failed\n", hi);
	DEBUG_ASSERT(mi->from_connections == NULL, "%p: connections not null\n", mi);
	DEBUG_ASSERT(mi->to_connections == NULL, "%p: connections not null\n", mi);
	DEBUG_ASSERT(!(mi->flags & ECM_DB_MAPPING_FLAGS_INSERTED), "%p: inserted\n", mi);
	DEBUG_ASSERT((hi->flags & ECM_DB_HOST_FLAGS_INSERTED), "%p: not inserted\n", hi);
	DEBUG_ASSERT(!mi->from && !mi->to && !mi->tcp_from && !mi->tcp_to && !mi->udp_from && !mi->udp_to, "%p: count errors\n", mi);
	spin_unlock_bh(&ecm_db_lock);

	mi->arg = arg;
	mi->final = final;

       	/*
	 * Compute hash table position for insertion
	 */
	hash_index = ecm_db_mapping_generate_hash_index(hi->address, port);
	mi->hash_index = hash_index;

       	/*
	 * Record port
	 */
	mi->port = port;

	/*
	 * Mapping takes a ref to the host
	 */
	ecm_db_host_ref(hi);
	mi->host = hi;

	/*
	 * Set time
	 */
	spin_lock_bh(&ecm_db_lock);
	mi->time_added = ecm_db_time;

	/*
	 * Record the mapping is inserted
	 */
	mi->flags |= ECM_DB_MAPPING_FLAGS_INSERTED;

	/*
	 * Add into the global list
	 */
	mi->prev = NULL;
	mi->next = ecm_db_mappings;
	if (ecm_db_mappings) {
		ecm_db_mappings->prev = mi;
	}
	ecm_db_mappings = mi;

	/*
	 * Insert mapping into the mappings hash table
	 */
	mi->hash_next = ecm_db_mapping_table[hash_index];
	if (ecm_db_mapping_table[hash_index]) {
		ecm_db_mapping_table[hash_index]->hash_prev = mi;
	}
	ecm_db_mapping_table[hash_index] = mi;
	ecm_db_mapping_table_lengths[hash_index]++;
	DEBUG_ASSERT(ecm_db_mapping_table_lengths[hash_index] > 0, "%p: invalid table len %d\n", hi, ecm_db_mapping_table_lengths[hash_index]);

	/*
	 * Insert mapping into the host mapping list
	 */
	mi->mapping_prev = NULL;
	mi->mapping_next = hi->mappings;
	if (hi->mappings) {
		hi->mappings->mapping_prev = mi;
	}
	hi->mappings = mi;
	hi->mapping_count++;
	spin_unlock_bh(&ecm_db_lock);

	/*
	 * Throw add event to the listeners
 	 */
	DEBUG_TRACE("%p: Throw mapping added event\n", mi);
	li = ecm_db_listeners_get_and_ref_first();
	while (li) {
		struct ecm_db_listener_instance *lin;
		if (li->mapping_added) {
			li->mapping_added(li->arg, mi);
		}

		/*
		 * Get next listener
		 */
		lin = ecm_db_listener_get_and_ref_next(li);
		ecm_db_listener_deref(li);
		li = lin;
	}
}
EXPORT_SYMBOL(ecm_db_mapping_add);

/*
 * ecm_db_host_add()
 *	Add a host instance into the database
 */
void ecm_db_host_add(struct ecm_db_host_instance *hi, struct ecm_db_node_instance *ni, ip_addr_t address, bool on_link,
					ecm_db_host_final_callback_t final, void *arg)
{
	ecm_db_host_hash_t hash_index;
	struct ecm_db_listener_instance *li;

	spin_lock_bh(&ecm_db_lock);
	DEBUG_CHECK_MAGIC(hi, ECM_DB_HOST_INSTANCE_MAGIC, "%p: magic failed\n", hi);
	DEBUG_CHECK_MAGIC(ni, ECM_DB_NODE_INSTANCE_MAGIC, "%p: magic failed\n", ni);
	DEBUG_ASSERT((hi->mappings == NULL) && (hi->mapping_count == 0), "%p: mappings not null\n", hi);
	DEBUG_ASSERT((hi->node == NULL), "%p: node not null\n", hi);
	DEBUG_ASSERT(!(hi->flags & ECM_DB_HOST_FLAGS_INSERTED), "%p: inserted\n", hi);
	spin_unlock_bh(&ecm_db_lock);

	hi->arg = arg;
	hi->final = final;
	ECM_IP_ADDR_COPY(hi->address, address);
	hi->on_link = on_link;

       	/*
	 * Compute hash index into which host will be added
	 */
	hash_index = ecm_db_host_generate_hash_index(address);
	hi->hash_index = hash_index;

	/*
	 * Host takes a ref to the node
	 */
	ecm_db_node_ref(ni);
	hi->node = ni;

	/*
	 * Add into the global list
	 */
	spin_lock_bh(&ecm_db_lock);
	hi->flags |= ECM_DB_HOST_FLAGS_INSERTED;
	hi->prev = NULL;
	hi->next = ecm_db_hosts;
	if (ecm_db_hosts) {
		ecm_db_hosts->prev = hi;
	}
	ecm_db_hosts = hi;

	/*
	 * Add host into the hash table
	 */
	hi->hash_next = ecm_db_host_table[hash_index];
	if (ecm_db_host_table[hash_index]) {
		ecm_db_host_table[hash_index]->hash_prev = hi;
	}
	ecm_db_host_table[hash_index] = hi;
	ecm_db_host_table_lengths[hash_index]++;
	DEBUG_ASSERT(ecm_db_host_table_lengths[hash_index] > 0, "%p: invalid table len %d\n", hi, ecm_db_host_table_lengths[hash_index]);

	/*
	 * Set time of add
	 */
	hi->time_added = ecm_db_time;

	/*
	 * Insert host into the node hosts list
	 */
	hi->host_prev = NULL;
	hi->host_next = ni->hosts;
	if (ni->hosts) {
		ni->hosts->host_prev = hi;
	}
	ni->hosts = hi;
	ni->host_count++;
	spin_unlock_bh(&ecm_db_lock);

	/*
	 * Throw add event to the listeners
 	 */
	DEBUG_TRACE("%p: Throw host added event\n", hi);
	li = ecm_db_listeners_get_and_ref_first();
	while (li) {
		struct ecm_db_listener_instance *lin;
		if (li->host_added) {
			li->host_added(li->arg, hi);
		}

		/*
		 * Get next listener
		 */
		lin = ecm_db_listener_get_and_ref_next(li);
		ecm_db_listener_deref(li);
		li = lin;
	}
}
EXPORT_SYMBOL(ecm_db_host_add);

/*
 * ecm_db_node_add()
 *	Add a node instance into the database
 */
void ecm_db_node_add(struct ecm_db_node_instance *ni, struct ecm_db_iface_instance *ii, uint8_t *address,
					ecm_db_node_final_callback_t final, void *arg)
{
	ecm_db_node_hash_t hash_index;
	struct ecm_db_listener_instance *li;

	spin_lock_bh(&ecm_db_lock);
	DEBUG_CHECK_MAGIC(ni, ECM_DB_NODE_INSTANCE_MAGIC, "%p: magic failed\n", ni);
	DEBUG_CHECK_MAGIC(ii, ECM_DB_IFACE_INSTANCE_MAGIC, "%p: magic failed\n", ii);
	DEBUG_ASSERT(address, "%p: address null\n", ni);
	DEBUG_ASSERT((ni->hosts == NULL) && (ni->host_count == 0), "%p: hosts not null\n", ni);
	DEBUG_ASSERT((ni->iface == NULL), "%p: iface not null\n", ni);
	DEBUG_ASSERT(!(ni->flags & ECM_DB_NODE_FLAGS_INSERTED), "%p: inserted\n", ni);
	spin_unlock_bh(&ecm_db_lock);

	memcpy(ni->address, address, ETH_ALEN);
	ni->arg = arg;
	ni->final = final;

	/*
	 * Compute hash chain for insertion
	 */
	hash_index = ecm_db_node_generate_hash_index(address);
	ni->hash_index = hash_index;

	/*
	 * Node takes a ref to the iface
	 */
	ecm_db_iface_ref(ii);
	ni->iface = ii;

	/*
	 * Add into the global list
	 */
	spin_lock_bh(&ecm_db_lock);
	ni->flags |= ECM_DB_NODE_FLAGS_INSERTED;
	ni->prev = NULL;
	ni->next = ecm_db_nodes;
	if (ecm_db_nodes) {
		ecm_db_nodes->prev = ni;
	}
	ecm_db_nodes = ni;

	/*
	 * Insert into the hash chain
	 */
	ni->hash_next = ecm_db_node_table[hash_index];
	if (ecm_db_node_table[hash_index]) {
		ecm_db_node_table[hash_index]->hash_prev = ni;
	}
	ecm_db_node_table[hash_index] = ni;
	ecm_db_node_table_lengths[hash_index]++;
	DEBUG_ASSERT(ecm_db_node_table_lengths[hash_index] > 0, "%p: invalid table len %d\n", ni, ecm_db_node_table_lengths[hash_index]);

	/*
	 * Set time of add
	 */
	ni->time_added = ecm_db_time;

	/*
	 * Insert node into the iface nodes list
	 */
	ni->node_prev = NULL;
	ni->node_next = ii->nodes;
	if (ii->nodes) {
		ii->nodes->node_prev = ni;
	}
	ii->nodes = ni;
	ii->node_count++;
	spin_unlock_bh(&ecm_db_lock);

	/*
	 * Throw add event to the listeners
 	 */
	DEBUG_TRACE("%p: Throw node added event\n", ni);
	li = ecm_db_listeners_get_and_ref_first();
	while (li) {
		struct ecm_db_listener_instance *lin;
		if (li->node_added) {
			li->node_added(li->arg, ni);
		}

		/*
		 * Get next listener
		 */
		lin = ecm_db_listener_get_and_ref_next(li);
		ecm_db_listener_deref(li);
		li = lin;
	}
}
EXPORT_SYMBOL(ecm_db_node_add);

/*
 * ecm_db_iface_xml_state_get_open()
 *	Get the start of XML state for an interface object
 */
static int ecm_db_iface_xml_state_get_open(struct ecm_db_iface_instance *ii, char *buf, int buf_sz)
{
	int count;
	int node_count;
	uint32_t time_added;
	uint64_t from_data_total;
	uint64_t to_data_total;
	uint64_t from_packet_total;
	uint64_t to_packet_total;
	uint64_t from_data_total_dropped;
	uint64_t to_data_total_dropped;
	uint64_t from_packet_total_dropped;
	uint64_t to_packet_total_dropped;
	int32_t interface_identifier;
	int32_t nss_interface_identifier;
	char name[IFNAMSIZ];
	int32_t mtu;
	ecm_db_iface_type_t type;

	DEBUG_CHECK_MAGIC(ii, ECM_DB_IFACE_INSTANCE_MAGIC, "%p: magic failed\n", ii);
	DEBUG_TRACE("%p: Open iface msg\n", ii);

	/*
	 * Create a small xml stats block, like:
	 * <iface blah="" ... >
	 * Extract general information from the iface for inclusion into the message
	 */
	node_count = ecm_db_iface_node_count_get(ii);
	time_added = ii->time_added;
	ecm_db_iface_data_stats_get(ii, &from_data_total, &to_data_total,
			&from_packet_total, &to_packet_total,
			&from_data_total_dropped, &to_data_total_dropped,
			&from_packet_total_dropped, &to_packet_total_dropped);
	type = ii->type;
	spin_lock_bh(&ecm_db_lock);
	strcpy(name, ii->name);
	mtu = ii->mtu;
	interface_identifier = ii->interface_identifier;
	nss_interface_identifier = ii->nss_interface_identifier;
	spin_unlock_bh(&ecm_db_lock);

	/*
	 * Prep the message
	 */
	count = snprintf(buf, buf_sz,
		"<iface type=\"%d\" name=\"%s\" nodes=\"%d\" time_added=\"%u\""
		" mtu=\"%d\" interface_identifier=\"%d\" nss_interface_identifier=\"%d\""
		" from_data_total=\"%llu\" to_data_total=\"%llu\" from_packet_total=\"%llu\" to_packet_total=\"%llu\""
		" from_data_total_dropped=\"%llu\" to_data_total_dropped=\"%llu\" from_packet_total_dropped=\"%llu\" to_packet_total_dropped=\"%llu\">\n",
		type,
		name,
		node_count,
		time_added,
		mtu,
		interface_identifier,
		nss_interface_identifier,
		from_data_total,
		to_data_total,
		from_packet_total,
		to_packet_total,
		from_data_total_dropped,
		to_data_total_dropped,
		from_packet_total_dropped,
		to_packet_total_dropped);

	if ((count <= 0) || (count >= buf_sz)) {
		return -1;
	}

	return count;
}

/*
 * ecm_db_iface_xml_state_get_close()
 *	Get the end of XML state for an interface object
 */
static int ecm_db_iface_xml_state_get_close(struct ecm_db_iface_instance *ii, char *buf, int buf_sz)
{
	int count;

	DEBUG_CHECK_MAGIC(ii, ECM_DB_IFACE_INSTANCE_MAGIC, "%p: magic failed\n", ii);
	DEBUG_TRACE("%p: Close iface msg\n", ii);

	/*
	 * Create a small xml stats block, like:
	 * </iface>
	 */

	/*
	 * Prep the message
	 */
	count = snprintf(buf, buf_sz, "</iface>\n");

	if ((count <= 0) || (count >= buf_sz)) {
		return -1;
	}

	return count;
}

/*
 * ecm_db_iface_ethernet_xml_state_get()
 * 	Return interface type specific state
 */
static int ecm_db_iface_ethernet_xml_state_get(struct ecm_db_iface_instance *ii, char *buf, int buf_sz)
{
	int count;
	int total;
	uint8_t address[ETH_ALEN];

	DEBUG_CHECK_MAGIC(ii, ECM_DB_IFACE_INSTANCE_MAGIC, "%p: magic failed\n", ii);
	spin_lock_bh(&ecm_db_lock);
	memcpy(address, ii->type_info.ethernet.address, ETH_ALEN);
	spin_unlock_bh(&ecm_db_lock);

	/*
	 * Write out opening element
	 */
	total = 0;
	count = ecm_db_iface_xml_state_get_open(ii, buf + total, buf_sz - total);
	if ((count <= 0) || (count >= (buf_sz - total))) {
		return -1;
	}
	total += count;

	/*
	 * Write out type specific data
	 */
	count = snprintf(buf + total, buf_sz - total, "<ethernet address=\"%pM\"/>\n", address);
	if ((count <= 0) || (count >= (buf_sz - total))) {
		return -1;
	}
	total += count;

	/*
	 * Write out closing element
	 */
	count = ecm_db_iface_xml_state_get_close(ii, buf + total, buf_sz - total);
	if ((count <= 0) || (count >= (buf_sz - total))) {
		return -1;
	}
	total += count;
	return total;
}

/*
 * ecm_db_iface_add_ethernet()
 *	Add a iface instance into the database
 */
void ecm_db_iface_add_ethernet(struct ecm_db_iface_instance *ii, uint8_t *address, char *name, int32_t mtu,
					int32_t interface_identifier, int32_t nss_interface_identifier,
					ecm_db_iface_final_callback_t final, void *arg)
{
	ecm_db_iface_hash_t hash_index;
	struct ecm_db_listener_instance *li;
	struct ecm_db_interface_info_ethernet *type_info;

	spin_lock_bh(&ecm_db_lock);
	DEBUG_CHECK_MAGIC(ii, ECM_DB_IFACE_INSTANCE_MAGIC, "%p: magic failed\n", ii);
	DEBUG_ASSERT(address, "%p: address null\n", ii);
	DEBUG_ASSERT((ii->nodes == NULL) && (ii->node_count == 0), "%p: nodes not null\n", ii);
	DEBUG_ASSERT(!(ii->flags & ECM_DB_IFACE_FLAGS_INSERTED), "%p: inserted\n", ii);
	DEBUG_ASSERT(name, "%p: no name given\n", ii);
	spin_unlock_bh(&ecm_db_lock);

	/*
	 * Record general info
	 */
	ii->type = ECM_DB_IFACE_TYPE_ETHERNET;
	ii->xml_state_get = ecm_db_iface_ethernet_xml_state_get;
	ii->arg = arg;
	ii->final = final;
	strcpy(ii->name, name);
	ii->mtu = mtu;
	ii->interface_identifier = interface_identifier;
	ii->nss_interface_identifier = nss_interface_identifier;

	/*
	 * Type specific info
	 */
	type_info = &ii->type_info.ethernet;
	memcpy(type_info->address, address, ETH_ALEN);

	/*
	 * Compute hash chain for insertion
	 */
	hash_index = ecm_db_iface_generate_hash_index_ethernet(address);
	ii->hash_index = hash_index;

	/*
	 * Add into the global list
	 */
	spin_lock_bh(&ecm_db_lock);
	ii->flags |= ECM_DB_IFACE_FLAGS_INSERTED;
	ii->prev = NULL;
	ii->next = ecm_db_interfaces;
	if (ecm_db_interfaces) {
		ecm_db_interfaces->prev = ii;
	}
	ecm_db_interfaces = ii;

	/*
	 * Insert into chain
	 */
	ii->hash_next = ecm_db_iface_table[hash_index];
	if (ecm_db_iface_table[hash_index]) {
		ecm_db_iface_table[hash_index]->hash_prev = ii;
	}
	ecm_db_iface_table[hash_index] = ii;
	ecm_db_iface_table_lengths[hash_index]++;
	DEBUG_ASSERT(ecm_db_iface_table_lengths[hash_index] > 0, "%p: invalid table len %d\n", ii, ecm_db_iface_table_lengths[hash_index]);

	DEBUG_INFO("%p: interface inserted at hash index %u, hash prev is %p, type: %d\n", ii, ii->hash_index, ii->hash_prev, ii->type);

	/*
	 * Set time of addition
	 */
	ii->time_added = ecm_db_time;
	spin_unlock_bh(&ecm_db_lock);

	/*
	 * Throw add event to the listeners
 	 */
	DEBUG_TRACE("%p: Throw iface added event\n", ii);
	li = ecm_db_listeners_get_and_ref_first();
	while (li) {
		struct ecm_db_listener_instance *lin;
		if (li->iface_added) {
			li->iface_added(li->arg, ii);
		}

		/*
		 * Get next listener
		 */
		lin = ecm_db_listener_get_and_ref_next(li);
		ecm_db_listener_deref(li);
		li = lin;
	}
}
EXPORT_SYMBOL(ecm_db_iface_add_ethernet);

/*
 * ecm_db_iface_lag_xml_state_get()
 * 	Return interface type specific state
 */
static int ecm_db_iface_lag_xml_state_get(struct ecm_db_iface_instance *ii, char *buf, int buf_sz)
{
	int count;
	int total;
	uint8_t address[ETH_ALEN];

	DEBUG_CHECK_MAGIC(ii, ECM_DB_IFACE_INSTANCE_MAGIC, "%p: magic failed\n", ii);
	spin_lock_bh(&ecm_db_lock);
	memcpy(address, ii->type_info.lag.address, ETH_ALEN);
	spin_unlock_bh(&ecm_db_lock);

	/*
	 * Write out opening element
	 */
	total = 0;
	count = ecm_db_iface_xml_state_get_open(ii, buf + total, buf_sz - total);
	if ((count <= 0) || (count >= (buf_sz - total))) {
		return -1;
	}
	total += count;

	/*
	 * Write out type specific data
	 */
	count = snprintf(buf + total, buf_sz - total, "<lag address=\"%pM\"/>\n", address);
	if ((count <= 0) || (count >= (buf_sz - total))) {
		return -1;
	}
	total += count;

	/*
	 * Write out closing element
	 */
	count = ecm_db_iface_xml_state_get_close(ii, buf + total, buf_sz - total);
	if ((count <= 0) || (count == (buf_sz - total))) {
		return -1;
	}
	total += count;
	return total;
}

/*
 * ecm_db_iface_add_lag()
 *	Add a iface instance into the database
 */
void ecm_db_iface_add_lag(struct ecm_db_iface_instance *ii, uint8_t *address, char *name, int32_t mtu,
					int32_t interface_identifier, int32_t nss_interface_identifier,
					ecm_db_iface_final_callback_t final, void *arg)
{
	ecm_db_iface_hash_t hash_index;
	struct ecm_db_listener_instance *li;
	struct ecm_db_interface_info_lag *type_info;

	spin_lock_bh(&ecm_db_lock);
	DEBUG_CHECK_MAGIC(ii, ECM_DB_IFACE_INSTANCE_MAGIC, "%p: magic failed\n", ii);
	DEBUG_ASSERT(address, "%p: address null\n", ii);
	DEBUG_ASSERT((ii->nodes == NULL) && (ii->node_count == 0), "%p: nodes not null\n", ii);
	DEBUG_ASSERT(!(ii->flags & ECM_DB_IFACE_FLAGS_INSERTED), "%p: inserted\n", ii);
	DEBUG_ASSERT(name, "%p: no name given\n", ii);
	spin_unlock_bh(&ecm_db_lock);

	/*
	 * Record general info
	 */
	ii->type = ECM_DB_IFACE_TYPE_LAG;
	ii->xml_state_get = ecm_db_iface_lag_xml_state_get;
	ii->arg = arg;
	ii->final = final;
	strcpy(ii->name, name);
	ii->mtu = mtu;
	ii->interface_identifier = interface_identifier;
	ii->nss_interface_identifier = nss_interface_identifier;

	/*
	 * Type specific info
	 */
	type_info = &ii->type_info.lag;
	memcpy(type_info->address, address, ETH_ALEN);

	/*
	 * Compute hash chain for insertion
	 */
	hash_index = ecm_db_iface_generate_hash_index_ethernet(address);
	ii->hash_index = hash_index;

	/*
	 * Add into the global list
	 */
	spin_lock_bh(&ecm_db_lock);
	ii->flags |= ECM_DB_IFACE_FLAGS_INSERTED;
	ii->prev = NULL;
	ii->next = ecm_db_interfaces;
	if (ecm_db_interfaces) {
		ecm_db_interfaces->prev = ii;
	}
	ecm_db_interfaces = ii;

	/*
	 * Insert into chain
	 */
	ii->hash_next = ecm_db_iface_table[hash_index];
	if (ecm_db_iface_table[hash_index]) {
		ecm_db_iface_table[hash_index]->hash_prev = ii;
	}
	ecm_db_iface_table[hash_index] = ii;
	ecm_db_iface_table_lengths[hash_index]++;
	DEBUG_ASSERT(ecm_db_iface_table_lengths[hash_index] > 0, "%p: invalid table len %d\n", ii, ecm_db_iface_table_lengths[hash_index]);

	DEBUG_INFO("%p: interface inserted at hash index %u, hash prev is %p, type: %d\n", ii, ii->hash_index, ii->hash_prev, ii->type);

	/*
	 * Set time of addition
	 */
	ii->time_added = ecm_db_time;
	spin_unlock_bh(&ecm_db_lock);

	/*
	 * Throw add event to the listeners
 	 */
	DEBUG_TRACE("%p: Throw iface added event\n", ii);
	li = ecm_db_listeners_get_and_ref_first();
	while (li) {
		struct ecm_db_listener_instance *lin;
		if (li->iface_added) {
			li->iface_added(li->arg, ii);
		}

		/*
		 * Get next listener
		 */
		lin = ecm_db_listener_get_and_ref_next(li);
		ecm_db_listener_deref(li);
		li = lin;
	}
}
EXPORT_SYMBOL(ecm_db_iface_add_lag);

/*
 * ecm_db_iface_bridge_xml_state_get()
 * 	Return interface type specific state
 */
static int ecm_db_iface_bridge_xml_state_get(struct ecm_db_iface_instance *ii, char *buf, int buf_sz)
{
	int count;
	int total;
	uint8_t address[ETH_ALEN];

	DEBUG_CHECK_MAGIC(ii, ECM_DB_IFACE_INSTANCE_MAGIC, "%p: magic failed\n", ii);
	spin_lock_bh(&ecm_db_lock);
	memcpy(address, ii->type_info.bridge.address, ETH_ALEN);
	spin_unlock_bh(&ecm_db_lock);

	/*
	 * Write out opening element
	 */
	total = 0;
	count = ecm_db_iface_xml_state_get_open(ii, buf + total, buf_sz - total);
	if ((count <= 0) || (count >= (buf_sz - total))) {
		return -1;
	}
	total += count;

	/*
	 * Write out type specific data
	 */
	count = snprintf(buf + total, buf_sz - total, "<bridge address=\"%pM\"/>\n", address);
	if ((count <= 0) || (count >= (buf_sz - total))) {
		return -1;
	}
	total += count;

	/*
	 * Write out closing element
	 */
	count = ecm_db_iface_xml_state_get_close(ii, buf + total, buf_sz - total);
	if ((count <= 0) || (count >= (buf_sz - total))) {
		return -1;
	}
	total += count;
	return total;
}

/*
 * ecm_db_iface_add_bridge()
 *	Add a iface instance into the database
 */
void ecm_db_iface_add_bridge(struct ecm_db_iface_instance *ii, uint8_t *address, char *name, int32_t mtu,
					int32_t interface_identifier, int32_t nss_interface_identifier,
					ecm_db_iface_final_callback_t final, void *arg)
{
	ecm_db_iface_hash_t hash_index;
	struct ecm_db_listener_instance *li;
	struct ecm_db_interface_info_bridge *type_info;

	spin_lock_bh(&ecm_db_lock);
	DEBUG_CHECK_MAGIC(ii, ECM_DB_IFACE_INSTANCE_MAGIC, "%p: magic failed\n", ii);
	DEBUG_ASSERT(address, "%p: address null\n", ii);
	DEBUG_ASSERT((ii->nodes == NULL) && (ii->node_count == 0), "%p: nodes not null\n", ii);
	DEBUG_ASSERT(!(ii->flags & ECM_DB_IFACE_FLAGS_INSERTED), "%p: inserted\n", ii);
	DEBUG_ASSERT(name, "%p: no name given\n", ii);
	spin_unlock_bh(&ecm_db_lock);

	/*
	 * Record general info
	 */
	ii->type = ECM_DB_IFACE_TYPE_BRIDGE;
	ii->xml_state_get = ecm_db_iface_bridge_xml_state_get;
	ii->arg = arg;
	ii->final = final;
	strcpy(ii->name, name);
	ii->mtu = mtu;
	ii->interface_identifier = interface_identifier;
	ii->nss_interface_identifier = nss_interface_identifier;

	/*
	 * Type specific info
	 */
	type_info = &ii->type_info.bridge;
	memcpy(type_info->address, address, ETH_ALEN);

	/*
	 * Compute hash chain for insertion
	 */
	hash_index = ecm_db_iface_generate_hash_index_ethernet(address);
	ii->hash_index = hash_index;

	/*
	 * Add into the global list
	 */
	spin_lock_bh(&ecm_db_lock);
	ii->flags |= ECM_DB_IFACE_FLAGS_INSERTED;
	ii->prev = NULL;
	ii->next = ecm_db_interfaces;
	if (ecm_db_interfaces) {
		ecm_db_interfaces->prev = ii;
	}
	ecm_db_interfaces = ii;

	/*
	 * Insert into chain
	 */
	ii->hash_next = ecm_db_iface_table[hash_index];
	if (ecm_db_iface_table[hash_index]) {
		ecm_db_iface_table[hash_index]->hash_prev = ii;
	}
	ecm_db_iface_table[hash_index] = ii;
	ecm_db_iface_table_lengths[hash_index]++;
	DEBUG_ASSERT(ecm_db_iface_table_lengths[hash_index] > 0, "%p: invalid table len %d\n", ii, ecm_db_iface_table_lengths[hash_index]);

	DEBUG_INFO("%p: interface inserted at hash index %u, hash prev is %p, type: %d\n", ii, ii->hash_index, ii->hash_prev, ii->type);

	/*
	 * Set time of addition
	 */
	ii->time_added = ecm_db_time;
	spin_unlock_bh(&ecm_db_lock);

	/*
	 * Throw add event to the listeners
 	 */
	DEBUG_TRACE("%p: Throw iface added event\n", ii);
	li = ecm_db_listeners_get_and_ref_first();
	while (li) {
		struct ecm_db_listener_instance *lin;
		if (li->iface_added) {
			li->iface_added(li->arg, ii);
		}

		/*
		 * Get next listener
		 */
		lin = ecm_db_listener_get_and_ref_next(li);
		ecm_db_listener_deref(li);
		li = lin;
	}
}
EXPORT_SYMBOL(ecm_db_iface_add_bridge);

/*
 * ecm_db_iface_vlan_xml_state_get()
 * 	Return interface type specific state
 */
static int ecm_db_iface_vlan_xml_state_get(struct ecm_db_iface_instance *ii, char *buf, int buf_sz)
{
	int count;
	int total;
	uint8_t address[ETH_ALEN];
	uint16_t vlan_tag;

	DEBUG_CHECK_MAGIC(ii, ECM_DB_IFACE_INSTANCE_MAGIC, "%p: magic failed\n", ii);
	spin_lock_bh(&ecm_db_lock);
	memcpy(address, ii->type_info.vlan.address, ETH_ALEN);
	vlan_tag = ii->type_info.vlan.vlan_tag;
	spin_unlock_bh(&ecm_db_lock);

	/*
	 * Write out opening element
	 */
	total = 0;
	count = ecm_db_iface_xml_state_get_open(ii, buf + total, buf_sz - total);
	if ((count <= 0) || (count >= (buf_sz - total))) {
		return -1;
	}
	total += count;

	/*
	 * Write out type specific data
	 */
	count = snprintf(buf + total, buf_sz - total, "<vlan address=\"%pM\" vlan_tag=\"%x\"/>\n", address, vlan_tag);
	if ((count <= 0) || (count >= (buf_sz - total))) {
		return -1;
	}
	total += count;

	/*
	 * Write out closing element
	 */
	count = ecm_db_iface_xml_state_get_close(ii, buf + total, buf_sz - total);
	if ((count <= 0) || (count >= (buf_sz - total))) {
		return -1;
	}
	total += count;
	return total;
}

/*
 * ecm_db_iface_add_vlan()
 *	Add a iface instance into the database
 */
void ecm_db_iface_add_vlan(struct ecm_db_iface_instance *ii, uint8_t *address, uint16_t vlan_tag, char *name, int32_t mtu,
					int32_t interface_identifier, int32_t nss_interface_identifier,
					ecm_db_iface_final_callback_t final, void *arg)
{
	ecm_db_iface_hash_t hash_index;
	struct ecm_db_listener_instance *li;
	struct ecm_db_interface_info_vlan *type_info;

	spin_lock_bh(&ecm_db_lock);
	DEBUG_CHECK_MAGIC(ii, ECM_DB_IFACE_INSTANCE_MAGIC, "%p: magic failed\n", ii);
	DEBUG_ASSERT(address, "%p: address null\n", ii);
	DEBUG_ASSERT((ii->nodes == NULL) && (ii->node_count == 0), "%p: nodes not null\n", ii);
	DEBUG_ASSERT(!(ii->flags & ECM_DB_IFACE_FLAGS_INSERTED), "%p: inserted\n", ii);
	DEBUG_ASSERT(name, "%p: no name given\n", ii);
	spin_unlock_bh(&ecm_db_lock);

	/*
	 * Record general info
	 */
	ii->type = ECM_DB_IFACE_TYPE_VLAN;
	ii->xml_state_get = ecm_db_iface_vlan_xml_state_get;
	ii->arg = arg;
	ii->final = final;
	strcpy(ii->name, name);
	ii->mtu = mtu;
	ii->interface_identifier = interface_identifier;
	ii->nss_interface_identifier = nss_interface_identifier;

	/*
	 * Type specific info
	 */
	type_info = &ii->type_info.vlan;
	type_info->vlan_tag = vlan_tag;
	memcpy(type_info->address, address, ETH_ALEN);

	/*
	 * Compute hash chain for insertion
	 */
	hash_index = ecm_db_iface_generate_hash_index_ethernet(address);
	ii->hash_index = hash_index;

	/*
	 * Add into the global list
	 */
	spin_lock_bh(&ecm_db_lock);
	ii->flags |= ECM_DB_IFACE_FLAGS_INSERTED;
	ii->prev = NULL;
	ii->next = ecm_db_interfaces;
	if (ecm_db_interfaces) {
		ecm_db_interfaces->prev = ii;
	}
	ecm_db_interfaces = ii;

	/*
	 * Insert into chain
	 */
	ii->hash_next = ecm_db_iface_table[hash_index];
	if (ecm_db_iface_table[hash_index]) {
		ecm_db_iface_table[hash_index]->hash_prev = ii;
	}
	ecm_db_iface_table[hash_index] = ii;
	ecm_db_iface_table_lengths[hash_index]++;
	DEBUG_ASSERT(ecm_db_iface_table_lengths[hash_index] > 0, "%p: invalid table len %d\n", ii, ecm_db_iface_table_lengths[hash_index]);

	DEBUG_INFO("%p: interface inserted at hash index %u, hash prev is %p, type: %d\n", ii, ii->hash_index, ii->hash_prev, ii->type);

	/*
	 * Set time of addition
	 */
	ii->time_added = ecm_db_time;
	spin_unlock_bh(&ecm_db_lock);

	/*
	 * Throw add event to the listeners
 	 */
	DEBUG_TRACE("%p: Throw iface added event\n", ii);
	li = ecm_db_listeners_get_and_ref_first();
	while (li) {
		struct ecm_db_listener_instance *lin;
		if (li->iface_added) {
			li->iface_added(li->arg, ii);
		}

		/*
		 * Get next listener
		 */
		lin = ecm_db_listener_get_and_ref_next(li);
		ecm_db_listener_deref(li);
		li = lin;
	}
}
EXPORT_SYMBOL(ecm_db_iface_add_vlan);

/*
 * ecm_db_iface_pppoe_xml_state_get()
 * 	Return interface type specific state
 */
static int ecm_db_iface_pppoe_xml_state_get(struct ecm_db_iface_instance *ii, char *buf, int buf_sz)
{
	int count;
	int total;
	uint16_t pppoe_session_id;
	uint8_t remote_mac[ETH_ALEN];

	DEBUG_CHECK_MAGIC(ii, ECM_DB_IFACE_INSTANCE_MAGIC, "%p: magic failed\n", ii);
	spin_lock_bh(&ecm_db_lock);
	pppoe_session_id = ii->type_info.pppoe.pppoe_session_id;
	memcpy(remote_mac, ii->type_info.pppoe.remote_mac, ETH_ALEN);
	spin_unlock_bh(&ecm_db_lock);

	/*
	 * Write out opening element
	 */
	total = 0;
	count = ecm_db_iface_xml_state_get_open(ii, buf + total, buf_sz - total);
	if ((count <= 0) || (count >= (buf_sz - total))) {
		return -1;
	}
	total += count;

	/*
	 * Write out type specific data
	 */
	count = snprintf(buf + total, buf_sz - total, "<pppoe pppoe_session_id=\"%u\" remote_mac=\"%pM\"/>\n",
			pppoe_session_id, remote_mac);
	if ((count <= 0) || (count >= (buf_sz - total))) {
		return -1;
	}
	total += count;

	/*
	 * Write out closing element
	 */
	count = ecm_db_iface_xml_state_get_close(ii, buf + total, buf_sz - total);
	if ((count <= 0) || (count >= (buf_sz - total))) {
		return -1;
	}
	total += count;
	return total;
}

/*
 * ecm_db_iface_add_pppoe()
 *	Add a iface instance into the database
 */
void ecm_db_iface_add_pppoe(struct ecm_db_iface_instance *ii, uint16_t pppoe_session_id, uint8_t *remote_mac,
					char *name, int32_t mtu, int32_t interface_identifier,
					int32_t nss_interface_identifier, ecm_db_iface_final_callback_t final,
					void *arg)
{
	ecm_db_iface_hash_t hash_index;
	struct ecm_db_listener_instance *li;
	struct ecm_db_interface_info_pppoe *type_info;

	spin_lock_bh(&ecm_db_lock);
	DEBUG_CHECK_MAGIC(ii, ECM_DB_IFACE_INSTANCE_MAGIC, "%p: magic failed\n", ii);
	DEBUG_ASSERT((ii->nodes == NULL) && (ii->node_count == 0), "%p: nodes not null\n", ii);
	DEBUG_ASSERT(!(ii->flags & ECM_DB_IFACE_FLAGS_INSERTED), "%p: inserted\n", ii);
	DEBUG_ASSERT(name, "%p: no name given\n", ii);
	spin_unlock_bh(&ecm_db_lock);

	/*
	 * Record general info
	 */
	ii->type = ECM_DB_IFACE_TYPE_PPPOE;
	ii->xml_state_get = ecm_db_iface_pppoe_xml_state_get;
	ii->arg = arg;
	ii->final = final;
	strcpy(ii->name, name);
	ii->mtu = mtu;
	ii->interface_identifier = interface_identifier;
	ii->nss_interface_identifier = nss_interface_identifier;

	/*
	 * Type specific info
	 */
	type_info = &ii->type_info.pppoe;
	type_info->pppoe_session_id = pppoe_session_id;
	memcpy(type_info->remote_mac, remote_mac, ETH_ALEN);

	/*
	 * Compute hash chain for insertion
	 */
	hash_index = ecm_db_iface_generate_hash_index_pppoe(pppoe_session_id);
	ii->hash_index = hash_index;

	/*
	 * Add into the global list
	 */
	spin_lock_bh(&ecm_db_lock);
	ii->flags |= ECM_DB_IFACE_FLAGS_INSERTED;
	ii->prev = NULL;
	ii->next = ecm_db_interfaces;
	if (ecm_db_interfaces) {
		ecm_db_interfaces->prev = ii;
	}
	ecm_db_interfaces = ii;

	/*
	 * Insert into chain
	 */
	ii->hash_next = ecm_db_iface_table[hash_index];
	if (ecm_db_iface_table[hash_index]) {
		ecm_db_iface_table[hash_index]->hash_prev = ii;
	}
	ecm_db_iface_table[hash_index] = ii;
	ecm_db_iface_table_lengths[hash_index]++;
	DEBUG_ASSERT(ecm_db_iface_table_lengths[hash_index] > 0, "%p: invalid table len %d\n", ii, ecm_db_iface_table_lengths[hash_index]);

	DEBUG_INFO("%p: interface inserted at hash index %u, hash prev is %p, type: %d\n", ii, ii->hash_index, ii->hash_prev, ii->type);

	/*
	 * Set time of addition
	 */
	ii->time_added = ecm_db_time;
	spin_unlock_bh(&ecm_db_lock);

	/*
	 * Throw add event to the listeners
 	 */
	DEBUG_TRACE("%p: Throw iface added event\n", ii);
	li = ecm_db_listeners_get_and_ref_first();
	while (li) {
		struct ecm_db_listener_instance *lin;
		if (li->iface_added) {
			li->iface_added(li->arg, ii);
		}

		/*
		 * Get next listener
		 */
		lin = ecm_db_listener_get_and_ref_next(li);
		ecm_db_listener_deref(li);
		li = lin;
	}
}
EXPORT_SYMBOL(ecm_db_iface_add_pppoe);

/*
 * ecm_db_iface_unknown_xml_state_get()
 * 	Return interface type specific state
 */
static int ecm_db_iface_unknown_xml_state_get(struct ecm_db_iface_instance *ii, char *buf, int buf_sz)
{
	int count;
	int total;
	uint32_t os_specific_ident;

	DEBUG_CHECK_MAGIC(ii, ECM_DB_IFACE_INSTANCE_MAGIC, "%p: magic failed\n", ii);
	spin_lock_bh(&ecm_db_lock);
	os_specific_ident = ii->type_info.unknown.os_specific_ident;
	spin_unlock_bh(&ecm_db_lock);

	/*
	 * Write out opening element
	 */
	total = 0;
	count = ecm_db_iface_xml_state_get_open(ii, buf + total, buf_sz - total);
	if ((count <= 0) || (count >= (buf_sz - total))) {
		return -1;
	}
	total += count;

	/*
	 * Write out type specific data
	 */
	count = snprintf(buf + total, buf_sz - total, "<unknown os_specific_ident=\"%u\"/>\n", os_specific_ident);
	if ((count <= 0) || (count >= (buf_sz - total))) {
		return -1;
	}
	total += count;

	/*
	 * Write out closing element
	 */
	count = ecm_db_iface_xml_state_get_close(ii, buf + total, buf_sz - total);
	if ((count <= 0) || (count >= (buf_sz - total))) {
		return -1;
	}
	total += count;
	return total;
}

/*
 * ecm_db_iface_loopback_xml_state_get()
 * 	Return interface type specific state
 */
static int ecm_db_iface_loopback_xml_state_get(struct ecm_db_iface_instance *ii, char *buf, int buf_sz)
{
	int count;
	int total;
	uint32_t os_specific_ident;

	DEBUG_CHECK_MAGIC(ii, ECM_DB_IFACE_INSTANCE_MAGIC, "%p: magic failed\n", ii);
	spin_lock_bh(&ecm_db_lock);
	os_specific_ident = ii->type_info.loopback.os_specific_ident;
	spin_unlock_bh(&ecm_db_lock);

	/*
	 * Write out opening element
	 */
	total = 0;
	count = ecm_db_iface_xml_state_get_open(ii, buf + total, buf_sz - total);
	if ((count <= 0) || (count >= (buf_sz - total))) {
		return -1;
	}
	total += count;

	/*
	 * Write out type specific data
	 */
	count = snprintf(buf + total, buf_sz - total, "<loopback os_specific_ident=\"%u\"/>\n", os_specific_ident);
	if ((count <= 0) || (count >= (buf_sz - total))) {
		return -1;
	}
	total += count;

	/*
	 * Write out closing element
	 */
	count = ecm_db_iface_xml_state_get_close(ii, buf + total, buf_sz - total);
	if ((count <= 0) || (count >= (buf_sz - total))) {
		return -1;
	}
	total += count;
	return total;
}

/*
 * ecm_db_iface_ipsec_tunnel_xml_state_get()
 * 	Return interface type specific state
 *
 * GGG TODO Output state on ipsec tunnel specific data
 */
static int ecm_db_iface_ipsec_tunnel_xml_state_get(struct ecm_db_iface_instance *ii, char *buf, int buf_sz)
{
	int count;
	int total;
	uint32_t os_specific_ident;

	DEBUG_CHECK_MAGIC(ii, ECM_DB_IFACE_INSTANCE_MAGIC, "%p: magic failed\n", ii);
	spin_lock_bh(&ecm_db_lock);
	os_specific_ident = ii->type_info.ipsec_tunnel.os_specific_ident;
	spin_unlock_bh(&ecm_db_lock);

	/*
	 * Write out opening element
	 */
	total = 0;
	count = ecm_db_iface_xml_state_get_open(ii, buf + total, buf_sz - total);
	if ((count <= 0) || (count >= (buf_sz - total))) {
		return -1;
	}
	total += count;

	/*
	 * Write out type specific data
	 */
	count = snprintf(buf + total, buf_sz - total, "<ipsec_tunnel os_specific_ident=\"%u\"/>\n", os_specific_ident);
	if ((count <= 0) || (count >= (buf_sz - total))) {
		return -1;
	}
	total += count;

	/*
	 * Write out closing element
	 */
	count = ecm_db_iface_xml_state_get_close(ii, buf + total, buf_sz - total);
	if ((count <= 0) || (count >= (buf_sz - total))) {
		return -1;
	}
	total += count;
	return total;
}

/*
 * ecm_db_iface_add_unknown()
 *	Add a iface instance into the database
 */
void ecm_db_iface_add_unknown(struct ecm_db_iface_instance *ii, uint32_t os_specific_ident, char *name, int32_t mtu,
					int32_t interface_identifier, int32_t nss_interface_identifier,
					ecm_db_iface_final_callback_t final, void *arg)
{
	ecm_db_iface_hash_t hash_index;
	struct ecm_db_listener_instance *li;
	struct ecm_db_interface_info_unknown *type_info;

	spin_lock_bh(&ecm_db_lock);
	DEBUG_CHECK_MAGIC(ii, ECM_DB_IFACE_INSTANCE_MAGIC, "%p: magic failed\n", ii);
	DEBUG_ASSERT((ii->nodes == NULL) && (ii->node_count == 0), "%p: nodes not null\n", ii);
	DEBUG_ASSERT(!(ii->flags & ECM_DB_IFACE_FLAGS_INSERTED), "%p: inserted\n", ii);
	DEBUG_ASSERT(name, "%p: no name given\n", ii);
	spin_unlock_bh(&ecm_db_lock);

	/*
	 * Record general info
	 */
	ii->type = ECM_DB_IFACE_TYPE_UNKNOWN;
	ii->xml_state_get = ecm_db_iface_unknown_xml_state_get;
	ii->arg = arg;
	ii->final = final;
	strcpy(ii->name, name);
	ii->mtu = mtu;
	ii->interface_identifier = interface_identifier;
	ii->nss_interface_identifier = nss_interface_identifier;

	/*
	 * Type specific info
	 */
	type_info = &ii->type_info.unknown;
	type_info->os_specific_ident = os_specific_ident;

	/*
	 * Compute hash chain for insertion
	 */
	hash_index = ecm_db_iface_generate_hash_index_unknown(os_specific_ident);
	ii->hash_index = hash_index;

	/*
	 * Add into the global list
	 */
	spin_lock_bh(&ecm_db_lock);
	ii->flags |= ECM_DB_IFACE_FLAGS_INSERTED;
	ii->prev = NULL;
	ii->next = ecm_db_interfaces;
	if (ecm_db_interfaces) {
		ecm_db_interfaces->prev = ii;
	}
	ecm_db_interfaces = ii;

	/*
	 * Insert into chain
	 */
	ii->hash_next = ecm_db_iface_table[hash_index];
	if (ecm_db_iface_table[hash_index]) {
		ecm_db_iface_table[hash_index]->hash_prev = ii;
	}
	ecm_db_iface_table[hash_index] = ii;
	ecm_db_iface_table_lengths[hash_index]++;
	DEBUG_ASSERT(ecm_db_iface_table_lengths[hash_index] > 0, "%p: invalid table len %d\n", ii, ecm_db_iface_table_lengths[hash_index]);

	DEBUG_INFO("%p: interface inserted at hash index %u, hash prev is %p, type: %d\n", ii, ii->hash_index, ii->hash_prev, ii->type);

	/*
	 * Set time of addition
	 */
	ii->time_added = ecm_db_time;
	spin_unlock_bh(&ecm_db_lock);

	/*
	 * Throw add event to the listeners
 	 */
	DEBUG_TRACE("%p: Throw iface added event\n", ii);
	li = ecm_db_listeners_get_and_ref_first();
	while (li) {
		struct ecm_db_listener_instance *lin;
		if (li->iface_added) {
			li->iface_added(li->arg, ii);
		}

		/*
		 * Get next listener
		 */
		lin = ecm_db_listener_get_and_ref_next(li);
		ecm_db_listener_deref(li);
		li = lin;
	}
}
EXPORT_SYMBOL(ecm_db_iface_add_unknown);

/*
 * ecm_db_iface_add_loopback()
 *	Add a iface instance into the database
 */
void ecm_db_iface_add_loopback(struct ecm_db_iface_instance *ii, uint32_t os_specific_ident, char *name, int32_t mtu,
					int32_t interface_identifier, int32_t nss_interface_identifier,
					ecm_db_iface_final_callback_t final, void *arg)
{
	ecm_db_iface_hash_t hash_index;
	struct ecm_db_listener_instance *li;
	struct ecm_db_interface_info_loopback *type_info;

	spin_lock_bh(&ecm_db_lock);
	DEBUG_CHECK_MAGIC(ii, ECM_DB_IFACE_INSTANCE_MAGIC, "%p: magic failed\n", ii);
	DEBUG_ASSERT((ii->nodes == NULL) && (ii->node_count == 0), "%p: nodes not null\n", ii);
	DEBUG_ASSERT(!(ii->flags & ECM_DB_IFACE_FLAGS_INSERTED), "%p: inserted\n", ii);
	DEBUG_ASSERT(name, "%p: no name given\n", ii);
	spin_unlock_bh(&ecm_db_lock);

	/*
	 * Record general info
	 */
	ii->type = ECM_DB_IFACE_TYPE_LOOPBACK;
	ii->xml_state_get = ecm_db_iface_loopback_xml_state_get;
	ii->arg = arg;
	ii->final = final;
	strcpy(ii->name, name);
	ii->mtu = mtu;
	ii->interface_identifier = interface_identifier;
	ii->nss_interface_identifier = nss_interface_identifier;

	/*
	 * Type specific info
	 */
	type_info = &ii->type_info.loopback;
	type_info->os_specific_ident = os_specific_ident;

	/*
	 * Compute hash chain for insertion
	 */
	hash_index = ecm_db_iface_generate_hash_index_loopback(os_specific_ident);
	ii->hash_index = hash_index;

	/*
	 * Add into the global list
	 */
	spin_lock_bh(&ecm_db_lock);
	ii->flags |= ECM_DB_IFACE_FLAGS_INSERTED;
	ii->prev = NULL;
	ii->next = ecm_db_interfaces;
	if (ecm_db_interfaces) {
		ecm_db_interfaces->prev = ii;
	}
	ecm_db_interfaces = ii;

	/*
	 * Insert into chain
	 */
	ii->hash_next = ecm_db_iface_table[hash_index];
	if (ecm_db_iface_table[hash_index]) {
		ecm_db_iface_table[hash_index]->hash_prev = ii;
	}
	ecm_db_iface_table[hash_index] = ii;
	ecm_db_iface_table_lengths[hash_index]++;
	DEBUG_ASSERT(ecm_db_iface_table_lengths[hash_index] > 0, "%p: invalid table len %d\n", ii, ecm_db_iface_table_lengths[hash_index]);

	DEBUG_INFO("%p: interface inserted at hash index %u, hash prev is %p, type: %d\n", ii, ii->hash_index, ii->hash_prev, ii->type);

	/*
	 * Set time of addition
	 */
	ii->time_added = ecm_db_time;
	spin_unlock_bh(&ecm_db_lock);

	/*
	 * Throw add event to the listeners
 	 */
	DEBUG_TRACE("%p: Throw iface added event\n", ii);
	li = ecm_db_listeners_get_and_ref_first();
	while (li) {
		struct ecm_db_listener_instance *lin;
		if (li->iface_added) {
			li->iface_added(li->arg, ii);
		}

		/*
		 * Get next listener
		 */
		lin = ecm_db_listener_get_and_ref_next(li);
		ecm_db_listener_deref(li);
		li = lin;
	}
}
EXPORT_SYMBOL(ecm_db_iface_add_loopback);

/*
 * ecm_db_iface_add_sit()
 *	Add a iface instance into the database
 */
void ecm_db_iface_add_sit(struct ecm_db_iface_instance *ii, struct ecm_db_interface_info_sit *type_info, char *name, int32_t mtu,
					int32_t interface_identifier, int32_t nss_interface_identifier,
					ecm_db_iface_final_callback_t final, void *arg)
{
	ecm_db_iface_hash_t hash_index;
	struct ecm_db_listener_instance *li;

	spin_lock_bh(&ecm_db_lock);
	DEBUG_CHECK_MAGIC(ii, ECM_DB_IFACE_INSTANCE_MAGIC, "%p: magic failed\n", ii);
	DEBUG_ASSERT((ii->nodes == NULL) && (ii->node_count == 0), "%p: nodes not null\n", ii);
	DEBUG_ASSERT(!(ii->flags & ECM_DB_IFACE_FLAGS_INSERTED), "%p: inserted\n", ii);
	DEBUG_ASSERT(name, "%p: no name given\n", ii);
	spin_unlock_bh(&ecm_db_lock);

	/*
	 * Record general info
	 */
	ii->type = ECM_DB_IFACE_TYPE_SIT;
	ii->xml_state_get = ecm_db_iface_loopback_xml_state_get;
	ii->arg = arg;
	ii->final = final;
	strcpy(ii->name, name);
	ii->mtu = mtu;
	ii->interface_identifier = interface_identifier;
	ii->nss_interface_identifier = nss_interface_identifier;

	/*
	 * Type specific info to be copied
	 */
	ii->type_info.sit = *type_info;

	/*
	 * Compute hash chain for insertion
	 */
	hash_index = ecm_db_iface_generate_hash_index_sit(type_info->saddr, type_info->daddr);
	ii->hash_index = hash_index;

	/*
	 * Add into the global list
	 */
	spin_lock_bh(&ecm_db_lock);
	ii->flags |= ECM_DB_IFACE_FLAGS_INSERTED;
	ii->prev = NULL;
	ii->next = ecm_db_interfaces;
	if (ecm_db_interfaces) {
		ecm_db_interfaces->prev = ii;
	}
	ecm_db_interfaces = ii;

	/*
	 * Insert into chain
	 */
	ii->hash_next = ecm_db_iface_table[hash_index];
	if (ecm_db_iface_table[hash_index]) {
		ecm_db_iface_table[hash_index]->hash_prev = ii;
	}
	ecm_db_iface_table[hash_index] = ii;
	ecm_db_iface_table_lengths[hash_index]++;
	DEBUG_ASSERT(ecm_db_iface_table_lengths[hash_index] > 0, "%p: invalid table len %d\n", ii, ecm_db_iface_table_lengths[hash_index]);

	DEBUG_INFO("%p: interface inserted at hash index %u, hash prev is %p, type: %d\n", ii, ii->hash_index, ii->hash_prev, ii->type);

	/*
	 * Set time of addition
	 */
	ii->time_added = ecm_db_time;
	spin_unlock_bh(&ecm_db_lock);

	/*
	 * Throw add event to the listeners
 	 */
	DEBUG_TRACE("%p: Throw iface added event\n", ii);
	li = ecm_db_listeners_get_and_ref_first();
	while (li) {
		struct ecm_db_listener_instance *lin;
		if (li->iface_added) {
			li->iface_added(li->arg, ii);
		}

		/*
		 * Get next listener
		 */
		lin = ecm_db_listener_get_and_ref_next(li);
		ecm_db_listener_deref(li);
		li = lin;
	}
}
EXPORT_SYMBOL(ecm_db_iface_add_sit);

/*
 * ecm_db_iface_add_tunipip6()
 *	Add a iface instance into the database
 */
void ecm_db_iface_add_tunipip6(struct ecm_db_iface_instance *ii, struct ecm_db_interface_info_tunipip6 *type_info, char *name, int32_t mtu,
					int32_t interface_identifier, int32_t nss_interface_identifier,
					ecm_db_iface_final_callback_t final, void *arg)
{
	ecm_db_iface_hash_t hash_index;
	struct ecm_db_listener_instance *li;

	spin_lock_bh(&ecm_db_lock);
	DEBUG_CHECK_MAGIC(ii, ECM_DB_IFACE_INSTANCE_MAGIC, "%p: magic failed\n", ii);
	DEBUG_ASSERT((ii->nodes == NULL) && (ii->node_count == 0), "%p: nodes not null\n", ii);
	DEBUG_ASSERT(!(ii->flags & ECM_DB_IFACE_FLAGS_INSERTED), "%p: inserted\n", ii);
	DEBUG_ASSERT(name, "%p: no name given\n", ii);
	spin_unlock_bh(&ecm_db_lock);

	/*
	 * Record general info
	 */
	ii->type = ECM_DB_IFACE_TYPE_TUNIPIP6;
	ii->xml_state_get = ecm_db_iface_loopback_xml_state_get;
	ii->arg = arg;
	ii->final = final;
	strcpy(ii->name, name);
	ii->mtu = mtu;
	ii->interface_identifier = interface_identifier;
	ii->nss_interface_identifier = nss_interface_identifier;

	/*
	 * Type specific info to be copied
	 */
	ii->type_info.tunipip6 = *type_info;

	/*
	 * Compute hash chain for insertion
	 */
	hash_index = ecm_db_iface_generate_hash_index_tunipip6(type_info->saddr, type_info->daddr);
	ii->hash_index = hash_index;

	/*
	 * Add into the global list
	 */
	spin_lock_bh(&ecm_db_lock);
	ii->flags |= ECM_DB_IFACE_FLAGS_INSERTED;
	ii->prev = NULL;
	ii->next = ecm_db_interfaces;
	if (ecm_db_interfaces) {
		ecm_db_interfaces->prev = ii;
	}
	ecm_db_interfaces = ii;

	/*
	 * Insert into chain
	 */
	ii->hash_next = ecm_db_iface_table[hash_index];
	if (ecm_db_iface_table[hash_index]) {
		ecm_db_iface_table[hash_index]->hash_prev = ii;
	}
	ecm_db_iface_table[hash_index] = ii;
	ecm_db_iface_table_lengths[hash_index]++;
	DEBUG_ASSERT(ecm_db_iface_table_lengths[hash_index] > 0, "%p: invalid table len %d\n", ii, ecm_db_iface_table_lengths[hash_index]);

	DEBUG_INFO("%p: interface inserted at hash index %u, hash prev is %p, type: %d\n", ii, ii->hash_index, ii->hash_prev, ii->type);

	/*
	 * Set time of addition
	 */
	ii->time_added = ecm_db_time;
	spin_unlock_bh(&ecm_db_lock);

	/*
	 * Throw add event to the listeners
 	 */
	DEBUG_TRACE("%p: Throw iface added event\n", ii);
	li = ecm_db_listeners_get_and_ref_first();
	while (li) {
		struct ecm_db_listener_instance *lin;
		if (li->iface_added) {
			li->iface_added(li->arg, ii);
		}

		/*
		 * Get next listener
		 */
		lin = ecm_db_listener_get_and_ref_next(li);
		ecm_db_listener_deref(li);
		li = lin;
	}
}
EXPORT_SYMBOL(ecm_db_iface_add_tunipip6);

/*
 * ecm_db_iface_add_ipsec_tunnel()
 *	Add a iface instance into the database
 *
 * GGG TODO This needs to take ipsec tunnel endpoint information etc. something very appropriate for ipsec tunnels, anyhow.
 */
void ecm_db_iface_add_ipsec_tunnel(struct ecm_db_iface_instance *ii, uint32_t os_specific_ident, char *name, int32_t mtu,
					int32_t interface_identifier, int32_t nss_interface_identifier,
					ecm_db_iface_final_callback_t final, void *arg)
{
	ecm_db_iface_hash_t hash_index;
	struct ecm_db_listener_instance *li;
	struct ecm_db_interface_info_ipsec_tunnel *type_info;

	spin_lock_bh(&ecm_db_lock);
	DEBUG_CHECK_MAGIC(ii, ECM_DB_IFACE_INSTANCE_MAGIC, "%p: magic failed\n", ii);
	DEBUG_ASSERT((ii->nodes == NULL) && (ii->node_count == 0), "%p: nodes not null\n", ii);
	DEBUG_ASSERT(!(ii->flags & ECM_DB_IFACE_FLAGS_INSERTED), "%p: inserted\n", ii);
	DEBUG_ASSERT(name, "%p: no name given\n", ii);
	spin_unlock_bh(&ecm_db_lock);

	/*
	 * Record general info
	 */
	ii->type = ECM_DB_IFACE_TYPE_LOOPBACK;
	ii->xml_state_get = ecm_db_iface_ipsec_tunnel_xml_state_get;
	ii->arg = arg;
	ii->final = final;
	strcpy(ii->name, name);
	ii->mtu = mtu;
	ii->interface_identifier = interface_identifier;
	ii->nss_interface_identifier = nss_interface_identifier;

	/*
	 * Type specific info
	 */
	type_info = &ii->type_info.ipsec_tunnel;
	type_info->os_specific_ident = os_specific_ident;

	/*
	 * Compute hash chain for insertion
	 */
	hash_index = ecm_db_iface_generate_hash_index_ipsec_tunnel(os_specific_ident);
	ii->hash_index = hash_index;

	/*
	 * Add into the global list
	 */
	spin_lock_bh(&ecm_db_lock);
	ii->flags |= ECM_DB_IFACE_FLAGS_INSERTED;
	ii->prev = NULL;
	ii->next = ecm_db_interfaces;
	if (ecm_db_interfaces) {
		ecm_db_interfaces->prev = ii;
	}
	ecm_db_interfaces = ii;

	/*
	 * Insert into chain
	 */
	ii->hash_next = ecm_db_iface_table[hash_index];
	if (ecm_db_iface_table[hash_index]) {
		ecm_db_iface_table[hash_index]->hash_prev = ii;
	}
	ecm_db_iface_table[hash_index] = ii;
	ecm_db_iface_table_lengths[hash_index]++;
	DEBUG_ASSERT(ecm_db_iface_table_lengths[hash_index] > 0, "%p: invalid table len %d\n", ii, ecm_db_iface_table_lengths[hash_index]);

	DEBUG_INFO("%p: interface inserted at hash index %u, hash prev is %p, type: %d\n", ii, ii->hash_index, ii->hash_prev, ii->type);

	/*
	 * Set time of addition
	 */
	ii->time_added = ecm_db_time;
	spin_unlock_bh(&ecm_db_lock);

	/*
	 * Throw add event to the listeners
 	 */
	DEBUG_TRACE("%p: Throw iface added event\n", ii);
	li = ecm_db_listeners_get_and_ref_first();
	while (li) {
		struct ecm_db_listener_instance *lin;
		if (li->iface_added) {
			li->iface_added(li->arg, ii);
		}

		/*
		 * Get next listener
		 */
		lin = ecm_db_listener_get_and_ref_next(li);
		ecm_db_listener_deref(li);
		li = lin;
	}
}
EXPORT_SYMBOL(ecm_db_iface_add_ipsec_tunnel);

/*
 * ecm_db_listener_add()
 *	Add a listener instance into the database.
 */
void ecm_db_listener_add(struct ecm_db_listener_instance *li,
							ecm_db_iface_listener_added_callback_t iface_added,
							ecm_db_iface_listener_removed_callback_t iface_removed,
							ecm_db_node_listener_added_callback_t node_added,
							ecm_db_node_listener_removed_callback_t node_removed,
							ecm_db_host_listener_added_callback_t host_added,
							ecm_db_host_listener_removed_callback_t host_removed,
							ecm_db_mapping_listener_added_callback_t mapping_added,
							ecm_db_mapping_listener_removed_callback_t mapping_removed,
							ecm_db_connection_listener_added_callback_t connection_added,
							ecm_db_connection_listener_removed_callback_t connection_removed,
							ecm_db_listener_final_callback_t final,
							void *arg)
{
	spin_lock_bh(&ecm_db_lock);
	DEBUG_CHECK_MAGIC(li, ECM_DB_LISTENER_INSTANCE_MAGIC, "%p: magic failed\n", li);
	DEBUG_ASSERT(!(li->flags & ECM_DB_LISTENER_FLAGS_INSERTED), "%p: inserted\n", li);
	spin_unlock_bh(&ecm_db_lock);

	li->arg = arg;
	li->final = final;
	li->iface_added = iface_added;
	li->iface_removed = iface_removed;
	li->node_added = node_added;
	li->node_removed = node_removed;
	li->host_added = host_added;
	li->host_removed = host_removed;
	li->mapping_added = mapping_added;
	li->mapping_removed = mapping_removed;
	li->connection_added = connection_added;
	li->connection_removed = connection_removed;

	/*
	 * Add instance into listener list
	 */
	spin_lock_bh(&ecm_db_lock);
	li->flags |= ECM_DB_LISTENER_FLAGS_INSERTED;
	li->next = ecm_db_listeners;
	ecm_db_listeners = li;
	spin_unlock_bh(&ecm_db_lock);
}
EXPORT_SYMBOL(ecm_db_listener_add);

/*
 * ecm_db_connection_alloc()
 *	Allocate a connection instance
 */
struct ecm_db_connection_instance *ecm_db_connection_alloc(void)
{
	struct ecm_db_connection_instance *ci;

	/*
	 * Allocate the connection
	 */
	ci = (struct ecm_db_connection_instance *)kzalloc(sizeof(struct ecm_db_connection_instance), GFP_ATOMIC | __GFP_NOWARN);
	if (!ci) {
		DEBUG_WARN("Connection alloc failed\n");
		return NULL;
	}

	/*
	 * Initialise the defunct timer entry
	 */
	ecm_db_timer_group_entry_init(&ci->defunct_timer, ecm_db_connection_defunct_callback, ci);

	/*
	 * Refs is 1 for the creator of the connection
	 */
	ci->refs = 1;
	DEBUG_SET_MAGIC(ci, ECM_DB_CONNECTION_INSTANCE_MAGIC);

	/*
	 * If the master thread is terminating then we cannot create new instances
	 */
	spin_lock_bh(&ecm_db_lock);
	if (ecm_db_terminate_pending) {
		spin_unlock_bh(&ecm_db_lock);
		DEBUG_WARN("Thread terminating\n");
		kfree(ci);
		return NULL;
	}

	/*
	 * Assign runtime unique serial
	 */
	ci->serial = ecm_db_connection_serial++;

	/*
	 * Initialise the interfaces from/to lists.
	 * Interfaces are added from end of array.
	 */
	ci->from_interface_first = ECM_DB_IFACE_HEIRARCHY_MAX;
	ci->to_interface_first = ECM_DB_IFACE_HEIRARCHY_MAX;
	ci->from_nat_interface_first = ECM_DB_IFACE_HEIRARCHY_MAX;
	ci->to_nat_interface_first = ECM_DB_IFACE_HEIRARCHY_MAX;

	/*
	 * Thread must remain active for this object
	 */
	ecm_db_thread_refs++;
	DEBUG_ASSERT(ecm_db_thread_refs > 0, "Thread ref count wrap %d\n", ecm_db_thread_refs);

	ecm_db_connection_count++;
	DEBUG_ASSERT(ecm_db_connection_count > 0, "%p: connection count wrap\n", ci);
	spin_unlock_bh(&ecm_db_lock);

	DEBUG_TRACE("Connection created %p\n", ci);
	return ci;
}
EXPORT_SYMBOL(ecm_db_connection_alloc);

/*
 * ecm_db_mapping_alloc()
 *	Allocate a mapping instance
 */
struct ecm_db_mapping_instance *ecm_db_mapping_alloc(void)
{
	struct ecm_db_mapping_instance *mi;

	mi = (struct ecm_db_mapping_instance *)kzalloc(sizeof(struct ecm_db_mapping_instance), GFP_ATOMIC | __GFP_NOWARN);
	if (!mi) {
		DEBUG_WARN("Alloc failed\n");
		return NULL;
	}

	mi->refs = 1;
	DEBUG_SET_MAGIC(mi, ECM_DB_MAPPING_INSTANCE_MAGIC);

	/*
	 * Alloc operation must be atomic to ensure thread and module can be held
	 */
	spin_lock_bh(&ecm_db_lock);

	/*
	 * If the event processing thread is terminating then we cannot create new instances
	 */
	if (ecm_db_terminate_pending) {
		spin_unlock_bh(&ecm_db_lock);
		DEBUG_WARN("Thread terminating\n");
		kfree(mi);
		return NULL;
	}

	/*
	 * Thread must remain active for this object
	 */
	ecm_db_thread_refs++;
	DEBUG_ASSERT(ecm_db_thread_refs > 0, "Thread ref count wrap %d\n", ecm_db_thread_refs);

	ecm_db_mapping_count++;
	spin_unlock_bh(&ecm_db_lock);

	DEBUG_TRACE("Mapping created %p\n", mi);
	return mi;
}
EXPORT_SYMBOL(ecm_db_mapping_alloc);


/*
 * ecm_db_host_alloc()
 *	Allocate a host instance
 */
struct ecm_db_host_instance *ecm_db_host_alloc(void)
{
	struct ecm_db_host_instance *hi;
	hi = (struct ecm_db_host_instance *)kzalloc(sizeof(struct ecm_db_host_instance), GFP_ATOMIC | __GFP_NOWARN);
	if (!hi) {
		DEBUG_WARN("Alloc failed\n");
		return NULL;
	}

	hi->refs = 1;
	DEBUG_SET_MAGIC(hi, ECM_DB_HOST_INSTANCE_MAGIC);

	/*
	 * Alloc operation must be atomic to ensure thread and module can be held
	 */
	spin_lock_bh(&ecm_db_lock);

	/*
	 * If the event processing thread is terminating then we cannot create new instances
	 */
	if (ecm_db_terminate_pending) {
		spin_unlock_bh(&ecm_db_lock);
		DEBUG_WARN("Thread terminating\n");
		kfree(hi);
		return NULL;
	}

	/*
	 * Thread must remain active for this object
	 */
	ecm_db_thread_refs++;
	DEBUG_ASSERT(ecm_db_thread_refs > 0, "Thread ref count wrap %d\n", ecm_db_thread_refs);

	ecm_db_host_count++;
	spin_unlock_bh(&ecm_db_lock);

	DEBUG_TRACE("Host created %p\n", hi);
	return hi;
}
EXPORT_SYMBOL(ecm_db_host_alloc);

/*
 * ecm_db_node_alloc()
 *	Allocate a node instance
 */
struct ecm_db_node_instance *ecm_db_node_alloc(void)
{
	struct ecm_db_node_instance *ni;

	ni = (struct ecm_db_node_instance *)kzalloc(sizeof(struct ecm_db_node_instance), GFP_ATOMIC | __GFP_NOWARN);
	if (!ni) {
		DEBUG_WARN("Alloc failed\n");
		return NULL;
	}

	ni->refs = 1;
	DEBUG_SET_MAGIC(ni, ECM_DB_NODE_INSTANCE_MAGIC);

	/*
	 * Alloc operation must be atomic to ensure thread and module can be held
	 */
	spin_lock_bh(&ecm_db_lock);

	/*
	 * If the event processing thread is terminating then we cannot create new instances
	 */
	if (ecm_db_terminate_pending) {
		spin_unlock_bh(&ecm_db_lock);
		DEBUG_WARN("Thread terminating\n");
		kfree(ni);
		return NULL;
	}

	/*
	 * Thread must remain active for this object
	 */
	ecm_db_thread_refs++;
	DEBUG_ASSERT(ecm_db_thread_refs > 0, "Thread ref count wrap %d\n", ecm_db_thread_refs);

	ecm_db_node_count++;
	spin_unlock_bh(&ecm_db_lock);

	DEBUG_TRACE("Node created %p\n", ni);
	return ni;
}
EXPORT_SYMBOL(ecm_db_node_alloc);

/*
 * ecm_db_iface_alloc()
 *	Allocate a iface instance
 */
struct ecm_db_iface_instance *ecm_db_iface_alloc(void)
{
	struct ecm_db_iface_instance *ii;

	ii = (struct ecm_db_iface_instance *)kzalloc(sizeof(struct ecm_db_iface_instance), GFP_ATOMIC | __GFP_NOWARN);
	if (!ii) {
		DEBUG_WARN("Alloc failed\n");
		return NULL;
	}

	ii->refs = 1;
	DEBUG_SET_MAGIC(ii, ECM_DB_IFACE_INSTANCE_MAGIC);

	/*
	 * Alloc operation must be atomic to ensure thread and module can be held
	 */
	spin_lock_bh(&ecm_db_lock);

	/*
	 * If the event processing thread is terminating then we cannot create new instances
	 */
	if (ecm_db_terminate_pending) {
		spin_unlock_bh(&ecm_db_lock);
		DEBUG_WARN("Thread terminating\n");
		kfree(ii);
		return NULL;
	}

	/*
	 * Thread must remain active for this object
	 */
	ecm_db_thread_refs++;
	DEBUG_ASSERT(ecm_db_thread_refs > 0, "Thread ref count wrap %d\n", ecm_db_thread_refs);

	ecm_db_iface_count++;
	spin_unlock_bh(&ecm_db_lock);

	DEBUG_TRACE("iface created %p\n", ii);
	return ii;
}
EXPORT_SYMBOL(ecm_db_iface_alloc);

/*
 * ecm_db_listener_alloc()
 *	Allocate a listener instance
 */
struct ecm_db_listener_instance *ecm_db_listener_alloc(void)
{
	struct ecm_db_listener_instance *li;

	li = (struct ecm_db_listener_instance *)kzalloc(sizeof(struct ecm_db_listener_instance), GFP_ATOMIC | __GFP_NOWARN);
	if (!li) {
		DEBUG_WARN("Alloc failed\n");
		return NULL;
	}

	li->refs = 1;
	DEBUG_SET_MAGIC(li, ECM_DB_LISTENER_INSTANCE_MAGIC);

	/*
	 * Alloc operation must be atomic to ensure thread and module can be held
	 */
	spin_lock_bh(&ecm_db_lock);

	/*
	 * If the event processing thread is terminating then we cannot create new instances
	 */
	if (ecm_db_terminate_pending) {
		spin_unlock_bh(&ecm_db_lock);
		DEBUG_WARN("Thread terminating\n");
		kfree(li);
		return NULL;
	}

	/*
	 * Thread must remain active for this object
	 */
	ecm_db_thread_refs++;
	DEBUG_ASSERT(ecm_db_thread_refs > 0, "Thread ref count wrap %d\n", ecm_db_thread_refs);

	ecm_db_listeners_count++;
	DEBUG_ASSERT(ecm_db_listeners_count > 0, "%p: listener count wrap\n", li);

	DEBUG_TRACE("Listener created %p\n", li);
	spin_unlock_bh(&ecm_db_lock);
	return li;
}
EXPORT_SYMBOL(ecm_db_listener_alloc);

/*
 * ecm_db_time_get()
 *	Return database time, in seconds since the database started.
 */
uint32_t ecm_db_time_get(void)
{
	uint32_t time_now;
	spin_lock_bh(&ecm_db_lock);
	time_now = ecm_db_time;
	spin_unlock_bh(&ecm_db_lock);
	return time_now;
}
EXPORT_SYMBOL(ecm_db_time_get);

/*
 * ecm_db_get_terminate()
 */
static ssize_t ecm_db_get_terminate(struct sys_device *dev,
				  struct sysdev_attribute *attr,
				  char *buf)
{
	unsigned int n;
	ssize_t count;

	spin_lock_bh(&ecm_db_lock);
	n = ecm_db_terminate_pending;
	spin_unlock_bh(&ecm_db_lock);
	count = snprintf(buf, (ssize_t)PAGE_SIZE, "%u\n", n);
	return count;
}

/*
 * ecm_db_set_terminate()
 *	Writing anything to this 'file' will cause the default classifier to terminate
 */
static ssize_t ecm_db_set_terminate(struct sys_device *dev,
				  struct sysdev_attribute *attr,
				  const char *buf, size_t count)
{
	DEBUG_INFO("Terminate\n");
	spin_lock_bh(&ecm_db_lock);

	/*
	 * If user has already requested termination then we don't do it again
	 */
	if (ecm_db_terminate_pending) {
		spin_unlock_bh(&ecm_db_lock);
		return 0;
	}

	ecm_db_terminate_pending = true;
	ecm_db_thread_refs--;
	DEBUG_ASSERT(ecm_db_thread_refs >= 0, "Terminate wrap: %d\n", ecm_db_thread_refs);
	wake_up_process(ecm_db_thread);
	spin_unlock_bh(&ecm_db_lock);

	return count;
}

/*
 * ecm_db_get_state_dev_major()
 */
static ssize_t ecm_db_get_state_dev_major(struct sys_device *dev,
				  struct sysdev_attribute *attr,
				  char *buf)
{
	ssize_t count;
	int major;

	spin_lock_bh(&ecm_db_lock);
	major = ecm_db_dev_major_id;
	spin_unlock_bh(&ecm_db_lock);

	count = snprintf(buf, (ssize_t)PAGE_SIZE, "%d\n", major);

	return count;
}

/*
 * ecm_db_get_connection_count()
 */
static ssize_t ecm_db_get_connection_count(struct sys_device *dev,
				  struct sysdev_attribute *attr,
				  char *buf)
{
	ssize_t count;
	int num;

	/*
	 * Operate under our locks
	 */
	spin_lock_bh(&ecm_db_lock);
	num = ecm_db_connection_count;
	spin_unlock_bh(&ecm_db_lock);

	count = snprintf(buf, (ssize_t)PAGE_SIZE, "%d\n", num);
	return count;
}

/*
 * ecm_db_get_host_count()
 */
static ssize_t ecm_db_get_host_count(struct sys_device *dev,
				  struct sysdev_attribute *attr,
				  char *buf)
{
	ssize_t count;
	int num;

	/*
	 * Operate under our locks
	 */
	spin_lock_bh(&ecm_db_lock);
	num = ecm_db_host_count;
	spin_unlock_bh(&ecm_db_lock);

	count = snprintf(buf, (ssize_t)PAGE_SIZE, "%d\n", num);
	return count;
}

/*
 * ecm_db_get_mapping_count()
 */
static ssize_t ecm_db_get_mapping_count(struct sys_device *dev,
				  struct sysdev_attribute *attr,
				  char *buf)
{
	ssize_t count;
	int num;

	/*
	 * Operate under our locks
	 */
	spin_lock_bh(&ecm_db_lock);
	num = ecm_db_mapping_count;
	spin_unlock_bh(&ecm_db_lock);

	count = snprintf(buf, (ssize_t)PAGE_SIZE, "%d\n", num);
	return count;
}

/*
 * ecm_db_get_node_count()
 */
static ssize_t ecm_db_get_node_count(struct sys_device *dev,
				  struct sysdev_attribute *attr,
				  char *buf)
{
	ssize_t count;
	int num;

	/*
	 * Operate under our locks
	 */
	spin_lock_bh(&ecm_db_lock);
	num = ecm_db_node_count;
	spin_unlock_bh(&ecm_db_lock);

	count = snprintf(buf, (ssize_t)PAGE_SIZE, "%d\n", num);
	return count;
}

/*
 * ecm_db_get_iface_count()
 */
static ssize_t ecm_db_get_iface_count(struct sys_device *dev,
				  struct sysdev_attribute *attr,
				  char *buf)
{
	ssize_t count;
	int num;

	/*
	 * Operate under our locks
	 */
	spin_lock_bh(&ecm_db_lock);
	num = ecm_db_iface_count;
	spin_unlock_bh(&ecm_db_lock);

	count = snprintf(buf, (ssize_t)PAGE_SIZE, "%d\n", num);
	return count;
}

/*
 * ecm_db_get_defunct_all()
 *	Reading this file returns the accumulated total of all objects
 */
static ssize_t ecm_db_get_defunct_all(struct sys_device *dev,
				  struct sysdev_attribute *attr,
				  char *buf)
{
	ssize_t count;
	int num;

	/*
	 * Operate under our locks
	 */
	spin_lock_bh(&ecm_db_lock);
	num = ecm_db_connection_count + ecm_db_mapping_count + ecm_db_host_count
			+ ecm_db_node_count + ecm_db_iface_count;
	spin_unlock_bh(&ecm_db_lock);

	count = snprintf(buf, (ssize_t)PAGE_SIZE, "%d\n", num);
	return count;
}

/*
 * ecm_db_set_defunct_all()
 */
static ssize_t ecm_db_set_defunct_all(struct sys_device *dev,
				  struct sysdev_attribute *attr,
				  const char *buf, size_t count)
{
	ecm_db_connection_defunct_all();
	return count;
}

/*
 * ecm_db_get_connection_counts_simple()
 *	Return total of connections for each simple protocol (tcp, udp, other).  Primarily for use by the luci-bwc service.
 */
static ssize_t ecm_db_get_connection_counts_simple(struct sys_device *dev,
				  struct sysdev_attribute *attr,
				  char *buf)
{
	int tcp_count;
	int udp_count;
	int other_count;
	int total_count;
	ssize_t count;

	/*
	 * Get snapshot of the protocol counts
	 */
	spin_lock_bh(&ecm_db_lock);
	tcp_count = ecm_db_connection_count_by_protocol[IPPROTO_TCP];
	udp_count = ecm_db_connection_count_by_protocol[IPPROTO_UDP];
	total_count = ecm_db_connection_count;
	other_count = total_count - (tcp_count + udp_count);
	spin_unlock_bh(&ecm_db_lock);

	count = snprintf(buf, (ssize_t)PAGE_SIZE, "tcp %d udp %d other %d total %d\n", tcp_count, udp_count, other_count, total_count);
	return count;
}

/*
 * ecm_db_get_state_file_output_mask()
 */
static ssize_t ecm_db_get_state_file_output_mask(struct sys_device *dev,
				  struct sysdev_attribute *attr,
				  char *buf)
{
	ssize_t count;
	int num;

	/*
	 * Operate under our locks
	 */
	spin_lock_bh(&ecm_db_lock);
	num = ecm_db_state_file_output_mask;
	spin_unlock_bh(&ecm_db_lock);

	count = snprintf(buf, (ssize_t)PAGE_SIZE, "%d\n", num);
	return count;
}

/*
 * ecm_db_set_state_file_output_mask()
 */
static ssize_t ecm_db_set_state_file_output_mask(struct sys_device *dev,
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
	DEBUG_TRACE("ecm_db_state_file_output_mask = %x\n", num);

	/*
	 * Operate under our locks
	 */
	spin_lock_bh(&ecm_db_lock);
	ecm_db_state_file_output_mask = num;
	spin_unlock_bh(&ecm_db_lock);

	return count;
}

/*
 * SysFS attributes for the default classifier itself.
 */
static SYSDEV_ATTR(terminate, 0644, ecm_db_get_terminate, ecm_db_set_terminate);
static SYSDEV_ATTR(state_dev_major, 0444, ecm_db_get_state_dev_major, NULL);
static SYSDEV_ATTR(connection_count, 0444, ecm_db_get_connection_count, NULL);
static SYSDEV_ATTR(host_count, 0444, ecm_db_get_host_count, NULL);
static SYSDEV_ATTR(mapping_count, 0444, ecm_db_get_mapping_count, NULL);
static SYSDEV_ATTR(node_count, 0444, ecm_db_get_node_count, NULL);
static SYSDEV_ATTR(iface_count, 0444, ecm_db_get_iface_count, NULL);
static SYSDEV_ATTR(defunct_all, 0644, ecm_db_get_defunct_all, ecm_db_set_defunct_all);
static SYSDEV_ATTR(connection_counts_simple, 0444, ecm_db_get_connection_counts_simple, NULL);
static SYSDEV_ATTR(state_file_output_mask, 0644, ecm_db_get_state_file_output_mask, ecm_db_set_state_file_output_mask);

/*
 * SysFS class of the ubicom default classifier
 * SysFS control points can be found at /sys/devices/system/ecm_db/ecm_dbX/
 */
static struct sysdev_class ecm_db_sysclass = {
	.name = "ecm_db",
};

/*
 * ecm_db_connection_heirarchy_xml_state_get()
 *	Output XML state for an interface heirarchy list.
 *
 * Return value is comptible with snprintf()
 */
static int ecm_db_connection_heirarchy_xml_state_get(char *element, struct ecm_db_iface_instance *interfaces[], int32_t first_interface,
								char *buf, int buf_sz)
{
	int count;
	int total;
	int i;
	
	/*
	 * Output the opening element
	 */
	total = 0;
	count = snprintf(buf + total,
			buf_sz - total,
			"<%s count=\"%d\">\n",
			element,
			ECM_DB_IFACE_HEIRARCHY_MAX - first_interface);
	if ((count <= 0) || (count >= (buf_sz - total))) {
		return -1;
	}
	total += count;

	/*
	 * Iterate the interface heirarchy list and output the information
	 */
	for (i = first_interface; i < ECM_DB_IFACE_HEIRARCHY_MAX; ++i) {
		struct ecm_db_iface_instance *ii = interfaces[i];
		DEBUG_TRACE("Element: %s, Output interface @ %d: %p\n", element, i, ii);
		count = ii->xml_state_get(ii, buf + total, buf_sz - total);
		if ((count <= 0) || (count >= (buf_sz - total))) {
			return -1;
		}
		total += count;
	}

	/*
	 * Output closing element
	 */
	count = snprintf(buf + total,
			buf_sz - total,
			"</%s>\n",
			element);
	if ((count <= 0) || (count >= (buf_sz - total))) {
		return -1;
	}
	total += count;
	return total;
}

/*
 * ecm_db_char_dev_conn_msg_prep()
 *	Prepare a connection message
 */
static bool ecm_db_char_dev_conn_msg_prep(struct ecm_db_state_file_instance *sfi)
{
	int msg_len;
	int extra_msg_len;
	long int expires_in;
	int sport;
	int sport_nat;
	char snode_address[25];
	char sip_address[50];
	char sip_address_nat[50];
	char dnode_address[25];
	int dport;
	int dport_nat;
	char dip_address[50];
	char dip_address_nat[50];
	ecm_db_direction_t direction;
	int protocol;
	bool is_routed;
	uint32_t time_added;
	uint32_t serial;
	uint64_t from_data_total;
	uint64_t to_data_total;
	uint64_t from_packet_total;
	uint64_t to_packet_total;
	uint64_t from_data_total_dropped;
	uint64_t to_data_total_dropped;
	uint64_t from_packet_total_dropped;
	uint64_t to_packet_total_dropped;
	struct ecm_db_host_instance *hi;
	int aci_index;
	int aci_count;
	struct ecm_front_end_connection_instance *feci;
	struct ecm_classifier_instance *assignments[ECM_CLASSIFIER_TYPES];
	int32_t first_interface;
	struct ecm_db_iface_instance *interfaces[ECM_DB_IFACE_HEIRARCHY_MAX];

	DEBUG_TRACE("%p: Prep conn msg for %p\n", sfi, sfi->ci);

	/*
	 * Identify expiration
	 */
	spin_lock_bh(&ecm_db_lock);
	if (sfi->ci->defunct_timer.group == ECM_DB_TIMER_GROUPS_MAX) {
		expires_in = -1;
	} else {
		expires_in = (long int)(sfi->ci->defunct_timer.timeout - ecm_db_time);
		if (expires_in <= 0) {
			expires_in = 0;
		}
	}
	spin_unlock_bh(&ecm_db_lock);

	/*
	 * Extract information from the connection for inclusion into the message
	 */
	sport = sfi->ci->mapping_from->port;
	sport_nat = sfi->ci->mapping_nat_from->port;
	dport = sfi->ci->mapping_to->port;
	dport_nat = sfi->ci->mapping_nat_to->port;

	hi = sfi->ci->mapping_to->host;
	ecm_ip_addr_to_string(dip_address, hi->address);
	sprintf(dnode_address, "%pM", hi->node->address);
	hi = sfi->ci->mapping_nat_to->host;
	ecm_ip_addr_to_string(dip_address_nat, hi->address);

	hi = sfi->ci->mapping_from->host;
	ecm_ip_addr_to_string(sip_address, hi->address);
	sprintf(snode_address, "%pM", hi->node->address);
	hi = sfi->ci->mapping_nat_from->host;
	ecm_ip_addr_to_string(sip_address_nat, hi->address);

	direction = sfi->ci->direction;
	protocol = sfi->ci->protocol;
	is_routed = sfi->ci->is_routed;
	time_added = sfi->ci->time_added;
	serial = sfi->ci->serial;
	ecm_db_connection_data_stats_get(sfi->ci, &from_data_total, &to_data_total,
			&from_packet_total, &to_packet_total,
			&from_data_total_dropped, &to_data_total_dropped,
			&from_packet_total_dropped, &to_packet_total_dropped);

	/*
	 * Use fresh buffer
	 */	
	sfi->msgp = sfi->msg_buffer;

	/*
	 * Prep the message
	 */
	msg_len = snprintf(sfi->msgp, ECM_DB_STATE_FILE_BUFFER_SIZE,
			"<conn serial=\"%u\" sip_address=\"%s\" sip_address_nat=\"%s\" sport=\"%d\" sport_nat=\"%d\" snode_address=\"%s\""
			" dip_address=\"%s\" dip_address_nat=\"%s\" dport=\"%d\" dport_nat=\"%d\" dnode_address=\"%s\""
			" protocol=\"%d\" is_routed=\"%d\" expires=\"%ld\" direction=\"%d\" time_added=\"%u\""
			" from_data_total=\"%llu\" to_data_total=\"%llu\" from_packet_total=\"%llu\" to_packet_total=\"%llu\" from_data_total_dropped=\"%llu\" to_data_total_dropped=\"%llu\" from_packet_total_dropped=\"%llu\" to_packet_total_dropped=\"%llu\">\n",
			serial,
			sip_address,
			sip_address_nat,
			sport,
			sport_nat,
			snode_address,
			dip_address,
			dip_address_nat,
			dport,
			dport_nat,
			dnode_address,
			protocol,
			is_routed,
			expires_in,
			direction,
			time_added,
			from_data_total,
			to_data_total,
			from_packet_total,
			to_packet_total,
			from_data_total_dropped,
			to_data_total_dropped,
			from_packet_total_dropped,
			to_packet_total_dropped);

	if ((msg_len <= 0) || (msg_len >= ECM_DB_STATE_FILE_BUFFER_SIZE)) {
		return false;
	}

	/*
	 * Output interface heirarchy information for this connection
	 */
	first_interface = ecm_db_connection_from_interfaces_get_and_ref(sfi->ci, interfaces);
	extra_msg_len = ecm_db_connection_heirarchy_xml_state_get("from_interfaces", interfaces, first_interface, sfi->msgp + msg_len, ECM_DB_STATE_FILE_BUFFER_SIZE - msg_len);
	ecm_db_connection_interfaces_deref(interfaces, first_interface);
	if ((extra_msg_len <= 0) || (extra_msg_len >= (ECM_DB_STATE_FILE_BUFFER_SIZE - msg_len))) {
		return false;
	}
	msg_len += extra_msg_len;

	first_interface = ecm_db_connection_to_interfaces_get_and_ref(sfi->ci, interfaces);
	extra_msg_len = ecm_db_connection_heirarchy_xml_state_get("to_interfaces", interfaces, first_interface, sfi->msgp + msg_len, ECM_DB_STATE_FILE_BUFFER_SIZE - msg_len);
	ecm_db_connection_interfaces_deref(interfaces, first_interface);
	if ((extra_msg_len <= 0) || (extra_msg_len >= (ECM_DB_STATE_FILE_BUFFER_SIZE - msg_len))) {
		return false;
	}
	msg_len += extra_msg_len;

	first_interface = ecm_db_connection_from_nat_interfaces_get_and_ref(sfi->ci, interfaces);
	extra_msg_len = ecm_db_connection_heirarchy_xml_state_get("from_nat_interfaces", interfaces, first_interface, sfi->msgp + msg_len, ECM_DB_STATE_FILE_BUFFER_SIZE - msg_len);
	ecm_db_connection_interfaces_deref(interfaces, first_interface);
	if ((extra_msg_len <= 0) || (extra_msg_len >= (ECM_DB_STATE_FILE_BUFFER_SIZE - msg_len))) {
		return false;
	}
	msg_len += extra_msg_len;

	first_interface = ecm_db_connection_to_nat_interfaces_get_and_ref(sfi->ci, interfaces);
	extra_msg_len = ecm_db_connection_heirarchy_xml_state_get("to_nat_interfaces", interfaces, first_interface, sfi->msgp + msg_len, ECM_DB_STATE_FILE_BUFFER_SIZE - msg_len);
	ecm_db_connection_interfaces_deref(interfaces, first_interface);
	if ((extra_msg_len <= 0) || (extra_msg_len >= (ECM_DB_STATE_FILE_BUFFER_SIZE - msg_len))) {
		return false;
	}
	msg_len += extra_msg_len;

	/*
	 * Output front end state
	 */
	feci = ecm_db_connection_front_end_get_and_ref(sfi->ci);
	extra_msg_len = feci->xml_state_get(feci, sfi->msgp + msg_len, ECM_DB_STATE_FILE_BUFFER_SIZE - msg_len);
	feci->deref(feci);
	if ((extra_msg_len <= 0) || (extra_msg_len >= (ECM_DB_STATE_FILE_BUFFER_SIZE - msg_len))) {
		return false;
	}
	msg_len += extra_msg_len;

	/*
	 * Grab references to the assigned classifiers so we can produce state for them
	 */
	aci_count = ecm_db_connection_classifier_assignments_get_and_ref(sfi->ci, assignments);

	/*
	 * Iterate the assigned classifiers and provide a state record for each
	 */
	for (aci_index = 0; aci_index < aci_count; ++aci_index) {
		struct ecm_classifier_instance *aci;

		aci = assignments[aci_index];
		extra_msg_len = aci->xml_state_get(aci, sfi->msgp + msg_len, ECM_DB_STATE_FILE_BUFFER_SIZE - msg_len);

		if ((extra_msg_len <= 0) || (extra_msg_len >= (ECM_DB_STATE_FILE_BUFFER_SIZE - msg_len))) {
			ecm_db_connection_assignments_release(aci_count, assignments);
			return false;
		}

		msg_len += extra_msg_len;
	}
	ecm_db_connection_assignments_release(aci_count, assignments);

	/*
	 * Write out end element
	 */
	extra_msg_len = snprintf(sfi->msgp + msg_len, ECM_DB_STATE_FILE_BUFFER_SIZE - msg_len, "</conn>\n");
	if ((extra_msg_len <= 0) || (extra_msg_len >= (ECM_DB_STATE_FILE_BUFFER_SIZE - msg_len))) {
		return false;
	}
	msg_len += extra_msg_len;
 
	/*
	 * Record the message length
	 */
	sfi->msg_len = msg_len;
	DEBUG_TRACE("%p: Prepped msg %s\n", sfi, sfi->msgp);
	return true;
}

/*
 * ecm_db_char_dev_mapping_msg_prep()
 *	Prepare a mapping message
 */
static bool ecm_db_char_dev_mapping_msg_prep(struct ecm_db_state_file_instance *sfi)
{
	int msg_len;
	int port;
	char address[25];
	int tcp_from;
	int tcp_to;
	int udp_from;
	int udp_to;
	int from;
	int to;
	int tcp_nat_from;
	int tcp_nat_to;
	int udp_nat_from;
	int udp_nat_to;
	int nat_from;
	int nat_to;
	uint32_t time_added;
	uint64_t from_data_total;
	uint64_t to_data_total;
	uint64_t from_packet_total;
	uint64_t to_packet_total;
	uint64_t from_data_total_dropped;
	uint64_t to_data_total_dropped;
	uint64_t from_packet_total_dropped;
	uint64_t to_packet_total_dropped;
	char node_address[25];
	struct ecm_db_host_instance *hi;

	DEBUG_TRACE("%p: Prep mapping msg for %p\n", sfi, sfi->mi);

	/*
	 * Create a small xml stats element for our mapping.
	 * Extract information from the mapping for inclusion into the message
	 */
	ecm_db_mapping_port_count_get(sfi->mi, &tcp_from, &tcp_to, &udp_from, &udp_to, &from, &to,
			&tcp_nat_from, &tcp_nat_to, &udp_nat_from, &udp_nat_to, &nat_from, &nat_to);
	port = sfi->mi->port;
	time_added = sfi->mi->time_added;
	ecm_db_mapping_data_stats_get(sfi->mi, &from_data_total, &to_data_total,
			&from_packet_total, &to_packet_total,
			&from_data_total_dropped, &to_data_total_dropped,
			&from_packet_total_dropped, &to_packet_total_dropped);
	hi = sfi->mi->host;
	ecm_ip_addr_to_string(address, hi->address);
	sprintf(node_address, "%pM", hi->node->address);

	/*
	 * Use fresh buffer
	 */	
	sfi->msgp = sfi->msg_buffer;

	/*
	 * Prep the message
	 */
	msg_len = snprintf(sfi->msgp, ECM_DB_STATE_FILE_BUFFER_SIZE,
			"<mapping address=\"%s\" port=\"%d\" from=\"%d\" to=\"%d\" tcp_from=\"%d\" tcp_to=\"%d\" udp_from=\"%d\" udp_to=\"%d\""
			" nat_from=\"%d\" nat_to=\"%d\" tcp_nat_from=\"%d\" tcp_nat_to=\"%d\" udp_nat_from=\"%d\" udp_nat_to=\"%d\""
			" from_data_total=\"%llu\" to_data_total=\"%llu\" from_packet_total=\"%llu\" to_packet_total=\"%llu\""
			" from_data_total_dropped=\"%llu\" to_data_total_dropped=\"%llu\" from_packet_total_dropped=\"%llu\" to_packet_total_dropped=\"%llu\""
			" time_added=\"%u\" node_address=\"%s\"/>\n",
			address,
			port,
			from,
			to,
			tcp_from,
			tcp_to,
			udp_from,
			udp_to,
			nat_from,
			nat_to,
			tcp_nat_from,
			tcp_nat_to,
			udp_nat_from,
			udp_nat_to,
			from_data_total,
			to_data_total,
			from_packet_total,
			to_packet_total,
			from_data_total_dropped,
			to_data_total_dropped,
			from_packet_total_dropped,
			to_packet_total_dropped,
			time_added,
			node_address);

	if ((msg_len <= 0) || (msg_len >= ECM_DB_STATE_FILE_BUFFER_SIZE)) {
		return false;
	}

	sfi->msg_len = msg_len;
	DEBUG_TRACE("%p: Prepped msg %s\n", sfi, sfi->msgp);
	return true;
}

/*
 * ecm_db_char_dev_host_msg_prep()
 *	Prepare a host message
 */
static bool ecm_db_char_dev_host_msg_prep(struct ecm_db_state_file_instance *sfi)
{
	int msg_len;
	char address[50];
	int mapping_count;
	uint32_t time_added;
	uint64_t from_data_total;
	uint64_t to_data_total;
	uint64_t from_packet_total;
	uint64_t to_packet_total;
	uint64_t from_data_total_dropped;
	uint64_t to_data_total_dropped;
	uint64_t from_packet_total_dropped;
	uint64_t to_packet_total_dropped;
	char node_address[25];
	bool on_link;

	DEBUG_TRACE("%p: Prep host msg for %p\n", sfi, sfi->hi);

	/*
	 * Create a small xml stats element for our host.
	 * Extract information from the host for inclusion into the message
	 */
	mapping_count = ecm_db_host_mapping_count_get(sfi->hi);
	ecm_ip_addr_to_string(address, sfi->hi->address);
	time_added = sfi->hi->time_added;
	ecm_db_host_data_stats_get(sfi->hi, &from_data_total, &to_data_total,
			&from_packet_total, &to_packet_total,
			&from_data_total_dropped, &to_data_total_dropped,
			&from_packet_total_dropped, &to_packet_total_dropped);
	sprintf(node_address, "%pM", sfi->hi->node->address);
	on_link = sfi->hi->on_link;

	/*
	 * Use fresh buffer
	 */	
	sfi->msgp = sfi->msg_buffer;

	/*
	 * Prep the message
	 */
	msg_len = snprintf(sfi->msgp, ECM_DB_STATE_FILE_BUFFER_SIZE,
		"<host address=\"%s\" mappings=\"%d\" time_added=\"%u\" node_address=\"%s\" on_link=\"%d\""
		" from_data_total=\"%llu\" to_data_total=\"%llu\" from_packet_total=\"%llu\" to_packet_total=\"%llu\""
		" from_data_total_dropped=\"%llu\" to_data_total_dropped=\"%llu\" from_packet_total_dropped=\"%llu\" to_packet_total_dropped=\"%llu\"/>\n",
		address,
		mapping_count,
		time_added,
		node_address,
		on_link,
		from_data_total,
		to_data_total,
		from_packet_total,
		to_packet_total,
		from_data_total_dropped,
		to_data_total_dropped,
		from_packet_total_dropped,
		to_packet_total_dropped);

	if ((msg_len <= 0) || (msg_len >= ECM_DB_STATE_FILE_BUFFER_SIZE)) {
		return false;
	}

	sfi->msg_len = msg_len;
	DEBUG_TRACE("%p: Prepped msg %s\n", sfi, sfi->msgp);
	return true;
}

/*
 * ecm_db_char_dev_nod__msg_prep()
 *	Prepare a node message
 */
static bool ecm_db_char_dev_node_msg_prep(struct ecm_db_state_file_instance *sfi)
{
	int msg_len;
	char address[25];
	int host_count;
	uint32_t time_added;
	uint64_t from_data_total;
	uint64_t to_data_total;
	uint64_t from_packet_total;
	uint64_t to_packet_total;
	uint64_t from_data_total_dropped;
	uint64_t to_data_total_dropped;
	uint64_t from_packet_total_dropped;
	uint64_t to_packet_total_dropped;

	DEBUG_TRACE("%p: Prep node msg for %p\n", sfi, sfi->ni);

	/*
	 * Create a small xml stats block for our managed node, like:
	 * <node address="" hosts="" time_added="" from_data_total="" to_data_total="" />
	 *
	 * Extract information from the node for inclusion into the message
	 */
	host_count = ecm_db_node_host_count_get(sfi->ni);
	time_added = sfi->ni->time_added;
	ecm_db_node_data_stats_get(sfi->ni, &from_data_total, &to_data_total,
			&from_packet_total, &to_packet_total,
			&from_data_total_dropped, &to_data_total_dropped,
			&from_packet_total_dropped, &to_packet_total_dropped);
	sprintf(address, "%pM", sfi->ni->address);

	/*
	 * Use fresh buffer
	 */	
	sfi->msgp = sfi->msg_buffer;

	/*
	 * Prep the message
	 */
	msg_len = snprintf(sfi->msgp, ECM_DB_STATE_FILE_BUFFER_SIZE,
		"<node address=\"%s\" mappings=\"%d\" time_added=\"%u\""
		" from_data_total=\"%llu\" to_data_total=\"%llu\" from_packet_total=\"%llu\" to_packet_total=\"%llu\""
		" from_data_total_dropped=\"%llu\" to_data_total_dropped=\"%llu\" from_packet_total_dropped=\"%llu\" to_packet_total_dropped=\"%llu\" />\n",
		address,
		host_count,
		time_added,
		from_data_total,
		to_data_total,
		from_packet_total,
		to_packet_total,
		from_data_total_dropped,
		to_data_total_dropped,
		from_packet_total_dropped,
		to_packet_total_dropped);

	if ((msg_len <= 0) || (msg_len >= ECM_DB_STATE_FILE_BUFFER_SIZE)) {
		return false;
	}

	sfi->msg_len = msg_len;
	DEBUG_TRACE("%p: Prepped msg %s\n", sfi, sfi->msgp);
	return true;
}

/*
 * ecm_db_char_dev_iface_msg_prep()
 *	Prepare an interface message
 */
static bool ecm_db_char_dev_iface_msg_prep(struct ecm_db_state_file_instance *sfi)
{
	int msg_len;

	DEBUG_TRACE("%p: Prep iface msg for %p\n", sfi, sfi->ii);

	/*
	 * Use fresh buffer
	 */	
	sfi->msgp = sfi->msg_buffer;

	/*
	 * Prep the message
	 */
	msg_len = sfi->ii->xml_state_get(sfi->ii, sfi->msgp, ECM_DB_STATE_FILE_BUFFER_SIZE);

	if ((msg_len <= 0) || (msg_len >= ECM_DB_STATE_FILE_BUFFER_SIZE)) {
		return false;
	}

	/*
	 * Record the message length
	 */
	sfi->msg_len = msg_len;
	DEBUG_TRACE("%p: Prepped msg %s\n", sfi, sfi->msgp);
	return true;
}

/*
 * ecm_db_char_dev_conn_chain_msg_prep()
 *	Generate an conn hash table chain message
 */
static bool ecm_db_char_dev_conn_chain_msg_prep(struct ecm_db_state_file_instance *sfi)
{
	int chain_len;
	int msg_len;
	DEBUG_TRACE("%p: Prep conn chain msg\n", sfi);

	/*
	 * Get hash table chain length
	 */
	spin_lock_bh(&ecm_db_lock);
	chain_len = ecm_db_connection_table_lengths[sfi->connection_hash_index];
	spin_unlock_bh(&ecm_db_lock);

	/*
	 * Use fresh buffer
	 */	
	sfi->msgp = sfi->msg_buffer;

	/*
	 * Create a small xml stats block like:
	 * <conn_chain hash_index="" chain_length=""/>
	 */
	msg_len = snprintf(sfi->msgp, ECM_DB_STATE_FILE_BUFFER_SIZE,
			"<conn_chain hash_index=\"%d\" chain_length=\"%d\"/>\n",
			sfi->connection_hash_index,
			chain_len);
	if ((msg_len <= 0) || (msg_len >= ECM_DB_STATE_FILE_BUFFER_SIZE)) {
		return false;
	}

	sfi->msg_len = msg_len;
	DEBUG_TRACE("%p: Prepped msg %s\n", sfi, sfi->msgp);
	return true;
}

/*
 * ecm_db_char_dev_mapping_chain_msg_prep()
 *	Generate an mapping hash table chain message
 */
static bool ecm_db_char_dev_mapping_chain_msg_prep(struct ecm_db_state_file_instance *sfi)
{
	int chain_len;
	int msg_len;
	DEBUG_TRACE("%p: Prep mapping chain msg\n", sfi);

	/*
	 * Get hash table chain length
	 */
	spin_lock_bh(&ecm_db_lock);
	chain_len = ecm_db_mapping_table_lengths[sfi->mapping_hash_index];
	spin_unlock_bh(&ecm_db_lock);

	/*
	 * Use fresh buffer
	 */	
	sfi->msgp = sfi->msg_buffer;

	/*
	 * Create a small xml stats block like:
	 * <mapping_chain hash_index="" chain_length=""/>
	 */
	msg_len = snprintf(sfi->msgp, ECM_DB_STATE_FILE_BUFFER_SIZE,
			"<mapping_chain hash_index=\"%d\" chain_length=\"%d\"/>\n",
			sfi->mapping_hash_index,
			chain_len);
	if ((msg_len <= 0) || (msg_len >= ECM_DB_STATE_FILE_BUFFER_SIZE)) {
		return false;
	}

	sfi->msg_len = msg_len;
	DEBUG_TRACE("%p: Prepped msg %s\n", sfi, sfi->msgp);
	return true;
}

/*
 * ecm_db_char_dev_host_chain_msg_prep()
 *	Generate an host hash table chain message
 */
static bool ecm_db_char_dev_host_chain_msg_prep(struct ecm_db_state_file_instance *sfi)
{
	int chain_len;
	int msg_len;
	DEBUG_TRACE("%p: Prep host chain msg\n", sfi);

	/*
	 * Get hash table chain length
	 */
	spin_lock_bh(&ecm_db_lock);
	chain_len = ecm_db_host_table_lengths[sfi->host_hash_index];
	spin_unlock_bh(&ecm_db_lock);

	/*
	 * Use fresh buffer
	 */	
	sfi->msgp = sfi->msg_buffer;

	/*
	 * Create a small xml stats block like:
	 * <host_chain hash_index="" chain_length=""/>
	 */
	msg_len = snprintf(sfi->msgp, ECM_DB_STATE_FILE_BUFFER_SIZE,
			"<host_chain hash_index=\"%d\" chain_length=\"%d\"/>\n",
			sfi->host_hash_index,
			chain_len);
	if ((msg_len <= 0) || (msg_len >= ECM_DB_STATE_FILE_BUFFER_SIZE)) {
		return false;
	}

	sfi->msg_len = msg_len;
	DEBUG_TRACE("%p: Prepped msg %s\n", sfi, sfi->msgp);
	return true;
}

/*
 * ecm_db_char_dev_node_chain_msg_prep()
 *	Generate an node hash table chain message
 */
static bool ecm_db_char_dev_node_chain_msg_prep(struct ecm_db_state_file_instance *sfi)
{
	int chain_len;
	int msg_len;
	DEBUG_TRACE("%p: Prep node chain msg\n", sfi);

	/*
	 * Get hash table chain length
	 */
	spin_lock_bh(&ecm_db_lock);
	chain_len = ecm_db_node_table_lengths[sfi->node_hash_index];
	spin_unlock_bh(&ecm_db_lock);

	/*
	 * Use fresh buffer
	 */	
	sfi->msgp = sfi->msg_buffer;

	/*
	 * Create a small xml stats block like:
	 * <node_chain hash_index="" chain_length=""/>
	 */
	msg_len = snprintf(sfi->msgp, ECM_DB_STATE_FILE_BUFFER_SIZE,
			"<node_chain hash_index=\"%d\" chain_length=\"%d\"/>\n",
			sfi->node_hash_index,
			chain_len);
	if ((msg_len <= 0) || (msg_len >= ECM_DB_STATE_FILE_BUFFER_SIZE)) {
		return false;
	}

	sfi->msg_len = msg_len;
	DEBUG_TRACE("%p: Prepped msg %s\n", sfi, sfi->msgp);
	return true;
}

/*
 * ecm_db_char_dev_iface_chain_msg_prep()
 *	Generate an interface hash table chain message
 */
static bool ecm_db_char_dev_iface_chain_msg_prep(struct ecm_db_state_file_instance *sfi)
{
	int chain_len;
	int msg_len;
	DEBUG_TRACE("%p: Prep iface chain msg\n", sfi);

	/*
	 * Get hash table chain length
	 */
	spin_lock_bh(&ecm_db_lock);
	chain_len = ecm_db_iface_table_lengths[sfi->iface_hash_index];
	spin_unlock_bh(&ecm_db_lock);

	/*
	 * Use fresh buffer
	 */	
	sfi->msgp = sfi->msg_buffer;

	/*
	 * Create a small xml stats block like:
	 * <iface_chain hash_index="" chain_length=""/>
	 */
	msg_len = snprintf(sfi->msgp, ECM_DB_STATE_FILE_BUFFER_SIZE,
			"<iface_chain hash_index=\"%d\" chain_length=\"%d\"/>\n",
			sfi->iface_hash_index,
			chain_len);
	if ((msg_len <= 0) || (msg_len >= ECM_DB_STATE_FILE_BUFFER_SIZE)) {
		return false;
	}

	sfi->msg_len = msg_len;
	DEBUG_TRACE("%p: Prepped msg %s\n", sfi, sfi->msgp);
	return true;
}

/*
 * ecm_db_char_dev_protocol_count_msg_prep()
 *	Generate a protocol usage message
 */
static bool ecm_db_char_dev_protocol_count_msg_prep(struct ecm_db_state_file_instance *sfi)
{
	int count;
	int msg_len;
	DEBUG_TRACE("%p: Prep protocol msg\n", sfi);

	/*
	 * Get protocol connection total count
	 */
	spin_lock_bh(&ecm_db_lock);
	count = ecm_db_connection_count_by_protocol[sfi->protocol];
	spin_unlock_bh(&ecm_db_lock);

	/*
	 * Use fresh buffer
	 */	
	sfi->msgp = sfi->msg_buffer;

	/*
	 * Create a small xml stats block like:
	 * <conn_proto_count protocol="" count=""/>
	 */
	msg_len = snprintf(sfi->msgp, ECM_DB_STATE_FILE_BUFFER_SIZE,
			"<conn_proto_count protocol=\"%d\" count=\"%d\"/>\n",
			sfi->protocol,
			count);
	if ((msg_len <= 0) || (msg_len >= ECM_DB_STATE_FILE_BUFFER_SIZE)) {
		return false;
	}
	sfi->msg_len = msg_len;
	DEBUG_TRACE("%p: Prepped msg %s\n", sfi, sfi->msgp);
	return true;
}

/*
 * ecm_db_char_device_open()
 *	Opens the special char device file which we use to dump our state.
 * 
 */
static int ecm_db_char_device_open(struct inode *inode, struct file *file)
{
	struct ecm_db_state_file_instance *sfi;

	DEBUG_INFO("State open\n");

	/*
	 * Allocate state information for the reading
	 */
	DEBUG_ASSERT(file->private_data == NULL, "unexpected double open: %p?\n", file->private_data);

	sfi = (struct ecm_db_state_file_instance *)kzalloc(sizeof(struct ecm_db_state_file_instance), GFP_ATOMIC | __GFP_NOWARN);
	if (!sfi) {
		return -ENOMEM;
	}
	DEBUG_SET_MAGIC(sfi, ECM_DB_STATE_FILE_INSTANCE_MAGIC);
	file->private_data = sfi;

	/*
	 * Snapshot output mask for this file
	 */
	spin_lock_bh(&ecm_db_lock);
	sfi->output_mask = ecm_db_state_file_output_mask;
	spin_unlock_bh(&ecm_db_lock);

	/*
	 * Take references to each object list that we are going to generate state for.
	 */
	if (sfi->output_mask & ECM_DB_STATE_FILE_OUTPUT_CONNECTIONS) {
		sfi->ci = ecm_db_connections_get_and_ref_first();
	}
	if (sfi->output_mask & ECM_DB_STATE_FILE_OUTPUT_MAPPINGS) {
		sfi->mi = ecm_db_mappings_get_and_ref_first();
	}
	if (sfi->output_mask & ECM_DB_STATE_FILE_OUTPUT_HOSTS) {
		sfi->hi = ecm_db_hosts_get_and_ref_first();
	}
	if (sfi->output_mask & ECM_DB_STATE_FILE_OUTPUT_NODES) {
		sfi->ni = ecm_db_nodes_get_and_ref_first();
	}
	if (sfi->output_mask & ECM_DB_STATE_FILE_OUTPUT_INTERFACES) {
		sfi->ii = ecm_db_interfaces_get_and_ref_first();
	}

	/*
	 * Cannot do this if the event processing thread is exiting
	 */
	spin_lock_bh(&ecm_db_lock);
	if (ecm_db_terminate_pending) {
		spin_unlock_bh(&ecm_db_lock);

		if (sfi->ci) {
			ecm_db_connection_deref(sfi->ci);
		}
		if (sfi->mi) {
			ecm_db_mapping_deref(sfi->mi);
		}
		if (sfi->hi) {
			ecm_db_host_deref(sfi->hi);
		}
		if (sfi->ni) {
			ecm_db_node_deref(sfi->ni);
		}
		if (sfi->ii) {
			ecm_db_iface_deref(sfi->ii);
		}

		kfree(sfi);
		DEBUG_WARN("Terminating\n");
		return -EBUSY;
	}
	spin_unlock_bh(&ecm_db_lock);

	DEBUG_INFO("State opened %p\n", sfi);

	return 0;
}

/*
 * ecm_db_char_device_release()
 *	Called when a process closes the device file.
 */
static int ecm_db_char_device_release(struct inode *inode, struct file *file)
{
	struct ecm_db_state_file_instance *sfi;

	sfi = (struct ecm_db_state_file_instance *)file->private_data;
	DEBUG_CHECK_MAGIC(sfi, ECM_DB_STATE_FILE_INSTANCE_MAGIC, "%p: magic failed", sfi);
	DEBUG_INFO("%p: State close\n", sfi);

	/*
	 * Release any references held
	 */
	if (sfi->ci) {
		ecm_db_connection_deref(sfi->ci);
	}
	if (sfi->mi) {
		ecm_db_mapping_deref(sfi->mi);
	}
	if (sfi->hi) {
		ecm_db_host_deref(sfi->hi);
	}
	if (sfi->ni) {
		ecm_db_node_deref(sfi->ni);
	}
	if (sfi->ii) {
		ecm_db_iface_deref(sfi->ii);
	}
	DEBUG_CLEAR_MAGIC(sfi);
	kfree(sfi);

	return 0;
}

/*
 * ecm_db_char_device_read()
 *	Called to read the state
 */
static ssize_t ecm_db_char_device_read(struct file *file,	/* see include/linux/fs.h   */
			   char *buffer,				/* buffer to fill with data */
			   size_t length,				/* length of the buffer     */
			   loff_t *offset)				/* Doesn't apply - this is a char file */
{
	struct ecm_db_state_file_instance *sfi;
	int bytes_read = 0;						/* Number of bytes actually written to the buffer */

	sfi = (struct ecm_db_state_file_instance *)file->private_data;
	DEBUG_CHECK_MAGIC(sfi, ECM_DB_STATE_FILE_INSTANCE_MAGIC, "%p: magic failed", sfi);
	DEBUG_TRACE("%p: State read up to length %d bytes\n", sfi, length);

	do {
		/*
		 * If there is still some message remaining to be output then complete that first
		 */
		if (sfi->msg_len) {
			break;
		}

		if (!sfi->doc_start_written) {
			sfi->msgp = sfi->msg_buffer;
			sfi->msg_len = sprintf(sfi->msgp, "<ecm_db>\n");
			sfi->doc_start_written = true;
			break;
		}

		if (sfi->ci) {
			struct ecm_db_connection_instance *cin;
			if (!ecm_db_char_dev_conn_msg_prep(sfi)) {
				return -EIO;
			}

			/*
			 * Next connection for when we return
			 */
			cin = ecm_db_connection_get_and_ref_next(sfi->ci);
			ecm_db_connection_deref(sfi->ci);
			sfi->ci = cin;

			break;
		}

		if (sfi->mi) {
			struct ecm_db_mapping_instance *min;
			if (!ecm_db_char_dev_mapping_msg_prep(sfi)) {
				return -EIO;
			}

			/*
			 * Next mapping for when we return
			 */
			min = ecm_db_mapping_get_and_ref_next(sfi->mi);
			ecm_db_mapping_deref(sfi->mi);
			sfi->mi = min;

			break;
		}

		if (sfi->hi) {
			struct ecm_db_host_instance *hin;
			if (!ecm_db_char_dev_host_msg_prep(sfi)) {
				return -EIO;
			}

			/*
			 * Next host for when we return
			 */
			hin = ecm_db_host_get_and_ref_next(sfi->hi);
			ecm_db_host_deref(sfi->hi);
			sfi->hi = hin;
			
			break;
		}

		if (sfi->ni) {
			struct ecm_db_node_instance *nin;
			if (!ecm_db_char_dev_node_msg_prep(sfi)) {
				return -EIO;
			}

			/*
			 * Next node for when we return
			 */
			nin = ecm_db_node_get_and_ref_next(sfi->ni);
			ecm_db_node_deref(sfi->ni);
			sfi->ni = nin;
		
			break;
		}

		if (sfi->ii) {
			struct ecm_db_iface_instance *iin;
			if (!ecm_db_char_dev_iface_msg_prep(sfi)) {
				return -EIO;
			}

			/*
			 * Next iface for when we return
			 */
			iin = ecm_db_interface_get_and_ref_next(sfi->ii);
			ecm_db_iface_deref(sfi->ii);
			sfi->ii = iin;

			break;
		}

		if ((sfi->output_mask & ECM_DB_STATE_FILE_OUTPUT_CONNECTIONS_CHAIN) && (sfi->connection_hash_index < ECM_DB_CONNECTION_HASH_SLOTS)) {
			if (!ecm_db_char_dev_conn_chain_msg_prep(sfi)) {
				return -EIO;
			}
			sfi->connection_hash_index++;
			break;
		}

		if ((sfi->output_mask & ECM_DB_STATE_FILE_OUTPUT_MAPPINGS_CHAIN) && (sfi->mapping_hash_index < ECM_DB_MAPPING_HASH_SLOTS)) {
			if (!ecm_db_char_dev_mapping_chain_msg_prep(sfi)) {
				return -EIO;
			}
			sfi->mapping_hash_index++;
			break;
		}

		if ((sfi->output_mask & ECM_DB_STATE_FILE_OUTPUT_HOSTS_CHAIN) && (sfi->host_hash_index < ECM_DB_HOST_HASH_SLOTS)) {
			if (!ecm_db_char_dev_host_chain_msg_prep(sfi)) {
				return -EIO;
			}
			sfi->host_hash_index++;
			break;
		}

		if ((sfi->output_mask & ECM_DB_STATE_FILE_OUTPUT_NODES_CHAIN) && (sfi->node_hash_index < ECM_DB_NODE_HASH_SLOTS)) {
			if (!ecm_db_char_dev_node_chain_msg_prep(sfi)) {
				return -EIO;
			}
			sfi->node_hash_index++;
			break;
		}

		if ((sfi->output_mask & ECM_DB_STATE_FILE_OUTPUT_INTERFACES_CHAIN) && (sfi->iface_hash_index < ECM_DB_IFACE_HASH_SLOTS)) {
			if (!ecm_db_char_dev_iface_chain_msg_prep(sfi)) {
				return -EIO;
			}
			sfi->iface_hash_index++;
			break;
		}

		if ((sfi->output_mask & ECM_DB_STATE_FILE_OUTPUT_PROTOCOL_COUNTS) && (sfi->protocol < 256)) {
			if (!ecm_db_char_dev_protocol_count_msg_prep(sfi)) {
				return -EIO;
			}
			sfi->protocol++;
			break;
		}

		if (!sfi->doc_end_written) {
			sfi->msgp = sfi->msg_buffer;
			sfi->msg_len = sprintf(sfi->msgp, "</ecm_db>\n");
			sfi->doc_end_written = true;
			break;
		}

		/*
		 * EOF
		 */
		return 0;
	} while (false);

	/*
	 * If supplied buffer is small we limit what we output
	 */
	bytes_read = sfi->msg_len;
	if (bytes_read > length) {
		bytes_read = length;
	}
	if (copy_to_user(buffer, sfi->msgp, bytes_read)) {
		return -EIO;
	}
	sfi->msg_len -= bytes_read;
	sfi->msgp += bytes_read;

	DEBUG_TRACE("State read done, bytes_read %d bytes\n", bytes_read);

	/* 
	 * Most read functions return the number of bytes put into the buffer
	 */
	return bytes_read;
}

/*
 * ecm_db_char_device_write()
 */
static ssize_t ecm_db_char_device_write(struct file *filp, const char *buff, size_t len, loff_t * off)
{
	return -EINVAL;
}

/*
 * File operations used in the char device
 *	NOTE: The char device is a simple file that allows us to dump our connection tracking state
 */
static struct file_operations ecm_db_fops = {
	.read = ecm_db_char_device_read,
	.write = ecm_db_char_device_write,
	.open = ecm_db_char_device_open,
	.release = ecm_db_char_device_release
};

/*
 * ecm_db_timer_callback()
 *	Manage expiration of connections
 * NOTE: This is softirq context
 */
static void ecm_db_timer_callback(unsigned long data)
{
	uint32_t timer;

	/*
	 * Increment timer.
	 */
	spin_lock_bh(&ecm_db_lock);
	timer = ++ecm_db_time;
	spin_unlock_bh(&ecm_db_lock);
	DEBUG_TRACE("Garbage timer tick %d\n", timer);

	/*
	 * Check timer groups
	 */
	ecm_db_timer_groups_check(timer);

	/*
	 * Set the timer for the next second
	 */
	ecm_db_timer.expires += HZ;
	if (ecm_db_timer.expires <= jiffies) {
		DEBUG_WARN("losing time %lu, jiffies = %lu\n", ecm_db_timer.expires, jiffies);
		ecm_db_timer.expires = jiffies + HZ;
	}
	add_timer(&ecm_db_timer);
}

/*
 * ecm_db_thread_fn()
 *	A thread to handle tasks that can only be done in thread context.
 */
static int ecm_db_thread_fn(void *arg)
{
	int result;

	DEBUG_INFO("DB Thread start\n");

	/*
	 * Get reference to this module - release it when thread exits
	 */
	if (!try_module_get(THIS_MODULE)) {
		return -EINVAL;
	}

	/*
	 * Register the sysfs class
	 */
	result = sysdev_class_register(&ecm_db_sysclass);
	if (result) {
		DEBUG_ERROR("Failed to register SysFS class %d\n", result);
		goto task_cleanup_1;
	}

	/*
	 * Register SYSFS device control
	 */
	memset(&ecm_db_sys_dev, 0, sizeof(ecm_db_sys_dev));
	ecm_db_sys_dev.id = 0;
	ecm_db_sys_dev.cls = &ecm_db_sysclass;
	result = sysdev_register(&ecm_db_sys_dev);
	if (result) {
		DEBUG_ERROR("Failed to register SysFS device %d\n", result);
		goto task_cleanup_2;
	}

	/*
	 * Create files, one for each parameter supported by this module
	 */
	result = sysdev_create_file(&ecm_db_sys_dev, &attr_state_dev_major);
	if (result) {
		DEBUG_ERROR("Failed to register dev major file %d\n", result);
		goto task_cleanup_3;
	}

	result = sysdev_create_file(&ecm_db_sys_dev, &attr_terminate);
	if (result) {
		DEBUG_ERROR("Failed to register terminate file %d\n", result);
		goto task_cleanup_4;
	}

	/*
	 * Register a char device that we will use to provide a dump of our state
	 */
	result = register_chrdev(0, ecm_db_sysclass.name, &ecm_db_fops);
	if (result < 0) {
                DEBUG_ERROR("Failed to register chrdev %d\n", result);
		goto task_cleanup_5;
	}
	ecm_db_dev_major_id = result;
	DEBUG_TRACE("registered chr dev major id assigned %d\n", ecm_db_dev_major_id);

	result = sysdev_create_file(&ecm_db_sys_dev, &attr_connection_count);
	if (result) {
		DEBUG_ERROR("Failed to register conn count SysFS file\n");
		goto task_cleanup_6;
	}

	result = sysdev_create_file(&ecm_db_sys_dev, &attr_host_count);
	if (result) {
		DEBUG_ERROR("Failed to register host count SysFS file\n");
		goto task_cleanup_7;
	}

	result = sysdev_create_file(&ecm_db_sys_dev, &attr_mapping_count);
	if (result) {
		DEBUG_ERROR("Failed to register mapping count SysFS file\n");
		goto task_cleanup_8;
	}

	result = sysdev_create_file(&ecm_db_sys_dev, &attr_defunct_all);
	if (result) {
		DEBUG_ERROR("Failed to register expire all SysFS file\n");
		goto task_cleanup_9;
	}

	result = sysdev_create_file(&ecm_db_sys_dev, &attr_node_count);
	if (result) {
		DEBUG_ERROR("Failed to register node count SysFS file\n");
		goto task_cleanup_10;
	}

	result = sysdev_create_file(&ecm_db_sys_dev, &attr_iface_count);
	if (result) {
		DEBUG_ERROR("Failed to register iface count SysFS file\n");
		goto task_cleanup_11;
	}

	result = sysdev_create_file(&ecm_db_sys_dev, &attr_connection_counts_simple);
	if (result) {
		DEBUG_ERROR("Failed to register connection counts simple SysFS file\n");
		goto task_cleanup_12;
	}

	result = sysdev_create_file(&ecm_db_sys_dev, &attr_state_file_output_mask);
	if (result) {
		DEBUG_ERROR("Failed to register state_file_output_mask SysFS file\n");
		goto task_cleanup_13;
	}

	/*
	 * Set a timer to manage cleanup of expired connections
	 */
	init_timer(&ecm_db_timer);
	ecm_db_timer.function = ecm_db_timer_callback;
	ecm_db_timer.data = 0;
	ecm_db_timer.expires = jiffies + HZ;
	add_timer(&ecm_db_timer);

	/*
	 * Initialise timer groups with time values
	 */
	ecm_db_timer_groups[ECM_DB_TIMER_GROUPS_CLASSIFIER_DETERMINE_GENERIC_TIMEOUT].time = ECM_DB_CLASSIFIER_DETERMINE_GENERIC_TIMEOUT;
	ecm_db_timer_groups[ECM_DB_TIMER_GROUPS_CLASSIFIER_DETERMINE_GENERIC_TIMEOUT].tg = ECM_DB_TIMER_GROUPS_CLASSIFIER_DETERMINE_GENERIC_TIMEOUT;
	ecm_db_timer_groups[ECM_DB_TIMER_GROUPS_CONNECTION_GENERIC_TIMEOUT].time = ECM_DB_CONNECTION_GENERIC_TIMEOUT;
	ecm_db_timer_groups[ECM_DB_TIMER_GROUPS_CONNECTION_GENERIC_TIMEOUT].tg = ECM_DB_TIMER_GROUPS_CONNECTION_GENERIC_TIMEOUT;
	ecm_db_timer_groups[ECM_DB_TIMER_GROUPS_CONNECTION_IGMP_TIMEOUT].time = ECM_DB_CONNECTION_IGMP_TIMEOUT;
	ecm_db_timer_groups[ECM_DB_TIMER_GROUPS_CONNECTION_IGMP_TIMEOUT].tg = ECM_DB_TIMER_GROUPS_CONNECTION_IGMP_TIMEOUT;
	ecm_db_timer_groups[ECM_DB_TIMER_GROUPS_CONNECTION_UDP_GENERIC_TIMEOUT].time = ECM_DB_CONNECTION_UDP_TIMEOUT;
	ecm_db_timer_groups[ECM_DB_TIMER_GROUPS_CONNECTION_UDP_GENERIC_TIMEOUT].tg = ECM_DB_TIMER_GROUPS_CONNECTION_UDP_GENERIC_TIMEOUT;
	ecm_db_timer_groups[ECM_DB_TIMER_GROUPS_CONNECTION_UDP_WKP_TIMEOUT].time = ECM_DB_CONNECTION_UDP_TIMEOUT;
	ecm_db_timer_groups[ECM_DB_TIMER_GROUPS_CONNECTION_UDP_WKP_TIMEOUT].tg = ECM_DB_TIMER_GROUPS_CONNECTION_UDP_WKP_TIMEOUT;
	ecm_db_timer_groups[ECM_DB_TIMER_GROUPS_CONNECTION_ICMP_TIMEOUT].time = ECM_DB_CONNECTION_ICMP_TIMEOUT;
	ecm_db_timer_groups[ECM_DB_TIMER_GROUPS_CONNECTION_ICMP_TIMEOUT].tg = ECM_DB_TIMER_GROUPS_CONNECTION_ICMP_TIMEOUT;
	ecm_db_timer_groups[ECM_DB_TIMER_GROUPS_CONNECTION_TCP_SHORT_TIMEOUT].time = ECM_DB_CONNECTION_TCP_SHORT_TIMEOUT;
	ecm_db_timer_groups[ECM_DB_TIMER_GROUPS_CONNECTION_TCP_SHORT_TIMEOUT].tg = ECM_DB_TIMER_GROUPS_CONNECTION_TCP_SHORT_TIMEOUT;
	ecm_db_timer_groups[ECM_DB_TIMER_GROUPS_CONNECTION_TCP_RESET_TIMEOUT].time = ECM_DB_CONNECTION_TCP_RST_TIMEOUT;
	ecm_db_timer_groups[ECM_DB_TIMER_GROUPS_CONNECTION_TCP_RESET_TIMEOUT].tg = ECM_DB_TIMER_GROUPS_CONNECTION_TCP_RESET_TIMEOUT;
	ecm_db_timer_groups[ECM_DB_TIMER_GROUPS_CONNECTION_TCP_LONG_TIMEOUT].time = ECM_DB_CONNECTION_TCP_LONG_TIMEOUT;
	ecm_db_timer_groups[ECM_DB_TIMER_GROUPS_CONNECTION_TCP_LONG_TIMEOUT].tg = ECM_DB_TIMER_GROUPS_CONNECTION_TCP_LONG_TIMEOUT;
	ecm_db_timer_groups[ECM_DB_TIMER_GROUPS_CONNECTION_PPTP_DATA_TIMEOUT].time = ECM_DB_CONNECTION_PPTP_DATA_TIMEOUT;
	ecm_db_timer_groups[ECM_DB_TIMER_GROUPS_CONNECTION_PPTP_DATA_TIMEOUT].tg = ECM_DB_TIMER_GROUPS_CONNECTION_PPTP_DATA_TIMEOUT;
	ecm_db_timer_groups[ECM_DB_TIMER_GROUPS_CONNECTION_RTCP_TIMEOUT].time = ECM_DB_CONNECTION_RTCP_TIMEOUT;
	ecm_db_timer_groups[ECM_DB_TIMER_GROUPS_CONNECTION_RTCP_TIMEOUT].tg = ECM_DB_TIMER_GROUPS_CONNECTION_RTCP_TIMEOUT;
	ecm_db_timer_groups[ECM_DB_TIMER_GROUPS_CONNECTION_RTSP_TIMEOUT].time = ECM_DB_CONNECTION_TCP_LONG_TIMEOUT;
	ecm_db_timer_groups[ECM_DB_TIMER_GROUPS_CONNECTION_RTSP_TIMEOUT].tg = ECM_DB_TIMER_GROUPS_CONNECTION_RTSP_TIMEOUT;
	ecm_db_timer_groups[ECM_DB_TIMER_GROUPS_CONNECTION_RTSP_FAST_TIMEOUT].time = ECM_DB_CONNECTION_RTSP_FAST_TIMEOUT;
	ecm_db_timer_groups[ECM_DB_TIMER_GROUPS_CONNECTION_RTSP_FAST_TIMEOUT].tg = ECM_DB_TIMER_GROUPS_CONNECTION_RTSP_FAST_TIMEOUT;
	ecm_db_timer_groups[ECM_DB_TIMER_GROUPS_CONNECTION_RTSP_SLOW_TIMEOUT].time = ECM_DB_CONNECTION_RTSP_SLOW_TIMEOUT;
	ecm_db_timer_groups[ECM_DB_TIMER_GROUPS_CONNECTION_RTSP_SLOW_TIMEOUT].tg = ECM_DB_TIMER_GROUPS_CONNECTION_RTSP_SLOW_TIMEOUT;
	ecm_db_timer_groups[ECM_DB_TIMER_GROUPS_CONNECTION_DNS_TIMEOUT].time = ECM_DB_CONNECTION_DNS_TIMEOUT;
	ecm_db_timer_groups[ECM_DB_TIMER_GROUPS_CONNECTION_DNS_TIMEOUT].tg = ECM_DB_TIMER_GROUPS_CONNECTION_DNS_TIMEOUT;
	ecm_db_timer_groups[ECM_DB_TIMER_GROUPS_CONNECTION_FTP_TIMEOUT].time = ECM_DB_CONNECTION_FTP_TIMEOUT;
	ecm_db_timer_groups[ECM_DB_TIMER_GROUPS_CONNECTION_FTP_TIMEOUT].tg = ECM_DB_TIMER_GROUPS_CONNECTION_FTP_TIMEOUT;
	ecm_db_timer_groups[ECM_DB_TIMER_GROUPS_CONNECTION_BITTORRENT_TIMEOUT].time = ECM_DB_CONNECTION_BITTORRENT_TIMEOUT;
	ecm_db_timer_groups[ECM_DB_TIMER_GROUPS_CONNECTION_BITTORRENT_TIMEOUT].tg = ECM_DB_TIMER_GROUPS_CONNECTION_BITTORRENT_TIMEOUT;

	/*
	 * H323 timeout value is 8 hours (8h * 60m * 60s == 28800 seconds).
	 */
	ecm_db_timer_groups[ECM_DB_TIMER_GROUPS_CONNECTION_H323_TIMEOUT].time = ECM_DB_CONNECTION_H323_TIMEOUT;
	ecm_db_timer_groups[ECM_DB_TIMER_GROUPS_CONNECTION_H323_TIMEOUT].tg = ECM_DB_TIMER_GROUPS_CONNECTION_H323_TIMEOUT;

	/*
	 * IKE Timeout (seconds) = 15 hours
	 */
	ecm_db_timer_groups[ECM_DB_TIMER_GROUPS_CONNECTION_IKE_TIMEOUT].time = ECM_DB_CONNECTION_IKE_TIMEOUT;
	ecm_db_timer_groups[ECM_DB_TIMER_GROUPS_CONNECTION_IKE_TIMEOUT].tg = ECM_DB_TIMER_GROUPS_CONNECTION_IKE_TIMEOUT;

	ecm_db_timer_groups[ECM_DB_TIMER_GROUPS_CONNECTION_ESP_TIMEOUT].time = ECM_DB_CONNECTION_ESP_TIMEOUT;
	ecm_db_timer_groups[ECM_DB_TIMER_GROUPS_CONNECTION_ESP_TIMEOUT].tg = ECM_DB_TIMER_GROUPS_CONNECTION_ESP_TIMEOUT;
	ecm_db_timer_groups[ECM_DB_TIMER_GROUPS_CONNECTION_ESP_PENDING_TIMEOUT].time = ECM_DB_CONNECTION_ESP_PENDING_TIMEOUT;
	ecm_db_timer_groups[ECM_DB_TIMER_GROUPS_CONNECTION_ESP_PENDING_TIMEOUT].tg = ECM_DB_TIMER_GROUPS_CONNECTION_ESP_PENDING_TIMEOUT;

	ecm_db_timer_groups[ECM_DB_TIMER_GROUPS_CONNECTION_SDP_TIMEOUT].time = ECM_DB_CONNECTION_SDP_TIMEOUT;
	ecm_db_timer_groups[ECM_DB_TIMER_GROUPS_CONNECTION_SDP_TIMEOUT].tg = ECM_DB_TIMER_GROUPS_CONNECTION_SDP_TIMEOUT;
	ecm_db_timer_groups[ECM_DB_TIMER_GROUPS_CONNECTION_SIP_TIMEOUT].time = ECM_DB_CONNECTION_SIP_TIMEOUT;
	ecm_db_timer_groups[ECM_DB_TIMER_GROUPS_CONNECTION_SIP_TIMEOUT].tg = ECM_DB_TIMER_GROUPS_CONNECTION_SIP_TIMEOUT;

	/*
	 * Reset connection by protocol counters
	 */
	memset(ecm_db_connection_count_by_protocol, 0, sizeof(ecm_db_connection_count_by_protocol));

	/*
	 * Allow wakeup signals
	 */
	allow_signal(SIGCONT);

	/*
	 * Set state to interruptible so that we don't miss any wake up calls
	 * during processing of events
	 * NOTE: Any wakeups while we are processing will set the state to TASK_RUNNING and we simply wont sleep on schedule()
	 */
	__set_current_state(TASK_INTERRUPTIBLE);

	spin_lock_bh(&ecm_db_lock);

	/*
	 * Give the thread one refs - this requires the user to terminate the thread
	 */
	ecm_db_thread_refs = 1;

	while (ecm_db_thread_refs) {
		spin_unlock_bh(&ecm_db_lock);

		/*
		 * Sleep and wait for a wakeup.
		 */
		DEBUG_TRACE("ecm_db sleep\n");
		schedule();
		__set_current_state(TASK_INTERRUPTIBLE);

		spin_lock_bh(&ecm_db_lock);
	}
	DEBUG_INFO("ecm_db terminate\n");
	DEBUG_ASSERT(ecm_db_terminate_pending, "User has not requested terminate\n");
	spin_unlock_bh(&ecm_db_lock);

	/*
	 * Destroy garbage timer
	 * Timer must be cancelled outside of holding db lock - if the timer callback runs on another CPU we would deadlock
	 * as we would wait for the callback to finish and it would wait indefinately for the lock to be released!
	 */
	del_timer(&ecm_db_timer);

	result = 0;

	sysdev_remove_file(&ecm_db_sys_dev, &attr_state_file_output_mask);
task_cleanup_13:
	sysdev_remove_file(&ecm_db_sys_dev, &attr_connection_counts_simple);
task_cleanup_12:
	sysdev_remove_file(&ecm_db_sys_dev, &attr_iface_count);
task_cleanup_11:
	sysdev_remove_file(&ecm_db_sys_dev, &attr_node_count);
task_cleanup_10:
	sysdev_remove_file(&ecm_db_sys_dev, &attr_defunct_all);
task_cleanup_9:
	sysdev_remove_file(&ecm_db_sys_dev, &attr_mapping_count);
task_cleanup_8:
	sysdev_remove_file(&ecm_db_sys_dev, &attr_host_count);
task_cleanup_7:
	sysdev_remove_file(&ecm_db_sys_dev, &attr_connection_count);
task_cleanup_6:
	unregister_chrdev(ecm_db_dev_major_id, ecm_db_sysclass.name);
task_cleanup_5:
	sysdev_remove_file(&ecm_db_sys_dev, &attr_terminate);
task_cleanup_4:
	sysdev_remove_file(&ecm_db_sys_dev, &attr_state_dev_major);
task_cleanup_3:
	sysdev_unregister(&ecm_db_sys_dev);
task_cleanup_2:
	sysdev_class_unregister(&ecm_db_sysclass);
task_cleanup_1:

	module_put(THIS_MODULE);
	return result;
}

/*
 * ecm_db_init()
 */
static int __init ecm_db_init(void)
{
	DEBUG_INFO("ECM Module init\n");

	/*
	 * Initialise our global database lock
	 */
	spin_lock_init(&ecm_db_lock);

	/*
	 * Create a thread to handle the start/stop of the database.
	 * NOTE: We use a thread as some things we need to do cannot be done in this context
	 */
	ecm_db_thread = kthread_create(ecm_db_thread_fn, NULL, "%s", "ecm_db");
	if (!ecm_db_thread) {
		return -EINVAL;
	}
	wake_up_process(ecm_db_thread);
	return 0;
}

/*
 * ecm_db_exit()
 */
static void __exit ecm_db_exit(void)
{
	DEBUG_INFO("ECM DB Module exit\n");
	DEBUG_ASSERT(!ecm_db_thread_refs, "Thread has refs %d\n", ecm_db_thread_refs);
}

module_init(ecm_db_init)
module_exit(ecm_db_exit)

MODULE_AUTHOR("Qualcomm Atheros, Inc.");
MODULE_DESCRIPTION("ECM Database");
#ifdef MODULE_LICENSE
MODULE_LICENSE("Dual BSD/GPL");
#endif
