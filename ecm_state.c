/*
 **************************************************************************
 * Copyright (c) 2015, The Linux Foundation.  All rights reserved.
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

#include <linux/version.h>
#include <linux/types.h>
#include <linux/ip.h>
#include <linux/module.h>
#include <linux/sysctl.h>
#include <linux/kthread.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <asm/unaligned.h>
#include <asm/uaccess.h>	/* for put_user */
#include <linux/inet.h>
#include <linux/ipv6.h>
#include <linux/netfilter_bridge.h>

/*
 * Debug output levels
 * 0 = OFF
 * 1 = ASSERTS / ERRORS
 * 2 = 1 + WARN
 * 3 = 2 + INFO
 * 4 = 3 + TRACE
 */
#define DEBUG_LEVEL ECM_STATE_DEBUG_LEVEL

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
#define ECM_STATE_FILE_INSTANCE_MAGIC 0xB3FE

/*
 * System device linkage
 */
static struct device ecm_state_dev;				/* System device linkage */

/*
 * Locking of the state - concurrency control
 */
static spinlock_t ecm_state_lock;					/* Protect the table from SMP access. */

/*
 * Character device stuff - used to communicate status back to user space
 */
#define ECM_STATE_FILE_BUFFER_SIZE 8192
static int ecm_state_dev_major_id = 0;			/* Major ID of registered char dev from which we can dump out state to userspace */

#define ECM_STATE_FILE_OUTPUT_CONNECTIONS 1
#define ECM_STATE_FILE_OUTPUT_MAPPINGS 2
#define ECM_STATE_FILE_OUTPUT_HOSTS 4
#define ECM_STATE_FILE_OUTPUT_NODES 8
#define ECM_STATE_FILE_OUTPUT_INTERFACES 16
#define ECM_STATE_FILE_OUTPUT_CONNECTIONS_CHAIN 32
#define ECM_STATE_FILE_OUTPUT_MAPPINGS_CHAIN 64
#define ECM_STATE_FILE_OUTPUT_HOSTS_CHAIN 128
#define ECM_STATE_FILE_OUTPUT_NODES_CHAIN 256
#define ECM_STATE_FILE_OUTPUT_INTERFACES_CHAIN 512
#define ECM_STATE_FILE_OUTPUT_PROTOCOL_COUNTS 1024
#define ECM_STATE_FILE_OUTPUT_CLASSIFIER_TYPE_ASSIGNMENTS 2048

/*
 * Assistive flags for classifier connection type assignments
 */
#define ECM_STATE_FILE_CTA_FLAG_ELEMENT_START_UNWRITTEN 1
#define ECM_STATE_FILE_CTA_FLAG_CONTENT_UNWRITTEN 2
#define ECM_STATE_FILE_CTA_FLAG_ELEMENT_END_UNWRITTEN 4

/*
 * struct ecm_state_file_instance
 *	Structure used as state per open instance of our db state file
 */
struct ecm_state_file_instance {
	int output_mask;				/* The content types wanted by the user */
	struct ecm_db_connection_instance *ci;		/* All connections list iterator */
	struct ecm_db_mapping_instance *mi;		/* All mappings list iterator */
	struct ecm_db_host_instance *hi;		/* All hosts list iterator */
	struct ecm_db_node_instance *ni;		/* All nodes list iterator */
	struct ecm_db_iface_instance *ii;		/* All interfaces list iterator */
	struct ecm_db_connection_instance *classifier_type_assignments[ECM_CLASSIFIER_TYPES];
							/* Classifier type connection assignments iterator, one for each classifier type */
	int classifier_type_assignments_flags[ECM_CLASSIFIER_TYPES];
							/* Classifier type connection assignments flags to assist the iteration */
	int connection_hash_index;			/* Connection hash table lengths iterator */
	int mapping_hash_index;				/* Mapping hash table lengths iterator */
	int host_hash_index;				/* Host hash table lengths iterator */
	int node_hash_index;				/* Node hash table lengths iterator */
	int iface_hash_index;				/* Interface hash table lengths iterator */
	int protocol;					/* Protocol connection count iterator */
	bool doc_start_written;				/* Has xml doc opening element been written? */
	bool doc_end_written;				/* Has xml doc closing element been written? */
	char msg_buffer[ECM_STATE_FILE_BUFFER_SIZE];	/* Used to hold the current state message being output */
	char *msgp;					/* Points into the msg buffer as we output it piece by piece */
	int msg_len;					/* Length of the buffer still to be written out */
#if (DEBUG_LEVEL > 0)
	uint16_t magic;
#endif
};
static int ecm_state_file_output_mask = ECM_STATE_FILE_OUTPUT_CONNECTIONS;
							/* Bit mask specifies which data to output in the state file */

/*
 * ecm_db_get_state_dev_major()
 */
static ssize_t ecm_db_get_state_dev_major(struct device *dev,
				  struct device_attribute *attr,
				  char *buf)
{
	ssize_t count;
	int major;

	spin_lock_bh(&ecm_state_lock);
	major = ecm_state_dev_major_id;
	spin_unlock_bh(&ecm_state_lock);

	count = snprintf(buf, (ssize_t)PAGE_SIZE, "%d\n", major);

	return count;
}

/*
 * ecm_db_get_state_file_output_mask()
 */
static ssize_t ecm_db_get_state_file_output_mask(struct device *dev,
				  struct device_attribute *attr,
				  char *buf)
{
	ssize_t count;
	int num;

	/*
	 * Operate under our locks
	 */
	spin_lock_bh(&ecm_state_lock);
	num = ecm_state_file_output_mask;
	spin_unlock_bh(&ecm_state_lock);

	count = snprintf(buf, (ssize_t)PAGE_SIZE, "%d\n", num);
	return count;
}

/*
 * ecm_db_set_state_file_output_mask()
 */
static ssize_t ecm_db_set_state_file_output_mask(struct device *dev,
				  struct device_attribute *attr,
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
	DEBUG_TRACE("ecm_state_file_output_mask = %x\n", num);

	/*
	 * Operate under our locks
	 */
	spin_lock_bh(&ecm_state_lock);
	ecm_state_file_output_mask = num;
	spin_unlock_bh(&ecm_state_lock);

	return count;
}

/*
 * SysFS attributes for the default classifier itself.
 */
static DEVICE_ATTR(state_dev_major, 0444, ecm_db_get_state_dev_major, NULL);
static DEVICE_ATTR(state_file_output_mask, 0644, ecm_db_get_state_file_output_mask, ecm_db_set_state_file_output_mask);

/*
 * System device attribute array.
 */
static struct device_attribute *ecm_state_attrs[] = {
	&dev_attr_state_dev_major,
	&dev_attr_state_file_output_mask,
};

/*
 * Sub system node of the ECM DB State
 * Sys device control points can be found at /sys/devices/system/ecm_state/ecm_stateX/
 */
static struct bus_type ecm_state_subsys = {
	.name = "ecm_state",
	.dev_name = "ecm_state",
};

/*
 * ecm_state_dev_release()
 *	This is a dummy release function for device.
 */
static void ecm_state_dev_release(struct device *dev)
{

}

/*
 * ecm_state_char_dev_conn_msg_prep()
 *	Prepare a connection message
 */
static bool ecm_state_char_dev_conn_msg_prep(struct ecm_state_file_instance *sfi)
{
	int msg_len;

	DEBUG_TRACE("%p: Prep conn msg for %p\n", sfi, sfi->ci);

	/*
	 * Use fresh buffer
	 */
	sfi->msgp = sfi->msg_buffer;

	/*
	 * Prep the message
	 */
	msg_len = ecm_db_connection_xml_state_get(sfi->ci, sfi->msgp, ECM_STATE_FILE_BUFFER_SIZE);

	if ((msg_len <= 0) || (msg_len >= ECM_STATE_FILE_BUFFER_SIZE)) {
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
 * ecm_state_char_dev_mapping_msg_prep()
 *	Prepare a mapping message
 */
static bool ecm_state_char_dev_mapping_msg_prep(struct ecm_state_file_instance *sfi)
{
	int msg_len;

	DEBUG_TRACE("%p: Prep mapping msg for %p\n", sfi, sfi->mi);

	/*
	 * Use fresh buffer
	 */
	sfi->msgp = sfi->msg_buffer;

	/*
	 * Prep the message
	 */
	msg_len = ecm_db_mapping_xml_state_get(sfi->mi, sfi->msgp, ECM_STATE_FILE_BUFFER_SIZE);

	if ((msg_len <= 0) || (msg_len >= ECM_STATE_FILE_BUFFER_SIZE)) {
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
 * ecm_state_char_dev_host_msg_prep()
 *	Prepare a host message
 */
static bool ecm_state_char_dev_host_msg_prep(struct ecm_state_file_instance *sfi)
{
	int msg_len;

	DEBUG_TRACE("%p: Prep host msg for %p\n", sfi, sfi->hi);

	/*
	 * Use fresh buffer
	 */
	sfi->msgp = sfi->msg_buffer;

	/*
	 * Prep the message
	 */
	msg_len = ecm_db_host_xml_state_get(sfi->hi, sfi->msgp, ECM_STATE_FILE_BUFFER_SIZE);

	if ((msg_len <= 0) || (msg_len >= ECM_STATE_FILE_BUFFER_SIZE)) {
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
 * ecm_state_char_dev_nod__msg_prep()
 *	Prepare a node message
 */
static bool ecm_state_char_dev_node_msg_prep(struct ecm_state_file_instance *sfi)
{
	int msg_len;

	DEBUG_TRACE("%p: Prep node msg for %p\n", sfi, sfi->ni);

	/*
	 * Use fresh buffer
	 */
	sfi->msgp = sfi->msg_buffer;

	/*
	 * Prep the message
	 */
	msg_len = ecm_db_node_xml_state_get(sfi->ni, sfi->msgp, ECM_STATE_FILE_BUFFER_SIZE);

	if ((msg_len <= 0) || (msg_len >= ECM_STATE_FILE_BUFFER_SIZE)) {
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
 * ecm_state_char_dev_iface_msg_prep()
 *	Prepare an interface message
 */
static bool ecm_state_char_dev_iface_msg_prep(struct ecm_state_file_instance *sfi)
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
	msg_len = ecm_db_iface_xml_state_get(sfi->ii, sfi->msgp, ECM_STATE_FILE_BUFFER_SIZE);

	if ((msg_len <= 0) || (msg_len >= ECM_STATE_FILE_BUFFER_SIZE)) {
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
 * ecm_state_char_dev_conn_chain_msg_prep()
 *	Generate an conn hash table chain message
 */
static bool ecm_state_char_dev_conn_chain_msg_prep(struct ecm_state_file_instance *sfi)
{
	int chain_len;
	int msg_len;
	DEBUG_TRACE("%p: Prep conn chain msg\n", sfi);

	/*
	 * Get hash table chain length
	 */
	chain_len = ecm_db_connection_hash_table_lengths_get(sfi->connection_hash_index);

	/*
	 * Use fresh buffer
	 */
	sfi->msgp = sfi->msg_buffer;

	/*
	 * Create a small xml stats block like:
	 * <conn_chain hash_index="" chain_length=""/>
	 */
	msg_len = snprintf(sfi->msgp, ECM_STATE_FILE_BUFFER_SIZE,
			"<conn_chain hash_index=\"%d\" chain_length=\"%d\"/>\n",
			sfi->connection_hash_index,
			chain_len);

	if ((msg_len <= 0) || (msg_len >= ECM_STATE_FILE_BUFFER_SIZE)) {
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
 * ecm_state_char_dev_mapping_chain_msg_prep()
 *	Generate an mapping hash table chain message
 */
static bool ecm_state_char_dev_mapping_chain_msg_prep(struct ecm_state_file_instance *sfi)
{
	int chain_len;
	int msg_len;
	DEBUG_TRACE("%p: Prep mapping chain msg\n", sfi);

	/*
	 * Get hash table chain length
	 */
	chain_len = ecm_db_mapping_hash_table_lengths_get(sfi->mapping_hash_index);

	/*
	 * Use fresh buffer
	 */
	sfi->msgp = sfi->msg_buffer;

	/*
	 * Create a small xml stats block like:
	 * <mapping_chain hash_index="" chain_length=""/>
	 */
	msg_len = snprintf(sfi->msgp, ECM_STATE_FILE_BUFFER_SIZE,
			"<mapping_chain hash_index=\"%d\" chain_length=\"%d\"/>\n",
			sfi->mapping_hash_index,
			chain_len);

	if ((msg_len <= 0) || (msg_len >= ECM_STATE_FILE_BUFFER_SIZE)) {
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
 * ecm_state_char_dev_host_chain_msg_prep()
 *	Generate an host hash table chain message
 */
static bool ecm_state_char_dev_host_chain_msg_prep(struct ecm_state_file_instance *sfi)
{
	int chain_len;
	int msg_len;
	DEBUG_TRACE("%p: Prep host chain msg\n", sfi);

	/*
	 * Get hash table chain length
	 */
	chain_len = ecm_db_host_hash_table_lengths_get(sfi->host_hash_index);

	/*
	 * Use fresh buffer
	 */
	sfi->msgp = sfi->msg_buffer;

	/*
	 * Create a small xml stats block like:
	 * <host_chain hash_index="" chain_length=""/>
	 */
	msg_len = snprintf(sfi->msgp, ECM_STATE_FILE_BUFFER_SIZE,
			"<host_chain hash_index=\"%d\" chain_length=\"%d\"/>\n",
			sfi->host_hash_index,
			chain_len);

	if ((msg_len <= 0) || (msg_len >= ECM_STATE_FILE_BUFFER_SIZE)) {
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
 * ecm_state_char_dev_node_chain_msg_prep()
 *	Generate an node hash table chain message
 */
static bool ecm_state_char_dev_node_chain_msg_prep(struct ecm_state_file_instance *sfi)
{
	int chain_len;
	int msg_len;
	DEBUG_TRACE("%p: Prep node chain msg\n", sfi);

	/*
	 * Get hash table chain length
	 */
	chain_len = ecm_db_node_hash_table_lengths_get(sfi->node_hash_index);

	/*
	 * Use fresh buffer
	 */
	sfi->msgp = sfi->msg_buffer;

	/*
	 * Create a small xml stats block like:
	 * <node_chain hash_index="" chain_length=""/>
	 */
	msg_len = snprintf(sfi->msgp, ECM_STATE_FILE_BUFFER_SIZE,
			"<node_chain hash_index=\"%d\" chain_length=\"%d\"/>\n",
			sfi->node_hash_index,
			chain_len);

	if ((msg_len <= 0) || (msg_len >= ECM_STATE_FILE_BUFFER_SIZE)) {
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
 * ecm_state_char_dev_iface_chain_msg_prep()
 *	Generate an interface hash table chain message
 */
static bool ecm_state_char_dev_iface_chain_msg_prep(struct ecm_state_file_instance *sfi)
{
	int chain_len;
	int msg_len;
	DEBUG_TRACE("%p: Prep iface chain msg\n", sfi);

	/*
	 * Get hash table chain length
	 */
	chain_len = ecm_db_iface_hash_table_lengths_get(sfi->iface_hash_index);

	/*
	 * Use fresh buffer
	 */
	sfi->msgp = sfi->msg_buffer;

	/*
	 * Create a small xml stats block like:
	 * <iface_chain hash_index="" chain_length=""/>
	 */
	msg_len = snprintf(sfi->msgp, ECM_STATE_FILE_BUFFER_SIZE,
			"<iface_chain hash_index=\"%d\" chain_length=\"%d\"/>\n",
			sfi->iface_hash_index,
			chain_len);

	if ((msg_len <= 0) || (msg_len >= ECM_STATE_FILE_BUFFER_SIZE)) {
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
 * ecm_state_char_dev_protocol_count_msg_prep()
 *	Generate a protocol usage message
 */
static bool ecm_state_char_dev_protocol_count_msg_prep(struct ecm_state_file_instance *sfi)
{
	int count;
	int msg_len;
	DEBUG_TRACE("%p: Prep protocol msg\n", sfi);

	/*
	 * Get protocol connection total count
	 */
	count = ecm_db_connection_count_by_protocol_get(sfi->protocol);

	/*
	 * Use fresh buffer
	 */
	sfi->msgp = sfi->msg_buffer;

	/*
	 * Create a small xml stats block like:
	 * <conn_proto_count protocol="" count=""/>
	 */
	msg_len = snprintf(sfi->msgp, ECM_STATE_FILE_BUFFER_SIZE,
			"<conn_proto_count protocol=\"%d\" count=\"%d\"/>\n",
			sfi->protocol,
			count);

	if ((msg_len <= 0) || (msg_len >= ECM_STATE_FILE_BUFFER_SIZE)) {
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
 * ecm_state_char_dev_cta_msg_prep()
 *	Generate a classifier type assignment message
 */
static bool ecm_state_char_dev_cta_msg_prep(struct ecm_state_file_instance *sfi, ecm_classifier_type_t ca_type)
{
	int msg_len;
	struct ecm_db_connection_instance *ci;
	int flags;

	DEBUG_TRACE("%p: Prep classifier type assignment msg: %d\n", sfi, ca_type);

	/*
	 * Use fresh buffer
	 */
	sfi->msgp = sfi->msg_buffer;

	/*
	 * Output message according to where we are with iteration.
	 * Output element start?
	 * We are producing an element like:
	 * <classifier_conn_type_assignment ca_type="2">
	 *	<connection serial="1625"/>
	 *	...
	 * </classifier_conn_type_assignment>
	 */
	flags = sfi->classifier_type_assignments_flags[ca_type];
	if (flags & ECM_STATE_FILE_CTA_FLAG_ELEMENT_START_UNWRITTEN) {
		msg_len = snprintf(sfi->msgp, ECM_STATE_FILE_BUFFER_SIZE,
				"<classifier_conn_type_assignment ca_type=\"%d\">\n",
				ca_type);
		if ((msg_len <= 0) || (msg_len >= ECM_STATE_FILE_BUFFER_SIZE)) {
			return false;
		}
		sfi->msg_len = msg_len;
		DEBUG_TRACE("%p: Prepped msg %s\n", sfi, sfi->msgp);

		sfi->classifier_type_assignments_flags[ca_type] &= ~ECM_STATE_FILE_CTA_FLAG_ELEMENT_START_UNWRITTEN;
		return true;
	}

	/*
	 * Output connection detail, if any further to output for this type.
	 */
	ci = sfi->classifier_type_assignments[ca_type];
	if (ci) {
		uint32_t serial;

		serial = ecm_db_connection_serial_get(ci);
		msg_len = snprintf(sfi->msgp, ECM_STATE_FILE_BUFFER_SIZE,
				"<connection serial=\"%u\"/>\n",
				serial);
		if ((msg_len <= 0) || (msg_len >= ECM_STATE_FILE_BUFFER_SIZE)) {
			return false;
		}
		sfi->msg_len = msg_len;
		DEBUG_TRACE("%p: Prepped msg %s\n", sfi, sfi->msgp);

		/*
		 * Prep next connection for when we are called again, releasing this one.
		 */
		if (!(sfi->classifier_type_assignments[ca_type] = ecm_db_connection_by_classifier_type_assignment_get_and_ref_next(ci, ca_type))) {
			sfi->classifier_type_assignments_flags[ca_type] &= ~ECM_STATE_FILE_CTA_FLAG_CONTENT_UNWRITTEN;
		}
		ecm_db_connection_by_classifier_type_assignment_deref(ci, ca_type);
		return true;
	}

	/*
	 * Output closing element?
	 */
	if (flags & ECM_STATE_FILE_CTA_FLAG_ELEMENT_END_UNWRITTEN) {
		msg_len = snprintf(sfi->msgp, ECM_STATE_FILE_BUFFER_SIZE,
				"</classifier_conn_type_assignment>\n");
		if ((msg_len <= 0) || (msg_len >= ECM_STATE_FILE_BUFFER_SIZE)) {
			return false;
		}
		sfi->msg_len = msg_len;
		DEBUG_TRACE("%p: Prepped msg %s\n", sfi, sfi->msgp);

		sfi->classifier_type_assignments_flags[ca_type] &= ~ECM_STATE_FILE_CTA_FLAG_ELEMENT_END_UNWRITTEN;
		return true;
	}

	return true;
}

/*
 * ecm_state_file_classifier_type_assignments_release()
 *	Releases any uniterated classifier assignments
 */
static void ecm_state_file_classifier_type_assignments_release(struct ecm_state_file_instance *sfi)
{
	ecm_classifier_type_t ca_type;

	for (ca_type = 0; ca_type < ECM_CLASSIFIER_TYPES; ++ca_type) {
		struct ecm_db_connection_instance *ci;

		ci = sfi->classifier_type_assignments[ca_type];
		if (!ci) {
			continue;
		}

		ecm_db_connection_by_classifier_type_assignment_deref(ci, ca_type);
	}
}

/*
 * ecm_state_char_device_open()
 *	Opens the special char device file which we use to dump our state.
 */
static int ecm_state_char_device_open(struct inode *inode, struct file *file)
{
	struct ecm_state_file_instance *sfi;

	DEBUG_INFO("State open\n");

	/*
	 * Allocate state information for the reading
	 */
	DEBUG_ASSERT(file->private_data == NULL, "unexpected double open: %p?\n", file->private_data);

	sfi = (struct ecm_state_file_instance *)kzalloc(sizeof(struct ecm_state_file_instance), GFP_ATOMIC | __GFP_NOWARN);
	if (!sfi) {
		return -ENOMEM;
	}
	DEBUG_SET_MAGIC(sfi, ECM_STATE_FILE_INSTANCE_MAGIC);
	file->private_data = sfi;

	/*
	 * Snapshot output mask for this file
	 */
	spin_lock_bh(&ecm_state_lock);
	sfi->output_mask = ecm_state_file_output_mask;
	spin_unlock_bh(&ecm_state_lock);

	/*
	 * Get the first indicies for hash and protocol stats should they be needed.
	 * NOTE: There are no references held here so it does not matter to get them all even if they are not wanted.
	 */
	sfi->connection_hash_index = ecm_db_connection_hash_index_get_first();
	sfi->mapping_hash_index = ecm_db_mapping_hash_index_get_first();
	sfi->host_hash_index = ecm_db_host_hash_index_get_first();
	sfi->node_hash_index = ecm_db_node_hash_index_get_first();
	sfi->iface_hash_index = ecm_db_iface_hash_index_get_first();
	sfi->protocol = ecm_db_protocol_get_first();

	/*
	 * Take references to each object list that we are going to generate state for.
	 */
	if (sfi->output_mask & ECM_STATE_FILE_OUTPUT_CONNECTIONS) {
		sfi->ci = ecm_db_connections_get_and_ref_first();
	}
	if (sfi->output_mask & ECM_STATE_FILE_OUTPUT_MAPPINGS) {
		sfi->mi = ecm_db_mappings_get_and_ref_first();
	}
	if (sfi->output_mask & ECM_STATE_FILE_OUTPUT_HOSTS) {
		sfi->hi = ecm_db_hosts_get_and_ref_first();
	}
	if (sfi->output_mask & ECM_STATE_FILE_OUTPUT_NODES) {
		sfi->ni = ecm_db_nodes_get_and_ref_first();
	}
	if (sfi->output_mask & ECM_STATE_FILE_OUTPUT_INTERFACES) {
		sfi->ii = ecm_db_interfaces_get_and_ref_first();
	}
	if (sfi->output_mask & ECM_STATE_FILE_OUTPUT_CLASSIFIER_TYPE_ASSIGNMENTS) {
		ecm_classifier_type_t ca_type;

		/*
		 * Iterate all classifier type assignments.
		 * Hold the head of each list to start us off on our iterating process.
		 */
		for (ca_type = 0; ca_type < ECM_CLASSIFIER_TYPES; ++ca_type) {
			if ((sfi->classifier_type_assignments[ca_type] = ecm_db_connection_by_classifier_type_assignment_get_and_ref_first(ca_type))) {
				/*
				 * There is some content to write for this ca_type
				 */
				sfi->classifier_type_assignments_flags[ca_type] =
						ECM_STATE_FILE_CTA_FLAG_ELEMENT_START_UNWRITTEN | ECM_STATE_FILE_CTA_FLAG_CONTENT_UNWRITTEN | ECM_STATE_FILE_CTA_FLAG_ELEMENT_END_UNWRITTEN;

			}
		}
	}

	DEBUG_INFO("State opened %p\n", sfi);

	return 0;
}

/*
 * ecm_state_char_device_release()
 *	Called when a process closes the device file.
 */
static int ecm_state_char_device_release(struct inode *inode, struct file *file)
{
	struct ecm_state_file_instance *sfi;

	sfi = (struct ecm_state_file_instance *)file->private_data;
	DEBUG_CHECK_MAGIC(sfi, ECM_STATE_FILE_INSTANCE_MAGIC, "%p: magic failed", sfi);
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
	ecm_state_file_classifier_type_assignments_release(sfi);

	DEBUG_CLEAR_MAGIC(sfi);
	kfree(sfi);

	return 0;
}

/*
 * ecm_state_char_device_read()
 *	Called to read the state
 */
static ssize_t ecm_state_char_device_read(struct file *file,	/* see include/linux/fs.h   */
			   char *buffer,				/* buffer to fill with data */
			   size_t length,				/* length of the buffer     */
			   loff_t *offset)				/* Doesn't apply - this is a char file */
{
	struct ecm_state_file_instance *sfi;
	int bytes_read = 0;						/* Number of bytes actually written to the buffer */
	ecm_classifier_type_t ca_type;

	sfi = (struct ecm_state_file_instance *)file->private_data;
	DEBUG_CHECK_MAGIC(sfi, ECM_STATE_FILE_INSTANCE_MAGIC, "%p: magic failed", sfi);
	DEBUG_TRACE("%p: State read up to length %d bytes\n", sfi, length);

	/*
	 * If there is still some message remaining to be output then complete that first
	 */
	if (sfi->msg_len) {
		goto char_device_read_output;
	}

	if (!sfi->doc_start_written) {
		sfi->msgp = sfi->msg_buffer;
		sfi->msg_len = sprintf(sfi->msgp, "<ecm_state>\n");
		sfi->doc_start_written = true;
		goto char_device_read_output;
	}

	if (sfi->ci) {
		struct ecm_db_connection_instance *cin;
		if (!ecm_state_char_dev_conn_msg_prep(sfi)) {
			return -EIO;
		}

		/*
		 * Next connection for when we return
		 */
		cin = ecm_db_connection_get_and_ref_next(sfi->ci);
		ecm_db_connection_deref(sfi->ci);
		sfi->ci = cin;

		goto char_device_read_output;
	}

	if (sfi->mi) {
		struct ecm_db_mapping_instance *min;
		if (!ecm_state_char_dev_mapping_msg_prep(sfi)) {
			return -EIO;
		}

		/*
		 * Next mapping for when we return
		 */
		min = ecm_db_mapping_get_and_ref_next(sfi->mi);
		ecm_db_mapping_deref(sfi->mi);
		sfi->mi = min;

		goto char_device_read_output;
	}

	if (sfi->hi) {
		struct ecm_db_host_instance *hin;
		if (!ecm_state_char_dev_host_msg_prep(sfi)) {
			return -EIO;
		}

		/*
		 * Next host for when we return
		 */
		hin = ecm_db_host_get_and_ref_next(sfi->hi);
		ecm_db_host_deref(sfi->hi);
		sfi->hi = hin;

		goto char_device_read_output;
	}

	if (sfi->ni) {
		struct ecm_db_node_instance *nin;
		if (!ecm_state_char_dev_node_msg_prep(sfi)) {
			return -EIO;
		}

		/*
		 * Next node for when we return
		 */
		nin = ecm_db_node_get_and_ref_next(sfi->ni);
		ecm_db_node_deref(sfi->ni);
		sfi->ni = nin;

		goto char_device_read_output;
	}

	if (sfi->ii) {
		struct ecm_db_iface_instance *iin;
		if (!ecm_state_char_dev_iface_msg_prep(sfi)) {
			return -EIO;
		}

		/*
		 * Next iface for when we return
		 */
		iin = ecm_db_interface_get_and_ref_next(sfi->ii);
		ecm_db_iface_deref(sfi->ii);
		sfi->ii = iin;

		goto char_device_read_output;
	}

	if ((sfi->output_mask & ECM_STATE_FILE_OUTPUT_CONNECTIONS_CHAIN) && (sfi->connection_hash_index >= 0)) {
		if (!ecm_state_char_dev_conn_chain_msg_prep(sfi)) {
			return -EIO;
		}
		sfi->connection_hash_index = ecm_db_connection_hash_index_get_next(sfi->connection_hash_index);
		goto char_device_read_output;
	}

	if ((sfi->output_mask & ECM_STATE_FILE_OUTPUT_MAPPINGS_CHAIN) && (sfi->mapping_hash_index >= 0)) {
		if (!ecm_state_char_dev_mapping_chain_msg_prep(sfi)) {
			return -EIO;
		}
		sfi->mapping_hash_index = ecm_db_mapping_hash_index_get_next(sfi->mapping_hash_index);
		goto char_device_read_output;
	}

	if ((sfi->output_mask & ECM_STATE_FILE_OUTPUT_HOSTS_CHAIN) && (sfi->host_hash_index >= 0)) {
		if (!ecm_state_char_dev_host_chain_msg_prep(sfi)) {
			return -EIO;
		}
		sfi->host_hash_index = ecm_db_host_hash_index_get_next(sfi->host_hash_index);
		goto char_device_read_output;
	}

	if ((sfi->output_mask & ECM_STATE_FILE_OUTPUT_NODES_CHAIN) && (sfi->node_hash_index >= 0)) {
		if (!ecm_state_char_dev_node_chain_msg_prep(sfi)) {
			return -EIO;
		}
		sfi->node_hash_index = ecm_db_node_hash_index_get_next(sfi->node_hash_index);
		goto char_device_read_output;
	}

	if ((sfi->output_mask & ECM_STATE_FILE_OUTPUT_INTERFACES_CHAIN) && (sfi->iface_hash_index >= 0)) {
		if (!ecm_state_char_dev_iface_chain_msg_prep(sfi)) {
			return -EIO;
		}
		sfi->iface_hash_index = ecm_db_iface_hash_index_get_next(sfi->iface_hash_index);
		goto char_device_read_output;
	}

	if ((sfi->output_mask & ECM_STATE_FILE_OUTPUT_PROTOCOL_COUNTS) && (sfi->protocol >= 0)) {
		if (!ecm_state_char_dev_protocol_count_msg_prep(sfi)) {
			return -EIO;
		}
		sfi->protocol = ecm_db_protocol_get_next(sfi->protocol);
		goto char_device_read_output;
	}

	for (ca_type = 0; ca_type < ECM_CLASSIFIER_TYPES; ++ca_type) {
		int flags;

		flags = sfi->classifier_type_assignments_flags[ca_type];

		if (!flags) {
			/*
			 * Nothing further to write out for this ca_type
			 */
			continue;
		}
		if (!ecm_state_char_dev_cta_msg_prep(sfi, ca_type)) {
			return -EIO;
		}
		goto char_device_read_output;
	}

	if (!sfi->doc_end_written) {
		sfi->msgp = sfi->msg_buffer;
		sfi->msg_len = sprintf(sfi->msgp, "</ecm_state>\n");
		sfi->doc_end_written = true;
		goto char_device_read_output;
	}

	/*
	 * EOF
	 */
	return 0;

char_device_read_output:

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
 * ecm_state_char_device_write()
 */
static ssize_t ecm_state_char_device_write(struct file *filp, const char *buff, size_t len, loff_t * off)
{
	return -EINVAL;
}

/*
 * File operations used in the char device
 *	NOTE: The char device is a simple file that allows us to dump our connection tracking state
 */
static struct file_operations ecm_state_fops = {
	.read = ecm_state_char_device_read,
	.write = ecm_state_char_device_write,
	.open = ecm_state_char_device_open,
	.release = ecm_state_char_device_release
};

/*
 * ecm_state_init()
 */
int ecm_state_init(void)
{
	int result;
	int attr_index;
	DEBUG_INFO("ECM State init\n");

	/*
	 * Initialise our global lock
	 */
	spin_lock_init(&ecm_state_lock);

	/*
	 * Register system device subsystem
	 */
	result = subsys_system_register(&ecm_state_subsys, NULL);
	if (result) {
		DEBUG_ERROR("Failed to register subsystem %d\n", result);
		return result;
	}

	/*
	 * Register system device that represents us
	 */
	memset(&ecm_state_dev, 0, sizeof(ecm_state_dev));
	ecm_state_dev.id = 0;
	ecm_state_dev.bus = &ecm_state_subsys;
	ecm_state_dev.release = ecm_state_dev_release;
	result = device_register(&ecm_state_dev);
	if (result) {
		DEBUG_ERROR("Failed to register system device %d\n", result);
		goto init_cleanup_1;
	}

	/*
	 * Create files, one for each parameter supported
	 */
	for (attr_index = 0; attr_index < ARRAY_SIZE(ecm_state_attrs); attr_index++) {
		result = device_create_file(&ecm_state_dev, ecm_state_attrs[attr_index]);
		if (result) {
			DEBUG_ERROR("Failed to create attribute file %d\n", result);
			goto init_cleanup_2;
		}
	}

	/*
	 * Register a char device that we will use to provide a dump of our state
	 */
	result = register_chrdev(0, ecm_state_subsys.name, &ecm_state_fops);
	if (result < 0) {
                DEBUG_ERROR("Failed to register chrdev %d\n", result);
		goto init_cleanup_2;
	}
	ecm_state_dev_major_id = result;
	DEBUG_TRACE("registered chr dev major id assigned %d\n", ecm_state_dev_major_id);

	return 0;

init_cleanup_2:
	/*
	 * Unwind the attributes we have created so far
	 */
	while (--attr_index >= 0) {
		device_remove_file(&ecm_state_dev, ecm_state_attrs[attr_index]);
	}
	device_unregister(&ecm_state_dev);
init_cleanup_1:
	bus_unregister(&ecm_state_subsys);

	return result;
}
EXPORT_SYMBOL(ecm_state_init);

/*
 * ecm_state_exit()
 */
void ecm_state_exit(void)
{
	int attr_index;

	DEBUG_INFO("ECM State exit\n");

	unregister_chrdev(ecm_state_dev_major_id, ecm_state_subsys.name);

	for (attr_index = 0; attr_index < ARRAY_SIZE(ecm_state_attrs); attr_index++) {
		device_remove_file(&ecm_state_dev, ecm_state_attrs[attr_index]);
	}

	device_unregister(&ecm_state_dev);
	bus_unregister(&ecm_state_subsys);
}
EXPORT_SYMBOL(ecm_state_exit);

