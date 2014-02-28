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

/*
 * Bridge device macros
 */
#define ecm_front_end_is_bridge_port(dev) (dev && (dev->priv_flags & IFF_BRIDGE_PORT))
#define ecm_front_end_is_bridge_device(dev) (dev->priv_flags & IFF_EBRIDGE)

/*
 * LAN Aggregation device macros
 */
#define ecm_front_end_is_lag_master(dev) ((dev->flags & IFF_MASTER)	\
							 && (dev->priv_flags & IFF_BONDING))
#define ecm_front_end_is_lag_slave(dev)	((dev->flags & IFF_SLAVE)	\
							 && (dev->priv_flags & IFF_BONDING))


/*
 * Front end methods
 */
struct ecm_front_end_connection_instance;
typedef void (*ecm_front_end_connection_decelerate_method_t)(struct ecm_front_end_connection_instance *feci);
typedef void (*ecm_front_end_connection_accel_state_get_method_t)(struct ecm_front_end_connection_instance *feci, ecm_classifier_acceleration_mode_t *accel_mode, int *count, int *limit, bool *can_accel);
typedef void (*ecm_front_end_connection_ref_method_t)(struct ecm_front_end_connection_instance *feci);
typedef int (*ecm_front_end_connection_deref_callback_t)(struct ecm_front_end_connection_instance *feci);
typedef void (*ecm_front_end_connection_accel_count_reset_method_t)(struct ecm_front_end_connection_instance *feci);
typedef void (*ecm_front_end_connection_accel_ceased_method_t)(struct ecm_front_end_connection_instance *feci);
typedef int (*ecm_front_end_connection_xml_state_get_callback_t)(struct ecm_front_end_connection_instance *feci, char *buf, int buf_sz);
											/* Get XML state output, buf has buf_sz bytes available.  Returns number of bytes written.
											 * Function has failed if the return is (<= 0) || (return value == buf_sz).
											 * The return code is compatible with snprintf().
											 */

/*
 * Connection front end instance
 *	Each new connection requires it to also have one of these to maintain front end specific information and operations
 */
struct ecm_front_end_connection_instance {
	ecm_front_end_connection_ref_method_t ref;				/* Ref the instance */
	ecm_front_end_connection_deref_callback_t deref;			/* Deref the instance */
	ecm_front_end_connection_decelerate_method_t decelerate;		/* Decelerate a connection */
	ecm_front_end_connection_accel_state_get_method_t accel_state_get;	/* Get the acceleration state */
	ecm_front_end_connection_accel_count_reset_method_t accel_count_reset;	/* Reset acceleration count */
	ecm_front_end_connection_accel_ceased_method_t accel_ceased;		/* Acceleration has stopped */
	ecm_front_end_connection_xml_state_get_callback_t xml_state_get;	/* Obtain XML formatted state for this object */
};

