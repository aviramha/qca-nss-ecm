##########################################################################
# Copyright (c) 2014-2015, The Linux Foundation. All rights reserved.
# Permission to use, copy, modify, and/or distribute this software for
# any purpose with or without fee is hereby granted, provided that the
# above copyright notice and this permission notice appear in all copies.
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
# OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
##########################################################################

# ###################################################
# Makefile for the QCA NSS ECM
# ###################################################

obj-m += ecm.o

ecm-y := \
	 ecm_tracker_udp.o \
	 ecm_tracker_tcp.o \
	 ecm_tracker_datagram.o \
	 ecm_tracker.o \
	 frontends/nss/ecm_nss_ipv4.o \
	 frontends/nss/ecm_nss_ported_ipv4.o \
	 ecm_db.o \
	 ecm_classifier_default.o \
	 ecm_conntrack_notifier.o \
	 ecm_interface.o \
	 ecm_init.o

# #############################################################################
# Define ECM_INTERFACE_BOND_ENABLE=y in order to enable
# Bonding / Link Aggregation support.
# #############################################################################
ifneq ($(findstring 3.4, $(KERNELVERSION)),)
ECM_INTERFACE_BOND_ENABLE=y
endif
ecm-$(ECM_INTERFACE_BOND_ENABLE) += ecm_bond_notifier.o
ccflags-$(ECM_INTERFACE_BOND_ENABLE) += -DECM_INTERFACE_BOND_ENABLE

# #############################################################################
# Define ECM_INTERFACE_PPP_ENABLE=y in order
# to enable support for PPP and, specifically, PPPoE acceleration.
# #############################################################################
ECM_INTERFACE_PPP_ENABLE=y
ccflags-$(ECM_INTERFACE_PPP_ENABLE) += -DECM_INTERFACE_PPP_ENABLE

# #############################################################################
# Define ECM_INTERFACE_SIT_ENABLE=y in order
# to enable support for SIT interface.
# #############################################################################
ifneq ($(findstring 3.4, $(KERNELVERSION)),)
ECM_INTERFACE_SIT_ENABLE=y
endif
ccflags-$(ECM_INTERFACE_SIT_ENABLE) += -DECM_INTERFACE_SIT_ENABLE

# #############################################################################
# Define ECM_INTERFACE_TUNIPIP6_ENABLE=y in order
# to enable support for TUNIPIP6 interface.
# #############################################################################
ifneq ($(findstring 3.4, $(KERNELVERSION)),)
ECM_INTERFACE_TUNIPIP6_ENABLE=y
endif
ccflags-$(ECM_INTERFACE_TUNIPIP6_ENABLE) += -DECM_INTERFACE_TUNIPIP6_ENABLE

# #############################################################################
# Define ECM_INTERFACE_VLAN_ENABLE=y in order to enable support for VLAN
# #############################################################################
ECM_INTERFACE_VLAN_ENABLE=y
ccflags-$(ECM_INTERFACE_VLAN_ENABLE) += -DECM_INTERFACE_VLAN_ENABLE

# #############################################################################
# Define ECM_INTERFACE_IPSEC_ENABLE=y in order to enable support for IPSEC
# #############################################################################
ECM_INTERFACE_IPSEC_ENABLE=y
ccflags-$(ECM_INTERFACE_IPSEC_ENABLE) += -DECM_INTERFACE_IPSEC_ENABLE

# #############################################################################
# Define ECM_FRONT_END_IPV6_ENABLE=y in order to enable IPv6 front end.
# #############################################################################
ECM_FRONT_END_IPV6_ENABLE=y
ecm-$(ECM_FRONT_END_IPV6_ENABLE) += frontends/nss/ecm_front_end_ipv6.o
ccflags-$(ECM_FRONT_END_IPV6_ENABLE) += -DECM_FRONT_END_IPV6_ENABLE

# #############################################################################
# Define ECM_CLASSIFIER_NL_ENABLE=y in order to enable NL classifier.
# #############################################################################
ifneq ($(findstring 3.4, $(KERNELVERSION)),)
ECM_CLASSIFIER_NL_ENABLE=y
endif
ecm-$(ECM_CLASSIFIER_NL_ENABLE) += ecm_classifier_nl.o
ccflags-$(ECM_CLASSIFIER_NL_ENABLE) += -DECM_CLASSIFIER_NL_ENABLE

# #############################################################################
# Define ECM_CLASSIFIER_DSCP_ENABLE=y in order to enable DSCP classifier.
# #############################################################################
ECM_CLASSIFIER_DSCP_ENABLE=y
ecm-$(ECM_CLASSIFIER_DSCP_ENABLE) += ecm_classifier_dscp.o
ccflags-$(ECM_CLASSIFIER_DSCP_ENABLE) += -DECM_CLASSIFIER_DSCP_ENABLE

# #############################################################################
# Define ECM_CLASSIFIER_HYFI_ENABLE=y in order to enable
# the Hy-Fi classifier in ECM. Currently disabled until the integration
# with Hy-Fi is completed.
# #############################################################################
ecm-$(ECM_CLASSIFIER_HYFI_ENABLE) += ecm_classifier_hyfi.o
ccflags-$(ECM_CLASSIFIER_HYFI_ENABLE) += -DECM_CLASSIFIER_HYFI_ENABLE

# #############################################################################
# Define ECM_NON_PORTED_SUPPORT_ENABLE=y in order to enable non-ported protocol.
# #############################################################################
ECM_NON_PORTED_SUPPORT_ENABLE=y
ecm-$(ECM_NON_PORTED_SUPPORT_ENABLE) += frontends/nss/ecm_nss_non_ported_ipv4.o
ccflags-$(ECM_NON_PORTED_SUPPORT_ENABLE) += -DECM_NON_PORTED_SUPPORT_ENABLE

# #############################################################################
# Define ECM_STATE_OUTPUT_ENABLE=y to support XML state output
# #############################################################################
ECM_STATE_OUTPUT_ENABLE=y
ecm-$(ECM_STATE_OUTPUT_ENABLE) += ecm_state.o
ccflags-$(ECM_STATE_OUTPUT_ENABLE) += -DECM_STATE_OUTPUT_ENABLE

# #############################################################################
# Debug flags, set these to = 0 if you want to disable all debugging for that
# file.
# By turning off debugs you gain maximum ECM performance.
# #############################################################################
ccflags-y += -DECM_CLASSIFIER_DSCP_DEBUG_LEVEL=1
ccflags-y += -DECM_CLASSIFIER_HYFI_DEBUG_LEVEL=1
ccflags-y += -DECM_CLASSIFIER_NL_DEBUG_LEVEL=1
ccflags-y += -DECM_CLASSIFIER_DEFAULT_DEBUG_LEVEL=1
ccflags-y += -DECM_DB_DEBUG_LEVEL=1
ccflags-y += -DECM_FRONT_END_IPV4_DEBUG_LEVEL=1
ccflags-y += -DECM_FRONT_END_IPV6_DEBUG_LEVEL=1
ccflags-y += -DECM_CONNTRACK_NOTIFIER_DEBUG_LEVEL=1
ccflags-y += -DECM_TRACKER_DEBUG_LEVEL=1
ccflags-y += -DECM_TRACKER_DATAGRAM_DEBUG_LEVEL=1
ccflags-y += -DECM_TRACKER_TCP_DEBUG_LEVEL=1
ccflags-y += -DECM_TRACKER_UDP_DEBUG_LEVEL=1
ccflags-y += -DECM_BOND_NOTIFIER_DEBUG_LEVEL=1
ccflags-y += -DECM_INTERFACE_DEBUG_LEVEL=1
ccflags-y += -DECM_NSS
ccflags-y += -DECM_STATE_DEBUG_LEVEL=1

ccflags-y += -I$(obj)/ -I$(obj)/frontends/include -I$(obj)/frontends/nss

obj ?= .

