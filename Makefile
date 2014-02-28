##########################################################################
# Copyright (c) 2014, The Linux Foundation. All rights reserved.
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

obj-m += ecm_classifier_hyfi.o
obj-m += ecm_classifier_nl.o
obj-m += ecm_tracker_udp.o
obj-m += ecm_tracker_tcp.o
obj-m += ecm_tracker_datagram.o
obj-m += ecm_tracker.o
obj-m += ecm_front_end_ipv4.o
obj-m += ecm_front_end_ipv6.o
obj-m += ecm_db.o
obj-m += ecm_classifier_default.o
obj-m += ecm_conntrack_notifier.o
obj-m += ecm_interface.o
obj-m += ecm_bond_notifier.o

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

#
# Include paths added for bridge and NSS header files
#
ccflags-y += -I$(TOPDIR)/qca/src/linux/net/bridge
ccflags-y += -I$(TOPDIR)/qca/src/qca-nss-drv
ccflags-y += -I$(TOPDIR)/qca/src/qca-hyfi-bridge/hyfi-netfilter

obj ?= .

