/*
 **************************************************************************
 * Copyright (c) 2014-2015, The Linux Foundation.  All rights reserved.
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
#include <linux/module.h>
#include <linux/of.h>
#include <linux/debugfs.h>

#include "ecm_front_end_ipv4.h"

struct dentry *ecm_dentry;	/* Dentry object for top level ecm debugfs directory */

extern int ecm_db_init(struct dentry *dentry);
extern void ecm_db_connection_defunct_all(void);
extern void ecm_db_exit(void);

extern int ecm_classifier_default_init(struct dentry *dentry);
extern void ecm_classifier_default_exit(void);

#ifdef ECM_CLASSIFIER_NL_ENABLE
extern int ecm_classifier_nl_rules_init(struct dentry *dentry);
extern void ecm_classifier_nl_rules_exit(void);
#endif

#ifdef ECM_CLASSIFIER_HYFI_ENABLE
extern int ecm_classifier_hyfi_rules_init(struct dentry *dentry);
extern void ecm_classifier_hyfi_rules_exit(void);
#endif

extern int ecm_interface_init(void);
extern void ecm_interface_exit(void);

#ifdef ECM_INTERFACE_BOND_ENABLE
extern int ecm_bond_notifier_init(struct dentry *dentry);
extern void ecm_bond_notifier_stop(int);
extern void ecm_bond_notifier_exit(void);
#endif

extern int ecm_front_end_ipv4_init(struct dentry *dentry);
extern void ecm_front_end_ipv4_stop(int);
extern void ecm_front_end_ipv4_exit(void);

#ifdef ECM_IPV6_ENABLE
extern int ecm_front_end_ipv6_init(struct dentry *dentry);
extern void ecm_front_end_ipv6_stop(int);
extern void ecm_front_end_ipv6_exit(void);
#endif

extern int ecm_conntrack_notifier_init(struct dentry *dentry);
extern void ecm_conntrack_notifier_stop(int);
extern void ecm_conntrack_notifier_exit(void);

#ifdef ECM_CLASSIFIER_DSCP_ENABLE
extern int ecm_classifier_dscp_init(struct dentry *dentry);
extern void ecm_classifier_dscp_exit(void);
#endif

#ifdef ECM_STATE_OUTPUT_ENABLE
extern int ecm_state_init(struct dentry *dentry);
extern void ecm_state_exit(void);
#endif

#ifdef ECM_CLASSIFIER_PCC_ENABLE
extern int ecm_classifier_pcc_init(struct dentry *dentry);
extern void ecm_classifier_pcc_exit(void);
#endif

/*
 * ecm_init()
 */
static int __init ecm_init(void)
{
	int ret;

	/*
	 * Run only for IPQ8064 platform, if the device tree is used.
	 */
#ifdef CONFIG_OF
	if (!of_machine_is_compatible("qcom,ipq8064")) {
		printk(KERN_WARNING "Not compatible platform for ECM\n");
		return 0;
	}
#endif
	printk(KERN_INFO "ECM init\n");

	ecm_dentry = debugfs_create_dir("ecm", NULL);
	if (!ecm_dentry) {
		printk("Failed to create ecm directory in debugfs\n");
		return -1;
	}

	ret = ecm_db_init(ecm_dentry);
	if (0 != ret) {
		goto err_db;
	}

	ret = ecm_classifier_default_init(ecm_dentry);
	if (0 != ret) {
		goto err_cls_default;
	}

#ifdef ECM_CLASSIFIER_NL_ENABLE
	ret = ecm_classifier_nl_rules_init(ecm_dentry);
	if (0 != ret) {
		goto err_cls_nl;
	}
#endif

#ifdef ECM_CLASSIFIER_HYFI_ENABLE
	ret = ecm_classifier_hyfi_rules_init(ecm_dentry);
	if (0 != ret) {
		goto err_cls_hyfi;
	}
#endif

#ifdef ECM_CLASSIFIER_DSCP_ENABLE
	ret = ecm_classifier_dscp_init(ecm_dentry);
	if (0 != ret) {
		goto err_cls_dscp;
	}
#endif

#ifdef ECM_CLASSIFIER_PCC_ENABLE
	ret = ecm_classifier_pcc_init(ecm_dentry);
	if (0 != ret) {
		goto err_cls_pcc;
	}
#endif

	ret = ecm_interface_init();
	if (0 != ret) {
		goto err_iface;
	}

#ifdef ECM_INTERFACE_BOND_ENABLE
	ret = ecm_bond_notifier_init(ecm_dentry);
	if (0 != ret) {
		goto err_bond;
	}
#endif

	ret = ecm_front_end_ipv4_init(ecm_dentry);
	if (0 != ret) {
		goto err_fe_ipv4;
	}

#ifdef ECM_IPV6_ENABLE
	ret = ecm_front_end_ipv6_init(ecm_dentry);
	if (0 != ret) {
		goto err_fe_ipv6;
	}
#endif

	ret = ecm_conntrack_notifier_init(ecm_dentry);
	if (0 != ret) {
		goto err_ct;
	}

#ifdef ECM_STATE_OUTPUT_ENABLE
	ret = ecm_state_init(ecm_dentry);
	if (0 != ret) {
		goto err_state;
	}
#endif

	printk(KERN_INFO "ECM init complete\n");
	return 0;

#ifdef ECM_STATE_OUTPUT_ENABLE
err_state:
	ecm_conntrack_notifier_exit();
#endif
err_ct:
#ifdef ECM_IPV6_ENABLE
	ecm_front_end_ipv6_exit();
err_fe_ipv6:
#endif
	ecm_front_end_ipv4_exit();
err_fe_ipv4:
#ifdef ECM_INTERFACE_BOND_ENABLE
	ecm_bond_notifier_exit();
err_bond:
#endif
	ecm_interface_exit();
err_iface:
#ifdef ECM_CLASSIFIER_PCC_ENABLE
	ecm_classifier_pcc_exit();
err_cls_pcc:
#endif
#ifdef ECM_CLASSIFIER_DSCP_ENABLE
	ecm_classifier_dscp_exit();
err_cls_dscp:
#endif
#ifdef ECM_CLASSIFIER_HYFI_ENABLE
	ecm_classifier_hyfi_rules_exit();
err_cls_hyfi:
#endif
#ifdef ECM_CLASSIFIER_NL_ENABLE
	ecm_classifier_nl_rules_exit();
err_cls_nl:
#endif
	ecm_classifier_default_exit();
err_cls_default:
	ecm_db_exit();
err_db:
	debugfs_remove_recursive(ecm_dentry);

	printk(KERN_INFO "ECM init failed: %d\n", ret);
	return ret;
}

/*
 * ecm_exit()
 */
static void __exit ecm_exit(void)
{
	printk(KERN_INFO "ECM exit\n");

	/*
	 * If the platform is not IPQ8064 and device tree is enabled,
	 * this means ECM started but none of the features are used.
	 * So, just return here.
	 */
#ifdef CONFIG_OF
	if (!of_machine_is_compatible("qcom,ipq8064")) {
		return;
	}
#endif

	/* call stop on anything that requires a prepare-to-exit signal */
	printk(KERN_INFO "stop conntrack notifier\n");
	ecm_conntrack_notifier_stop(1);
	printk(KERN_INFO "stop front_end_ipv4\n");
	ecm_front_end_ipv4_stop(1);
#ifdef ECM_IPV6_ENABLE
	printk(KERN_INFO "stop front_end_ipv6\n");
	ecm_front_end_ipv6_stop(1);
#endif
#ifdef ECM_INTERFACE_BOND_ENABLE
	printk(KERN_INFO "stop bond notifier\n");
	ecm_bond_notifier_stop(1);
#endif
	printk(KERN_INFO "defunct all db connections\n");
	ecm_db_connection_defunct_all();

	/* now call exit on each module */
#ifdef ECM_STATE_OUTPUT_ENABLE
	printk(KERN_INFO "stop state\n");
	ecm_state_exit();
#endif
	printk(KERN_INFO "exit conntrack notifier\n");
	ecm_conntrack_notifier_exit();
	printk(KERN_INFO "exit front_end_ipv4\n");
	ecm_front_end_ipv4_exit();
#ifdef ECM_IPV6_ENABLE
	printk(KERN_INFO "exit front_end_ipv6\n");
	ecm_front_end_ipv6_exit();
#endif
#ifdef ECM_INTERFACE_BOND_ENABLE
	printk(KERN_INFO "exit bond notifier\n");
	ecm_bond_notifier_exit();
#endif
	printk(KERN_INFO "exit interface\n");
	ecm_interface_exit();

#ifdef ECM_CLASSIFIER_PCC_ENABLE
	printk(KERN_INFO "exit pcc classifier\n");
	ecm_classifier_pcc_exit();
#endif
#ifdef ECM_CLASSIFIER_DSCP_ENABLE
	printk(KERN_INFO "exit dscp classifier\n");
	ecm_classifier_dscp_exit();
#endif
#ifdef ECM_CLASSIFIER_HYFI_ENABLE
	printk(KERN_INFO "exit hyfi classifier\n");
	ecm_classifier_hyfi_rules_exit();
#endif
#ifdef ECM_CLASSIFIER_NL_ENABLE
	printk(KERN_INFO "exit nl classifier\n");
	ecm_classifier_nl_rules_exit();
#endif
	printk(KERN_INFO "exit default classifier\n");
	ecm_classifier_default_exit();
	printk(KERN_INFO "exit db\n");
	ecm_db_exit();

	if (ecm_dentry != NULL) {
		printk("remove ecm debugfs\n");
		debugfs_remove_recursive(ecm_dentry);
	}

	printk(KERN_INFO "ECM exit complete\n");
}

module_init(ecm_init)
module_exit(ecm_exit)

MODULE_AUTHOR("Qualcomm Atheros, Inc.");
MODULE_DESCRIPTION("ECM Core");
#ifdef MODULE_LICENSE
MODULE_LICENSE("Dual BSD/GPL");
#endif

