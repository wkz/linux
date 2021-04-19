// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <linux/skbuff.h>
#include <net/switchdev.h>

#include "br_private.h"

DEFINE_STATIC_KEY_FALSE(br_switchdev_fwd_offload_used);

void nbp_switchdev_frame_mark(const struct net_bridge_port *p,
			      struct sk_buff *skb)
{
	if (p->hwdom)
		BR_INPUT_SKB_CB(skb)->src_hwdom = p->hwdom;
}

bool nbp_switchdev_allowed_egress(const struct net_bridge_port *p,
				  const struct sk_buff *skb)
{
	if (static_branch_unlikely(&br_switchdev_fwd_offload_used)) {
		if (test_bit(p->hwdom, &BR_INPUT_SKB_CB(skb)->fwd_hwdoms))
			return false;
	}

	return !skb->offload_fwd_mark ||
	       BR_INPUT_SKB_CB(skb)->src_hwdom != p->hwdom;
}

void *br_switchdev_accel_priv_rcu(const struct net_device *dev)
{
	const struct net_bridge_port *p = br_port_get_rcu(dev);

	return p->accel_priv;
}

/* Flags that can be offloaded to hardware */
#define BR_PORT_FLAGS_HW_OFFLOAD (BR_LEARNING | BR_FLOOD | \
				  BR_MCAST_FLOOD | BR_BCAST_FLOOD)

int br_switchdev_set_port_flag(struct net_bridge_port *p,
			       unsigned long flags,
			       unsigned long mask,
			       struct netlink_ext_ack *extack)
{
	struct switchdev_attr attr = {
		.orig_dev = p->dev,
	};
	struct switchdev_notifier_port_attr_info info = {
		.attr = &attr,
	};
	int err;

	mask &= BR_PORT_FLAGS_HW_OFFLOAD;
	if (!mask)
		return 0;

	attr.id = SWITCHDEV_ATTR_ID_PORT_PRE_BRIDGE_FLAGS;
	attr.u.brport_flags.val = flags;
	attr.u.brport_flags.mask = mask;

	/* We run from atomic context here */
	err = call_switchdev_notifiers(SWITCHDEV_PORT_ATTR_SET, p->dev,
				       &info.info, extack);
	err = notifier_to_errno(err);
	if (err == -EOPNOTSUPP)
		return 0;

	if (err) {
		if (extack && !extack->_msg)
			NL_SET_ERR_MSG_MOD(extack,
					   "bridge flag offload is not supported");
		return -EOPNOTSUPP;
	}

	attr.id = SWITCHDEV_ATTR_ID_PORT_BRIDGE_FLAGS;
	attr.flags = SWITCHDEV_F_DEFER;

	err = switchdev_port_attr_set(p->dev, &attr, extack);
	if (err) {
		if (extack && !extack->_msg)
			NL_SET_ERR_MSG_MOD(extack,
					   "error setting offload flag on port");
		return err;
	}

	return 0;
}

void
br_switchdev_fdb_notify(const struct net_bridge_fdb_entry *fdb, int type)
{
	struct switchdev_notifier_fdb_info info = {
		.addr = fdb->key.addr.addr,
		.vid = fdb->key.vlan_id,
		.added_by_user = test_bit(BR_FDB_ADDED_BY_USER, &fdb->flags),
		.is_local = test_bit(BR_FDB_LOCAL, &fdb->flags),
		.offloaded = test_bit(BR_FDB_OFFLOADED, &fdb->flags),
	};

	if (!fdb->dst)
		return;

	switch (type) {
	case RTM_DELNEIGH:
		call_switchdev_notifiers(SWITCHDEV_FDB_DEL_TO_DEVICE,
					 fdb->dst->dev, &info.info, NULL);
		break;
	case RTM_NEWNEIGH:
		call_switchdev_notifiers(SWITCHDEV_FDB_ADD_TO_DEVICE,
					 fdb->dst->dev, &info.info, NULL);
		break;
	}
}

int br_switchdev_port_vlan_add(struct net_device *dev, u16 vid, u16 flags,
			       struct netlink_ext_ack *extack)
{
	struct switchdev_obj_port_vlan v = {
		.obj.orig_dev = dev,
		.obj.id = SWITCHDEV_OBJ_ID_PORT_VLAN,
		.flags = flags,
		.vid = vid,
	};

	return switchdev_port_obj_add(dev, &v.obj, extack);
}

int br_switchdev_port_vlan_del(struct net_device *dev, u16 vid)
{
	struct switchdev_obj_port_vlan v = {
		.obj.orig_dev = dev,
		.obj.id = SWITCHDEV_OBJ_ID_PORT_VLAN,
		.vid = vid,
	};

	return switchdev_port_obj_del(dev, &v.obj);
}

static void nbp_switchdev_fwd_offload_add(struct net_bridge_port *p)
{
	void *priv;

	if (!(p->dev->features & NETIF_F_HW_L2FW_DOFFLOAD))
		return;

	priv = p->dev->netdev_ops->ndo_dfwd_add_station(p->dev, p->br->dev);
	if (!IS_ERR_OR_NULL(priv)) {
		static_branch_inc(&br_switchdev_fwd_offload_used);
		p->flags |= BR_FORWARD_OFFLOAD;
		p->accel_priv = priv;
	}
}

static void nbp_switchdev_fwd_offload_del(struct net_bridge_port *p)
{
	if (!(p->flags & BR_FORWARD_OFFLOAD))
		return;

	p->dev->netdev_ops->ndo_dfwd_del_station(p->dev, p->accel_priv);

	p->accel_priv = NULL;
	p->flags &= ~BR_FORWARD_OFFLOAD;
	static_branch_dec(&br_switchdev_fwd_offload_used);
}

static int nbp_switchdev_hwdom_set(struct net_bridge_port *joining)
{
	struct net_bridge *br = joining->br;
	struct net_bridge_port *p;
	int hwdom;

	/* joining is yet to be added to the port list. */
	list_for_each_entry(p, &br->port_list, list) {
		if (netdev_port_same_parent_id(joining->dev, p->dev)) {
			joining->hwdom = p->hwdom;
			return 0;
		}
	}

	hwdom = find_next_zero_bit(&br->busy_hwdoms, BITS_PER_LONG, 1);
	if (hwdom >= BITS_PER_LONG)
		return -EBUSY;

	set_bit(hwdom, &br->busy_hwdoms);
	joining->hwdom = hwdom;
	return 0;
}

static void nbp_switchdev_hwdom_put(struct net_bridge_port *leaving)
{
	struct net_bridge *br = leaving->br;
	struct net_bridge_port *p;

	if (!leaving->hwdom)
		return;

	/* leaving is no longer in the port list. */
	list_for_each_entry(p, &br->port_list, list) {
		if (p->hwdom == leaving->hwdom)
			return;
	}

	clear_bit(leaving->hwdom, &br->busy_hwdoms);
}

int nbp_switchdev_add(struct net_bridge_port *p)
{
	struct netdev_phys_item_id ppid = { };
	int err;

	ASSERT_RTNL();

	err = dev_get_port_parent_id(p->dev, &ppid, true);
	if (err) {
		if (err == -EOPNOTSUPP)
			return 0;
		return err;
	}

	err = nbp_switchdev_hwdom_set(p);
	if (err)
		return err;

	if (p->hwdom)
		nbp_switchdev_fwd_offload_add(p);

	return 0;
}

void nbp_switchdev_del(struct net_bridge_port *p)
{
	ASSERT_RTNL();

	nbp_switchdev_fwd_offload_del(p);
	nbp_switchdev_hwdom_put(p);
}
