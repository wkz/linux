// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <linux/skbuff.h>
#include <net/ip.h>
#include <net/switchdev.h>

#include "br_private.h"

static struct static_key_false br_switchdev_tx_fwd_offload;

static bool nbp_switchdev_can_offload_tx_fwd(const struct net_bridge_port *p,
					     const struct sk_buff *skb)
{
	if (!static_branch_unlikely(&br_switchdev_tx_fwd_offload))
		return false;

	return (p->flags & BR_TX_FWD_OFFLOAD) &&
	       (p->hwdom != BR_INPUT_SKB_CB(skb)->src_hwdom);
}

bool br_switchdev_frame_uses_tx_fwd_offload(struct sk_buff *skb)
{
	if (!static_branch_unlikely(&br_switchdev_tx_fwd_offload))
		return false;

	return BR_INPUT_SKB_CB(skb)->tx_fwd_offload;
}

void br_switchdev_frame_set_offload_fwd_mark(struct sk_buff *skb)
{
	skb->offload_fwd_mark = br_switchdev_frame_uses_tx_fwd_offload(skb);
}

/* Mark the frame for TX forwarding offload if this egress port supports it */
void nbp_switchdev_frame_mark_tx_fwd_offload(const struct net_bridge_port *p,
					     struct sk_buff *skb)
{
	if (nbp_switchdev_can_offload_tx_fwd(p, skb))
		BR_INPUT_SKB_CB(skb)->tx_fwd_offload = true;
}

/* Lazily adds the hwdom of the egress bridge port to the bit mask of hwdoms
 * that the skb has been already forwarded to, to avoid further cloning to
 * other ports in the same hwdom by making nbp_switchdev_allowed_egress()
 * return false.
 */
void nbp_switchdev_frame_mark_tx_fwd_to_hwdom(const struct net_bridge_port *p,
					      struct sk_buff *skb)
{
	if (nbp_switchdev_can_offload_tx_fwd(p, skb))
		set_bit(p->hwdom, &BR_INPUT_SKB_CB(skb)->fwd_hwdoms);
}

void nbp_switchdev_frame_mark(const struct net_bridge_port *p,
			      struct sk_buff *skb)
{
	if (p->hwdom)
		BR_INPUT_SKB_CB(skb)->src_hwdom = p->hwdom;
}

bool nbp_switchdev_allowed_egress(const struct net_bridge_port *p,
				  const struct sk_buff *skb)
{
	struct br_input_skb_cb *cb = BR_INPUT_SKB_CB(skb);

	return !test_bit(p->hwdom, &cb->fwd_hwdoms) &&
		(!skb->offload_fwd_mark || cb->src_hwdom != p->hwdom);
}

/* Flags that can be offloaded to hardware */
#define BR_PORT_FLAGS_HW_OFFLOAD (BR_LEARNING | BR_FLOOD | BR_PORT_MAB | \
				  BR_MCAST_FLOOD | BR_BCAST_FLOOD | BR_PORT_LOCKED | \
				  BR_HAIRPIN_MODE | BR_ISOLATED | BR_MULTICAST_TO_UNICAST)

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
		NL_SET_ERR_MSG_WEAK_MOD(extack,
					"bridge flag offload is not supported");
		return -EOPNOTSUPP;
	}

	attr.id = SWITCHDEV_ATTR_ID_PORT_BRIDGE_FLAGS;
	attr.flags = SWITCHDEV_F_DEFER;

	err = switchdev_port_attr_set(p->dev, &attr, extack);
	if (err) {
		NL_SET_ERR_MSG_WEAK_MOD(extack,
					"error setting offload flag on port");
		return err;
	}

	return 0;
}

static void br_switchdev_fdb_populate(struct net_bridge *br,
				      struct switchdev_notifier_fdb_info *item,
				      const struct net_bridge_fdb_entry *fdb,
				      const void *ctx)
{
	const struct net_bridge_port *p = READ_ONCE(fdb->dst);

	item->addr = fdb->key.addr.addr;
	item->vid = fdb->key.vlan_id;
	item->added_by_user = test_bit(BR_FDB_ADDED_BY_USER, &fdb->flags);
	item->offloaded = test_bit(BR_FDB_OFFLOADED, &fdb->flags);
	item->is_local = test_bit(BR_FDB_LOCAL, &fdb->flags);
	item->locked = false;
	item->info.dev = (!p || item->is_local) ? br->dev : p->dev;
	item->info.ctx = ctx;
}

void
br_switchdev_fdb_notify(struct net_bridge *br,
			const struct net_bridge_fdb_entry *fdb, int type)
{
	struct switchdev_notifier_fdb_info item;

	if (test_bit(BR_FDB_LOCKED, &fdb->flags))
		return;

	/* Entries with these flags were created using ndm_state == NUD_REACHABLE,
	 * ndm_flags == NTF_MASTER( | NTF_STICKY), ext_flags == 0 by something
	 * equivalent to 'bridge fdb add ... master dynamic (sticky)'.
	 * Drivers don't know how to deal with these, so don't notify them to
	 * avoid confusing them.
	 */
	if (test_bit(BR_FDB_ADDED_BY_USER, &fdb->flags) &&
	    !test_bit(BR_FDB_STATIC, &fdb->flags) &&
	    !test_bit(BR_FDB_ADDED_BY_EXT_LEARN, &fdb->flags))
		return;

	br_switchdev_fdb_populate(br, &item, fdb, NULL);

	switch (type) {
	case RTM_DELNEIGH:
		call_switchdev_notifiers(SWITCHDEV_FDB_DEL_TO_DEVICE,
					 item.info.dev, &item.info, NULL);
		break;
	case RTM_NEWNEIGH:
		call_switchdev_notifiers(SWITCHDEV_FDB_ADD_TO_DEVICE,
					 item.info.dev, &item.info, NULL);
		break;
	}
}

int br_switchdev_port_vlan_add(struct net_device *dev, u16 vid, u16 flags,
			       bool changed, struct netlink_ext_ack *extack)
{
	struct switchdev_obj_port_vlan v = {
		.obj.orig_dev = dev,
		.obj.id = SWITCHDEV_OBJ_ID_PORT_VLAN,
		.flags = flags,
		.vid = vid,
		.changed = changed,
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

static int nbp_switchdev_hwdom_set(struct net_bridge_port *joining)
{
	struct net_bridge *br = joining->br;
	struct net_bridge_port *p;
	int hwdom;

	/* joining is yet to be added to the port list. */
	list_for_each_entry(p, &br->port_list, list) {
		if (netdev_phys_item_id_same(&joining->ppid, &p->ppid)) {
			joining->hwdom = p->hwdom;
			return 0;
		}
	}

	hwdom = find_next_zero_bit(&br->busy_hwdoms, BR_HWDOM_MAX, 1);
	if (hwdom >= BR_HWDOM_MAX)
		return -EBUSY;

	set_bit(hwdom, &br->busy_hwdoms);
	joining->hwdom = hwdom;
	return 0;
}

static void nbp_switchdev_hwdom_put(struct net_bridge_port *leaving)
{
	struct net_bridge *br = leaving->br;
	struct net_bridge_port *p;

	/* leaving is no longer in the port list. */
	list_for_each_entry(p, &br->port_list, list) {
		if (p->hwdom == leaving->hwdom)
			return;
	}

	clear_bit(leaving->hwdom, &br->busy_hwdoms);
}

static int nbp_switchdev_add(struct net_bridge_port *p,
			     struct netdev_phys_item_id ppid,
			     bool tx_fwd_offload,
			     struct netlink_ext_ack *extack)
{
	int err;

	if (p->offload_count) {
		/* Prevent unsupported configurations such as a bridge port
		 * which is a bonding interface, and the member ports are from
		 * different hardware switches.
		 */
		if (!netdev_phys_item_id_same(&p->ppid, &ppid)) {
			NL_SET_ERR_MSG_MOD(extack,
					   "Same bridge port cannot be offloaded by two physical switches");
			return -EBUSY;
		}

		/* Tolerate drivers that call switchdev_bridge_port_offload()
		 * more than once for the same bridge port, such as when the
		 * bridge port is an offloaded bonding/team interface.
		 */
		p->offload_count++;

		return 0;
	}

	p->ppid = ppid;
	p->offload_count = 1;

	err = nbp_switchdev_hwdom_set(p);
	if (err)
		return err;

	if (tx_fwd_offload) {
		p->flags |= BR_TX_FWD_OFFLOAD;
		static_branch_inc(&br_switchdev_tx_fwd_offload);
	}

	return 0;
}

static void nbp_switchdev_del(struct net_bridge_port *p)
{
	if (WARN_ON(!p->offload_count))
		return;

	p->offload_count--;

	if (p->offload_count)
		return;

	if (p->hwdom)
		nbp_switchdev_hwdom_put(p);

	if (p->flags & BR_TX_FWD_OFFLOAD) {
		p->flags &= ~BR_TX_FWD_OFFLOAD;
		static_branch_dec(&br_switchdev_tx_fwd_offload);
	}
}

static int
br_switchdev_fdb_replay_one(struct net_bridge *br, struct notifier_block *nb,
			    const struct net_bridge_fdb_entry *fdb,
			    unsigned long action, const void *ctx)
{
	struct switchdev_notifier_fdb_info item;
	int err;

	br_switchdev_fdb_populate(br, &item, fdb, ctx);

	err = nb->notifier_call(nb, action, &item);
	return notifier_to_errno(err);
}

static int
br_switchdev_fdb_replay(const struct net_device *br_dev, const void *ctx,
			bool adding, struct notifier_block *nb)
{
	struct net_bridge_fdb_entry *fdb;
	struct net_bridge *br;
	unsigned long action;
	int err = 0;

	if (!nb)
		return 0;

	if (!netif_is_bridge_master(br_dev))
		return -EINVAL;

	br = netdev_priv(br_dev);

	if (adding)
		action = SWITCHDEV_FDB_ADD_TO_DEVICE;
	else
		action = SWITCHDEV_FDB_DEL_TO_DEVICE;

	rcu_read_lock();

	hlist_for_each_entry_rcu(fdb, &br->fdb_list, fdb_node) {
		err = br_switchdev_fdb_replay_one(br, nb, fdb, action, ctx);
		if (err)
			break;
	}

	rcu_read_unlock();

	return err;
}

static int br_switchdev_vlan_attr_replay(struct net_device *br_dev,
					 const void *ctx,
					 struct notifier_block *nb,
					 struct netlink_ext_ack *extack)
{
	struct switchdev_notifier_port_attr_info attr_info = {
		.info = {
			.dev = br_dev,
			.extack = extack,
			.ctx = ctx,
		},
	};
	struct net_bridge *br = netdev_priv(br_dev);
	struct net_bridge_vlan_group *vg;
	struct switchdev_attr attr;
	struct net_bridge_vlan *v;
	int err;

	attr_info.attr = &attr;
	attr.orig_dev = br_dev;

	vg = br_vlan_group(br);
	if (!vg)
		return 0;

	list_for_each_entry(v, &vg->vlan_list, vlist) {
		if (v->msti) {
			attr.id = SWITCHDEV_ATTR_ID_VLAN_MSTI;
			attr.u.vlan_msti.vid = v->vid;
			attr.u.vlan_msti.msti = v->msti;

			err = nb->notifier_call(nb, SWITCHDEV_PORT_ATTR_SET,
						&attr_info);
			err = notifier_to_errno(err);
			if (err)
				return err;
		}
	}

	return 0;
}

static int
br_switchdev_vlan_replay_one(struct notifier_block *nb,
			     struct net_device *dev,
			     struct switchdev_obj_port_vlan *vlan,
			     const void *ctx, unsigned long action,
			     struct netlink_ext_ack *extack)
{
	struct switchdev_notifier_port_obj_info obj_info = {
		.info = {
			.dev = dev,
			.extack = extack,
			.ctx = ctx,
		},
		.obj = &vlan->obj,
	};
	int err;

	err = nb->notifier_call(nb, action, &obj_info);
	return notifier_to_errno(err);
}

static int br_switchdev_vlan_replay_group(struct notifier_block *nb,
					  struct net_device *dev,
					  struct net_bridge_vlan_group *vg,
					  const void *ctx, unsigned long action,
					  struct netlink_ext_ack *extack)
{
	struct net_bridge_vlan *v;
	int err = 0;
	u16 pvid;

	if (!vg)
		return 0;

	pvid = br_get_pvid(vg);

	list_for_each_entry(v, &vg->vlan_list, vlist) {
		struct switchdev_obj_port_vlan vlan = {
			.obj.orig_dev = dev,
			.obj.id = SWITCHDEV_OBJ_ID_PORT_VLAN,
			.flags = br_vlan_flags(v, pvid),
			.vid = v->vid,
		};

		if (!br_vlan_should_use(v))
			continue;

		err = br_switchdev_vlan_replay_one(nb, dev, &vlan, ctx,
						   action, extack);
		if (err)
			return err;
	}

	return 0;
}

static int br_switchdev_vlan_replay(struct net_device *br_dev,
				    const void *ctx, bool adding,
				    struct notifier_block *nb,
				    struct netlink_ext_ack *extack)
{
	struct net_bridge *br = netdev_priv(br_dev);
	struct net_bridge_port *p;
	unsigned long action;
	int err;

	ASSERT_RTNL();

	if (!nb)
		return 0;

	if (!netif_is_bridge_master(br_dev))
		return -EINVAL;

	if (adding)
		action = SWITCHDEV_PORT_OBJ_ADD;
	else
		action = SWITCHDEV_PORT_OBJ_DEL;

	err = br_switchdev_vlan_replay_group(nb, br_dev, br_vlan_group(br),
					     ctx, action, extack);
	if (err)
		return err;

	list_for_each_entry(p, &br->port_list, list) {
		struct net_device *dev = p->dev;

		err = br_switchdev_vlan_replay_group(nb, dev,
						     nbp_vlan_group(p),
						     ctx, action, extack);
		if (err)
			return err;
	}

	if (adding) {
		err = br_switchdev_vlan_attr_replay(br_dev, ctx, nb, extack);
		if (err)
			return err;
	}

	return 0;
}

#ifdef CONFIG_BRIDGE_IGMP_SNOOPING
struct br_switchdev_mdb_complete_info {
	struct net_bridge_port *port;
	struct br_ip ip;
};

static void br_switchdev_mdb_complete(struct net_device *dev, int err, void *priv)
{
	struct br_switchdev_mdb_complete_info *data = priv;
	struct net_bridge_port_group __rcu **pp;
	struct net_bridge_port_group *p;
	struct net_bridge_mdb_entry *mp;
	struct net_bridge_port *port = data->port;
	struct net_bridge *br = port->br;

	if (err)
		goto err;

	spin_lock_bh(&br->multicast_lock);
	mp = br_mdb_ip_get(br, &data->ip);
	if (!mp)
		goto out;
	for (pp = &mp->ports; (p = mlock_dereference(*pp, br)) != NULL;
	     pp = &p->next) {
		if (p->key.port != port)
			continue;
		p->flags |= MDB_PG_FLAGS_OFFLOAD;
	}
out:
	spin_unlock_bh(&br->multicast_lock);
err:
	kfree(priv);
}

static void br_switchdev_mdb_populate(struct switchdev_obj_port_mdb *mdb,
				      const struct br_ip *ip)
{
	if (ip->proto == htons(ETH_P_IP))
		ip_eth_mc_map(ip->dst.ip4, mdb->addr);
#if IS_ENABLED(CONFIG_IPV6)
	else if (ip->proto == htons(ETH_P_IPV6))
		ipv6_eth_mc_map(&ip->dst.ip6, mdb->addr);
#endif
	else
		ether_addr_copy(mdb->addr, ip->dst.mac_addr);

	mdb->vid = ip->vid;
}

static void br_switchdev_mdb_do(struct net_device *dev,
				struct net_device *orig_dev,
				const struct br_ip *ip,
				int type,
				enum switchdev_obj_id id)
{
	struct br_switchdev_mdb_complete_info *complete_info;
	struct switchdev_obj_port_mdb mdb = {
		.obj = {
			.id = id,
			.flags = SWITCHDEV_F_DEFER,
			.orig_dev = orig_dev,
		},
	};

	br_switchdev_mdb_populate(&mdb, ip);

	switch (type) {
	case RTM_NEWMDB:
		if (netif_is_bridge_port(orig_dev)) {
			complete_info = kmalloc(sizeof(*complete_info), GFP_ATOMIC);
			if (!complete_info)
				break;

			complete_info->port = br_port_get_rcu(orig_dev);
			complete_info->ip = *ip;
			mdb.obj.complete_priv = complete_info;
			mdb.obj.complete = br_switchdev_mdb_complete;

			if (switchdev_port_obj_add(dev, &mdb.obj, NULL))
				kfree(complete_info);
		} else {
			switchdev_port_obj_add(dev, &mdb.obj, NULL);
		}
		break;
	case RTM_DELMDB:
		switchdev_port_obj_del(dev, &mdb.obj);
		break;
	}
}

static void br_switchdev_mdb_do_lowers(struct net_device *dev,
				       const struct br_ip *ip, int type,
				       enum switchdev_obj_id id)
{
	struct net_device *lower_dev;
	struct list_head *iter;

	netdev_for_each_lower_dev(dev, lower_dev, iter)
		br_switchdev_mdb_do(lower_dev, dev, ip, type, id);
}

static void br_switchdev_port_mdb(struct net_device *dev,
				  const struct br_ip *ip, int type)
{
	br_switchdev_mdb_do(dev, dev, ip, type,
			    SWITCHDEV_OBJ_ID_PORT_MDB);
}

static void br_switchdev_host_mdb(struct net_device *dev,
				  const struct br_ip *ip, int type)
{
	br_switchdev_mdb_do_lowers(dev, ip, type, SWITCHDEV_OBJ_ID_HOST_MDB);
}

static void br_switchdev_mra_mdb_do(struct net_device *dev,
				    const struct br_ip *ip, int type)
{
	if (netif_is_bridge_master(dev))
		br_switchdev_mdb_do_lowers(dev, ip, type,
					   SWITCHDEV_OBJ_ID_MRA_MDB);
	else
		br_switchdev_mdb_do(dev, dev, ip, type,
				    SWITCHDEV_OBJ_ID_MRA_MDB);
}

static void br_switchdev_mra_mdb_mrouters(struct net_bridge_mcast *brmctx,
					  const struct br_ip *ip,
					  int type)
{
	struct net_bridge_mcast_port *pmctx;

	if (br_multicast_is_router(brmctx, &ip->proto))
		br_switchdev_mra_mdb_do(brmctx->br->dev, ip, type);

	switch (ntohs(ip->proto)) {
	case ETH_P_IP:
		hlist_for_each_entry_rcu(pmctx, &brmctx->ip4_mc_router_list,
					 ip4_rlist)
			br_switchdev_mra_mdb_do(pmctx->port->dev, ip, type);
		break;
#if IS_ENABLED(CONFIG_IPV6)
	case ETH_P_IPV6:
		hlist_for_each_entry_rcu(pmctx, &brmctx->ip6_mc_router_list,
					 ip6_rlist)
			br_switchdev_mra_mdb_do(pmctx->port->dev, ip, type);
		break;
#endif
	}
}

static void br_switchdev_mra_mdb(struct net_bridge *br,
				 struct net_bridge_port *port,
				 struct net_bridge_mdb_entry *mp,
				 int type)
{
	struct net_bridge_mcast *brmctx;

	if (br_group_is_l2(&mp->addr))
		/* No augments to be done for L2 groups, just send the
		 * the regular notifications, like we do for the port
		 * and host MDB.
		 */
		goto notify;

	brmctx = br_multicast_ctx_get(br, mp->addr.vid);

	if (((type == RTM_NEWMDB) && (br_mdb_weight(mp) == 1)) ||
	    ((type == RTM_DELMDB) && (br_mdb_weight(mp) == 0)))
		/* Either the first member was just added to this
		 * group, in which case have inject all known routers;
		 * or the last member was just removed, which means we
		 * have to remove all known routers, reverting the
		 * group to be unregistered.
		 */
		br_switchdev_mra_mdb_mrouters(brmctx, &mp->addr, type);

	if ((port && br_multicast_port_is_router(brmctx, port, mp->addr.proto)) ||
	    br_multicast_is_router(brmctx, &mp->addr.proto))
		/* Since the member in question is also a router, the
		 * group has either already been augmented with it
		 * (when adding); or the augment should remain in
		 * place (when removing).
		 */
		return;

notify:
	br_switchdev_mra_mdb_do(port ? port->dev : br->dev, &mp->addr, type);
}

void br_switchdev_mdb_notify(struct net_device *dev,
			     struct net_bridge_mdb_entry *mp,
			     struct net_bridge_port_group *pg,
			     int type)
{
	struct net_bridge *br = netdev_priv(dev);
	struct br_ip *ip = &mp->addr;

	if (pg)
		br_switchdev_port_mdb(pg->key.port->dev, ip, type);
	else
		br_switchdev_host_mdb(dev, ip, type);

	br_switchdev_mra_mdb(br, pg ? pg->key.port : NULL, mp, type);
}

static int
br_switchdev_mdb_replay_one(struct notifier_block *nb, struct net_device *dev,
			    const struct switchdev_obj_port_mdb *mdb,
			    unsigned long action, const void *ctx,
			    struct netlink_ext_ack *extack)
{
	struct switchdev_notifier_port_obj_info obj_info = {
		.info = {
			.dev = dev,
			.extack = extack,
			.ctx = ctx,
		},
		.obj = &mdb->obj,
	};
	int err;

	err = nb->notifier_call(nb, action, &obj_info);
	return notifier_to_errno(err);
}

static int br_switchdev_mdb_queue_one(struct list_head *mdb_list,
				      enum switchdev_obj_id id,
				      const struct br_ip *ip,
				      struct net_device *orig_dev)
{
	struct switchdev_obj_port_mdb *mdb;

	mdb = kzalloc(sizeof(*mdb), GFP_ATOMIC);
	if (!mdb)
		return -ENOMEM;

	mdb->obj.id = id;
	mdb->obj.orig_dev = orig_dev;
	br_switchdev_mdb_populate(mdb, ip);
	list_add_tail(&mdb->obj.list, mdb_list);

	return 0;
}

static void br_switchdev_mra_mrouter(struct net_device *dev, u16 vid, u16 proto,
				     int type)
{
	const struct net_bridge_mdb_entry *mp;
	struct net_bridge_port *port = NULL;
	struct net_bridge *br;

	if (netif_is_bridge_port(dev)) {
		port = br_port_get_rcu(dev);
		br = port->br;
	} else {
		br = netdev_priv(dev);
	}

	/* When adding a new router port (or host), inject it into all
	 * existing groups matching the VLAN and protocol of the
	 * router, for which the port (or host) is not already a
	 * member. When removing a router, remove the router port from
	 * all matching groups, for which the port is not also a
	 * member.
	 */
	hlist_for_each_entry_rcu(mp, &br->mdb_list, mdb_node) {
		struct net_bridge_port_group __rcu * const *pp;
		const struct net_bridge_port_group *p;

		if (mp->addr.vid != vid || ntohs(mp->addr.proto) != proto)
			continue;

		if (!port && !mp->host_joined) {
			br_switchdev_mra_mdb_do(br->dev, &mp->addr, type);
			continue;
		}

		for (pp = &mp->ports; (p = rcu_dereference(*pp)) != NULL;
		     pp = &p->next) {
			if (p->key.port == port)
				goto member;
		}

		br_switchdev_mra_mdb_do(port->dev, &mp->addr, type);
	member:
	}
}

void br_switchdev_mrouter_notify(struct net_device *dev,
				 bool on, u16 vid, u16 proto)
{
	struct switchdev_notifier_mrouter_info mri = {
		.info = {
			.dev = dev,
		},
		.vid = vid,
		.proto = proto,
	};

	if (on) {
		call_switchdev_notifiers(SWITCHDEV_MROUTER_ADD,
					 dev, &mri.info, NULL);
		br_switchdev_mra_mrouter(dev, vid, proto, RTM_NEWMDB);
	} else {
		br_switchdev_mra_mrouter(dev, vid, proto, RTM_DELMDB);
		call_switchdev_notifiers(SWITCHDEV_MROUTER_DEL,
					 dev, &mri.info, NULL);
	}
}

void br_switchdev_mrouter_notify_both(struct net_device *dev, bool on, u16 vid)
{
	br_switchdev_mrouter_notify(dev, on, vid, ETH_P_IP);
#if IS_ENABLED(CONFIG_IPV6)
	br_switchdev_mrouter_notify(dev, on, vid, ETH_P_IPV6);
#endif
}

#endif

static int
br_switchdev_mdb_replay(struct net_device *br_dev, struct net_device *dev,
			const void *ctx, bool adding, struct notifier_block *nb,
			struct netlink_ext_ack *extack)
{
#ifdef CONFIG_BRIDGE_IGMP_SNOOPING
	const struct net_bridge_mdb_entry *mp;
	struct switchdev_obj *obj, *tmp;
	struct net_bridge *br;
	unsigned long action;
	LIST_HEAD(mdb_list);
	int err = 0;

	ASSERT_RTNL();

	if (!nb)
		return 0;

	if (!netif_is_bridge_master(br_dev) || !netif_is_bridge_port(dev))
		return -EINVAL;

	br = netdev_priv(br_dev);

	if (!br_opt_get(br, BROPT_MULTICAST_ENABLED))
		return 0;

	/* We cannot walk over br->mdb_list protected just by the rtnl_mutex,
	 * because the write-side protection is br->multicast_lock. But we
	 * need to emulate the [ blocking ] calling context of a regular
	 * switchdev event, so since both br->multicast_lock and RCU read side
	 * critical sections are atomic, we have no choice but to pick the RCU
	 * read side lock, queue up all our events, leave the critical section
	 * and notify switchdev from blocking context.
	 */
	rcu_read_lock();

	hlist_for_each_entry_rcu(mp, &br->mdb_list, mdb_node) {
		struct net_bridge_port_group __rcu * const *pp;
		const struct net_bridge_port_group *p;

		if (mp->host_joined) {
			err = br_switchdev_mdb_queue_one(&mdb_list,
							 SWITCHDEV_OBJ_ID_HOST_MDB,
							 &mp->addr, br_dev);
			if (err) {
				rcu_read_unlock();
				goto out_free_mdb;
			}
		}

		for (pp = &mp->ports; (p = rcu_dereference(*pp)) != NULL;
		     pp = &p->next) {
			if (p->key.port->dev != dev)
				continue;

			err = br_switchdev_mdb_queue_one(&mdb_list,
							 SWITCHDEV_OBJ_ID_PORT_MDB,
							 &mp->addr, dev);
			if (err) {
				rcu_read_unlock();
				goto out_free_mdb;
			}
		}
	}

	rcu_read_unlock();

	if (adding)
		action = SWITCHDEV_PORT_OBJ_ADD;
	else
		action = SWITCHDEV_PORT_OBJ_DEL;

	list_for_each_entry(obj, &mdb_list, list) {
		err = br_switchdev_mdb_replay_one(nb, dev,
						  SWITCHDEV_OBJ_PORT_MDB(obj),
						  action, ctx, extack);
		if (err == -EOPNOTSUPP)
			err = 0;
		if (err)
			goto out_free_mdb;
	}

out_free_mdb:
	list_for_each_entry_safe(obj, tmp, &mdb_list, list) {
		list_del(&obj->list);
		kfree(SWITCHDEV_OBJ_PORT_MDB(obj));
	}

	if (err)
		return err;
#endif

	return 0;
}

static int nbp_switchdev_sync_objs(struct net_bridge_port *p, const void *ctx,
				   struct notifier_block *atomic_nb,
				   struct notifier_block *blocking_nb,
				   struct netlink_ext_ack *extack)
{
	struct net_device *br_dev = p->br->dev;
	struct net_device *dev = p->dev;
	int err;

	err = br_switchdev_vlan_replay(br_dev, ctx, true, blocking_nb, extack);
	if (err && err != -EOPNOTSUPP)
		return err;

	err = br_switchdev_mdb_replay(br_dev, dev, ctx, true, blocking_nb,
				      extack);
	if (err) {
		/* -EOPNOTSUPP not propagated from MDB replay. */
		return err;
	}

	err = br_switchdev_fdb_replay(br_dev, ctx, true, atomic_nb);
	if (err && err != -EOPNOTSUPP)
		return err;

	return 0;
}

static void nbp_switchdev_unsync_objs(struct net_bridge_port *p,
				      const void *ctx,
				      struct notifier_block *atomic_nb,
				      struct notifier_block *blocking_nb)
{
	struct net_device *br_dev = p->br->dev;
	struct net_device *dev = p->dev;

	br_switchdev_fdb_replay(br_dev, ctx, false, atomic_nb);

	br_switchdev_mdb_replay(br_dev, dev, ctx, false, blocking_nb, NULL);

	br_switchdev_vlan_replay(br_dev, ctx, false, blocking_nb, NULL);
}

/* Let the bridge know that this port is offloaded, so that it can assign a
 * switchdev hardware domain to it.
 */
int br_switchdev_port_offload(struct net_bridge_port *p,
			      struct net_device *dev, const void *ctx,
			      struct notifier_block *atomic_nb,
			      struct notifier_block *blocking_nb,
			      bool tx_fwd_offload,
			      struct netlink_ext_ack *extack)
{
	struct netdev_phys_item_id ppid;
	int err;

	err = dev_get_port_parent_id(dev, &ppid, false);
	if (err)
		return err;

	err = nbp_switchdev_add(p, ppid, tx_fwd_offload, extack);
	if (err)
		return err;

	err = nbp_switchdev_sync_objs(p, ctx, atomic_nb, blocking_nb, extack);
	if (err)
		goto out_switchdev_del;

	return 0;

out_switchdev_del:
	nbp_switchdev_del(p);

	return err;
}

void br_switchdev_port_unoffload(struct net_bridge_port *p, const void *ctx,
				 struct notifier_block *atomic_nb,
				 struct notifier_block *blocking_nb)
{
	nbp_switchdev_unsync_objs(p, ctx, atomic_nb, blocking_nb);

	nbp_switchdev_del(p);
}

int br_switchdev_port_replay(struct net_bridge_port *p,
			     struct net_device *dev, const void *ctx,
			     struct notifier_block *atomic_nb,
			     struct notifier_block *blocking_nb,
			     struct netlink_ext_ack *extack)
{
	return nbp_switchdev_sync_objs(p, ctx, atomic_nb, blocking_nb, extack);
}
