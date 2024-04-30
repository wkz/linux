// SPDX-License-Identifier: GPL-2.0+
/* Microchip Sparx5 Switch driver
 *
 * Copyright (c) 2024 Microchip Technology Inc. and its subsidiaries.
 */

#include <linux/etherdevice.h>
#include <linux/if_bridge.h>
#include <linux/if_ether.h>
#include <linux/inetdevice.h>
#include <linux/list.h>
#include <linux/refcount.h>
#include <linux/rhashtable.h>
#include <net/arp.h>
#include <net/fib_notifier.h>
#include <net/neighbour.h>
#include <net/netevent.h>
#include <net/nexthop.h>

#include "sparx5_main.h"

/* The main routing objects are
 *
 * 1) Router legs, which correspond to IP interfaces. They can have multiple IPs
 *    attached and are associated with a VLAN. Only routes with nexthops that
 *    egress on ports that are part of a router leg are considered for
 *    offloading.
 *
 * 2) Fib entries, which correspond to entries in the routing table.
 *    > ip route add 6.6.0.0/16 nexthop via 1.0.10.10
 *    will create fib entry for 6.6.0.0/16, if it is offloadable.
 *
 * 3) Nexthop groups and nexthops. Each fib entry has exactly one nexthop hop.
 *    To simplify the SW representation, we duplicate nexthops and nexthops
 *    groups for each fib entry, even when the same nexthop is used for many
 *    different routes.
 *
 * 4) Neigh entries, which correspond to directly connected neighbours. These are
 *    created mainly by ARP events. Their job is to maintain the association of
 *    L3 and L2 addressses.
 *
 *    The neigh entries are referenced by nexthops and fib entries. They are
 *    shared so we must keep track of the objects that are referencing them.
 *
 *    If a neighbour which is used in a nexthop group dies, we will set the mac
 *    to zero, so traffic for this nexthop is trapped.
 *
 *
 * Both fib_entry and neigh_entry can trigger writes to the LPM VCAP, and own
 * entries in HW. Fib entries own the corresponding route associated with them.
 * Neigh entries own a /32 route, for traffic destined directly to the neighbour.
 *
 * We have 3 main cases for routing:
 *
 * 1) Routes for directly connected subnets. E.g. router has IP 1.0.10.1, and
 *    routes subnet 1.0.10.0/24.
 *
 *    In this case, we have a fib_entry, with a non-gateway nexthop group. We
 *    install a LPM VCAP route, with action type arp entry, for 1.0.10.0/24 with
 *    a zero mac, to ensure frames destined for this subnet will be sent to the
 *    CPU and start the ARP process.
 *
 *    When we get the arp reply, we create a neigh_entry for each neighbour and
 *    install a direct route in the LPM VCAP for this neighbour. For example,
 *    1.0.10.11 is sent to DMAC 0x1111110001. This is how we route directly
 *    connected subnets.
 *
 *    Moreover, the fib_entry maintains a list of all neighbours discovered in
 *    the subnet it is routing. These neighbours hold a reference back to the
 *    fib_entry.
 *
 *                   |-> neigh_entry 1.0.10.10
 *        neigh_list |-> neigh_entry 1.0.10.11
 *                   |-> neigh_entry 1.0.10.12
 *                   |
 *   +-------------+ |  +--------------+
 *   |  fib_entry  |-+  | nexthop group|
 *   | 1.0.10.1/24 |----+              |
 *   +-------------+    |  nexthop --------> NULL (Write zero mac in VCAP)
 *                      +--------------+
 *
 *
 * 2) Routes for non-connected subnets. E.g. we are routing subnet 6.6.0.0/16,
 *    but we have no IP in this subnet. We are routing via nexthops, which are
 *    directly connected. Say we have >=2 nexthops.
 *
 *    In this case, have a fib_entry with a gateway nexthop group. Each nexthop
 *    points to a neigh_entry, corresponding to the gateway used for routing.
 *
 *    Say we use the nexthops:
 *
 *    - 1.0.11.10
 *    - 1.0.10.10
 *    - 1.0.9.10
 *
 *    We install a LPM VCAP route for 6.6.0.0/16, which contains a pointer to the
 *    hw arp table, and the size of the group. The ARP table contains the Mac
 *    addresses of the nexthops. The Mac addresses are supplied by neigh_entries.
 *
 *
 *   +-------------+    +--------------+
 *   |  fib_entry  |    | nexthop group|
 *   | 6.6.0.0/164 |----+              |
 *   +-------------+    |  nexthop --------> neigh_entry 1.0.11.10
 *                      |  nexthop --------> neigh_entry 1.0.10.10
 *                      |  nexthop --------> neigh_entry 1.0.9.10
 *                      +--------------+
 *
 *
 * 3) Local routes for traffic destined to the router. If the router has an IP
 *    1.0.10.1, then we must ensure this traffic is sent to the CPU.
 *    Therefore, we install a direct route for 1.0.10.1/32 in the LPM VCAP, with
 *    zero mac.
 *
 * On the hardware side, we use the VCAP LPM and ARP table for UC IPv4 routing.
 * HW picks the match found at the highest address in the VCAP LPM. To ensure the
 * longest prefix match we make sure to order the entries according to mask
 * length, with longer masks at higher addresses.
 *
 * It is possible to store ARP data, such as DMAC, directly in the VCAP LPM using
 * ARP entry actions. We do this whenever possible, so the ARP table is only used
 * when a route has multiple nexthops.
 *
 * With the above breakdown in mind, cases 1) and 3) use arp entries, and case 2)
 * use the arp table if the number of nexthops is >1.
 *
 * If the DMAC written to HW is all zero, the chip will trap the frame,
 * redirecting it to the CPU. This is how we get the kernel to perform ARP
 * requests on our behalf.
 *
 * The nexthop group must be laid out at contiguous addresses in the ARP table.
 * The VCAP LPM stores a pointer to the bottom address in the group, and the
 * group size. We do not use the arp pointer remap table.
 *
 * The layout of nexthops in a nexthop group matches the layout in HW, e.g.
 *
 * nhgi->nexthops[0] -> arp table address n
 * ...
 * nhgi->nexthops[k] -> arp table address n+k
 *
 * where the n is the ARP table offset (atbl_offset) for the group.
 */

#define SPARX5_MAX_ECMP_SIZE 16
#define SPARX5_RLEG_USE_GLOBAL_BASE_MAC 2

struct sparx5_fib_event_work {
	struct work_struct work;
	union {
		/* Expand for ipv6 and other fib event payload types */
		struct fib_entry_notifier_info fen_info;
	};
	struct sparx5 *sparx5;
	unsigned long event;
};

struct sparx5_rr_netevent_work {
	struct work_struct work;
	struct sparx5 *sparx5;
	struct neighbour *neigh;
	unsigned long event;
};

struct sparx5_rr_router_leg {
	struct net_device *dev;
	struct sparx5 *sparx5;
	struct list_head leg_list_node; /* Router member */
	unsigned char hwaddr[ETH_ALEN];
	u16 vmid; /* Internal id */
	u32 vid; /* VLAN id */
};

struct sparx5_iaddr {
	union {
		__be32 ipv4;
		struct in6_addr ipv6;
	}; /* Must be first */
	enum {
		SPARX5_IPV4 = 0,
		SPARX5_IPV6,
	} version;
};

#define SPARX5_IADDR_LEN(v) ((v) == SPARX5_IPV4 ? 32 : 128)

struct sparx5_rr_hw_route {
	u32 vrule_id;
	bool vrule_id_valid;
};

struct sparx5_rr_neigh_entry {
	struct sparx5_rr_neigh_key {
		struct net_device *dev;
		struct sparx5_iaddr iaddr;
	} key;
	struct rhash_head ht_node;
	struct sparx5_rr_fib_entry *fib_entry;
	struct list_head fib_list_node; /* Fib route for this neighbour */
	struct sparx5_port *lower_port; /* Need ref to a physical port below
					 * neigh egress dev.
					 */
	struct list_head nexthop_list; /* Nexthops using this neigh entry */
	struct sparx5_rr_hw_route hw_route;
	unsigned char hwaddr[ETH_ALEN];
	u16 vmid;
	bool connected;
};

struct sparx5_rr_nexthop {
	struct sparx5_rr_neigh_entry *neigh_entry;
	struct sparx5_rr_nexthop_group *grp;
	struct list_head neigh_list_node; /* Neigh entry member */
	struct list_head leg_list_node; /* Router leg member */
	struct sparx5_iaddr gw_addr;
	int ifindex;
	bool gateway;
	bool trapped;
};

struct sparx5_rr_nexthop_group_info {
	struct sparx5_rr_nexthop_group *grp;
	u16 atbl_offset;
	bool atbl_offset_valid;
	u8 count; /* HW allows up to 16 nexthops */
	struct sparx5_rr_nexthop nexthops[] __counted_by(count);
};

struct sparx5_rr_nexthop_group {
	struct sparx5_rr_fib_entry *fib_entry;
	struct sparx5_rr_nexthop_group_info *nhgi;
};

enum sparx5_rr_fib_type {
	SPARX5_RR_FIB_TYPE_INVALID = 0,
	SPARX5_RR_FIB_TYPE_LOCAL,
	SPARX5_RR_FIB_TYPE_UNICAST,
	SPARX5_RR_FIB_TYPE_MULTICAST,
	SPARX5_RR_FIB_TYPE_BLACKHOLE,
	SPARX5_RR_FIB_TYPE_PROHIBIT,
};

struct sparx5_rr_fib_key {
	struct sparx5_iaddr addr;
	u32 prefix_len;
	u32 tb_id; /* Routing table type: RT_TABLE_* */
};

struct sparx5_rr_fib_entry {
	struct sparx5_rr_fib_key key;
	enum sparx5_rr_fib_type type;
	struct rhash_head ht_node; /* Router member */
	struct list_head fib_lpm_node; /* Router member */
	struct list_head neigh_list; /* Neighbours under this route */
	struct sparx5_rr_hw_route hw_route;
	struct sparx5_rr_nexthop_group *nh_grp;
	struct sparx5_port *lower_port; /* For VCAP API */
	struct fib_entry_notifier_info fen4_info;
	u64 sort_key; /* For sw lpm lookup */
	bool trap;
	bool offload_fail;
};

static void sparx5_rr_schedule_work(struct sparx5 *sparx5,
				    struct work_struct *work)
{
	queue_work(sparx5->router->sparx5_router_owq, work);
}

static void sparx5_rr_split_mac(unsigned char mac[ETH_ALEN], u32 split,
				u32 *msb, u32 *lsb)
{
	u32 mask = GENMASK(split - 1, 0);
	u64 m = ether_addr_to_u64(mac);

	*lsb = m & mask;
	*msb = m >> split;
}

static int sparx5_rr_arp_tbl_grp_alloc(struct sparx5 *sparx5,
				       unsigned int nh_grp_size)
{
	int offset;

	offset = bitmap_find_next_zero_area(sparx5->router->arp_tbl_mask,
					    sparx5->data->consts.arp_tbl_cnt, 0,
					    nh_grp_size, 0);
	if (offset >= sparx5->data->consts.arp_tbl_cnt)
		return -ENOMEM;

	bitmap_set(sparx5->router->arp_tbl_mask, offset, nh_grp_size);

	return offset;
}

static void sparx5_rr_arp_tbl_grp_free(struct sparx5 *sparx5,
				       unsigned int nh_grp_size, int offset)
{
	bitmap_clear(sparx5->router->arp_tbl_mask, offset, nh_grp_size);
}

static int sparx5_vmid_alloc(struct sparx5 *sparx5)
{
	int vmid;

	vmid = find_first_zero_bit(sparx5->router->vmid_mask,
				   sparx5->data->consts.vmid_cnt);
	if (vmid >= sparx5->data->consts.vmid_cnt)
		return -ENOMEM;

	set_bit(vmid, sparx5->router->vmid_mask);

	return vmid;
}

static void sparx5_vmid_free(struct sparx5 *sparx5, u16 vmid)
{
	clear_bit(vmid, sparx5->router->vmid_mask);
}

static void sparx5_rr_nb2neigh_key(struct neighbour *n,
				   struct sparx5_rr_neigh_key *key)
{
	memset(key, 0, sizeof(*key));

	if (n->tbl->family == AF_INET) {
		key->iaddr.version = SPARX5_IPV4;
		key->iaddr.ipv4 = *(__be32 *)n->primary_key;
	} else {
		key->iaddr.version = SPARX5_IPV6;
		key->iaddr.ipv6 = *(struct in6_addr *)n->primary_key;
	}

	key->dev = n->dev;
}

static void
sparx5_rr_neigh_entry_offload_mark(struct sparx5_rr_neigh_entry *entry,
				   bool offloaded)
{
	struct neighbour *n;

	n = neigh_lookup(&arp_tbl, &entry->key.iaddr.ipv4, entry->key.dev);
	if (!n)
		return;

	if (offloaded)
		n->flags |= NTF_OFFLOADED;
	else
		n->flags &= ~NTF_OFFLOADED;

	neigh_release(n);
}

static const struct rhashtable_params sparx5_neigh_ht_params = {
	.key_offset = offsetof(struct sparx5_rr_neigh_entry, key),
	.head_offset = offsetof(struct sparx5_rr_neigh_entry, ht_node),
	.key_len = sizeof(struct sparx5_rr_neigh_key),
	.automatic_shrinking = true,
};

static const struct rhashtable_params sparx5_rr_fib_entry_ht_params = {
	.key_offset = offsetof(struct sparx5_rr_fib_entry, key),
	.head_offset = offsetof(struct sparx5_rr_fib_entry, ht_node),
	.key_len = sizeof(struct sparx5_rr_fib_key),
	.automatic_shrinking = true,
};

static bool
sparx5_rr_nexthop4_group_has_nexthop(struct sparx5_rr_nexthop_group *nh_grp,
				     __be32 gw, int ifindex)
{
	for (u8 i = 0; i < nh_grp->nhgi->count; i++) {
		struct sparx5_rr_nexthop *nh;

		nh = &nh_grp->nhgi->nexthops[i];
		if (nh->ifindex == ifindex && nh->gw_addr.ipv4 == gw)
			return true;
	}

	return false;
}

static bool
sparx5_rr_nexthop4_group_equal(struct sparx5_rr_nexthop_group *nh_grp,
			       struct fib_info *fi)
{
	u8 nhs = fib_info_num_path(fi);
	struct fib_nh_common *nhc;
	int ifindex;
	__be32 gw;

	if (nh_grp->nhgi->count != nhs)
		return false;

	for (u8 i = 0; i < nhs; i++) {
		nhc = fib_info_nhc(fi, i);
		ifindex = nhc->nhc_dev->ifindex;
		gw = nhc->nhc_gw.ipv4;
		if (!sparx5_rr_nexthop4_group_has_nexthop(nh_grp, gw, ifindex))
			return false;
	}

	return true;
}

static u16 sparx5_rr_route_sort_key(u32 prefix_len)
{
	/* Order longer prefixes at high addresses. */
	return SPARX5_IADDR_LEN(SPARX5_IPV6) - prefix_len;
}

static void sparx5_rr_to_fib_key(struct sparx5 *sparx5, u32 dst, int dst_len,
				 u32 tb_id, struct sparx5_rr_fib_key *key)
{
	memset(key, 0, sizeof(*key));
	key->addr.version = SPARX5_IPV4;
	key->addr.ipv4 = cpu_to_be32(dst);
	key->prefix_len = dst_len;
	key->tb_id = tb_id;
}

static void sparx5_rr_finfo_to_fib_key(struct sparx5 *sparx5,
				       struct fib_entry_notifier_info *fen_info,
				       struct sparx5_rr_fib_key *key)
{
	sparx5_rr_to_fib_key(sparx5, fen_info->dst, fen_info->dst_len,
			     fen_info->tb_id, key);
}

static bool
sparx5_rr_fib_entry_lpm4_match(__be32 addr,
			       struct sparx5_rr_fib_entry *fib_entry)
{
	__be32 mask = inet_make_mask(fib_entry->key.prefix_len);

	return !((addr ^ fib_entry->key.addr.ipv4) & mask);
}

static struct sparx5_rr_fib_entry *
sparx5_rr_fib_lpm4_lookup(struct sparx5 *sparx5, __be32 addr)
{
	struct sparx5_rr_fib_entry *iter;

	list_for_each_entry(iter, &sparx5->router->fib_lpm_list, fib_lpm_node) {
		if (sparx5_rr_fib_entry_lpm4_match(addr, iter))
			return iter;
	}

	return NULL;
}

static bool
sparx5_rr_fib_lpm4_is_interesting(struct sparx5_rr_fib_entry *fib_entry)
{
	/* No need to search through local FIB entries */
	return fib_entry->type == SPARX5_RR_FIB_TYPE_UNICAST;
}

static void sparx5_rr_fib_lpm4_insert(struct sparx5 *sparx5,
				      struct sparx5_rr_fib_entry *fib_entry)
{
	struct sparx5_rr_fib_entry *iter, *next = NULL;

	if (!sparx5_rr_fib_lpm4_is_interesting(fib_entry))
		return;

	list_for_each_entry(iter, &sparx5->router->fib_lpm_list, fib_lpm_node) {
		if (fib_entry->sort_key < iter->sort_key) {
			next = iter;
			break;
		}
	}

	if (!next) {
		list_add_tail(&fib_entry->fib_lpm_node,
			      &sparx5->router->fib_lpm_list);
		return;
	}

	/* Add before next entry */
	list_add_tail(&fib_entry->fib_lpm_node, &next->fib_lpm_node);
}

static void sparx5_rr_fib_lpm4_remove(struct sparx5_rr_fib_entry *fib_entry)
{
	if (!sparx5_rr_fib_lpm4_is_interesting(fib_entry))
		return;

	list_del(&fib_entry->fib_lpm_node);
}

static struct sparx5_rr_router_leg *
sparx5_rr_leg_find_by_dev(struct sparx5 *sparx5, struct net_device *dev)
{
	struct sparx5_rr_router_leg *leg;

	list_for_each_entry(leg, &sparx5->router->leg_list, leg_list_node) {
		if (leg->dev == dev)
			return leg;
	}

	return NULL;
}

static struct sparx5_rr_fib_entry *
sparx5_rr_fib_entry_lookup(struct sparx5 *sparx5, struct sparx5_rr_fib_key *key)
{
	return rhashtable_lookup_fast(&sparx5->router->fib_ht, key,
				      sparx5_rr_fib_entry_ht_params);
}

static int sparx5_rr_fib_entry_insert(struct sparx5 *sparx5,
				      struct sparx5_rr_fib_entry *fib_entry)
{
	return rhashtable_insert_fast(&sparx5->router->fib_ht,
				      &fib_entry->ht_node,
				      sparx5_rr_fib_entry_ht_params);
}

static void sparx5_rr_fib_entry_remove(struct sparx5 *sparx5,
				       struct sparx5_rr_fib_entry *fib_entry)
{
	rhashtable_remove_fast(&sparx5->router->fib_ht, &fib_entry->ht_node,
			       sparx5_rr_fib_entry_ht_params);
}

static struct sparx5_rr_neigh_entry *
sparx5_rr_neigh_entry_lookup(struct sparx5 *sparx5,
			     struct sparx5_rr_neigh_key *key)
{
	return rhashtable_lookup_fast(&sparx5->router->neigh_ht, key,
				      sparx5_neigh_ht_params);
}

static int sparx5_rr_neigh_entry_insert(struct sparx5 *sparx5,
					struct sparx5_rr_neigh_entry *entry)
{
	return rhashtable_insert_fast(&sparx5->router->neigh_ht,
				      &entry->ht_node, sparx5_neigh_ht_params);
}

static void sparx5_rr_neigh_entry_remove(struct sparx5 *sparx5,
					 struct sparx5_rr_neigh_entry *entry)
{
	rhashtable_remove_fast(&sparx5->router->neigh_ht, &entry->ht_node,
			       sparx5_neigh_ht_params);
}

static int sparx5_lower_dev_walk(struct net_device *lower_dev,
				 struct netdev_nested_priv *priv)
{
	int ret = 0;

	if (sparx5_netdevice_check(lower_dev)) {
		priv->data = (void *)netdev_priv(lower_dev);
		ret = 1;
	}

	return ret;
}

static struct sparx5_port *sparx5_port_dev_lower_find_rcu(struct net_device *dev)
{
	struct netdev_nested_priv priv = {
		.data = NULL,
	};

	if (sparx5_netdevice_check(dev))
		return netdev_priv(dev);

	netdev_walk_all_lower_dev_rcu(dev, sparx5_lower_dev_walk, &priv);

	return priv.data;
}

static struct sparx5_rr_neigh_entry *
sparx5_rr_neigh_entry_alloc(struct sparx5 *sparx5,
			    struct sparx5_rr_neigh_key *key,
			    struct sparx5_rr_router_leg *leg,
			    struct sparx5_port *port_below)
{
	struct sparx5_rr_neigh_entry *entry;

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return NULL;

	memcpy(&entry->key, key, sizeof(*key));

	entry->vmid = leg->vmid;
	entry->hw_route.vrule_id = 0;
	entry->hw_route.vrule_id_valid = false;
	entry->lower_port = port_below;
	entry->fib_entry = NULL;

	eth_zero_addr(entry->hwaddr);

	INIT_LIST_HEAD(&entry->nexthop_list);
	INIT_LIST_HEAD(&entry->fib_list_node);

	return entry;
}

static int sparx5_rr_neigh_entry_fib_link(struct sparx5 *sparx5,
					  struct sparx5_rr_neigh_entry *entry)
{
	struct sparx5_rr_fib_entry *fib_entry;

	fib_entry = sparx5_rr_fib_lpm4_lookup(sparx5, entry->key.iaddr.ipv4);
	if (!fib_entry)
		return -ENOENT;

	list_add(&entry->fib_list_node, &fib_entry->neigh_list);
	entry->fib_entry = fib_entry;

	return 0;
}

static struct sparx5_rr_neigh_entry *
sparx5_rr_neigh_entry_create(struct sparx5 *sparx5,
			     struct sparx5_rr_neigh_key *key)
{
	struct sparx5_rr_neigh_entry *entry;
	struct sparx5_rr_router_leg *leg;
	struct sparx5_port *port_below;
	int err;

	rcu_read_lock();
	port_below = sparx5_port_dev_lower_find_rcu(key->dev);
	rcu_read_unlock();
	if (!port_below)
		return ERR_PTR(-EINVAL);

	leg = sparx5_rr_leg_find_by_dev(sparx5, key->dev);
	if (!leg)
		return ERR_PTR(-EINVAL);

	entry = sparx5_rr_neigh_entry_alloc(sparx5, key, leg, port_below);
	if (!entry)
		return ERR_PTR(-ENOMEM);

	err = sparx5_rr_neigh_entry_insert(sparx5, entry);
	if (err)
		goto err_insert;

	err = sparx5_rr_neigh_entry_fib_link(sparx5, entry);
	if (err)
		goto err_fib_link;

	netdev_hold(entry->key.dev, NULL, GFP_KERNEL);

	return entry;

err_fib_link:
	sparx5_rr_neigh_entry_remove(sparx5, entry);
err_insert:
	kfree(entry);
	return ERR_PTR(err);
}

static int sparx5_rr_nexthop_neigh_init(struct sparx5 *sparx5,
					struct sparx5_rr_router_leg *leg,
					struct sparx5_rr_nexthop *nh)
{
	struct sparx5_rr_neigh_entry *neigh_entry;
	struct net_device *dev = leg->dev;
	struct sparx5_rr_neigh_key key;
	struct neighbour *n;
	int err = 0;

	if (!nh->gateway || nh->neigh_entry)
		return 0;

	/* Look up neighbor in the global IPv4 neighbor table. Takes ref to n. */
	n = neigh_lookup(&arp_tbl, &nh->gw_addr, dev);
	if (!n) {
		n = neigh_create(&arp_tbl, &nh->gw_addr, dev);
		if (IS_ERR(n))
			return PTR_ERR(n);
		/* Start arp process */
		neigh_event_send(n, NULL);
	}

	sparx5_rr_nb2neigh_key(n, &key);

	neigh_entry = sparx5_rr_neigh_entry_lookup(sparx5, &key);
	if (!neigh_entry) {
		neigh_entry = sparx5_rr_neigh_entry_create(sparx5, &key);
		if (IS_ERR(neigh_entry)) {
			err = PTR_ERR(neigh_entry);
			goto out;
		}
	}

	nh->neigh_entry = neigh_entry;
	list_add_tail(&nh->neigh_list_node, &neigh_entry->nexthop_list);

out:
	neigh_release(n);
	return err;
}

static void sparx5_rr_neigh_entry_destroy(struct sparx5 *sparx5,
					  struct sparx5_rr_neigh_entry *entry)
{
	WARN_ON(entry->hw_route.vrule_id_valid);

	if (entry->fib_entry)
		list_del(&entry->fib_list_node);

	sparx5_rr_neigh_entry_offload_mark(entry, false);
	sparx5_rr_neigh_entry_remove(sparx5, entry);
	netdev_put(entry->key.dev, NULL);

	dev_dbg(sparx5->dev,
		"Neigh entry destroyed vmid=%u mac=%pM ipv4=%pI4b\n",
		entry->vmid, entry->hwaddr, &entry->key.iaddr);

	kfree(entry);
}

static void sparx5_rr_neigh_entry_put(struct sparx5 *sparx5,
				      struct sparx5_rr_neigh_entry *neigh_entry)
{
	if (neigh_entry && list_empty(&neigh_entry->nexthop_list) &&
	    !neigh_entry->hw_route.vrule_id_valid)
		sparx5_rr_neigh_entry_destroy(sparx5, neigh_entry);
}

static void sparx5_rr_nexthop4_deinit(struct sparx5 *sparx5,
				      struct sparx5_rr_nexthop *nh)
{
	struct sparx5_rr_neigh_entry *neigh_entry = nh->neigh_entry;

	if (neigh_entry) {
		list_del(&nh->neigh_list_node);
		sparx5_rr_neigh_entry_put(sparx5, neigh_entry);
	}

	nh->neigh_entry = NULL;
}

static int sparx5_rr_nexthop4_init(struct sparx5 *sparx5,
				   struct sparx5_rr_nexthop_group *nh_grp,
				   struct sparx5_rr_nexthop *nh,
				   struct fib_nh *fib_nh)
{
	struct net_device *dev = fib_nh->fib_nh_dev;
	struct sparx5_rr_router_leg *leg;

	leg = sparx5_rr_leg_find_by_dev(sparx5, dev);
	if (!leg)
		return -EINVAL;

	nh->ifindex = dev->ifindex;
	nh->grp = nh_grp;
	nh->gateway = fib_nh->nh_common.nhc_gw_family != 0;
	nh->trapped = false;
	nh->neigh_entry = NULL;

	memset(&nh->gw_addr, 0, sizeof(nh->gw_addr));

	if (!nh->gateway)
		return 0;

	switch (fib_nh->nh_common.nhc_gw_family) {
	case AF_INET:
		nh->gw_addr.version = SPARX5_IPV4;
		nh->gw_addr.ipv4 = fib_nh->nh_common.nhc_gw.ipv4;
		break;
	case AF_INET6:
		nh->gw_addr.version = SPARX5_IPV6;
		nh->gw_addr.ipv6 = fib_nh->nh_common.nhc_gw.ipv6;
		break;
	default:
		return 0;
	}

	return sparx5_rr_nexthop_neigh_init(sparx5, leg, nh);
}

static int
sparx5_rr_nexthop4_group_info_init(struct sparx5 *sparx5,
				   struct sparx5_rr_nexthop_group *nh_grp,
				   struct fib_info *fi)
{
	struct sparx5_rr_nexthop_group_info *nhgi;
	unsigned int nhs = fib_info_num_path(fi);
	struct sparx5_rr_nexthop *nh;
	int err, i;

	nhgi = kzalloc(struct_size(nhgi, nexthops, nhs), GFP_KERNEL);
	if (!nhgi)
		return -ENOMEM;

	nh_grp->nhgi = nhgi;
	nhgi->grp = nh_grp;
	nhgi->atbl_offset_valid = false;
	nhgi->atbl_offset = 0;
	nhgi->count = nhs;

	for (i = 0; i < nhgi->count; i++) {
		struct fib_nh *fib_nh;

		nh = &nhgi->nexthops[i];
		fib_nh = fib_info_nh(fi, i);
		err = sparx5_rr_nexthop4_init(sparx5, nh_grp, nh, fib_nh);
		if (err)
			goto err_nexthop_init;
	}

	return 0;

err_nexthop_init:
	for (i--; i >= 0; i--) {
		nh = &nhgi->nexthops[i];
		sparx5_rr_nexthop4_deinit(sparx5, nh);
	}
	kfree(nhgi);
	return err;
}

static void
sparx5_rr_nexthop4_group_info_deinit(struct sparx5 *sparx5,
				     struct sparx5_rr_nexthop_group *nh_grp)
{
	struct sparx5_rr_nexthop_group_info *nhgi = nh_grp->nhgi;
	struct sparx5_rr_nexthop *nh;
	int i;

	WARN_ON(!nhgi->count);
	WARN_ON_ONCE(nhgi->atbl_offset_valid);

	for (i = nhgi->count - 1; i >= 0; i--) {
		nh = &nhgi->nexthops[i];

		sparx5_rr_nexthop4_deinit(sparx5, nh);
	}

	kfree(nhgi);
}

static void sparx5_rr_arp_tbl_hw_addr_apply(struct sparx5 *sparx5,
					    unsigned char mac[ETH_ALEN],
					    u16 evmid, int offset)
{
	u32 mac_msb, mac_lsb;

	sparx5_rr_split_mac(mac, 32, &mac_msb, &mac_lsb);

	spx5_rmw(ANA_L3_ARP_CFG_0_MAC_MSB_SET(mac_msb) |
		 ANA_L3_ARP_CFG_0_ARP_VMID_SET(evmid) |
		 ANA_L3_ARP_CFG_0_ARP_ENA_SET(1),
		 ANA_L3_ARP_CFG_0_ARP_ENA |
		 ANA_L3_ARP_CFG_0_ARP_VMID |
		 ANA_L3_ARP_CFG_0_MAC_MSB,
		 sparx5, ANA_L3_ARP_CFG_0(offset));

	spx5_wr(mac_lsb, sparx5, ANA_L3_ARP_CFG_1(offset));
}

static void sparx5_rr_arp_tbl_hw_addr_clear(struct sparx5 *sparx5, int offset)
{
	spx5_rmw(ANA_L3_ARP_CFG_0_ARP_ENA_SET(0), ANA_L3_ARP_CFG_0_ARP_ENA,
		 sparx5, ANA_L3_ARP_CFG_0(offset));
}

static void
sparx5_rr_nh_grp_arp_tbl_grp_clear(struct sparx5 *sparx5,
				   struct sparx5_rr_nexthop_group *nh_grp)
{
	int offset = nh_grp->nhgi->atbl_offset;

	if (nh_grp->nhgi->atbl_offset_valid)
		for (u8 i = 0; i < nh_grp->nhgi->count; i++)
			sparx5_rr_arp_tbl_hw_addr_clear(sparx5, offset + i);

	sparx5_rr_arp_tbl_grp_free(sparx5, nh_grp->nhgi->count, offset);
	nh_grp->nhgi->atbl_offset_valid = false;
}

static void sparx5_rr_nexthop4_group_put(struct sparx5 *sparx5,
					 struct sparx5_rr_nexthop_group *nh_grp)
{
	sparx5_rr_nh_grp_arp_tbl_grp_clear(sparx5, nh_grp);
	sparx5_rr_nexthop4_group_info_deinit(sparx5, nh_grp);
	kfree(nh_grp);
}

static struct sparx5_rr_nexthop_group *
sparx5_rr_nexthop4_group_create(struct sparx5 *sparx5, struct fib_info *fi)
{
	struct sparx5_rr_nexthop_group *nh_grp;
	int err;

	nh_grp = kzalloc(sizeof(*nh_grp), GFP_KERNEL);
	if (!nh_grp)
		return ERR_PTR(-ENOMEM);

	err = sparx5_rr_nexthop4_group_info_init(sparx5, nh_grp, fi);
	if (err)
		goto err_group_info_init;

	return nh_grp;

err_group_info_init:
	kfree(nh_grp);
	return ERR_PTR(err);
}

static enum sparx5_rr_fib_type sparx5_rr_rtm_type2fib_type(u8 type)
{
	switch (type) {
	case RTN_UNICAST:
		return SPARX5_RR_FIB_TYPE_UNICAST;
	case RTN_LOCAL:
		return SPARX5_RR_FIB_TYPE_LOCAL;
	case RTN_MULTICAST:
		return SPARX5_RR_FIB_TYPE_MULTICAST;
	case RTN_BLACKHOLE:
		return SPARX5_RR_FIB_TYPE_BLACKHOLE;
	case RTN_PROHIBIT:
		return SPARX5_RR_FIB_TYPE_PROHIBIT;
	default:
		return SPARX5_RR_FIB_TYPE_INVALID;
	}
}

static void
sparx5_rr_fib_entry_fen_info_replace(struct sparx5_rr_fib_entry *fib_entry,
				     struct fib_entry_notifier_info *fen_info)
{
	if (fib_entry->fen4_info.fi)
		/* Release and allow any previous fib_info to be deleted */
		fib_info_put(fib_entry->fen4_info.fi);

	/* Prevent the fib_info from being deleted while we store the fen_info */
	fib_info_hold(fen_info->fi);
	memcpy(&fib_entry->fen4_info, fen_info, sizeof(*fen_info));
}

static struct sparx5_rr_fib_entry *
sparx5_rr_fib_entry_create(struct sparx5 *sparx5, struct sparx5_rr_fib_key *key,
			   struct fib_entry_notifier_info *fen_info)
{
	struct sparx5_rr_nexthop_group *nh_grp;
	struct sparx5_rr_fib_entry *fib_entry;
	struct fib_nh_common *nhc;
	int err;

	fib_entry = kzalloc(sizeof(*fib_entry), GFP_KERNEL);
	if (!fib_entry)
		return ERR_PTR(-ENOMEM);

	memcpy(&fib_entry->key, key, sizeof(*key));
	fib_entry->fen4_info.fi = NULL;
	sparx5_rr_fib_entry_fen_info_replace(fib_entry, fen_info);
	fib_entry->type = sparx5_rr_rtm_type2fib_type(fen_info->type);
	fib_entry->sort_key = sparx5_rr_route_sort_key(key->prefix_len);

	err = sparx5_rr_fib_entry_insert(sparx5, fib_entry);
	if (err)
		goto err_fib_entry_insert;

	/* Need a lower port ref for VCAP API. TODO: Accommodate fib types
	 * without meaningful lower ports, such as blackholes.
	 */
	if (fen_info->fi->fib_nhs > 0) {
		nhc = fib_info_nhc(fen_info->fi, 0);
		rcu_read_lock();
		fib_entry->lower_port =
			sparx5_port_dev_lower_find_rcu(nhc->nhc_dev);
		rcu_read_unlock();
	}

	nh_grp = sparx5_rr_nexthop4_group_create(sparx5, fen_info->fi);
	if (IS_ERR(nh_grp)) {
		err = PTR_ERR(nh_grp);
		goto err_nexthop4_group_create;
	}

	fib_entry->nh_grp = nh_grp;
	nh_grp->fib_entry = fib_entry;
	INIT_LIST_HEAD(&fib_entry->neigh_list);

	sparx5_rr_fib_lpm4_insert(sparx5, fib_entry);

	return fib_entry;

err_nexthop4_group_create:
	sparx5_rr_fib_entry_remove(sparx5, fib_entry);
err_fib_entry_insert:
	fib_info_put(fen_info->fi);
	kfree(fib_entry);

	return ERR_PTR(err);
}

static void
sparx5_rr_fib4_entry_offload_mark(struct sparx5 *sparx5,
				  struct sparx5_rr_fib_entry *fib_entry)
{
	int dst_len = fib_entry->key.prefix_len;
	struct fib_rt_info fri;

	fri.fi = fib_entry->fen4_info.fi;
	fri.tb_id = fib_entry->key.tb_id;
	fri.dst = fib_entry->key.addr.ipv4;
	fri.dst_len = dst_len;
	fri.dscp = fib_entry->fen4_info.dscp;
	fri.type = fib_entry->fen4_info.type;
	fri.offload_failed = fib_entry->offload_fail;

	if (fib_entry->offload_fail) {
		fri.offload = false;
		fri.trap = false;
	} else {
		fri.offload = true;
		fri.trap = fib_entry->trap;
	}

	fib_alias_hw_flags_set(&init_net, &fri);
}

static int sparx5_rr_lpm4_arp_entry_create(struct sparx5 *sparx5,
					   struct net_device *port_dev,
					   __be32 addr, u32 prefix_len,
					   unsigned char mac[ETH_ALEN],
					   u16 evmid,
					   struct sparx5_rr_hw_route *hw_route)
{
	u32 priority = sparx5_rr_route_sort_key(prefix_len);
	struct vcap_control *vctrl = sparx5->vcap_ctrl;
	u32 mask = ntohl(inet_make_mask(prefix_len));
	u32 iaddr = ntohl(addr);
	struct vcap_rule *rule;
	u32 mac_msb, mac_lsb;
	int err;

	sparx5_rr_split_mac(mac, 32, &mac_msb, &mac_lsb);

	rule = vcap_alloc_rule(vctrl, port_dev, VCAP_CID_PREROUTING_L0,
			       VCAP_USER_L3, priority, 0);
	if (!rule)
		return -ENOMEM;

	err = vcap_rule_add_key_u32(rule, VCAP_KF_IP4_XIP, iaddr, mask);
	err |= vcap_rule_add_key_u32(rule, VCAP_KF_AFFIX, 0, 0);
	err |= vcap_rule_add_key_bit(rule, VCAP_KF_DST_FLAG, VCAP_BIT_1);
	if (err)
		goto free_rule;

	err = vcap_rule_add_action_u32(rule, VCAP_AF_MAC_MSB, mac_msb);
	err |= vcap_rule_add_action_u32(rule, VCAP_AF_MAC_LSB, mac_lsb);
	err |= vcap_rule_add_action_u32(rule, VCAP_AF_ARP_VMID, evmid);
	err |= vcap_rule_add_action_bit(rule, VCAP_AF_ARP_ENA, VCAP_BIT_1);
	if (err)
		goto free_rule;

	err = vcap_val_rule(rule, ETH_P_IP);
	if (err)
		goto free_rule;

	hw_route->vrule_id = rule->id;
	hw_route->vrule_id_valid = true;
	err = vcap_add_rule(rule);

free_rule:
	vcap_free_rule(rule);

	return err;
}

static int sparx5_rr_lpm4_arp_entry_mod(struct sparx5 *sparx5,
					unsigned char mac[ETH_ALEN], u16 evmid,
					u32 vrule_id)
{
	struct vcap_control *vctrl = sparx5->vcap_ctrl;
	struct vcap_rule *vrule;
	u32 mac_msb, mac_lsb;
	int err;

	sparx5_rr_split_mac(mac, 32, &mac_msb, &mac_lsb);

	vrule = vcap_get_rule(vctrl, vrule_id);
	if (IS_ERR(vrule))
		return -EINVAL;

	err = vcap_rule_mod_action_u32(vrule, VCAP_AF_MAC_MSB, mac_msb);
	err |= vcap_rule_mod_action_u32(vrule, VCAP_AF_MAC_LSB, mac_lsb);
	err |= vcap_rule_mod_action_u32(vrule, VCAP_AF_ARP_VMID, evmid);
	err |= vcap_rule_mod_action_bit(vrule, VCAP_AF_ARP_ENA, VCAP_BIT_1);
	if (err)
		goto free_rule;

	err = vcap_mod_rule(vrule);

free_rule:
	vcap_free_rule(vrule);

	return err;
}

static int
sparx5_rr_fib_entry_update_arp_entry(struct sparx5 *sparx5,
				     struct sparx5_rr_fib_entry *fib_entry,
				     unsigned char mac[ETH_ALEN], u16 evmid)
{
	struct vcap_control *vctrl = sparx5->vcap_ctrl;
	u32 vrule_id = fib_entry->hw_route.vrule_id;
	struct vcap_rule *vrule;
	u32 mac_msb, mac_lsb;
	int err;

	sparx5_rr_split_mac(mac, 32, &mac_msb, &mac_lsb);

	vrule = vcap_get_rule(vctrl, vrule_id);
	if (IS_ERR(vrule))
		return -EINVAL;

	switch (vrule->actionset) {
	case VCAP_AFS_ARP_ENTRY:
		err = vcap_rule_mod_action_u32(vrule, VCAP_AF_MAC_MSB, mac_msb);
		err |= vcap_rule_mod_action_u32(vrule, VCAP_AF_MAC_LSB,
						mac_lsb);
		if (err)
			goto free_rule;

		err = vcap_mod_rule(vrule);
		goto free_rule;
	case VCAP_AFS_ARP_PTR:
		/* Convert arp_ptr to arp_entry */
		err = sparx5_rr_lpm4_arp_entry_create(sparx5,
						      fib_entry->lower_port->ndev,
						      fib_entry->key.addr.ipv4,
						      fib_entry->key.prefix_len,
						      mac, evmid,
						      &fib_entry->hw_route);
		if (err)
			goto free_rule;

		sparx5_rr_nh_grp_arp_tbl_grp_clear(sparx5, fib_entry->nh_grp);
		err = vcap_del_rule(vctrl, fib_entry->lower_port->ndev,
				    vrule_id);
		goto free_rule;
	default:
		err = -EINVAL;
		WARN_ON(1); /* BUG */
	}

free_rule:
	vcap_free_rule(vrule);

	return err;
}

static int sparx5_rr_lpm4_arp_ptr_create(struct sparx5 *sparx5,
					 struct net_device *port_dev,
					 __be32 addr, u32 prefix_len,
					 u32 arp_offset_addr, u8 ecmp_size,
					 struct sparx5_rr_hw_route *hw_route)
{
	u32 priority = sparx5_rr_route_sort_key(prefix_len);
	struct vcap_control *vctrl = sparx5->vcap_ctrl;
	u32 mask = ntohl(inet_make_mask(prefix_len));
	u32 iaddr = ntohl(addr);
	struct vcap_rule *rule;
	int err;

	rule = vcap_alloc_rule(vctrl, port_dev, VCAP_CID_PREROUTING_L0,
			       VCAP_USER_L3, priority, 0);
	if (!rule)
		return PTR_ERR(rule);

	err = vcap_rule_add_key_u32(rule, VCAP_KF_IP4_XIP, iaddr, mask);
	err |= vcap_rule_add_key_u32(rule, VCAP_KF_AFFIX, 0, 0);
	err |= vcap_rule_add_key_bit(rule, VCAP_KF_DST_FLAG, VCAP_BIT_1);
	if (err)
		goto out;

	err = vcap_rule_add_action_u32(rule, VCAP_AF_ARP_PTR, arp_offset_addr);
	err |= vcap_rule_add_action_bit(rule, VCAP_AF_ARP_PTR_REMAP_ENA,
					VCAP_BIT_0);
	err |= vcap_rule_add_action_u32(rule, VCAP_AF_ECMP_CNT, ecmp_size - 1);
	err |= vcap_rule_add_action_u32(rule, VCAP_AF_RGID, 0);
	if (err)
		goto out;

	err = vcap_val_rule(rule, ETH_P_IP);
	if (err)
		goto out;

	hw_route->vrule_id = rule->id;
	hw_route->vrule_id_valid = true;
	err = vcap_add_rule(rule);

out:
	vcap_free_rule(rule);

	return err;
}

static int
sparx5_rr_fib_entry_ecmp_hw_apply(struct sparx5 *sparx5,
				  struct sparx5_rr_fib_entry *fib_entry)
{
	struct sparx5_rr_nexthop_group_info *nhgi = fib_entry->nh_grp->nhgi;
	struct net_device *lower_port = fib_entry->lower_port->ndev;
	struct sparx5_rr_neigh_entry *nh_neigh;
	struct sparx5_rr_nexthop *nh;
	int err, i, offset;

	offset = sparx5_rr_arp_tbl_grp_alloc(sparx5, nhgi->count);

	if (offset < 0) {
		fib_entry->offload_fail = true;
		return offset;
	}

	for (i = 0; i < nhgi->count; i++) {
		nh = &nhgi->nexthops[i];
		nh_neigh = nh->neigh_entry;
		nh->trapped = is_zero_ether_addr(nh_neigh->hwaddr);

		sparx5_rr_arp_tbl_hw_addr_apply(sparx5, nh_neigh->hwaddr,
						nh_neigh->vmid, offset + i);
	}
	err = sparx5_rr_lpm4_arp_ptr_create(sparx5, lower_port,
					    fib_entry->key.addr.ipv4,
					    fib_entry->key.prefix_len, offset,
					    nhgi->count, &fib_entry->hw_route);
	if (err)
		goto err_arp_ptr_create;

	nhgi->atbl_offset = offset;
	nhgi->atbl_offset_valid = true;
	fib_entry->offload_fail = false;

	return 0;

err_arp_ptr_create:
	for (i--; i >= 0; i--)
		sparx5_rr_arp_tbl_hw_addr_clear(sparx5, offset + i);
	sparx5_rr_arp_tbl_grp_free(sparx5, offset, nhgi->count);
	fib_entry->offload_fail = true;
	nhgi->atbl_offset_valid = false;

	return err;
}

static int sparx5_rr_fib_entry_hw_apply(struct sparx5 *sparx5,
					struct sparx5_rr_fib_entry *fib_entry)
{
	struct sparx5_rr_nexthop_group_info *nhgi = fib_entry->nh_grp->nhgi;
	struct net_device *lower_port = fib_entry->lower_port->ndev;
	unsigned char zero_mac[ETH_ALEN] __aligned(2);
	struct sparx5_rr_neigh_entry *nh_neigh;
	struct sparx5_rr_nexthop *nh;
	int err = 0;

	/* Trap frames with zero mac */
	eth_zero_addr(zero_mac);

	switch (fib_entry->type) {
	case SPARX5_RR_FIB_TYPE_LOCAL:
		/* Trap traffic destined for device itself, to ensure
		 * device can receive traffic even when default gateways are
		 * configured.
		 */
		if (WARN_ON(nhgi->count != 1 || nhgi->nexthops->gateway)) {
			err = -EINVAL;
			goto out;
		}

		fib_entry->trap = true;
		err = sparx5_rr_lpm4_arp_entry_create(sparx5,
						      lower_port,
						      fib_entry->key.addr.ipv4,
						      fib_entry->key.prefix_len,
						      zero_mac, 0,
						      &fib_entry->hw_route);
		goto out;
	case SPARX5_RR_FIB_TYPE_UNICAST:
		if (!nhgi->nexthops->gateway) {
			/* Directly connected subnet. Trap traffic for subnet. */
			err = sparx5_rr_lpm4_arp_entry_create(sparx5,
							      lower_port,
							      fib_entry->key.addr.ipv4,
							      fib_entry->key.prefix_len,
							      zero_mac, 0,
							      &fib_entry->hw_route);
			goto out;
		} else if (nhgi->count == 1) { /* Use arp_entry */
			nh = &nhgi->nexthops[0];
			nh_neigh = nh->neigh_entry;

			nh->trapped = is_zero_ether_addr(nh_neigh->hwaddr);

			err = sparx5_rr_lpm4_arp_entry_create(sparx5,
							      lower_port,
							      fib_entry->key.addr.ipv4,
							      fib_entry->key.prefix_len,
							      nh_neigh->hwaddr,
							      nh_neigh->vmid,
							      &fib_entry->hw_route);
			goto out;
		} else {
			err = sparx5_rr_fib_entry_ecmp_hw_apply(sparx5,
								fib_entry);
			goto out;
		}

		break;
	default:
		dev_err(sparx5->dev, "Fib entry offload, unhandled type=%d\n",
			fib_entry->type);
		return -EINVAL;
	}

out:
	fib_entry->offload_fail = !!err;
	sparx5_rr_fib4_entry_offload_mark(sparx5, fib_entry);

	return err;
}

static void sparx5_rr_nexthop_neigh_update(struct sparx5 *sparx5,
					   struct sparx5_rr_nexthop *nh,
					   bool entry_connected)
{
	unsigned char mac[ETH_ALEN] __aligned(2);
	int err;

	if (!nh->gateway)
		return;

	/* Trap traffic with zero mac */
	eth_zero_addr(mac);

	if (entry_connected)
		ether_addr_copy(mac, nh->neigh_entry->hwaddr);

	if (nh->trapped && !entry_connected)
		return;

	nh->trapped = !entry_connected;

	if (nh->grp->nhgi->count == 1) {
		err = sparx5_rr_fib_entry_update_arp_entry(sparx5,
							   nh->grp->fib_entry,
							   mac,
							   nh->neigh_entry->vmid);
		if (err)
			dev_err(sparx5->dev,
				"Nexthop fib entry update failed\n");

		return;
	}

	int nh_offset = (int)(ptrdiff_t)(nh - nh->grp->nhgi->nexthops);
	int grp_idx = nh->grp->nhgi->atbl_offset;

	sparx5_rr_arp_tbl_hw_addr_apply(sparx5, mac,
					nh->neigh_entry->vmid,
					grp_idx + nh_offset);
}

static void
sparx5_rr_nexthops_update_notify(struct sparx5 *sparx5,
				 struct sparx5_rr_neigh_entry *neigh_entry,
				 bool entry_connected)
{
	struct sparx5_rr_nexthop *nh;

	if (list_empty(&neigh_entry->nexthop_list))
		return;

	list_for_each_entry(nh, &neigh_entry->nexthop_list, neigh_list_node)
		sparx5_rr_nexthop_neigh_update(sparx5, nh, entry_connected);
}

static int sparx5_rr_neigh_entry_hw_apply(struct sparx5 *sparx5,
					  struct sparx5_rr_neigh_entry *entry)
{
	u32 prefix_len = SPARX5_IADDR_LEN(entry->key.iaddr.version);
	struct net_device *port_below = entry->lower_port->ndev;

	if (!entry->hw_route.vrule_id_valid) {
		return sparx5_rr_lpm4_arp_entry_create(sparx5, port_below,
						       entry->key.iaddr.ipv4,
						       prefix_len,
						       entry->hwaddr, entry->vmid,
						       &entry->hw_route);
	}
	return sparx5_rr_lpm4_arp_entry_mod(sparx5, entry->hwaddr, entry->vmid,
					    entry->hw_route.vrule_id);
}

static void sparx5_rr_neigh_entry_update(struct sparx5 *sparx5,
					 struct sparx5_rr_neigh_entry *entry,
					 bool adding)
{
	bool offloaded = adding;
	int err;

	if (!adding && !entry->connected && !entry->hw_route.vrule_id_valid)
		return;

	entry->connected = adding;

	if (adding) {
		err = sparx5_rr_neigh_entry_hw_apply(sparx5, entry);
		if (err)
			offloaded = false;
	} else if (entry->hw_route.vrule_id_valid) {
		vcap_del_rule(sparx5->vcap_ctrl, entry->lower_port->ndev,
			      entry->hw_route.vrule_id);
		entry->hw_route.vrule_id_valid = false;
	}

	return sparx5_rr_neigh_entry_offload_mark(entry, offloaded);
}

static void sparx5_rr_fib_entry_destroy(struct sparx5 *sparx5,
					struct sparx5_rr_fib_entry *fib_entry)
{
	struct sparx5_rr_neigh_entry *neigh_entry, *tmp;
	struct vcap_control *vctrl = sparx5->vcap_ctrl;

	sparx5_rr_fib_lpm4_remove(fib_entry);

	list_for_each_entry_safe(neigh_entry, tmp, &fib_entry->neigh_list,
				 fib_list_node) {
		list_del(&neigh_entry->fib_list_node);
		neigh_entry->fib_entry = NULL;

		/* Remove LPM VCAP entry for neighbour, if used */
		sparx5_rr_neigh_entry_update(sparx5, neigh_entry, false);
		sparx5_rr_nexthops_update_notify(sparx5, neigh_entry, false);
		sparx5_rr_neigh_entry_put(sparx5, neigh_entry);
	}

	sparx5_rr_fib_entry_remove(sparx5, fib_entry);
	sparx5_rr_nexthop4_group_put(sparx5, fib_entry->nh_grp);
	vcap_del_rule(vctrl, fib_entry->lower_port->ndev,
		      fib_entry->hw_route.vrule_id);
	fib_info_put(fib_entry->fen4_info.fi);
	kfree(fib_entry);
}

static void sparx5_rr_leg_hw_init(struct sparx5 *sparx5,
				  struct sparx5_rr_router_leg *leg)
{
	/* Associate Router leg VMID to VLAN */
	spx5_rmw(ANA_L3_VMID_CFG_VMID_SET(leg->vmid), ANA_L3_VMID_CFG_VMID,
		 sparx5, ANA_L3_VMID_CFG(leg->vid));

	/* Enable Router leg for VLAN */
	spx5_rmw(ANA_L3_VLAN_CFG_VLAN_RLEG_ENA_SET(1),
		 ANA_L3_VLAN_CFG_VLAN_RLEG_ENA, sparx5,
		 ANA_L3_VLAN_CFG(leg->vid));

	/* Configure router leg */
	spx5_rmw(ANA_L3_RLEG_CTRL_RLEG_IP4_UC_ENA_SET(1) |
		 ANA_L3_RLEG_CTRL_RLEG_EVID_SET(leg->vid),
		 ANA_L3_RLEG_CTRL_RLEG_IP4_UC_ENA |
		 ANA_L3_RLEG_CTRL_RLEG_EVID, sparx5,
		 ANA_L3_RLEG_CTRL(leg->vmid));

	/* Configure egress VLAN in rewriter */
	spx5_rmw(REW_RLEG_CTRL_RLEG_EVID_SET(leg->vid), REW_RLEG_CTRL_RLEG_EVID,
		 sparx5, REW_RLEG_CTRL(leg->vmid));
}

static void sparx5_rr_leg_hw_deinit(struct sparx5 *sparx5,
				    struct sparx5_rr_router_leg *leg)
{
	/* Disable Router leg for VLAN */
	spx5_rmw(ANA_L3_VLAN_CFG_VLAN_RLEG_ENA_SET(0),
		 ANA_L3_VLAN_CFG_VLAN_RLEG_ENA, sparx5,
		 ANA_L3_VLAN_CFG(leg->vid));

	/* Disable IPv4 UC routing on leg */
	spx5_rmw(ANA_L3_RLEG_CTRL_RLEG_IP4_UC_ENA_SET(0),
		 ANA_L3_RLEG_CTRL_RLEG_IP4_UC_ENA, sparx5,
		 ANA_L3_RLEG_CTRL(leg->vmid));
}

 /* Router legs are identified by their VMID in hw */
static struct sparx5_rr_router_leg *
sparx5_rr_leg_alloc(struct sparx5 *sparx5, struct net_device *dev, u16 vid)
{
	struct sparx5_rr_router_leg *leg;
	int next_vmid;

	next_vmid = sparx5_vmid_alloc(sparx5);
	if (next_vmid < 0)
		return NULL;

	leg = kzalloc(sizeof(*leg), GFP_KERNEL);
	if (!leg)
		goto err_kzalloc;

	INIT_LIST_HEAD(&leg->leg_list_node);
	leg->dev = dev;
	leg->vmid = next_vmid;
	leg->vid = vid;
	leg->sparx5 = sparx5;
	ether_addr_copy(leg->hwaddr, dev->dev_addr);

	return leg;

err_kzalloc:
	sparx5_vmid_free(sparx5, next_vmid);

	return NULL;
}

static void sparx5_rr_router_leg_destroy(struct sparx5_rr_router_leg *leg)
{
	struct sparx5 *sparx5 = leg->sparx5;

	sparx5_rr_leg_hw_deinit(sparx5, leg);
	atomic_sub(1, &sparx5->router->legs_count);
	sparx5_vmid_free(leg->sparx5, leg->vmid);
	list_del(&leg->leg_list_node);
	netdev_put(leg->dev, NULL);

	dev_dbg(sparx5->dev, "Leg destroy vid=%u vmid=%u\n", leg->vid,
		leg->vmid);

	kfree(leg);
}

static struct sparx5_rr_router_leg *
sparx5_rr_router_leg_create(struct sparx5 *sparx5, struct net_device *dev,
			    u16 vid)
{
	struct sparx5_rr_router_leg *leg;

	leg = sparx5_rr_leg_alloc(sparx5, dev, vid);
	if (!leg)
		return ERR_PTR(-ENOMEM);

	/* Prevent net device from being freed while we have added it to a router
	 * leg.
	 */
	netdev_hold(dev, NULL, GFP_KERNEL);

	list_add(&leg->leg_list_node, &sparx5->router->leg_list);
	atomic_add(1, &sparx5->router->legs_count);
	sparx5_rr_leg_hw_init(sparx5, leg);

	dev_dbg(sparx5->dev, "Leg create dev=%s vid=%u vmid=%u\n", dev->name,
		leg->vid, leg->vmid);

	return leg;
}

static void sparx5_rr_fib4_del(struct sparx5 *sparx5,
			       struct fib_entry_notifier_info *fen_info)
{
	struct sparx5_rr_fib_entry *fib_entry;
	struct sparx5_rr_fib_key key;

	sparx5_rr_finfo_to_fib_key(sparx5, fen_info, &key);

	fib_entry = sparx5_rr_fib_entry_lookup(sparx5, &key);
	if (!fib_entry)
		return;

	sparx5_rr_fib_entry_destroy(sparx5, fib_entry);
}

static bool sparx5_rr_dev_real_is_vlan_aware(struct net_device *dev)
{
	struct net_device *vlan_rdev;
	/* Support l3 offloading for:
	 *	1) upper vlan interfaces for br0. E.g. br0.10.
	 */
	if (is_vlan_dev(dev)) {
		if (netif_is_bridge_port(dev))
			return false;

		vlan_rdev = vlan_dev_real_dev(dev);
		if (sparx5_netdevice_check(vlan_rdev))
			return false;

		return netif_is_bridge_master(vlan_rdev) &&
		       br_vlan_enabled(vlan_rdev);
	}
	return false;
}

static bool
sparx5_rr_fib4_entry_should_offload(struct sparx5 *sparx5,
				    struct fib_entry_notifier_info *fen_info)
{
	struct fib_info *fi = fen_info->fi;

	if (!(fen_info->type == RTN_UNICAST || fen_info->type == RTN_LOCAL))
		return false;

	if (!(fen_info->tb_id == RT_TABLE_MAIN ||
	      fen_info->tb_id == RT_TABLE_LOCAL))
		return false;

	if (fi->nh)
		return false;

	if (fi->fib_nhs > SPARX5_MAX_ECMP_SIZE)
		return false;

	if (fi->fib_nhs > 0) {
		for (int i = 0; i < fi->fib_nhs; i++) {
			struct fib_nh_common *nhc = fib_info_nhc(fi, i);

			if (!sparx5_rr_dev_real_is_vlan_aware(nhc->nhc_dev))
				return false;

			/* hw only supports equal weight nexthops */
			if (nhc->nhc_weight != 1)
				return false;
		}
	}

	return true;
}

static int sparx5_rr_fib4_replace(struct sparx5 *sparx5,
				  struct fib_entry_notifier_info *fen_info)
{
	struct vcap_control *vctrl = sparx5->vcap_ctrl;
	struct sparx5_rr_nexthop_group *new_nh_grp;
	struct sparx5_rr_nexthop_group *old_nh_grp;
	struct sparx5_rr_fib_entry *fib_entry;
	struct sparx5_rr_fib_key key;
	u32 old_vrule_id;
	int err;

	sparx5_rr_finfo_to_fib_key(sparx5, fen_info, &key);

	fib_entry = sparx5_rr_fib_entry_lookup(sparx5, &key);

	if (!sparx5_rr_fib4_entry_should_offload(sparx5, fen_info)) {
		/* A previously offloadable fib, is modified to unoffloadable
		 * state, so we must remove it.
		 */
		if (fib_entry)
			sparx5_rr_fib_entry_destroy(sparx5, fib_entry);

		return 0;
	}

	if (!fib_entry) {
		/* Holds ref to fib_info */
		fib_entry = sparx5_rr_fib_entry_create(sparx5, &key, fen_info);
		if (!fib_entry) {
			dev_warn(sparx5->dev, "Failed to create fib entry\n");
			return PTR_ERR(fib_entry);
		}

		return sparx5_rr_fib_entry_hw_apply(sparx5, fib_entry);
	}

	old_nh_grp = fib_entry->nh_grp;
	old_vrule_id = fib_entry->hw_route.vrule_id;

	sparx5_rr_fib_entry_fen_info_replace(fib_entry, fen_info);

	if (sparx5_rr_nexthop4_group_equal(old_nh_grp, fen_info->fi))
		return 0;

	/* Nexthop group changed, prepare new group in SW */
	new_nh_grp = sparx5_rr_nexthop4_group_create(sparx5, fen_info->fi);
	if (IS_ERR(new_nh_grp)) {
		dev_warn(sparx5->dev, "Failed to create nexthop group\n");
		return PTR_ERR(new_nh_grp);
	}

	fib_entry->nh_grp = new_nh_grp;
	new_nh_grp->fib_entry = fib_entry;

	/* Write new rule to HW */
	err = sparx5_rr_fib_entry_hw_apply(sparx5, fib_entry);
	if (err) {
		fib_entry->nh_grp = old_nh_grp;
		new_nh_grp->fib_entry = NULL;
		sparx5_rr_nexthop4_group_put(sparx5, new_nh_grp);
		sparx5_rr_fib_entry_destroy(sparx5, fib_entry);
		return err;
	}

	/* Clean up old rule, and start routing traffic according to new rule */
	if (fib_entry->hw_route.vrule_id != old_vrule_id)
		vcap_del_rule(vctrl, fib_entry->lower_port->ndev, old_vrule_id);

	/* Remove old unused group */
	sparx5_rr_nexthop4_group_put(sparx5, old_nh_grp);

	return 0;
}

static void sparx5_rr_fib4_event_work(struct work_struct *work)
{
	struct sparx5_fib_event_work *fib_work =
		container_of(work, struct sparx5_fib_event_work, work);
	struct fib_entry_notifier_info *fen_info;
	struct sparx5 *sparx5 = fib_work->sparx5;
	int err;

	mutex_lock(&sparx5->router->lock);

	switch (fib_work->event) {
	case FIB_EVENT_ENTRY_REPLACE:
		fen_info = &fib_work->fen_info;

		err = sparx5_rr_fib4_replace(sparx5, fen_info);
		if (err)
			dev_warn(sparx5->dev, "FIB replace failed, ip=%pI4l\n",
				 &fen_info->dst);

		/* Release fib_info hold for workqueue */
		fib_info_put(fen_info->fi);
		break;
	case FIB_EVENT_ENTRY_DEL:
		fen_info = &fib_work->fen_info;
		sparx5_rr_fib4_del(sparx5, fen_info);
		fib_info_put(fen_info->fi);
		break;
	}

	mutex_unlock(&sparx5->router->lock);
	kfree(fib_work);
}

/* Handle fib events. Used to manage fib_entries which are the core routing data.
 * Called with rcu_read_lock()
 */
static int sparx5_rr_fib_event(struct notifier_block *nb, unsigned long event,
			       void *ptr)
{
	struct fib_entry_notifier_info *fen_info;
	struct sparx5_fib_event_work *fib_work;
	struct fib_notifier_info *info = ptr;
	struct sparx5_router *router;

	/* Only handle IPv4 for now */
	if (info->family != AF_INET)
		return NOTIFY_DONE;

	if (event != FIB_EVENT_ENTRY_REPLACE && event != FIB_EVENT_ENTRY_DEL)
		return NOTIFY_DONE;

	router = container_of(nb, struct sparx5_router, fib_nb);

	fib_work = kzalloc(sizeof(*fib_work), GFP_ATOMIC);
	if (!fib_work)
		return NOTIFY_BAD;

	fib_work->sparx5 = router->sparx5;
	fib_work->event = event;

	switch (info->family) {
	case AF_INET:
		INIT_WORK(&fib_work->work, sparx5_rr_fib4_event_work);

		fen_info = container_of(info, struct fib_entry_notifier_info,
					info);
		fib_work->fen_info = *fen_info;
		/* Hold fib_info while item is queued */
		fib_info_hold(fib_work->fen_info.fi);

		sparx5_rr_schedule_work(router->sparx5, &fib_work->work);
		break;
	default:
		goto err_fam_unhandled;
	}

	return NOTIFY_DONE;

err_fam_unhandled:
	WARN_ON_ONCE(1); /* BUG */
	kfree(fib_work);
	return NOTIFY_BAD;
}

static void sparx5_rr_neigh_event_work(struct work_struct *work)
{
	struct sparx5_rr_netevent_work *net_work =
		container_of(work, struct sparx5_rr_netevent_work, work);
	struct sparx5 *sparx5 = net_work->sparx5;
	unsigned char hwaddr[ETH_ALEN] __aligned(2);
	struct sparx5_rr_neigh_entry *entry;
	struct neighbour *n = net_work->neigh;
	struct sparx5_rr_neigh_key key;
	struct net_device *ndev;
	bool entry_connected;
	u8 nud_state, dead;

	read_lock_bh(&n->lock);
	ether_addr_copy(hwaddr, n->ha);
	ndev = n->dev;
	nud_state = n->nud_state;
	dead = n->dead;
	read_unlock_bh(&n->lock);

	mutex_lock(&sparx5->router->lock);

	sparx5_rr_nb2neigh_key(n, &key);

	entry_connected = nud_state & NUD_VALID && !dead;
	entry = sparx5_rr_neigh_entry_lookup(sparx5, &key);
	if (!entry_connected && !entry)
		goto out_mutex;

	if (!entry) {
		entry = sparx5_rr_neigh_entry_create(sparx5, &key);
		if (IS_ERR(entry))
			goto out_mutex;
	}

	if (entry->connected && entry_connected &&
	    ether_addr_equal(entry->hwaddr, hwaddr))
		goto out_mutex;

	ether_addr_copy(entry->hwaddr, hwaddr);
	sparx5_rr_neigh_entry_update(sparx5, entry, entry_connected);
	sparx5_rr_nexthops_update_notify(sparx5, entry, entry_connected);
	if (!entry_connected)
		sparx5_rr_neigh_entry_put(sparx5, entry);

out_mutex:
	mutex_unlock(&sparx5->router->lock);
	neigh_release(n);
	kfree(net_work);
}

/* Handle neighbour update events. Used to manage neigh_entries. */
static int sparx5_rr_netevent_event(struct notifier_block *nb,
				    unsigned long event, void *ptr)
{
	struct sparx5_rr_netevent_work *net_work;
	struct sparx5_router *router;
	struct neighbour *n;

	router = container_of(nb, struct sparx5_router, netevent_nb);

	switch (event) {
	case NETEVENT_NEIGH_UPDATE:
		n = ptr;

		if (n->tbl->family != AF_INET)
			return NOTIFY_DONE;

		net_work = kzalloc(sizeof(*net_work), GFP_ATOMIC);
		if (!net_work)
			return NOTIFY_BAD;

		neigh_clone(n);
		INIT_WORK(&net_work->work, sparx5_rr_neigh_event_work);
		net_work->sparx5 = router->sparx5;
		net_work->neigh = n;
		net_work->event = event;
		sparx5_rr_schedule_work(router->sparx5, &net_work->work);

		return NOTIFY_DONE;
	}

	return NOTIFY_DONE;
};

static void sparx5_rr_leg_base_mac_set(struct sparx5 *sparx5,
				       unsigned char mac[ETH_ALEN])
{
	u8 rleg_type_sel = SPARX5_RLEG_USE_GLOBAL_BASE_MAC;
	u32 mac_msb, mac_lsb;

	sparx5_rr_split_mac(mac, 24, &mac_msb, &mac_lsb);

	dev_dbg(sparx5->dev, "Router leg base MAC=%pM\n", mac);

	/* The global router leg MAC must be set consistently across ANA_L3, REW
	 * and EACL.
	 */
	spx5_wr(ANA_L3_RLEG_CFG_0_RLEG_MAC_LSB_SET(mac_lsb), sparx5,
		ANA_L3_RLEG_CFG_0);

	spx5_rmw(ANA_L3_RLEG_CFG_1_RLEG_MAC_MSB_SET(mac_msb) |
		 ANA_L3_RLEG_CFG_1_RLEG_MAC_TYPE_SEL_SET(rleg_type_sel),
		 ANA_L3_RLEG_CFG_1_RLEG_MAC_MSB |
		 ANA_L3_RLEG_CFG_1_RLEG_MAC_TYPE_SEL,
		 sparx5, ANA_L3_RLEG_CFG_1);

	/* Set global Router leg MAC (REW) */
	spx5_wr(REW_RLEG_CFG_0_RLEG_MAC_LSB_SET(mac_lsb), sparx5,
		REW_RLEG_CFG_0);

	spx5_rmw(REW_RLEG_CFG_1_RLEG_MAC_MSB_SET(mac_msb) |
		 REW_RLEG_CFG_1_RLEG_MAC_TYPE_SEL_SET(rleg_type_sel),
		 REW_RLEG_CFG_1_RLEG_MAC_MSB | REW_RLEG_CFG_1_RLEG_MAC_TYPE_SEL,
		 sparx5, REW_RLEG_CFG_1);

	/* Set global Router leg MAC (EACL) */
	spx5_wr(EACL_RLEG_CFG_0_RLEG_MAC_LSB_SET(mac_lsb), sparx5,
		EACL_RLEG_CFG_0);

	spx5_rmw(EACL_RLEG_CFG_1_RLEG_MAC_MSB_SET(mac_msb) |
		 EACL_RLEG_CFG_1_RLEG_MAC_TYPE_SEL_SET(rleg_type_sel),
		 EACL_RLEG_CFG_1_RLEG_MAC_MSB |
		 EACL_RLEG_CFG_1_RLEG_MAC_TYPE_SEL,
		 sparx5, EACL_RLEG_CFG_1);
}

static bool
sparx5_rr_router_leg_addr_list_empty(struct sparx5_rr_router_leg *leg)
{
	struct in_device *in_dev;

	rcu_read_lock();
	in_dev = __in_dev_get_rcu(leg->dev);
	if (in_dev && in_dev->ifa_list) {
		rcu_read_unlock();
		return false;
	}
	rcu_read_unlock();

	return true;
}

static int __sparx5_rr_inetaddr_event(struct sparx5 *sparx5,
				      struct net_device *dev,
				      unsigned long event)
{
	struct sparx5_rr_router_leg *leg;
	u16 vid;

	if (!sparx5_rr_dev_real_is_vlan_aware(dev))
		return 0;

	/* Our basic case: ipv4 addr/subnet added to vlan upper of
	 * bridge dev.
	 */
	switch (event) {
	case NETDEV_UP:
		leg = sparx5_rr_leg_find_by_dev(sparx5, dev);
		if (leg)
			return 0;

		/* HW allows at most 1 leg per VLAN, but we do not need to lookup
		 * leg by vid, since the kernel does not allow multiple vlan
		 * devs with the same vid on top of a given device.
		 */
		vid = vlan_dev_vlan_id(dev);

		leg = sparx5_rr_router_leg_create(sparx5, dev, vid);
		if (IS_ERR(leg))
			return PTR_ERR(leg);
		break;
	case NETDEV_DOWN:
		leg = sparx5_rr_leg_find_by_dev(sparx5, dev);
		if (!leg || !sparx5_rr_router_leg_addr_list_empty(leg))
			return 0;

		sparx5_rr_router_leg_destroy(leg);
		break;
	}

	return 0;
}

/* Handle events for ip address changes on ifs. Used to manage router legs. */
static int sparx5_rr_inetaddr_event(struct notifier_block *nb,
				    unsigned long event, void *ptr)
{
	struct in_ifaddr *ifa = (struct in_ifaddr *)ptr;
	struct net_device *dev = ifa->ifa_dev->dev;
	struct sparx5_router *router;
	int err = 0;

	if (event != NETDEV_DOWN)
		return notifier_from_errno(err);

	router = container_of(nb, struct sparx5_router, inetaddr_nb);
	mutex_lock(&router->lock);

	err = __sparx5_rr_inetaddr_event(router->sparx5, dev, event);

	mutex_unlock(&router->lock);

	return notifier_from_errno(err);
}

static int sparx5_rr_inetaddr_valid_event(struct notifier_block *nb,
					  unsigned long event, void *ptr)
{
	struct in_validator_info *ivi = (struct in_validator_info *)ptr;
	struct net_device *dev = ivi->ivi_dev->dev;
	struct sparx5_router *router;
	struct sparx5 *sparx5;
	int err = 0;

	if (event != NETDEV_UP)
		return NOTIFY_DONE;

	router = container_of(nb, struct sparx5_router, inetaddr_valid_nb);
	sparx5 = router->sparx5;

	mutex_lock(&sparx5->router->lock);

	err = __sparx5_rr_inetaddr_event(sparx5, dev, event);

	mutex_unlock(&sparx5->router->lock);
	return notifier_from_errno(err);
}

static int sparx5_rr_netdevice_event(struct notifier_block *nb,
				     unsigned long event, void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
	unsigned char mac[ETH_ALEN] __aligned(2);
	struct sparx5_router *router;
	struct sparx5 *sparx5;

	router = container_of(nb, struct sparx5_router, netdevice_nb);
	sparx5 = router->sparx5;

	/* Allow single bridge. Global router leg MAC tracks bridge mac. */
	if (!netif_is_bridge_master(dev))
		return NOTIFY_OK;

	switch (event) {
	case NETDEV_CHANGEADDR:
		ether_addr_copy(mac, dev->dev_addr);
		sparx5_rr_leg_base_mac_set(sparx5, mac);
		break;
	}

	return NOTIFY_OK;
}

int sparx5_rr_router_init(struct sparx5 *sparx5)
{
	struct sparx5_router *router;
	int err;

	router = kzalloc(sizeof(*sparx5->router), GFP_KERNEL);
	if (!router)
		return -ENOMEM;

	mutex_init(&router->lock);
	sparx5->router = router;
	router->sparx5 = sparx5;

	router->sparx5_router_owq =
		alloc_ordered_workqueue("sparx5_router_order", 0);
	if (!router->sparx5_router_owq) {
		err = -ENOMEM;
		goto err_alloc_workqueue;
	}

	router->fib_nb.notifier_call = sparx5_rr_fib_event;
	err = register_fib_notifier(&init_net, &router->fib_nb, NULL, NULL);
	if (err)
		goto err_register_fib_notifier;

	router->netevent_nb.notifier_call =
		sparx5_rr_netevent_event;
	err = register_netevent_notifier(&router->netevent_nb);
	if (err)
		goto err_register_netevent_notifier;

	router->inetaddr_nb.notifier_call = sparx5_rr_inetaddr_event;
	err = register_inetaddr_notifier(&router->inetaddr_nb);
	if (err)
		goto err_register_inetaddr_notifier;

	router->inetaddr_valid_nb.notifier_call =
		sparx5_rr_inetaddr_valid_event;
	err = register_inetaddr_validator_notifier(&router->inetaddr_valid_nb);
	if (err)
		goto err_register_inetaddr_valid_notifier;

	router->netdevice_nb.notifier_call = sparx5_rr_netdevice_event;
	err = register_netdevice_notifier(&router->netdevice_nb);
	if (err)
		goto err_register_netdevice_notifier;

	err = rhashtable_init(&router->neigh_ht,
			      &sparx5_neigh_ht_params);
	if (err)
		goto err_neigh_ht_init;

	err = rhashtable_init(&router->fib_ht,
			      &sparx5_rr_fib_entry_ht_params);
	if (err)
		goto err_fib_ht_init;

	INIT_LIST_HEAD(&router->leg_list);
	INIT_LIST_HEAD(&router->fib_lpm_list);
	atomic_set(&router->legs_count, 0);

	/* Enable L3 UC routing on all ports.
	 * TODO: track ports which are part of some VLAN with RLEG ENA.
	 */
	spx5_wr(~0, sparx5, ANA_L3_L3_UC_ENA);
	if (is_sparx5(sparx5)) {
		spx5_wr(~0, sparx5, ANA_L3_L3_UC_ENA1);
		spx5_wr(~0, sparx5, ANA_L3_L3_UC_ENA2);
	}

	/* Enable routing and global router options */
	spx5_rmw(ANA_L3_ROUTING_CFG_L3_ENA_MODE_SET(1) |
		 ANA_L3_ROUTING_CFG_RT_SMAC_UPDATE_ENA_SET(1) |
		 ANA_L3_ROUTING_CFG_CPU_RLEG_IP_HDR_FAIL_REDIR_ENA_SET(1) |
		 ANA_L3_ROUTING_CFG_CPU_IP4_OPTIONS_REDIR_ENA_SET(1),
		 ANA_L3_ROUTING_CFG_L3_ENA_MODE |
		 ANA_L3_ROUTING_CFG_RT_SMAC_UPDATE_ENA |
		 ANA_L3_ROUTING_CFG_CPU_RLEG_IP_HDR_FAIL_REDIR_ENA |
		 ANA_L3_ROUTING_CFG_CPU_IP4_OPTIONS_REDIR_ENA,
		 sparx5, ANA_L3_ROUTING_CFG);

	/* By default, routing related frame edits are done in REW, but when
	 * combining routing with PTP, ANA_ACL must be configured to change DMAC
	 * to next-hop DMAC in order to allow other information to be stored in
	 * the IFH.
	 *
	 * This enables routing related frame edits independently of VCAP_S2
	 * action ACL_RT_MODE.
	 */
	spx5_rmw(ANA_ACL_VCAP_S2_MISC_CTRL_ACL_RT_SEL_SET(1),
		 ANA_ACL_VCAP_S2_MISC_CTRL_ACL_RT_SEL, sparx5,
		 ANA_ACL_VCAP_S2_MISC_CTRL);

	return 0;

err_fib_ht_init:
	rhashtable_destroy(&router->neigh_ht);
err_neigh_ht_init:
	unregister_inetaddr_validator_notifier(&router->inetaddr_valid_nb);
err_register_netdevice_notifier:
	unregister_netdevice_notifier(&router->netdevice_nb);
err_register_inetaddr_valid_notifier:
	unregister_inetaddr_notifier(&router->inetaddr_nb);
err_register_inetaddr_notifier:
	unregister_netevent_notifier(&router->netevent_nb);
err_register_netevent_notifier:
	unregister_fib_notifier(&init_net, &router->fib_nb);
err_register_fib_notifier:
	destroy_workqueue(router->sparx5_router_owq);
err_alloc_workqueue:
	mutex_destroy(&router->lock);
	kfree(router);

	return err;
}

void sparx5_rr_router_deinit(struct sparx5 *sparx5)
{
	struct sparx5_router *router = sparx5->router;

	rhashtable_destroy(&sparx5->router->fib_ht);
	rhashtable_destroy(&sparx5->router->neigh_ht);
	unregister_netdevice_notifier(&sparx5->router->netdevice_nb);
	unregister_inetaddr_validator_notifier(&sparx5->router->inetaddr_valid_nb);
	unregister_inetaddr_notifier(&sparx5->router->inetaddr_nb);
	unregister_netevent_notifier(&sparx5->router->netevent_nb);
	unregister_fib_notifier(&init_net, &router->fib_nb);
	destroy_workqueue(sparx5->router->sparx5_router_owq);
	mutex_destroy(&router->lock);
	kfree(router);
}
