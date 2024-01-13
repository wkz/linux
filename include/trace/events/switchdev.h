/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM	switchdev

#if !defined(_TRACE_SWITCHDEV_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_SWITCHDEV_H

#include <linux/tracepoint.h>
#include <net/switchdev.h>

#define SWITCHDEV_TRACE_MSG_MAX 128

#if defined(CREATE_TRACE_POINTS)

static inline int switchdev_trace_id(char **msg, size_t *len, unsigned long id,
				     const char *const *names, size_t n_names)
{
	const char *name = NULL;
	int n;

	if (id < n_names)
		name = names[id];

	if (name)
		n = snprintf(*msg, *len, " %s", name);
	else
		n = snprintf(*msg, *len, " UNKNOWN<%lu>", id);

	*msg += n;
	*len -= n;
	return n < 0 ? n : 0;
}

static inline void switchdev_trace_msg_attr(char *msg, size_t len,
					   const struct switchdev_attr *attr)
{
#define _ATTR_ID_STRINGER(_id) [SWITCHDEV_ATTR_ID_ ## _id] = #_id
	static const char *const attr_id_strs[] = {
		SWITCHDEV_ATTR_ID_MAPPER(_ATTR_ID_STRINGER)
	};
#undef _ATTR_ID_STRINGER

	static const char *const stp_state_strs[] = {
		[BR_STATE_DISABLED] = "disabled",
		[BR_STATE_LISTENING] = "listening",
		[BR_STATE_LEARNING] = "learning",
		[BR_STATE_FORWARDING] = "forwarding",
		[BR_STATE_BLOCKING] = "blocking",
	};

	ssize_t n;

	if (switchdev_trace_id(&msg, &len, attr->id, attr_id_strs,
			       ARRAY_SIZE(attr_id_strs)))
		return;

	n = snprintf(msg, len, "(flags %#x orig %s)", attr->flags,
		     attr->orig_dev ? netdev_name(attr->orig_dev) : "(null)");
	if (n < 0)
		return;

	msg += n;
	len -= n;

	switch (attr->id) {
	case SWITCHDEV_ATTR_ID_PORT_STP_STATE:
		switchdev_trace_id(&msg, &len, attr->u.stp_state,
				   stp_state_strs, ARRAY_SIZE(stp_state_strs));
		return;
	case SWITCHDEV_ATTR_ID_PORT_MST_STATE:
		n = snprintf(msg, len, " msti %u", attr->u.mst_state.msti);
		if (n < 0)
			return;

		msg += n;
		len -= n;

		switchdev_trace_id(&msg, &len, attr->u.mst_state.state,
				   stp_state_strs, ARRAY_SIZE(stp_state_strs));
		return;
	case SWITCHDEV_ATTR_ID_PORT_PRE_BRIDGE_FLAGS:
	case SWITCHDEV_ATTR_ID_PORT_BRIDGE_FLAGS:
		snprintf(msg, len, " val %#lx mask %#lx",
			 attr->u.brport_flags.val,
			 attr->u.brport_flags.mask);
		return;
	case SWITCHDEV_ATTR_ID_PORT_MROUTER:
	case SWITCHDEV_ATTR_ID_BRIDGE_MROUTER:
		snprintf(msg, len, " %s",
			 attr->u.mrouter ? "enabled" : "disabled");
		return;
	case SWITCHDEV_ATTR_ID_BRIDGE_AGEING_TIME:
		snprintf(msg, len, " %ums",
			 jiffies_to_msecs(clock_t_to_jiffies(attr->u.ageing_time)));
		return;
	case SWITCHDEV_ATTR_ID_BRIDGE_VLAN_FILTERING:
		snprintf(msg, len, " %s",
			 attr->u.vlan_filtering ? "enabled" : "disabled");
		return;
	case SWITCHDEV_ATTR_ID_BRIDGE_VLAN_PROTOCOL:
		snprintf(msg, len, " %#x", attr->u.vlan_protocol);
		return;
	case SWITCHDEV_ATTR_ID_BRIDGE_MC_DISABLED:
		snprintf(msg, len, " %s",
			 attr->u.mc_disabled ? "active" : "inactive");
		return;
	case SWITCHDEV_ATTR_ID_BRIDGE_MST:
		snprintf(msg, len, " %s",
			 attr->u.mst ? "enabled" : "disabled");
		return;
	case SWITCHDEV_ATTR_ID_VLAN_MSTI:
		snprintf(msg, len, " vid %u msti %u",
			 attr->u.vlan_msti.vid, attr->u.vlan_msti.msti);
		return;
	default:
		return;
	}
}

static inline void switchdev_trace_msg_obj(char *msg, size_t len,
					   const struct switchdev_obj *obj)
{
#define _OBJ_ID_STRINGER(_id) [SWITCHDEV_OBJ_ID_ ## _id] = #_id
	static const char *const obj_id_strs[] = {
		SWITCHDEV_OBJ_ID_MAPPER(_OBJ_ID_STRINGER)
	};
#undef _OBJ_ID_STRINGER

	const struct switchdev_obj_port_vlan *vlan;
	const struct switchdev_obj_port_mdb *mdb;
	ssize_t n;

	if (switchdev_trace_id(&msg, &len, obj->id, obj_id_strs,
			       ARRAY_SIZE(obj_id_strs)))
		return;

	n = snprintf(msg, len, "(flags %#x orig %s)", obj->flags,
		     obj->orig_dev ? netdev_name(obj->orig_dev) : "(null)");
	if (n < 0)
		return;

	msg += n;
	len -= n;

	switch (obj->id) {
	case SWITCHDEV_OBJ_ID_PORT_VLAN:
		vlan = SWITCHDEV_OBJ_PORT_VLAN(obj);
		snprintf(msg, len, " vid %u flags %#x%s", vlan->vid,
			 vlan->flags, vlan->changed ? "(changed)" : "");
		break;
	case SWITCHDEV_OBJ_ID_PORT_MDB:
	case SWITCHDEV_OBJ_ID_HOST_MDB:
	case SWITCHDEV_OBJ_ID_MRA_MDB:
		mdb = SWITCHDEV_OBJ_PORT_MDB(obj);
		snprintf(msg, len, " vid %u addr %pM", mdb->vid, mdb->addr);
		break;
	default:
		break;
	}
}

static inline void switchdev_trace_msg_fdb(char *msg, size_t len,
					   const struct switchdev_notifier_fdb_info *fdbi)
{
	snprintf(msg, len, " vid %u addr %pM%s%s%s%s", fdbi->vid, fdbi->addr,
		 fdbi->added_by_user ? " added_by_user" : "",
		 fdbi->is_local ? " is_local" : "",
		 fdbi->locked ? " locked" : "",
		 fdbi->offloaded ? " offloaded" : "");
}

static inline void switchdev_trace_msg_mrouter(char *msg, size_t len,
					       const struct switchdev_notifier_mrouter_info *mri)
{
	switch (mri->proto) {
	case ETH_P_IP:
	case ETH_P_IPV6:
		snprintf(msg, len, " vid %u proto %s", mri->vid,
			 mri->proto == ETH_P_IP ? "ipv4" : "ipv6");
		break;
	default:
		snprintf(msg, len, " vid %u proto UNKNOWN<%#4x>", mri->vid,
			 mri->proto);
		break;
	}
}

static inline void switchdev_trace_msg_brport(char *msg, size_t len,
					   const struct switchdev_brport *brport)
{
	snprintf(msg, len, " dev %s%s",
		 brport->dev ? netdev_name(brport->dev) : "(null)",
		 brport->tx_fwd_offload ? " tx_fwd_offload" : "");
}

static inline void switchdev_trace_msg(char *msg, size_t len,
				       enum switchdev_notifier_type type,
				       const struct switchdev_notifier_info *info)
{
#define _TYPE_STRINGER(_id) [SWITCHDEV_ ## _id] = #_id
	static const char *const type_strs[] = {
		SWITCHDEV_TYPE_MAPPER(_TYPE_STRINGER)
	};
#undef _TYPE_STRINGER

	const struct switchdev_notifier_port_attr_info *attri;
	const struct switchdev_notifier_brport_info *brporti;
	const struct switchdev_notifier_port_obj_info *obji;
	const struct switchdev_notifier_mrouter_info *mri;
	const struct switchdev_notifier_fdb_info *fdbi;

	if (switchdev_trace_id(&msg, &len, type, type_strs, ARRAY_SIZE(type_strs)))
		return;

	switch (type) {
	case SWITCHDEV_FDB_FLUSH_TO_BRIDGE:
		fdbi = container_of(info, struct switchdev_notifier_fdb_info, info);
		snprintf(msg, len, " vid %u", fdbi->vid);
		return;
	case SWITCHDEV_FDB_ADD_TO_BRIDGE:
	case SWITCHDEV_FDB_DEL_TO_BRIDGE:
	case SWITCHDEV_FDB_ADD_TO_DEVICE:
	case SWITCHDEV_FDB_DEL_TO_DEVICE:
	case SWITCHDEV_FDB_OFFLOADED:
	case SWITCHDEV_VXLAN_FDB_ADD_TO_BRIDGE:
	case SWITCHDEV_VXLAN_FDB_DEL_TO_BRIDGE:
	case SWITCHDEV_VXLAN_FDB_ADD_TO_DEVICE:
	case SWITCHDEV_VXLAN_FDB_DEL_TO_DEVICE:
	case SWITCHDEV_VXLAN_FDB_OFFLOADED:
		fdbi = container_of(info, struct switchdev_notifier_fdb_info, info);
		switchdev_trace_msg_fdb(msg, len, fdbi);
		return;
	case SWITCHDEV_MROUTER_ADD:
	case SWITCHDEV_MROUTER_DEL:
		mri = container_of(info, struct switchdev_notifier_mrouter_info, info);
		switchdev_trace_msg_mrouter(msg, len, mri);
		return;
	case SWITCHDEV_PORT_OBJ_ADD:
	case SWITCHDEV_PORT_OBJ_DEL:
		obji = container_of(info, struct switchdev_notifier_port_obj_info, info);
		switchdev_trace_msg_obj(msg, len, obji->obj);
		return;
	case SWITCHDEV_PORT_ATTR_SET:
		attri = container_of(info, struct switchdev_notifier_port_attr_info, info);
		switchdev_trace_msg_attr(msg, len, attri->attr);
		return;
	case SWITCHDEV_BRPORT_OFFLOADED:
	case SWITCHDEV_BRPORT_UNOFFLOADED:
	case SWITCHDEV_BRPORT_REPLAY:
		brporti = container_of(info, struct switchdev_notifier_brport_info, info);
		switchdev_trace_msg_brport(msg, len, &brporti->brport);
		return;
	default:
		return;
	}
}
#endif

TRACE_EVENT(switchdev_call,

	TP_PROTO(bool atomic, unsigned long val,
		 const struct switchdev_notifier_info *info,
		 int err),

	TP_ARGS(atomic, val, info, err),

	TP_STRUCT__entry(
		__field(bool, atomic)
		__field(unsigned long, val)
		__string(dev, info->dev ? netdev_name(info->dev) : "(null)")
		__field(const struct switchdev_notifier_info *, info)
		__field(int, err)
		__array(char, msg, SWITCHDEV_TRACE_MSG_MAX)
	),

	TP_fast_assign(
		__entry->atomic = atomic;
		__entry->val = val;
		__assign_str(dev, info->dev ? netdev_name(info->dev) : "(null)");
		__entry->info = info;
		__entry->err = err;
		switchdev_trace_msg(__entry->msg, SWITCHDEV_TRACE_MSG_MAX, val, info);
	),

	TP_printk("%c (%s)%s -> %d", __entry->atomic ? 'A' : 'B',
		  __get_str(dev), __entry->msg, __entry->err)
);

#endif /* _TRACE_SWITCHDEV_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
