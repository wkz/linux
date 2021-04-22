/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _NET_DSA_MV88E6XXX_H
#define _NET_DSA_MV88E6XXX_H

#include <linux/netdevice.h>
#include <net/dsa.h>

#define MV88E6XXX_ACCEL_PRIV_PRESENT BIT(10)

static inline bool mv88e6xxx_accel_priv_to_dsa(void *accel_priv, u8 *dev, u8 *port)
{
	unsigned long tag = (unsigned long)accel_priv;

	if (!(tag & MV88E6XXX_ACCEL_PRIV_PRESENT))
		return false;

	*dev = (tag >> 5) & 0x1f;
	*port = tag & 0x1f;
	return true;
}

static inline void *mv88e6xxx_accel_priv_from_dsa(u8 dev, u8 port)
{
	unsigned long tag = MV88E6XXX_ACCEL_PRIV_PRESENT;

	tag |= (dev & 0x1f) << 5;
	tag |= port & 0x1f;

	return (void *)tag;
}

#endif /* _NET_DSA_MV88E6XXX_H */
