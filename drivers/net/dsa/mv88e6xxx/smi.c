// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Marvell 88E6xxx System Management Interface (SMI) support
 *
 * Copyright (c) 2008 Marvell Semiconductor
 *
 * Copyright (c) 2019 Vivien Didelot <vivien.didelot@gmail.com>
 */

#include "chip.h"
#include "global1.h"
#include "global2.h"
#include "smi.h"

/* The switch ADDR[4:1] configuration pins define the chip SMI device address
 * (ADDR[0] is always zero, thus only even SMI addresses can be strapped).
 *
 * When ADDR is all zero, the chip uses Single-chip Addressing Mode, assuming it
 * is the only device connected to the SMI master. In this mode it responds to
 * all 32 possible SMI addresses, and thus maps directly the internal devices.
 *
 * When ADDR is non-zero, the chip uses Multi-chip Addressing Mode, allowing
 * multiple devices to share the SMI interface. In this mode it responds to only
 * 2 registers, used to indirectly access the internal SMI devices.
 *
 * Some chips use a different scheme: Only the ADDR4 pin is used for
 * configuration, and the device responds to 16 of the 32 SMI
 * addresses, allowing two to coexist on the same SMI interface.
 */

static int mv88e6xxx_smi_direct_read(struct mv88e6xxx_chip *chip,
				     int dev, int reg, u16 *data)
{
	int ret;

	ret = mdiobus_read_nested(chip->bus, dev, reg);
	if (ret < 0)
		return ret;

	*data = ret & 0xffff;

	return 0;
}

static int mv88e6xxx_smi_direct_write(struct mv88e6xxx_chip *chip,
				      int dev, int reg, u16 data)
{
	int ret;

	ret = mdiobus_write_nested(chip->bus, dev, reg, data);
	if (ret < 0)
		return ret;

	return 0;
}

static int mv88e6xxx_smi_direct_wait(struct mv88e6xxx_chip *chip,
				     int dev, int reg, int bit, int val)
{
	const unsigned long timeout = jiffies + msecs_to_jiffies(50);
	u16 data;
	int err;
	int i;

	/* Even if the initial poll takes longer than 50ms, always do
	 * at least one more attempt.
	 */
	for (i = 0; time_before(jiffies, timeout) || (i < 2); i++) {
		err = mv88e6xxx_smi_direct_read(chip, dev, reg, &data);
		if (err)
			return err;

		if (!!(data & BIT(bit)) == !!val)
			return 0;

		if (i < 2)
			cpu_relax();
		else
			usleep_range(1000, 2000);
	}

	return -ETIMEDOUT;
}

static const struct mv88e6xxx_bus_ops mv88e6xxx_smi_direct_ops = {
	.read = mv88e6xxx_smi_direct_read,
	.write = mv88e6xxx_smi_direct_write,
};

static int mv88e6xxx_smi_dual_direct_read(struct mv88e6xxx_chip *chip,
					  int dev, int reg, u16 *data)
{
	return mv88e6xxx_smi_direct_read(chip, chip->sw_addr + dev, reg, data);
}

static int mv88e6xxx_smi_dual_direct_write(struct mv88e6xxx_chip *chip,
					   int dev, int reg, u16 data)
{
	return mv88e6xxx_smi_direct_write(chip, chip->sw_addr + dev, reg, data);
}

static const struct mv88e6xxx_bus_ops mv88e6xxx_smi_dual_direct_ops = {
	.read = mv88e6xxx_smi_dual_direct_read,
	.write = mv88e6xxx_smi_dual_direct_write,
};

/* Offset 0x00: SMI Command Register
 * Offset 0x01: SMI Data Register
 */

static int mv88e6xxx_smi_indirect_read(struct mv88e6xxx_chip *chip,
				       int dev, int reg, u16 *data)
{
	int err;

	err = mv88e6xxx_smi_direct_write(chip, chip->sw_addr,
					 MV88E6XXX_SMI_CMD,
					 MV88E6XXX_SMI_CMD_BUSY |
					 MV88E6XXX_SMI_CMD_MODE_22 |
					 MV88E6XXX_SMI_CMD_OP_22_READ |
					 (dev << 5) | reg);
	if (err)
		return err;

	err = mv88e6xxx_smi_direct_wait(chip, chip->sw_addr,
					MV88E6XXX_SMI_CMD, 15, 0);
	if (err)
		return err;

	return mv88e6xxx_smi_direct_read(chip, chip->sw_addr,
					 MV88E6XXX_SMI_DATA, data);
}

static int mv88e6xxx_smi_indirect_write(struct mv88e6xxx_chip *chip,
					int dev, int reg, u16 data)
{
	int err;

	err = mv88e6xxx_smi_direct_write(chip, chip->sw_addr,
					 MV88E6XXX_SMI_DATA, data);
	if (err)
		return err;

	err = mv88e6xxx_smi_direct_write(chip, chip->sw_addr,
					 MV88E6XXX_SMI_CMD,
					 MV88E6XXX_SMI_CMD_BUSY |
					 MV88E6XXX_SMI_CMD_MODE_22 |
					 MV88E6XXX_SMI_CMD_OP_22_WRITE |
					 (dev << 5) | reg);
	if (err)
		return err;

	return mv88e6xxx_smi_direct_wait(chip, chip->sw_addr,
					 MV88E6XXX_SMI_CMD, 15, 0);
}

static int mv88e6xxx_smi_indirect_init(struct mv88e6xxx_chip *chip)
{
	/* Ensure that the chip starts out in the ready state. As both
	 * reads and writes always ensure this on return, they can
	 * safely depend on the chip not being busy on entry.
	 */
	return mv88e6xxx_smi_direct_wait(chip, chip->sw_addr,
					 MV88E6XXX_SMI_CMD, 15, 0);
}

static const struct mv88e6xxx_bus_ops mv88e6xxx_smi_indirect_ops = {
	.read = mv88e6xxx_smi_indirect_read,
	.write = mv88e6xxx_smi_indirect_write,
	.init = mv88e6xxx_smi_indirect_init,
};

static u8 mv88e6393_smi_indirect_remap(int dev, int reg)
{
	static const u8 g1_remap[32] = {
		[MV88E6352_G1_VTU_FID] = MV88E6393_SMI_G1_VTU_FID,
		[MV88E6352_G1_VTU_SID] = MV88E6393_SMI_G1_VTU_SID,
		[MV88E6XXX_G1_STS] = MV88E6393_SMI_G1_STS,
		[MV88E6XXX_G1_VTU_OP] = MV88E6393_SMI_G1_VTU_OP,
		[MV88E6XXX_G1_VTU_VID] = MV88E6393_SMI_G1_VTU_VID,
		[MV88E6XXX_G1_VTU_DATA1] = MV88E6393_SMI_G1_VTU_DATA1,
		[MV88E6XXX_G1_VTU_DATA2] = MV88E6393_SMI_G1_VTU_DATA2,
		[MV88E6352_G1_ATU_FID] = MV88E6393_SMI_G1_ATU_FID,
		[MV88E6XXX_G1_ATU_CTL] = MV88E6393_SMI_G1_ATU_CTL,
		[MV88E6XXX_G1_ATU_OP] = MV88E6393_SMI_G1_ATU_OP,
		[MV88E6XXX_G1_ATU_DATA] = MV88E6393_SMI_G1_ATU_DATA,
		[MV88E6XXX_G1_ATU_MAC01] = MV88E6393_SMI_G1_ATU_MAC01,
		[MV88E6XXX_G1_ATU_MAC23] = MV88E6393_SMI_G1_ATU_MAC23,
		[MV88E6XXX_G1_ATU_MAC45] = MV88E6393_SMI_G1_ATU_MAC45,
		[MV88E6XXX_G1_FREE_Q_SIZE] = MV88E6393_SMI_G1_FREE_Q_SIZE,
		[MV88E6XXX_G1_STATS_OP] = MV88E6393_SMI_G1_STATS_OP,
		[MV88E6XXX_G1_STATS_COUNTER_32] = MV88E6393_SMI_G1_STATS_COUNTER_32,
		[MV88E6XXX_G1_STATS_COUNTER_01] = MV88E6393_SMI_G1_STATS_COUNTER_01,
	};

	static const u8 g2_remap[32] = {
		[MV88E6390_G2_IMP_COMM] = MV88E6393_SMI_G2_IMP_COMM,
		[MV88E6352_G2_AVB_CMD] = MV88E6393_SMI_G2_AVB_CMD,
		[MV88E6352_G2_AVB_DATA] = MV88E6393_SMI_G2_AVB_DATA,
		[MV88E6XXX_G2_SMI_PHY_CMD] = MV88E6393_SMI_G2_SMI_PHY_CMD,
		[MV88E6XXX_G2_SMI_PHY_DATA] = MV88E6393_SMI_G2_SMI_PHY_DATA,
		[MV88E6393X_G2_MACLINK_INT_SRC] = MV88E6393_SMI_G2_MACLINK_INT_SRC,
	};

	switch (dev) {
	case 0x1b:
		return g1_remap[reg];
	case 0x1c:
		return g2_remap[reg];
	}

	return 0;
}

static int mv88e6393_smi_indirect_read(struct mv88e6xxx_chip *chip,
				       int dev, int reg, u16 *data)
{
	u8 remap = mv88e6393_smi_indirect_remap(dev, reg);

	if (remap)
		return mv88e6xxx_smi_direct_read(chip, chip->sw_addr,
						 remap, data);

	return mv88e6xxx_smi_indirect_read(chip, dev, reg, data);
}

static int mv88e6393_smi_indirect_write(struct mv88e6xxx_chip *chip,
					int dev, int reg, u16 data)
{
	u8 remap = mv88e6393_smi_indirect_remap(dev, reg);

	if (remap)
		return mv88e6xxx_smi_direct_write(chip, chip->sw_addr,
						  remap, data);

	return mv88e6xxx_smi_indirect_write(chip, dev, reg, data);
}

static const struct mv88e6xxx_bus_ops mv88e6393_smi_indirect_ops = {
	.read = mv88e6393_smi_indirect_read,
	.write = mv88e6393_smi_indirect_write,
	.init = mv88e6xxx_smi_indirect_init,
};

int mv88e6xxx_smi_init(struct mv88e6xxx_chip *chip,
		       struct mii_bus *bus, int sw_addr)
{
	if (chip->info->dual_chip)
		chip->smi_ops = &mv88e6xxx_smi_dual_direct_ops;
	else if (sw_addr == 0)
		chip->smi_ops = &mv88e6xxx_smi_direct_ops;
	else if (chip->info->family == MV88E6XXX_FAMILY_6393)
		chip->smi_ops = &mv88e6393_smi_indirect_ops;
	else if (chip->info->multi_chip)
		chip->smi_ops = &mv88e6xxx_smi_indirect_ops;
	else
		return -EINVAL;

	chip->bus = bus;
	chip->sw_addr = sw_addr;

	if (chip->smi_ops->init)
		return chip->smi_ops->init(chip);

	return 0;
}
