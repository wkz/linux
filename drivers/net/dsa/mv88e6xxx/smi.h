/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Marvell 88E6xxx System Management Interface (SMI) support
 *
 * Copyright (c) 2008 Marvell Semiconductor
 *
 * Copyright (c) 2019 Vivien Didelot <vivien.didelot@gmail.com>
 */

#ifndef _MV88E6XXX_SMI_H
#define _MV88E6XXX_SMI_H

#include "chip.h"

/* Offset 0x00: SMI Command Register */
#define MV88E6XXX_SMI_CMD			0x00
#define MV88E6XXX_SMI_CMD_BUSY			0x8000
#define MV88E6XXX_SMI_CMD_MODE_MASK		0x1000
#define MV88E6XXX_SMI_CMD_MODE_45		0x0000
#define MV88E6XXX_SMI_CMD_MODE_22		0x1000
#define MV88E6XXX_SMI_CMD_OP_MASK		0x0c00
#define MV88E6XXX_SMI_CMD_OP_22_WRITE		0x0400
#define MV88E6XXX_SMI_CMD_OP_22_READ		0x0800
#define MV88E6XXX_SMI_CMD_OP_45_WRITE_ADDR	0x0000
#define MV88E6XXX_SMI_CMD_OP_45_WRITE_DATA	0x0400
#define MV88E6XXX_SMI_CMD_OP_45_READ_DATA	0x0800
#define MV88E6XXX_SMI_CMD_OP_45_READ_DATA_INC	0x0c00
#define MV88E6XXX_SMI_CMD_DEV_ADDR_MASK		0x003e
#define MV88E6XXX_SMI_CMD_REG_ADDR_MASK		0x001f

/* Offset 0x01: SMI Data Register */
#define MV88E6XXX_SMI_DATA			0x01

/* When using the 6393 in indirect addressing mode, a subset of the
 * most commonly used registers are directly mapped out to the chip's
 * top address space, allowing them to be directly accessed.
 */
#define MV88E6393_SMI_G1_VTU_FID		0x02
#define MV88E6393_SMI_G1_VTU_SID		0x03
#define MV88E6393_SMI_G1_STS			0x04
#define MV88E6393_SMI_G1_VTU_OP			0x05
#define MV88E6393_SMI_G1_VTU_VID		0x06
#define MV88E6393_SMI_G1_VTU_DATA1		0x07
#define MV88E6393_SMI_G1_VTU_DATA2		0x08
#define MV88E6393_SMI_G1_ATU_FID		0x09
#define MV88E6393_SMI_G1_ATU_CTL		0x0a
#define MV88E6393_SMI_G1_ATU_OP			0x0b
#define MV88E6393_SMI_G1_ATU_DATA		0x0c
#define MV88E6393_SMI_G1_ATU_MAC01		0x0d
#define MV88E6393_SMI_G1_ATU_MAC23		0x0e
#define MV88E6393_SMI_G1_ATU_MAC45		0x0f
#define MV88E6393_SMI_G2_IMP_COMM		0x13
#define MV88E6393_SMI_G2_AVB_CMD		0x16
#define MV88E6393_SMI_G2_AVB_DATA		0x17
#define MV88E6393_SMI_G2_SMI_PHY_CMD		0x18
#define MV88E6393_SMI_G2_SMI_PHY_DATA		0x19
#define MV88E6393_SMI_G2_MACLINK_INT_SRC	0x1a
#define MV88E6393_SMI_G1_FREE_Q_SIZE		0x1b
#define MV88E6393_SMI_G1_STATS_OP		0x1d
#define MV88E6393_SMI_G1_STATS_COUNTER_32	0x1e
#define MV88E6393_SMI_G1_STATS_COUNTER_01	0x1f


int mv88e6xxx_smi_init(struct mv88e6xxx_chip *chip,
		       struct mii_bus *bus, int sw_addr);

static inline int mv88e6xxx_smi_read(struct mv88e6xxx_chip *chip,
				     int dev, int reg, u16 *data)
{
	if (chip->smi_ops && chip->smi_ops->read)
		return chip->smi_ops->read(chip, dev, reg, data);

	return -EOPNOTSUPP;
}

static inline int mv88e6xxx_smi_write(struct mv88e6xxx_chip *chip,
				      int dev, int reg, u16 data)
{
	if (chip->smi_ops && chip->smi_ops->write)
		return chip->smi_ops->write(chip, dev, reg, data);

	return -EOPNOTSUPP;
}

#endif /* _MV88E6XXX_SMI_H */
