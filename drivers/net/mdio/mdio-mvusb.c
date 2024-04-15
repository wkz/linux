// SPDX-License-Identifier: GPL-2.0

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of_mdio.h>
#include <linux/phy.h>
#include <linux/usb.h>

#define USB_MARVELL_VID	0x1286

static const struct usb_device_id mvusb_mdio_table[] = {
	{ USB_DEVICE(USB_MARVELL_VID, 0x1fa4) },

	{}
};
MODULE_DEVICE_TABLE(usb, mvusb_mdio_table);

enum {
	MVUSB_C22_PREAMBLE0,
	MVUSB_C22_PREAMBLE1,
	MVUSB_C22_ADDR,
	MVUSB_C22_VAL,
};

enum {
	MVUSB_C45_PREAMBLE0,
	MVUSB_C45_PREAMBLE1,
	MVUSB_C45_PREAMBLE2,
	MVUSB_C45_PREAMBLE3,
	MVUSB_C45_REG_CMD,
	MVUSB_C45_REG,
	MVUSB_C45_CMD,
	MVUSB_C45_VAL,
};

struct mvusb_mdio {
	struct usb_device *udev;
	struct mii_bus *mdio;

	__le16 rst[2];
	__le16 c22[4];
	__le16 c45[8];
};

static int mvusb_mdio_do(struct mii_bus *mdio, void *tx, size_t txlen,
			 void *rx, size_t rxlen)
{
	struct mvusb_mdio *mvusb = mdio->priv;
	int err, alen;

	err = usb_bulk_msg(mvusb->udev, usb_sndbulkpipe(mvusb->udev, 2),
			   tx, txlen, &alen, 100);
	if (err)
		return err;

	if (!rx)
		return 0;

	return usb_bulk_msg(mvusb->udev, usb_rcvbulkpipe(mvusb->udev, 6),
			    rx, rxlen, &alen, 100);
}

static int mvusb_mdio_read_c22(struct mii_bus *mdio, int dev, int reg)
{
	struct mvusb_mdio *mvusb = mdio->priv;
	int err;

	mvusb->c22[MVUSB_C22_ADDR] = cpu_to_le16(0xa400 | (dev << 5) | reg);

	err = mvusb_mdio_do(mdio, mvusb->c22, 6, &mvusb->c22[MVUSB_C22_VAL], 2);

	return err ? : le16_to_cpu(mvusb->c22[MVUSB_C22_VAL]);
}

static int mvusb_mdio_write_c22(struct mii_bus *mdio, int dev, int reg, u16 val)
{
	struct mvusb_mdio *mvusb = mdio->priv;

	mvusb->c22[MVUSB_C22_ADDR] = cpu_to_le16(0x8000 | (dev << 5) | reg);
	mvusb->c22[MVUSB_C22_VAL]  = cpu_to_le16(val);

	return mvusb_mdio_do(mdio, mvusb->c22, 8, NULL, 0);
}

int mvusb_mdio_read_c45(struct mii_bus *mdio, int addr, int devnum, int regnum)
{
	struct mvusb_mdio *mvusb = mdio->priv;
	int err;

	mvusb->c45[MVUSB_C45_REG_CMD] = cpu_to_le16(0x8800 | (addr << 5) | devnum);
	mvusb->c45[MVUSB_C45_REG] = cpu_to_le16(regnum);
	mvusb->c45[MVUSB_C45_CMD] = cpu_to_le16(0xb000 | (addr << 5) | devnum);

	err = mvusb_mdio_do(mdio, mvusb->c45, 14, &mvusb->c45[MVUSB_C45_VAL], 2);

	return err ? : le16_to_cpu(mvusb->c45[MVUSB_C45_VAL]);
}

int mvusb_mdio_write_c45(struct mii_bus *mdio, int addr, int devnum,
			 int regnum, u16 val)
{
	struct mvusb_mdio *mvusb = mdio->priv;

	mvusb->c45[MVUSB_C45_REG_CMD] = cpu_to_le16(0x8800 | (addr << 5) | devnum);
	mvusb->c45[MVUSB_C45_REG] = cpu_to_le16(regnum);
	mvusb->c45[MVUSB_C45_CMD] = cpu_to_le16(0x8c00 | (addr << 5) | devnum);
	mvusb->c45[MVUSB_C45_VAL] = cpu_to_le16(val);

	return mvusb_mdio_do(mdio, mvusb->c45, 16, NULL, 0);
}

int mvusb_mdio_reset(struct mii_bus *mdio)
{
	struct mvusb_mdio *mvusb = mdio->priv;
	int err;

	mvusb->rst[0] = cpu_to_le16(0xe004);
	err = mvusb_mdio_do(mdio, mvusb->rst, 2, &mvusb->rst[1], 2);
	if (err)
		return err;

	mvusb->rst[0] = cpu_to_le16(0xc004);
	return mvusb_mdio_do(mdio, mvusb->rst, 4, NULL, 0);
}

static int mvusb_mdio_probe(struct usb_interface *interface,
			    const struct usb_device_id *id)
{
	struct device *dev = &interface->dev;
	struct mvusb_mdio *mvusb;
	struct mii_bus *mdio;
	int ret;

	mdio = devm_mdiobus_alloc_size(dev, sizeof(*mvusb));
	if (!mdio)
		return -ENOMEM;

	mvusb = mdio->priv;
	mvusb->mdio = mdio;
	mvusb->udev = usb_get_dev(interface_to_usbdev(interface));

	/* Reversed from USB PCAPs, no idea what these mean. */
	mvusb->c22[MVUSB_C22_PREAMBLE0] = cpu_to_le16(0xe800);
	mvusb->c22[MVUSB_C22_PREAMBLE1] = cpu_to_le16(0x0001);
	mvusb->c45[MVUSB_C45_PREAMBLE0] = cpu_to_le16(0xc008);
	mvusb->c45[MVUSB_C45_PREAMBLE1] = cpu_to_le16(0x0010);
	mvusb->c45[MVUSB_C45_PREAMBLE2] = cpu_to_le16(0xc009);
	mvusb->c45[MVUSB_C45_PREAMBLE3] = cpu_to_le16(0x0002);

	snprintf(mdio->id, MII_BUS_ID_SIZE, "mvusb-%s", dev_name(dev));
	mdio->name = mdio->id;
	mdio->parent = dev;
	mdio->read = mvusb_mdio_read_c22;
	mdio->write = mvusb_mdio_write_c22;
	mdio->read_c45 = mvusb_mdio_read_c45;
	mdio->write_c45 = mvusb_mdio_write_c45;
	mdio->reset = mvusb_mdio_reset;

	usb_set_intfdata(interface, mvusb);
	ret = of_mdiobus_register(mdio, dev->of_node);
	if (ret)
		goto put_dev;

	return 0;

put_dev:
	usb_put_dev(mvusb->udev);
	return ret;
}

static void mvusb_mdio_disconnect(struct usb_interface *interface)
{
	struct mvusb_mdio *mvusb = usb_get_intfdata(interface);
	struct usb_device *udev = mvusb->udev;

	mdiobus_unregister(mvusb->mdio);
	usb_set_intfdata(interface, NULL);
	usb_put_dev(udev);
}

static struct usb_driver mvusb_mdio_driver = {
	.name       = "mvusb_mdio",
	.id_table   = mvusb_mdio_table,
	.probe      = mvusb_mdio_probe,
	.disconnect = mvusb_mdio_disconnect,
};

module_usb_driver(mvusb_mdio_driver);

MODULE_AUTHOR("Tobias Waldekranz <tobias@waldekranz.com>");
MODULE_DESCRIPTION("Marvell USB MDIO Adapter");
MODULE_LICENSE("GPL");
