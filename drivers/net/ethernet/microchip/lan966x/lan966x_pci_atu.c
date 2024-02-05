// SPDX-License-Identifier: GPL-2.0+

#include "lan966x_main.h"
#include <linux/bitfield.h>
#include <linux/types.h>
#include <linux/bug.h>

/* In order for the FDMA device to dma to/from main memory, the DMA addresses
 * will have to be mapped inside the PCIe Outbound (OB) address space. Mappings
 * can be set up by configuring up to six regions in the PCIe ATU.
 *
 * This implementation takes a simple approach of dividing the regions in six
 * equally sized chunks.
 *
 * +-------------+------------+------------+------------+
 * | Index       | Region 0   | Region 1   | Region 5   |
 * +-------------+------------+------------+------------+
 * | Base addr   | 0x10000000 | 0x12a80000 | 0x1d480000 |
 * | Limit addr  | 0x12a7ffff | 0x154fffff | 0x1fefffff |
 * | Target addr | dma addr   | dma addr   | dma addr   |
 * +-------------+------------+------------+------------+
 *
 * Base addr is the start address of the region within the OB address space.
 * Limit addr is the end address of the region within the OB address space.
 * Target addr is the address to be translated to within the DMA address space.
 */

#define PCIE_ATU_REGION_ALIGN BIT(18) /* Align on 64KB boundary */
#define PCIE_ATU_OB_START    0x10000000
#define PCIE_ATU_OB_END      0x1fffffff
#define PCIE_ATU_REGION_SIZE round_down((PCIE_ATU_OB_END - PCIE_ATU_OB_START) \
	/ PCIE_ATU_REGION_MAX, PCIE_ATU_REGION_ALIGN)

#define PCIE_ATU_ADDR            0x300000
#define PCIE_ATU_IDX_SIZE        0x200
#define PCIE_ATU_ENA             0x4
#define PCIE_ATU_ENA_BIT         BIT(31)
#define PCIE_ATU_LWR_BASE_ADDR   0x8
#define PCIE_ATU_UPP_BASE_ADDR   0xc
#define PCIE_ATU_LIMIT_ADDR      0x10
#define PCIE_ATU_LWR_TARGET_ADDR 0x14
#define PCIE_ATU_UPP_TARGET_ADDR 0x18

static void *lan966x_fdma_pci_addr_get(struct lan966x *lan966x, int offset,
				       int idx)
{
	return lan966x->regs[TARGET_PCIE_DBI] + PCIE_ATU_ADDR +
	       PCIE_ATU_IDX_SIZE * idx + offset;
}

/* Configure the mapping in the ATU */
static void
lan966x_fdma_pci_configure_atu(struct lan966x *lan966x,
			       struct lan966x_pci_atu_region *region)
{
	int idx = region->idx;

	writel(PCIE_ATU_ENA_BIT,
	       lan966x_fdma_pci_addr_get(lan966x,
					 PCIE_ATU_ENA,
					 idx));

	writel(lower_32_bits(region->base_addr),
	       lan966x_fdma_pci_addr_get(lan966x,
					 PCIE_ATU_LWR_BASE_ADDR,
					 idx));

	writel(upper_32_bits(region->base_addr),
	       lan966x_fdma_pci_addr_get(lan966x,
					 PCIE_ATU_UPP_BASE_ADDR,
					 idx));

	writel(region->limit_addr,
	       lan966x_fdma_pci_addr_get(lan966x,
					 PCIE_ATU_LIMIT_ADDR,
					 idx));

	writel(lower_32_bits(region->target_addr),
	       lan966x_fdma_pci_addr_get(lan966x,
					 PCIE_ATU_LWR_TARGET_ADDR,
					 idx));

	writel(upper_32_bits(region->target_addr),
	       lan966x_fdma_pci_addr_get(lan966x,
					 PCIE_ATU_UPP_TARGET_ADDR,
					 idx));
}

/* Get a free region */
static struct lan966x_pci_atu_region *
lan966x_pci_atu_region_get(struct lan966x *lan966x)
{
	struct lan966x_pci_atu_region *regions = lan966x->atu_regions;
	int i;

	for (i = 0; i < PCIE_ATU_REGION_MAX; i++) {
		if (regions[i].target_addr)
			continue;

		pr_debug("%s:%u Using free region %u", __func__, __LINE__, i);

		return &regions[i];
	}

	return ERR_PTR(-ENOMEM);
}

/* Unmap a region */
int lan966x_pci_atu_region_unmap(struct lan966x *lan966x,
				 struct lan966x_pci_atu_region *region)
{
	struct lan966x_pci_atu_region *regions = lan966x->atu_regions;
	int i;

	for (i = 0; i < PCIE_ATU_REGION_MAX; i++) {
		if (regions[i].base_addr != region->base_addr)
			continue;

		pr_debug("%s:%u Unmapping region %u", __func__, __LINE__, i);

		region->target_addr = 0;

		lan966x_fdma_pci_configure_atu(lan966x, region);

		return 0;
	}

	return -ENOENT;
}

/* Map a region */
struct lan966x_pci_atu_region *
lan966x_pci_atu_region_map(struct lan966x *lan966x, u64 target_addr, int size)
{
	struct lan966x_pci_atu_region *region;

	if (size > PCIE_ATU_REGION_SIZE)
		return ERR_PTR(-E2BIG);

	region = lan966x_pci_atu_region_get(lan966x);
	if (IS_ERR(region))
		return region;

	region->target_addr = target_addr;

	lan966x_fdma_pci_configure_atu(lan966x, region);

	return region;
}

/* Convert a target addr to the equivalent base addr */
u64 lan966x_pci_atu_get_mapped_addr(struct lan966x_pci_atu_region *region,
				    u64 addr)
{
	return region->base_addr + (addr - region->target_addr);
}

/* Divide the OB address space in equally sized regions */
void lan966x_pci_atu_init(struct lan966x *lan966x)
{
	struct lan966x_pci_atu_region *regions = lan966x->atu_regions;
	int i;

	for (i = 0; i < PCIE_ATU_REGION_MAX; i++) {
		regions[i].base_addr =
			PCIE_ATU_OB_START + (i * PCIE_ATU_REGION_SIZE);
		regions[i].limit_addr =
			regions[i].base_addr + PCIE_ATU_REGION_SIZE - 1;
		regions[i].idx = i;
	}
}
