// SPDX-License-Identifier: GPL-2.0+
/* Microchip Sparx5 Switch driver
 *
 * Copyright (c) 2023 Microchip Technology Inc. and its subsidiaries.
 *
 * The Sparx5 Chip Register Model can be browsed at this location:
 * https://github.com/microchip-ung/sparx-5_reginfo
 */

#include <linux/types.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/interrupt.h>
#include <linux/ip.h>
#include <linux/dma-mapping.h>

#include "../sparx5_main_regs.h"
#include "../sparx5_main.h"
#include "../sparx5_port.h"

#include "fdma_api.h"

static struct page *lan969x_fdma_rx_alloc_page(struct sparx5 *sparx5,
					       struct sparx5_rx *rx,
					       struct fdma_db *db)
{
	dma_addr_t dma_addr;
	struct page *page;

	page = dev_alloc_pages(rx->page_order);
	if (unlikely(!page))
		return NULL;

	dma_addr = dma_map_page(sparx5->dev, page, 0,
				PAGE_SIZE << rx->page_order,
				DMA_FROM_DEVICE);
	if (unlikely(dma_mapping_error(sparx5->dev, dma_addr)))
		goto free_page;

	db->dataptr = dma_addr;

	return page;

free_page:
	__free_pages(page, rx->page_order);
	return NULL;
}

static void lan969x_fdma_rx_free_pages(struct sparx5 *sparx5,
				       struct sparx5_rx *rx)
{
	const struct sparx5_consts *consts = &sparx5->data->consts;
	struct fdma *fdma = rx->fdma;
	struct fdma_dcb *dcb;
	struct fdma_db *db;
	int i, j;

	for (i = 0; i < fdma->n_dcbs; ++i) {
		dcb = &fdma->dcbs[i];

		for (j = 0; j < consts->fdma_db_cnt; ++j) {
			db = &dcb->db[j];
			dma_unmap_single(sparx5->dev,
					 (dma_addr_t)db->dataptr,
					 PAGE_SIZE << rx->page_order,
					 DMA_FROM_DEVICE);
			__free_pages(rx->page[i][j], rx->page_order);
		}
	}
}

static void lan969x_fdma_rx_add_dcb(struct sparx5 *sparx5, struct sparx5_rx *rx,
				    struct fdma_dcb *dcb, u64 nextptr)
{
	const struct sparx5_consts *consts = &sparx5->data->consts;
	struct fdma *fdma = rx->fdma;
	struct fdma_db *db;
	int i;

	for (i = 0; i < consts->fdma_db_cnt; ++i) {
		db = &dcb->db[i];
		db->status = FDMA_DCB_STATUS_INTR;
	}

	dcb->nextptr = FDMA_DCB_INVALID_DATA;
	dcb->info = FDMA_DCB_INFO_DATAL(PAGE_SIZE << rx->page_order);

	fdma->last_dcb->nextptr = nextptr;
	fdma->last_dcb = dcb;
}

static bool lan969x_fdma_rx_more_frames(struct sparx5_rx *rx)
{
	struct fdma *fdma = rx->fdma;
	struct fdma_db *db;

	/* Check if there is any data */
	db = &fdma->dcbs[fdma->dcb_index].db[fdma->db_index];
	if (unlikely(!(db->status & FDMA_DCB_STATUS_DONE)))
		return false;

	return true;
}

static void lan969x_fdma_rx_reload(struct sparx5 *sparx5, struct sparx5_rx *rx)
{
	/* Reload the RX channel */
	spx5_wr(BIT(rx->fdma->channel_id), sparx5, FDMA_CH_RELOAD);
}

static struct sk_buff *lan969x_fdma_rx_get_frame(struct sparx5 *sparx5,
						 struct sparx5_rx *rx)
{
	struct fdma *fdma = rx->fdma;
	struct fdma_db *db;
	struct sk_buff *skb;
	struct page *page;
	struct frame_info fi;
	struct sparx5_port *port;

	/* Get the received frame and unmap it */
	db = &fdma->dcbs[fdma->dcb_index].db[fdma->db_index];
	page = rx->page[fdma->dcb_index][fdma->db_index];

	dma_sync_single_for_cpu(sparx5->dev, (dma_addr_t)db->dataptr,
				FDMA_DCB_STATUS_BLOCKL(db->status),
				DMA_FROM_DEVICE);

	skb = build_skb(page_address(page), PAGE_SIZE << rx->page_order);
	if (unlikely(!skb))
		goto unmap_page;

	skb_put(skb, fdma_db_len_get(db));

	sparx5_ifh_parse(sparx5, (u32 *)skb->data, &fi);
#ifdef CONFIG_SPARX5_SWITCH_APPL
	port = sparx5->ports[0];
#else
	port = fi.src_port < sparx5->data->consts.chip_ports ? sparx5->ports[fi.src_port] :
						  NULL;
#endif

	if (WARN_ON(fi.src_port >= sparx5->data->consts.chip_ports))
		goto free_skb;

	dma_unmap_single_attrs(sparx5->dev, (dma_addr_t)db->dataptr,
			       PAGE_SIZE << rx->page_order, DMA_FROM_DEVICE,
			       DMA_ATTR_SKIP_CPU_SYNC);

	skb->dev = port->ndev;
#ifdef CONFIG_SPARX5_SWITCH_APPL
	if (pskb_expand_head(skb, IFH_ENCAP_LEN, 0, GFP_ATOMIC))
		goto free_skb;

	*(u16 *)skb_push(skb, sizeof(u16)) = htons(sparx5->data->consts.ifh_id);
	*(u16 *)skb_push(skb, sizeof(u16)) = htons(IFH_ETH_TYPE);
	ether_addr_copy((u8 *)skb_push(skb, ETH_ALEN), ifh_smac);
	ether_addr_copy((u8 *)skb_push(skb, ETH_ALEN), ifh_dmac);
#else
	skb_pull(skb, IFH_LEN * sizeof(u32));

	if (likely(!(skb->dev->features & NETIF_F_RXFCS)))
		skb_trim(skb, skb->len - ETH_FCS_LEN);
#endif

	sparx5_ptp_rxtstamp(sparx5, skb, fi.src_port, fi.timestamp);
	skb->protocol = eth_type_trans(skb, skb->dev);

	if (test_bit(port->portno, sparx5->bridge_mask)) {
		skb->offload_fwd_mark = 1;
		skb_reset_network_header(skb);
	}

	skb->dev->stats.rx_bytes += skb->len;
	skb->dev->stats.rx_packets++;

	return skb;

free_skb:
	kfree_skb(skb);
unmap_page:
	dma_unmap_single_attrs(sparx5->dev, (dma_addr_t)db->dataptr,
			       PAGE_SIZE << rx->page_order, DMA_FROM_DEVICE,
			       DMA_ATTR_SKIP_CPU_SYNC);
	__free_pages(page, rx->page_order);

	return NULL;
}

static int lan969x_fdma_napi_poll(struct napi_struct *napi, int weight)
{
	struct sparx5_rx *rx = container_of(napi, struct sparx5_rx, napi);
	struct sparx5 *sparx5 = container_of(rx, struct sparx5, rx);
	const struct sparx5_consts *consts = &sparx5->data->consts;
	struct fdma *fdma = rx->fdma;
	int dcb_reload, counter = 0;
	struct fdma_dcb *old_dcb;
	struct fdma_db *db;
	struct sk_buff *skb;
	struct page *page;
	u64 nextptr;

	dcb_reload = fdma->dcb_index;

	/* Get all received skb */
	while (counter < weight) {
		if (!fdma_has_frames(fdma))
			break;

		skb = lan969x_fdma_rx_get_frame(sparx5, rx);

		napi_gro_receive(&rx->napi, skb);

		fdma_db_advance(fdma);
		counter++;
		/* Check if the DCB can be reused */
		if (fdma_dcb_is_reusable(fdma))
			continue;

		fdma_db_reset(fdma);
		rx->page[fdma->dcb_index][fdma->db_index] = NULL;
		fdma_dcb_advance(fdma);

		if (!skb)
			break;
	}

	/* Allocate new pages and map them */
	while (dcb_reload != fdma->dcb_index) {
		int j;

		for (j = 0; j < consts->fdma_db_cnt; ++j) {
			db = &fdma->dcbs[dcb_reload].db[j];
			page = lan969x_fdma_rx_alloc_page(sparx5, rx, db);
			if (unlikely(!page))
				break;
			rx->page[dcb_reload][j] = page;
		}

		old_dcb = &fdma->dcbs[dcb_reload];
		dcb_reload++;
		dcb_reload &= fdma->n_dcbs - 1;

		nextptr = fdma->dma + ((unsigned long)old_dcb -
				     (unsigned long)fdma->dcbs);
		lan969x_fdma_rx_add_dcb(sparx5, rx, old_dcb, nextptr);
		lan969x_fdma_rx_reload(sparx5, rx);
	}

	if (counter < weight && napi_complete_done(napi, counter))
		spx5_rmw(BIT(fdma->channel_id),
			 BIT(fdma->channel_id) & FDMA_INTR_DB_ENA_INTR_DB_ENA,
			 sparx5, FDMA_INTR_DB_ENA);

	return counter;
}

static int lan969x_fdma_rx_alloc(struct sparx5 *sparx5, struct sparx5_rx *rx)
{
	struct fdma *fdma = rx->fdma;
	struct fdma_dcb *dcb;
	struct fdma_db *db;
	struct page *page;
	int i, j;
	int size;

	/* calculate how many pages are needed to allocate the dcbs */
	size = sizeof(struct fdma_dcb) * fdma->n_dcbs;
	size = ALIGN(size, PAGE_SIZE);

	fdma->dcbs = dma_alloc_coherent(sparx5->dev, size, &fdma->dma, GFP_KERNEL);
	if (!fdma->dcbs)
		return -ENOMEM;

	fdma->last_dcb = fdma->dcbs;
	fdma->db_index = 0;
	fdma->dcb_index = 0;

	/* Now for each dcb allocate the dbs */
	for (i = 0; i < fdma->n_dcbs; ++i) {
		dcb = &fdma->dcbs[i];
		dcb->info = 0;

		/* For each db allocate a page and map it to the DB dataptr. */
		for (j = 0; j < fdma->n_dbs; ++j) {
			db = &dcb->db[j];
			page = lan969x_fdma_rx_alloc_page(sparx5, rx, db);
			if (!page)
				return -ENOMEM;

			db->status = 0;
			rx->page[i][j] = page;
		}

		lan969x_fdma_rx_add_dcb(sparx5, rx, dcb,
					fdma->dma + sizeof(*dcb) * i);
	}

	sparx5_fdma_llp_configure(sparx5, fdma->dma, fdma->channel_id);
	netif_napi_add_weight(rx->ndev, &rx->napi, lan969x_fdma_napi_poll,
			      FDMA_WEIGHT);
	napi_enable(&rx->napi);
	sparx5_fdma_rx_activate(sparx5, rx);

	return 0;
}

static void sparx5_fdma_tx_add_dcb(struct sparx5_tx *tx,
				   struct fdma_dcb *dcb,
				   u64 nextptr)
{
	int idx = 0;

	/* Reset the status of the DB */
	for (idx = 0; idx < tx->fdma->n_dbs; ++idx) {
		struct fdma_db *db = &dcb->db[idx];

		db->status = FDMA_DCB_STATUS_DONE;
	}
	dcb->nextptr = FDMA_DCB_INVALID_DATA;
	dcb->info = FDMA_DCB_INFO_DATAL(tx->max_mtu);
}

static int lan969x_fdma_tx_alloc(struct sparx5 *sparx5)
{
	struct sparx5_tx *tx = &sparx5->tx;
	struct fdma *fdma = tx->fdma;
	struct fdma_dcb *dcb;
	int idx, jdx;
	int size;

	size = sizeof(struct fdma_dcb) * fdma->n_dcbs;
	size = ALIGN(size, PAGE_SIZE);
	fdma->curr_dcb = dma_alloc_coherent(sparx5->dev, size, &fdma->dma, GFP_KERNEL);
	if (!fdma->curr_dcb)
		return -ENOMEM;
	fdma->first_dcb = fdma->curr_dcb;
	INIT_LIST_HEAD(&tx->db_list);
	/* Now for each dcb allocate the db */
	for (idx = 0; idx < fdma->n_dcbs; ++idx) {
		dcb = &fdma->curr_dcb[idx];
		dcb->info = 0;
		/* TX databuffers must be 16byte aligned */
		for (jdx = 0; jdx < fdma->n_dbs; ++jdx) {
			struct fdma_db *db_hw = &dcb->db[jdx];
			struct sparx5_db *db;
			dma_addr_t dma_addr;
			void *cpu_addr;

			cpu_addr = devm_kzalloc(sparx5->dev,
						tx->max_mtu,
						GFP_KERNEL);
			if (!cpu_addr)
				return -ENOMEM;

			dma_addr = dma_map_single(sparx5->dev, cpu_addr,
						  tx->max_mtu,
						  DMA_BIDIRECTIONAL);
			if (dma_mapping_error(sparx5->dev, dma_addr))
				return -ENOMEM;

			db_hw->dataptr = dma_addr;
			db_hw->status = 0;
			db = devm_kzalloc(sparx5->dev, sizeof(*db), GFP_KERNEL);
			if (!db)
				return -ENOMEM;
			db->cpu_addr = cpu_addr;
			list_add_tail(&db->list, &tx->db_list);
		}
		sparx5_fdma_tx_add_dcb(tx, dcb, fdma->dma + sizeof(*dcb) * idx);
		/* Let the curr_entry to point to the last allocated entry */
		if (idx == fdma->n_dcbs - 1)
			fdma->curr_dcb = dcb;
	}
	sparx5_fdma_llp_configure(sparx5, fdma->dma, fdma->channel_id);
	return 0;
}

int lan969x_fdma_stop(struct sparx5 *sparx5)
{
	u32 val;

	napi_disable(&sparx5->rx.napi);
	/* Stop the fdma and channel interrupts */
	sparx5_fdma_rx_deactivate(sparx5, &sparx5->rx);
	sparx5_fdma_tx_deactivate(sparx5, &sparx5->tx);
	/* Wait for the RX channel to stop */
	read_poll_timeout(sparx5_fdma_port_ctrl, val,
			  FDMA_PORT_CTRL_XTR_BUF_IS_EMPTY_GET(val) == 0,
			  500, 10000, 0, sparx5);

	lan969x_fdma_rx_free_pages(sparx5, &sparx5->rx);

	return 0;
}

int lan969x_fdma_start(struct sparx5 *sparx5)
{
	int err;

	sparx5->tx.max_mtu = sparx5_fdma_get_mtu(sparx5);
	sparx5->rx.ndev = sparx5_fdma_get_ndev(sparx5);

	/* Reset FDMA state */
	spx5_wr(FDMA_CTRL_NRESET_SET(0), sparx5, FDMA_CTRL);
	spx5_wr(FDMA_CTRL_NRESET_SET(1), sparx5, FDMA_CTRL);

	err = dma_set_mask_and_coherent(sparx5->dev, DMA_BIT_MASK(64));
	if (err) {
		dev_err(sparx5->dev, "Failed to set 64-bit FDMA mask");
		return err;
	}

	sparx5_fdma_injection_mode(sparx5);
	err = lan969x_fdma_rx_alloc(sparx5, &sparx5->rx);
	if (err) {
		dev_err(sparx5->dev, "Could not allocate RX buffers: %d\n", err);
		return err;
	}

	err = lan969x_fdma_tx_alloc(sparx5);
	if (err) {
		pr_info("%s:%u", __func__, __LINE__);
		dev_err(sparx5->dev, "Could not allocate TX buffers: %d\n", err);
		return err;
	}
	return err;
}

int lan969x_fdma_xmit(struct sparx5 *sparx5, u32 *ifh, struct sk_buff *skb)
{
	struct sparx5_tx *tx = &sparx5->tx;
	static bool first_time = true;
	struct fdma *fdma = tx->fdma;
	struct fdma_dcb *next_dcb_hw;
	struct fdma_db *db_hw;
	struct sparx5_db *db;

	next_dcb_hw = fdma_dcb_next_get(fdma);
	db_hw = &next_dcb_hw->db[0];

	dma_sync_single_for_cpu(sparx5->dev, db_hw->dataptr,
				skb->len + IFH_LEN * 4 + 4, DMA_BIDIRECTIONAL);
	if (!(db_hw->status & FDMA_DCB_STATUS_DONE))
		return -EINVAL;
	db = list_first_entry(&tx->db_list, struct sparx5_db, list);
	list_move_tail(&db->list, &tx->db_list);
	next_dcb_hw->nextptr = FDMA_DCB_INVALID_DATA;
	fdma->curr_dcb->nextptr = fdma->dma +
		((unsigned long)next_dcb_hw -
		 (unsigned long)fdma->first_dcb);
	fdma->curr_dcb = next_dcb_hw;
	memset(db->cpu_addr, 0, skb->len);
	memcpy(db->cpu_addr, ifh, IFH_LEN * 4);
	memcpy(db->cpu_addr + IFH_LEN * 4, skb->data, skb->len);
	db_hw->status = FDMA_DCB_STATUS_SOF |
			FDMA_DCB_STATUS_EOF |
			FDMA_DCB_STATUS_BLOCKO(0) |
			FDMA_DCB_STATUS_BLOCKL(skb->len + IFH_LEN * 4 + 4);
	dma_sync_single_for_device(sparx5->dev, db_hw->dataptr,
				   skb->len + IFH_LEN * 4 + 4,
				   DMA_BIDIRECTIONAL);
	if (first_time) {
		sparx5_fdma_tx_activate(sparx5, tx);
		first_time = false;
	} else {
		sparx5_fdma_reload(sparx5, fdma);
	}

	sparx5_consume_skb(skb);

	return NETDEV_TX_OK;
}
