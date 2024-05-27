// SPDX-License-Identifier: GPL-2.0+

#include <linux/bpf_trace.h>

#include "fdma_api.h"
#include "lan966x_main.h"

#define FDMA_PCI_DB_ALIGN 128

#define FDMA_PCI_DB_SIZE(mtu) ALIGN(mtu, FDMA_PCI_DB_ALIGN)

#define FDMA_PCI_TX_DB_OFFSET(mtu, dcb, db) \
	((sizeof(struct fdma_dcb) * FDMA_DCB_MAX) + \
	((dcb) * FDMA_TX_DCB_MAX_DBS + (db)) * FDMA_PCI_DB_SIZE(mtu) + \
	XDP_PACKET_HEADROOM)

#define FDMA_PCI_RX_DB_OFFSET(mtu, dcb, db) \
	((sizeof(struct fdma_dcb) * FDMA_DCB_MAX) + \
	((dcb) * FDMA_RX_DCB_MAX_DBS + (db)) * FDMA_PCI_DB_SIZE(mtu) + \
	XDP_PACKET_HEADROOM)

#define FDMA_PCI_TX_DMA_SIZE(mtu) \
	((sizeof(struct fdma_dcb) * FDMA_DCB_MAX) + \
	FDMA_DCB_MAX * FDMA_PCI_DB_SIZE(mtu) * FDMA_TX_DCB_MAX_DBS)

#define FDMA_PCI_RX_DMA_SIZE(mtu) \
	((sizeof(struct fdma_dcb) * FDMA_DCB_MAX) + \
	FDMA_DCB_MAX * FDMA_PCI_DB_SIZE(mtu) * FDMA_RX_DCB_MAX_DBS)

static dma_addr_t lan966x_fdma_pci_tx_db_dma_get(struct lan966x_tx *tx, int dcb,
						 int db)
{
	return tx->fdma->dma + FDMA_PCI_TX_DB_OFFSET(tx->lan966x->rx.max_mtu,
						     dcb,
						     db);
}

static void *lan966x_fdma_pci_tx_db_virt_get(struct lan966x_tx *tx, int dcb,
					     int db)
{
	return (u8 *)tx->fdma->dcbs + FDMA_PCI_TX_DB_OFFSET(tx->lan966x->rx.max_mtu,
							    dcb,
							    db);
}

static dma_addr_t lan966x_fdma_pci_rx_db_dma_get(struct lan966x_rx *rx, int dcb,
						 int db)
{
	return rx->fdma->dma + FDMA_PCI_RX_DB_OFFSET(rx->max_mtu, dcb, db);
}

static void *lan966x_fdma_pci_rx_db_virt_get(struct lan966x_rx *rx, int dcb,
					     int db)
{
	return (u8 *)rx->fdma->dcbs + FDMA_PCI_RX_DB_OFFSET(rx->max_mtu,
							    dcb,
							    db);
}

static int lan966x_fdma_pci_dataptr_cb(struct fdma *fdma, int dcb, int db,
				       u64 *dataptr)
{
	*dataptr = fdma_pci_atu_get_mapped_addr(fdma->atu_region,
						fdma_dataptr_get_contiguous(fdma, dcb, db));

	return 0;
}

static int lan966x_fdma_pci_nextptr_cb(struct fdma *fdma, int dcb, u64 *nextptr)
{
	u64 addr;

	fdma_nextptr_cb(fdma, dcb, &addr);

	*nextptr = fdma_pci_atu_get_mapped_addr(fdma->atu_region, addr);

	return 0;
}

static void lan966x_fdma_pci_rx_free(struct lan966x_rx *rx)
{
	struct fdma *fdma = rx->fdma;

	dma_free_coherent(rx->lan966x->dev,
			  FDMA_PCI_RX_DMA_SIZE(rx->max_mtu),
			  fdma->dcbs,
			  fdma->dma);

	fdma_pci_atu_region_unmap(fdma->atu_region);
}

static void lan966x_fdma_pci_tx_free(struct lan966x_tx *tx)
{
	struct fdma *fdma = tx->fdma;

	kfree(tx->dcbs_buf);

	dma_free_coherent(tx->lan966x->dev,
			  FDMA_PCI_TX_DMA_SIZE(tx->lan966x->rx.max_mtu),
			  fdma->dcbs,
			  fdma->dma);

	fdma_pci_atu_region_unmap(fdma->atu_region);
}

static void lan966x_fdma_pci_rx_add_dcb(struct lan966x_rx *rx,
					struct fdma_dcb *dcb, u64 nextptr)
{
	struct fdma *fdma = rx->fdma;

	for (int i = 0; i < FDMA_RX_DCB_MAX_DBS; ++i)
		dcb->db[i].status = FDMA_DCB_STATUS_INTR;

	dcb->nextptr = FDMA_DCB_INVALID_DATA;
	dcb->info = FDMA_DCB_INFO_DATAL(FDMA_PCI_DB_SIZE(rx->max_mtu));

	fdma->last_dcb->nextptr = fdma_pci_atu_get_mapped_addr(fdma->atu_region,
							       nextptr);
	fdma->last_dcb = dcb;
}

static void lan966x_fdma_pci_rx_setup(struct lan966x_rx *rx)
{
	struct fdma *fdma = rx->fdma;
	struct fdma_dcb *dcb;
	struct fdma_db *db;

	fdma->last_dcb = fdma->dcbs;
	fdma->db_index = 0;
	fdma->dcb_index = 0;

	for (int i = 0; i < FDMA_DCB_MAX; ++i) {
		dcb = &fdma->dcbs[i];
		dcb->info = 0;

		/* For each DB, map it to the dataptr of the DCB. */
		for (int j = 0; j < fdma->n_dbs; ++j) {
			struct fdma_pci_atu_region *region = fdma->atu_region;
			dma_addr_t addr = lan966x_fdma_pci_rx_db_dma_get(rx,
									 i,
									 j);

			db = &dcb->db[j];
			db->status = 0;
			db->dataptr = fdma_pci_atu_get_mapped_addr(region,
								   addr);
		}

		lan966x_fdma_pci_rx_add_dcb(rx,
					    dcb,
					    fdma->dma + sizeof(*dcb) * i);
	}
}

static int lan966x_fdma_pci_rx_alloc(struct lan966x_rx *rx)
{
	struct lan966x *lan966x = rx->lan966x;
	struct fdma *fdma = rx->fdma;
	u32 max_mtu = rx->max_mtu;

	/* RX memory layout, where N=FDMA_DCB_MAX and M=FDMA_RX_DCB_MAX_DBS)
	 * +-------+-------+---------+------+------+----------+
	 * | DCB 0 | DCB 1 | DCB N-1 | DB 0 | DB 1 | DB N*M-1 |
	 * +-------+-------+---------+------+------+----------+
	 */
	fdma->dcbs = dma_alloc_coherent(lan966x->dev,
					FDMA_PCI_RX_DMA_SIZE(max_mtu),
					&fdma->dma,
					GFP_KERNEL);
	if (!fdma->dcbs)
		return -ENOMEM;

	fdma->atu_region = fdma_pci_atu_region_map(&lan966x->atu,
						   fdma->dma,
						   FDMA_PCI_RX_DMA_SIZE(max_mtu));
	if (IS_ERR(fdma->atu_region)) {
		dma_free_coherent(lan966x->dev,
				  FDMA_PCI_RX_DMA_SIZE(max_mtu),
				  fdma->dcbs,
				  fdma->dma);
		return PTR_ERR(fdma->atu_region);
	}

	lan966x_fdma_pci_rx_setup(rx);

	lan966x_fdma_llp_configure(lan966x,
				   fdma->atu_region->base_addr,
				   fdma->channel_id);

	return 0;
}

static int lan966x_fdma_pci_tx_alloc(struct lan966x_tx *tx)
{
	struct lan966x *lan966x = tx->lan966x;
	struct fdma *fdma = tx->fdma;
	int err;

	err = fdma_alloc_coherent_and_map(lan966x->dev, fdma, &lan966x->atu);
	if (err)
		return err;

	fdma_dcbs_init(fdma,
		       FDMA_DCB_INFO_DATAL(fdma->db_size),
		       FDMA_DCB_STATUS_DONE);

	lan966x_fdma_llp_configure(lan966x,
				   fdma->atu_region->base_addr,
				   fdma->channel_id);

	return 0;
}

static void lan966x_fdma_pci_tx_clear_buf(struct lan966x *lan966x, int weight)
{
	struct lan966x_tx *tx = &lan966x->tx;
	struct lan966x_tx_dcb_buf *dcb_buf;
	struct fdma_db *db;
	unsigned long flags;
	bool clear = false;

	spin_lock_irqsave(&lan966x->tx_lock, flags);
	for (int i = 0; i < FDMA_DCB_MAX; ++i) {
		dcb_buf = &tx->dcbs_buf[i];

		if (!dcb_buf->used)
			continue;

		db = &tx->fdma->dcbs[i].db[0];
		if (!(db->status & FDMA_DCB_STATUS_DONE))
			continue;

		dcb_buf->dev->stats.tx_packets++;
		dcb_buf->dev->stats.tx_bytes += dcb_buf->len;

		dcb_buf->used = false;
		if (dcb_buf->use_skb && !dcb_buf->ptp)
			napi_consume_skb(dcb_buf->data.skb, weight);
		clear = true;
	}

	if (clear)
		lan966x_fdma_wakeup_netdev(lan966x);

	spin_unlock_irqrestore(&lan966x->tx_lock, flags);
}

static int lan966x_fdma_pci_rx_check_frame(struct lan966x_rx *rx, u64 *src_port)
{
	struct lan966x *lan966x = rx->lan966x;
	struct fdma *fdma = rx->fdma;
	struct lan966x_port *port;
	struct fdma_db *db;
	void *virt_addr;

	db = &fdma->dcbs[fdma->dcb_index].db[fdma->db_index];
	virt_addr = lan966x_fdma_pci_rx_db_virt_get(rx,
						    fdma->dcb_index,
						    fdma->db_index);

	lan966x_ifh_get_src_port(virt_addr, src_port);

	if (WARN_ON(*src_port >= lan966x->num_phys_ports))
		return FDMA_ERROR;

	port = lan966x->ports[*src_port];
	if (!lan966x_xdp_port_present(port))
		return FDMA_PASS;

	return lan966x_xdp_pci_run(port,
				   virt_addr,
				   FDMA_DCB_STATUS_BLOCKL(db->status));
}

static struct sk_buff *lan966x_fdma_pci_rx_get_frame(struct lan966x_rx *rx,
						     u64 src_port)
{
	struct lan966x *lan966x = rx->lan966x;
	struct fdma *fdma = rx->fdma;
	struct fdma_db *db;
	struct sk_buff *skb;
	u64 timestamp;

	/* Get the received frame and create an SKB for it */
	db = &fdma->dcbs[fdma->dcb_index].db[fdma->db_index];

	skb = __netdev_alloc_skb(rx->lan966x->fdma_ndev,
				 rx->max_mtu,
				 GFP_ATOMIC);

	skb_reserve(skb, XDP_PACKET_HEADROOM);

	memcpy(skb->data,
	       lan966x_fdma_pci_rx_db_virt_get(rx, fdma->dcb_index, fdma->db_index),
	       rx->max_mtu - XDP_PACKET_HEADROOM);

	if (unlikely(!skb))
		goto out;

	skb_put(skb, FDMA_DCB_STATUS_BLOCKL(db->status));

	lan966x_ifh_get_timestamp(skb->data, &timestamp);

	skb->dev = lan966x->ports[src_port]->dev;
	skb_pull(skb, IFH_LEN_BYTES);

	if (likely(!(skb->dev->features & NETIF_F_RXFCS)))
		skb_trim(skb, skb->len - ETH_FCS_LEN);

	lan966x_ptp_rxtstamp(lan966x, skb, src_port, timestamp);
	skb->protocol = eth_type_trans(skb, skb->dev);

	if (lan966x->bridge_mask & BIT(src_port)) {
		skb->offload_fwd_mark = 1;

		skb_reset_network_header(skb);
		if (!lan966x_hw_offload(lan966x, src_port, skb))
			skb->offload_fwd_mark = 0;
	}

	skb->dev->stats.rx_bytes += skb->len;
	skb->dev->stats.rx_packets++;

	return skb;

out:
	return NULL;
}

int lan966x_xdp_pci_setup(struct net_device *dev, struct netdev_bpf *xdp)
{
	struct lan966x_port *port = netdev_priv(dev);
	struct lan966x *lan966x = port->lan966x;
	struct bpf_prog *old_prog;
	bool old_xdp, new_xdp;

	old_xdp = lan966x_xdp_present(lan966x);
	old_prog = xchg(&port->xdp_prog, xdp->prog);
	new_xdp = lan966x_xdp_present(lan966x);

	if (old_xdp == new_xdp && old_prog)
		bpf_prog_put(old_prog);

	return 0;
}

static int lan966x_fdma_pci_get_next_dcb(struct fdma *fdma)
{
	struct fdma_db *db;
	int i;

	for (i = 0; i < fdma->n_dcbs; i++) {
		db = fdma_db_get(fdma, i, 0);

		if (!unlikely(fdma_db_is_done(db)))
			continue;
		if (fdma_is_last(fdma, &fdma->dcbs[i]))
			continue;

		return i;
	}

	return -1;
}

static int lan966x_fdma_pci_xmit_xdpf(struct lan966x_port *port, void *ptr,
				      u32 len)
{
	struct lan966x *lan966x = port->lan966x;
	struct lan966x_tx *tx = &lan966x->tx;
	struct fdma *fdma = tx->fdma;
	int next_to_use, ret = 0;
	void *virt_addr;
	__be32 *ifh;

	spin_lock(&lan966x->tx_lock);

	next_to_use = lan966x_fdma_pci_get_next_dcb(fdma);

	if (next_to_use < 0) {
		netif_stop_queue(port->dev);
		ret = NETDEV_TX_BUSY;
		goto out;
	}

	ifh = ptr;
	memset(ifh, 0, IFH_LEN_BYTES);
	lan966x_ifh_set_bypass(ifh, 1);
	lan966x_ifh_set_port(ifh, BIT_ULL(port->chip_port));

	/* Get the virtual addr of the next DB and copy frame incl. IFH to it.*/
	virt_addr = fdma_dataptr_virt_get_contiguous(fdma, fdma->dcb_index, 0);
	memcpy(virt_addr, ptr, len);

	fdma_dcb_add(fdma,
		     fdma->dcb_index,
		     0,
		     FDMA_DCB_STATUS_SOF |
		     FDMA_DCB_STATUS_EOF |
		     FDMA_DCB_STATUS_BLOCKO(0) |
		     FDMA_DCB_STATUS_BLOCKL(len));

	/* Start the transmission */
	lan966x_fdma_tx_start(tx);

out:
	spin_unlock(&lan966x->tx_lock);

	return ret;
}

int lan966x_xdp_pci_run(struct lan966x_port *port, void *data, u32 data_len)
{
	struct bpf_prog *xdp_prog = port->xdp_prog;
	struct lan966x *lan966x = port->lan966x;
	struct xdp_buff xdp;
	u32 act;

	xdp_init_buff(&xdp, lan966x->rx.max_mtu, &port->xdp_rxq);

	xdp_prepare_buff(&xdp,
			 data,
			 IFH_LEN_BYTES + XDP_PACKET_HEADROOM,
			 data_len - IFH_LEN_BYTES,
			 false);

	act = bpf_prog_run_xdp(xdp_prog, &xdp);
	switch (act) {
	case XDP_PASS:
		return FDMA_PASS;
	case XDP_TX:
		return lan966x_fdma_pci_xmit_xdpf(port, data, data_len) ?
		       FDMA_DROP : FDMA_TX;
	default:
		bpf_warn_invalid_xdp_action(port->dev, xdp_prog, act);
		fallthrough;
	case XDP_ABORTED:
		trace_xdp_exception(port->dev, xdp_prog, act);
		fallthrough;
	case XDP_DROP:
		return FDMA_DROP;
	}
}

static int lan966x_fdma_pci_xmit(struct sk_buff *skb, __be32 *ifh,
				 struct net_device *dev)
{
	struct lan966x_port *port = netdev_priv(dev);
	struct lan966x *lan966x = port->lan966x;
	struct lan966x_tx *tx = &lan966x->tx;
	struct fdma *fdma = tx->fdma;
	int next_to_use;
	void *virt_addr;

	next_to_use = lan966x_fdma_pci_get_next_dcb(fdma);

	if (next_to_use < 0) {
		netif_stop_queue(dev);
		return NETDEV_TX_BUSY;
	}

	if (skb_put_padto(skb, ETH_ZLEN)) {
		dev->stats.tx_dropped++;
		return NETDEV_TX_OK;
	}

	skb_tx_timestamp(skb);

	virt_addr = fdma_dataptr_virt_get_contiguous(fdma, next_to_use, 0);
	memcpy(virt_addr, ifh, IFH_LEN_BYTES);
	memcpy((u8 *)virt_addr + IFH_LEN_BYTES, skb->data, skb->len);

	fdma_dcb_add(fdma, next_to_use, 0,
		     FDMA_DCB_STATUS_SOF |
		     FDMA_DCB_STATUS_EOF |
		     FDMA_DCB_STATUS_BLOCKO(0) |
		     FDMA_DCB_STATUS_BLOCKL(IFH_LEN_BYTES + skb->len + ETH_FCS_LEN));

	/* Start the transmission */
	lan966x_fdma_tx_start(tx);

	return NETDEV_TX_OK;
}

static int lan966x_fdma_pci_napi_poll(struct napi_struct *napi, int weight)
{
	struct lan966x *lan966x = container_of(napi, struct lan966x, napi);
	struct lan966x_rx *rx = &lan966x->rx;
	struct fdma *fdma = rx->fdma;
	int dcb_reload, counter = 0;
	struct fdma_dcb *old_dcb;
	struct sk_buff *skb;
	u64 src_port;
	u64 nextptr;

	dcb_reload = fdma->dcb_index;

	lan966x_fdma_pci_tx_clear_buf(lan966x, weight);
	/* Get all received skb */
	while (counter < weight) {
		if (!lan966x_fdma_rx_more_frames(rx))
			break;
		counter++;
		switch (lan966x_fdma_pci_rx_check_frame(rx, &src_port)) {
		case FDMA_PASS:
			break;
		case FDMA_ERROR:
			lan966x_fdma_rx_advance_dcb(rx);
			goto allocate_new;
		case FDMA_TX:
			lan966x_fdma_rx_advance_dcb(rx);
			continue;
		case FDMA_DROP:
			lan966x_fdma_rx_advance_dcb(rx);
			continue;
		}
		skb = lan966x_fdma_pci_rx_get_frame(rx, src_port);

		/* Check if the DCB can be reused */
		fdma->db_index++;
		if (fdma->db_index != FDMA_RX_DCB_MAX_DBS) {
			napi_gro_receive(&lan966x->napi, skb);
			continue;
		}

		fdma->db_index = 0;

		lan966x_fdma_rx_advance_dcb(rx);
		if (!skb)
			goto allocate_new;

		napi_gro_receive(&lan966x->napi, skb);
	}
allocate_new:
	while (dcb_reload != fdma->dcb_index) {
		old_dcb = &fdma->dcbs[dcb_reload];
		dcb_reload++;
		dcb_reload &= FDMA_DCB_MAX - 1;

		nextptr = fdma->dma + ((unsigned long)old_dcb -
				      (unsigned long)fdma->dcbs);
		lan966x_fdma_pci_rx_add_dcb(rx, old_dcb, nextptr);
		lan966x_fdma_rx_reload(rx);
	}

	if (counter < weight && napi_complete_done(napi, counter))
		lan_wr(0xff, lan966x, FDMA_INTR_DB_ENA);

	return counter;
}

/* Reset existing rx and tx buffers */
static void lan966x_fdma_pci_reset_mem(struct lan966x *lan966x)
{
	struct lan966x_rx *rx = &lan966x->rx;
	struct lan966x_tx *tx = &lan966x->tx;
	struct fdma *fdma_rx = rx->fdma;
	u32 max_mtu = rx->max_mtu;

	memset(fdma_rx->dcbs, 0, FDMA_PCI_RX_DMA_SIZE(max_mtu));
	memset(tx->fdma->dcbs, 0, tx->fdma->size);

	lan966x_fdma_pci_rx_setup(rx);

	fdma_dcbs_init(tx->fdma,
		       FDMA_DCB_INFO_DATAL(tx->fdma->db_size),
		       FDMA_DCB_STATUS_DONE);

	lan966x_fdma_llp_configure(lan966x,
				   tx->fdma->atu_region->base_addr,
				   tx->fdma->channel_id);
	lan966x_fdma_llp_configure(lan966x,
				   fdma_rx->atu_region->base_addr,
				   fdma_rx->channel_id);
}

static int lan966x_fdma_pci_reload(struct lan966x *lan966x, int new_mtu)
{
	struct fdma_pci_atu_region *rx_atu = lan966x->rx.fdma->atu_region;
	struct fdma tx_fdma_old = *lan966x->tx.fdma;
	u32 old_mtu = lan966x->rx.max_mtu;
	int err, rx_size;
	dma_addr_t rx_dma;
	void *rx_dcbs;


	/* Store the old memory for later free or reuse */
	rx_dma = lan966x->rx.fdma->dma;
	rx_dcbs = lan966x->rx.fdma->dcbs;
	rx_size = FDMA_PCI_RX_DMA_SIZE(old_mtu);

	napi_synchronize(&lan966x->napi);
	napi_disable(&lan966x->napi);
	lan966x_fdma_stop_netdev(lan966x);
	lan966x_fdma_rx_disable(&lan966x->rx);

	lan966x->rx.max_mtu = new_mtu;

	lan966x->tx.fdma->db_size = FDMA_PCI_DB_SIZE(lan966x->rx.max_mtu);
	lan966x->tx.fdma->size = fdma_get_size_contiguous(lan966x->tx.fdma);

	err = lan966x_fdma_pci_rx_alloc(&lan966x->rx);
	if (err)
		goto restore;

	err = lan966x_fdma_pci_tx_alloc(&lan966x->tx);
	if (err) {
		lan966x_fdma_pci_rx_free(&lan966x->rx);
		goto restore;
	}

	lan966x_fdma_rx_start(&lan966x->rx);

	/* Free and unmap old memory */
	dma_free_coherent(lan966x->dev, rx_size, rx_dcbs, rx_dma);
	fdma_pci_atu_region_unmap(rx_atu);
	fdma_free_coherent_and_unmap(lan966x->dev, &tx_fdma_old);

	lan966x_fdma_wakeup_netdev(lan966x);
	napi_enable(&lan966x->napi);

	return err;
restore:

	/* No new buffers are allocated at this point. Use the old buffers,
	 * but reset them before starting the FDMA again.
	 */

	memcpy(lan966x->tx.fdma, &tx_fdma_old, sizeof(struct fdma));

	lan966x->rx.max_mtu = old_mtu;
	lan966x->rx.fdma->dma = rx_dma;
	lan966x->rx.fdma->dcbs = rx_dcbs;
	lan966x->rx.fdma->atu_region = rx_atu;

	lan966x_fdma_pci_reset_mem(lan966x);

	lan966x_fdma_rx_start(&lan966x->rx);
	lan966x_fdma_wakeup_netdev(lan966x);
	napi_enable(&lan966x->napi);

	return err;
}

static int __lan966x_fdma_pci_reload(struct lan966x *lan966x, int max_mtu)
{
	int err;
	u32 val;

	/* Disable the CPU port */
	lan_rmw(QSYS_SW_PORT_MODE_PORT_ENA_SET(0),
		QSYS_SW_PORT_MODE_PORT_ENA,
		lan966x, QSYS_SW_PORT_MODE(CPU_PORT));

	/* Flush the CPU queues */
	readx_poll_timeout(lan966x_qsys_sw_status, lan966x,
			   val, !(QSYS_SW_STATUS_EQ_AVAIL_GET(val)),
			   READL_SLEEP_US, READL_TIMEOUT_US);

	/* Add a sleep in case there are frames between the queues and the CPU
	 * port
	 */
	usleep_range(1000, 2000);

	err = lan966x_fdma_pci_reload(lan966x, max_mtu);

	/* Enable back the CPU port */
	lan_rmw(QSYS_SW_PORT_MODE_PORT_ENA_SET(1),
		QSYS_SW_PORT_MODE_PORT_ENA,
		lan966x,  QSYS_SW_PORT_MODE(CPU_PORT));

	return err;
}

static int lan966x_fdma_pci_change_mtu(struct lan966x *lan966x)
{
	int max_mtu;

	max_mtu = lan966x_fdma_get_max_frame(lan966x);
	if (max_mtu == lan966x->rx.max_mtu)
		return 0;

	return __lan966x_fdma_pci_reload(lan966x, max_mtu);
}

static struct fdma lan966x_fdma_tx = {
	.channel_id = FDMA_INJ_CHANNEL,
	.n_dcbs = 1024,
	.n_dbs = 1,
	.ops = {
		.dataptr_cb = &lan966x_fdma_pci_dataptr_cb,
		.nextptr_cb = &lan966x_fdma_pci_nextptr_cb,
	},
};

static int lan966x_fdma_pci_init(struct lan966x *lan966x)
{
	int err;

	if (!lan966x->fdma)
		return 0;

	/* The data blocks must be placed on 128-byte word aligned addresses in
	 * memory, and their length must be a multiple of 128 bytes.
	 */
	fdma_pci_atu_init(&lan966x->atu, lan966x->regs[TARGET_PCIE_DBI]);

	lan966x->rx.lan966x = lan966x;
	lan966x->rx.fdma->channel_id = FDMA_XTR_CHANNEL;
	lan966x->rx.max_mtu = lan966x_fdma_get_max_frame(lan966x);
	lan966x->tx.lan966x = lan966x;
	lan966x->tx.last_in_use = -1;
	lan966x->tx.fdma = &lan966x_fdma_tx;
	lan966x->tx.fdma->db_size = FDMA_PCI_DB_SIZE(lan966x->rx.max_mtu);
	lan966x->tx.fdma->size = fdma_get_size_contiguous(lan966x->tx.fdma);

	err = lan966x_fdma_pci_rx_alloc(&lan966x->rx);
	if (err)
		return err;

	err = lan966x_fdma_pci_tx_alloc(&lan966x->tx);
	if (err) {
		lan966x_fdma_pci_rx_free(&lan966x->rx);
		return err;
	}

	lan966x_fdma_rx_start(&lan966x->rx);

	return 0;
}

static void lan966x_fdma_pci_deinit(struct lan966x *lan966x)
{
	if (!lan966x->fdma)
		return;

	lan966x_fdma_rx_disable(&lan966x->rx);
	lan966x_fdma_tx_disable(&lan966x->tx);

	napi_synchronize(&lan966x->napi);
	napi_disable(&lan966x->napi);

	lan966x_fdma_pci_rx_free(&lan966x->rx);
	fdma_free_coherent_and_unmap(lan966x->dev, lan966x->tx.fdma);
}

const struct lan966x_match_data lan966x_pci_desc = {
	.ops = {
		.fdma_init = &lan966x_fdma_pci_init,
		.fdma_deinit = &lan966x_fdma_pci_deinit,
		.fdma_xmit = &lan966x_fdma_pci_xmit,
		.fdma_poll = &lan966x_fdma_pci_napi_poll,
		.fdma_mtu = &lan966x_fdma_pci_change_mtu,
		.xdp_setup = &lan966x_xdp_pci_setup,
	},
};
