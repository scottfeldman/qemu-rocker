/*
 * Rocker switch hardware register and descriptor definitions.
 *
 * Copyright (c) 2014 Scott Feldman <sfeldma@cumulusnetworks.com>
 *
 * This header file should be sharable between rocker device model
 * in qemu and the rocker Linux kernel driver.  As such, it comforms
 * to the Linux style-guide.
 *
 */

#ifndef _ROCKER_HW_
#define _ROCKER_HW_

/*
 * PCI configuration space
 */

/* not in pci_ids.h because rocker switch is a fictitious device */
#define PCI_VENDOR_ID_ROCKER		0x0666
#define PCI_DEVICE_ID_ROCKER		0x0001

#define ROCKER_PCI_REVISION		0x1
#define ROCKER_PCI_CLASS		PCI_CLASS_NETWORK_OTHER
#define ROCKER_PCI_SUBSYSTEM_VENDOR_ID	0x0000
#define ROCKER_PCI_SUBSYSTEM_ID		0x0000

#define ROCKER_PCI_INTERRUPT_PIN	1 /* interrupt pin A */

#define ROCKER_PCI_BAR0_SIZE		0x1000

/*
 * Rocker IRQ register offsets
 */
#define ROCKER_IRQ_MASK	0x0010
#define ROCKER_IRQ_STAT	0x0014

/*
 * Rocker IRQ status bits
 */
#define IRQ_LINK		(1 << 0)
#define IRQ_TX_DMA_DONE		(1 << 1)
#define IRQ_RX_DMA_DONE		(1 << 2)
#define IRQ_CMD_DMA_DONe	(1 << 3)
#define IRQ_EVENT_DMA_DONE	(1 << 5)

/*
 * Rocker DMA ring register offsets
 */
#define DMA_DESC_ADDR(x)		(0x0100 + (x) * 16)
#define DMA_COMP_ADDR(x)		(0x0108 + (x) * 16)
#define DMA_DESC_SIZE(x)		(0x0110 + (x) * 16)
#define DMA_DESC_HEAD(x)		(0x0114 + (x) * 16)
#define DMA_DESC_TAIL(x)		(0x0118 + (x) * 16)
#define DMA_DESC_CTRL(x)		(0x011c + (x) * 16)

#define ROCKER_DMA_RING_REG_SET(name, index) \
enum {\
	name ## _DMA_DESC_ADDR = DMA_DESC_ADDR(index),\
	name ## _DMA_COMP_ADDR = DMA_COMP_ADDR(index),\
	name ## _DMA_DESC_SIZE = DMA_DESC_SIZE(index),\
	name ## _DMA_DESC_HEAD = DMA_DESC_HEAD(index),\
	name ## _DMA_DESC_TAIL = DMA_DESC_TAIL(index),\
	name ## _DMA_DESC_CTRL = DMA_DESC_CTRL(index),\
}

ROCKER_DMA_RING_REG_SET(TX, 0);
ROCKER_DMA_RING_REG_SET(RX, 1);
ROCKER_DMA_RING_REG_SET(CMD, 2);
ROCKER_DMA_RING_REG_SET(EVENT, 3);

/*
 * Rocker DMA Descriptor and completion structs
 */
struct rocker_dma_tlv {
	uint32_t type;
	uint16_t len;
	uint8_t val[0] __attribute__((aligned(8)));
} __attribute__((packed, aligned (8)));

struct rocker_dma_desc {
	uint64_t buf_addr;
	uint64_t cookie;
	uint16_t buf_size;
} __attribute__((packed, aligned (8)));

struct rocker_comp_desc {
	struct rocker_dma_desc desc;
	uint64_t cookie_gen;
	uint16_t comp_written;
	uint16_t comp_status;
} __attribute__((packed, aligned(8)));

#endif /* _ROCKER_HW_ */
