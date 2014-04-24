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

#endif /* _ROCKER_HW_ */
