/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corp.
 */

#include <zephyr/kernel.h>
#include <zephyr/arch/x86/acpi.h>

static void vtd_dev_scope_info(struct acpi_dmar_dev_scope *dev_scope)
{
	struct acpi_dmar_dev_path *path;
	uint16_t id;
	int n_path;

	printk("\t\t\t. Type: ");

	switch (dev_scope->type) {
	case ACPI_DRHD_DEV_SCOPE_PCI_EPD:
		printk("PCI Endpoint");
		break;
	case ACPI_DRHD_DEV_SCOPE_PCI_SUB_H:
		printk("PCI Sub-hierarchy");
		break;
	case ACPI_DRHD_DEV_SCOPE_IOAPIC:
		printk("IOAPIC");
		break;
	case ACPI_DRHD_DEV_SCOPE_MSI_CAP_HPET:
		printk("MSI Capable HPET");
		break;
	case ACPI_DRHD_DEV_SCOPE_NAMESPACE_DEV:
		printk("ACPI name-space enumerated");
		break;
	default:
		printk("unknown\n");
		return;
	}

	id = z_acpi_get_dev_id_from_dmar(dev_scope->type);
	if (id != USHRT_MAX) {
		printk(" ID 0x%x", id);
	}

	printk("\n");

	printk("\t\t\t. Enumeration ID %u\n", dev_scope->enumeration_id);
	printk("\t\t\t. PCI Bus %u\n", dev_scope->start_bus_num);

	path = z_acpi_get_dev_scope_paths(dev_scope, &n_path);
	for (; n_path > 0; n_path--) {
		printk("\t\t\t. Path D:%u F:%u\n",
		       path->device, path->function);
		path = (struct acpi_dmar_dev_path *)(POINTER_TO_UINT(path) +
						     ACPI_DMAR_DEV_PATH_SIZE);
	}

	printk("\n");
}

static void vtd_drhd_info(struct acpi_drhd *drhd)
{
	struct acpi_dmar_dev_scope *dev_scope;
	int n_ds, i;

	if (drhd->flags & ACPI_DRHD_FLAG_INCLUDE_PCI_ALL) {
		printk("\t\t- Includes all PCI devices");
	} else {
		printk("\t\t- Includes only listed PCI devices");
	}

	printk(" under given Segment\n");

	printk("\t\t- Segment number %u\n", drhd->segment_num);
	printk("\t\t- Base Address 0x%llx\n", drhd->base_address);

	dev_scope = z_acpi_get_drhd_dev_scopes(drhd, &n_ds);
	if (dev_scope == NULL) {
		printk("\t\t- No device scopes\n");
		return;
	}

	printk("\t\t- Device Scopes:\n");
	for (i = 0; i < n_ds; i++) {
		vtd_dev_scope_info(dev_scope);
		dev_scope = (struct acpi_dmar_dev_scope *)(
			POINTER_TO_UINT(dev_scope) + dev_scope->length);
	}

	printk("\n");
}

static void vtd_info(void)
{
	struct acpi_dmar *dmar;

	dmar = z_acpi_find_dmar();
	if (dmar == NULL) {
		printk("\tIntel VT-D not supported or exposed\n");
		return;
	}

	printk("\tIntel VT-D Supported:\n");

	printk("\t-> X2APIC ");
	if (dmar->flags & ACPI_DMAR_FLAG_X2APIC_OPT_OUT) {
		printk("should be opted out\n");
	} else {
		printk("does not need to be opted out\n");
	}

	if (dmar->flags & ACPI_DMAR_FLAG_INTR_REMAP) {
		struct acpi_drhd *drhd;
		int hw_n, i;

		printk("\t-> Interrupt remapping supported\n");

		drhd = z_acpi_find_drhds(&hw_n);
		printk("\t-> %u remapping hardware found:\n", hw_n);

		for (i = 0; i < hw_n; i++) {
			printk("\t\tDRHD %u:\n", i);
			vtd_drhd_info(drhd);
			drhd = (struct acpi_drhd *)(POINTER_TO_UINT(drhd) +
						    drhd->entry.length);
		}
	} else {
		printk("\t-> Interrupt remapping not supported\n");
	}
}

static void ioapic_info(struct acpi_madt *madt)
{
	uintptr_t base = POINTER_TO_UINT(madt);
	uintptr_t offset;

	offset = POINTER_TO_UINT(madt->entries) - base;
	while (offset < madt->sdt.length) {
		struct acpi_madt_entry *entry;

		entry = (struct acpi_madt_entry *)(offset + base);
		if (entry->type == ACPI_MADT_ENTRY_IOAPIC) {
			struct acpi_ioapic *ioapic =
				(struct acpi_ioapic *)entry;

			printk("I/O APIC ID %u found at 0x%X handling "
			       "interrupt starting at %u\n",
			       ioapic->id, ioapic->addr, ioapic->gsi_number);
		}

		offset += entry->length;
	}
}

static void loapic_info(struct acpi_madt *madt)
{
	uintptr_t base = POINTER_TO_UINT(madt);
	uintptr_t offset;

	printk("Local APIC address 0x%x\n", madt->loapic);

	offset = POINTER_TO_UINT(madt->entries) - base;
	while (offset < madt->sdt.length) {
		struct acpi_madt_entry *entry;

		entry = (struct acpi_madt_entry *)(offset + base);
		if (entry->type == ACPI_MADT_ENTRY_LOAPIC_ADDR_OVRD) {
			struct acpi_loapic_addr_ovrd *loapic_addr =
				(struct acpi_loapic_addr_ovrd *)entry;

			printk("Local APIC address override 0x%llx\n",
			       loapic_addr->addr);
			break;
		}

		offset += entry->length;
	}

	offset = POINTER_TO_UINT(madt->entries) - base;
	while (offset < madt->sdt.length) {
		struct acpi_madt_entry *entry;

		entry = (struct acpi_madt_entry *)(offset + base);
		if (entry->type == ACPI_MADT_ENTRY_X2APIC) {
			struct acpi_loapic_nmi *nmi =
				(struct acpi_loapic_nmi *)entry;

			printk("Local API NMI: applying on processor "
			       "ACPI ID 0x%x, LINT %u\n",
			       nmi->acpi_id, nmi->loapic_lint);
		}

		offset += entry->length;
	}
}

static void x2apic_info(struct acpi_madt *madt)
{
	uintptr_t base = POINTER_TO_UINT(madt);
	uintptr_t offset;

	offset = POINTER_TO_UINT(madt->entries) - base;
	while (offset < madt->sdt.length) {
		struct acpi_madt_entry *entry;

		entry = (struct acpi_madt_entry *)(offset + base);
		if (entry->type == ACPI_MADT_ENTRY_X2APIC) {
			struct acpi_x2apic *x2apic =
				(struct acpi_x2apic *)entry;

			printk("X2APIC ID %u (ACPI UID %llu)\n",
			       x2apic->id, x2apic->acpi_uid);
		}

		offset += entry->length;
	}

	offset = POINTER_TO_UINT(madt->entries) - base;
	while (offset < madt->sdt.length) {
		struct acpi_madt_entry *entry;

		entry = (struct acpi_madt_entry *)(offset + base);
		if (entry->type == ACPI_MADT_ENTRY_X2APIC) {
			struct acpi_x2apic_nmi *nmi =
				(struct acpi_x2apic_nmi *)entry;

			printk("X2APIC API NMI: applying on processor "
			       "ACPI UID 0x%llx, LINT %u\n",
			       nmi->acpi_uid, nmi->loapic_lint);

		}

		offset += entry->length;
	}
}

static void irq_src_override_info(struct acpi_madt *madt)
{
	uintptr_t base = POINTER_TO_UINT(madt);
	uintptr_t offset;
	int n = 0;

	offset = POINTER_TO_UINT(madt->entries) - base;
	while (offset < madt->sdt.length) {
		struct acpi_madt_entry *entry;

		entry = (struct acpi_madt_entry *)(offset + base);
		if (entry->type == ACPI_MADT_ENTRY_INT_SRC_OVRD) {
			struct acpi_int_src_ovrd *irq_ovrd =
				(struct acpi_int_src_ovrd *)entry;

			if (n == 0) {
				printk("Interrupt Source override table:\n");
				printk("Bus\tIRQ Pin\t\tIOAPIC Pin\n"
				       "----------------------------------\n");
			}

			printk("%u\t%u\t\t%u\n",
			       irq_ovrd->bus, irq_ovrd->irq, irq_ovrd->gsi);

			n++;
		}

		offset += entry->length;
	}
}

static void irq_info(void)
{
	struct acpi_madt *madt = z_acpi_find_table(ACPI_MADT_SIGNATURE);

	if (!madt) {
		printk("No interrupt information\n");
		return;
	}

	ioapic_info(madt);

	printk("\n");

	loapic_info(madt);

	printk("\n");

	x2apic_info(madt);

	printk("\n");

	irq_src_override_info(madt);
}

void acpi(void)
{
	int nr_cpus;

	for (nr_cpus = 0; z_acpi_get_cpu(nr_cpus); ++nr_cpus) {
		/* count number of CPUs present */
	}

	if (nr_cpus == 0) {
		printk("ACPI: no RSDT/MADT found\n\n");
	} else {
		printk("ACPI: %d CPUs found\n", nr_cpus);

		for (int i = 0; i < nr_cpus; ++i) {
			struct acpi_cpu *cpu = z_acpi_get_cpu(i);
			printk("\tCPU #%d: APIC ID 0x%02x\n", i, cpu->apic_id);
		}
	}

	printk("\n");

	irq_info();

	printk("\n");

	vtd_info();

	printk("\n");
}
