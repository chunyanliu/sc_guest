/*
 * sc_guest.c
 *
 * Secure container with EPT isolation
 *
 * Copyright (C) 2017 Huawei Technologies Co., Ltd.
 * Copyright (C) 2017 Intel Corporation
 *
 * Authors:
 *   Chunyan Liu <liuchunyan9@huawei.com>
 *   Jason CJ Chen <jason.cj.chen@intel.com>
 *   Liu, Jingqi <jingqi.liu@intel.com>
 *   Ye, Weize <weize.ye@intel.com>
 *   Gu, jixing <jixing.gu@intel.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <asm/sections.h>
#include <linux/slab.h>
#include <asm/vdso.h>
#include <asm/vvar.h>
#include <linux/percpu.h>
#include <asm/e820.h>
#include <linux/bitmap.h>
#include <linux/cpumask.h>
#include <linux/kvm_para.h>
#include <asm/pgtable.h>
#include <linux/bootmem.h>
#include <linux/sched.h>
#include <asm/current.h>
#include <linux/ptrace.h>
#include <linux/mm.h>

#include <asm/sc_guest.h>

int sc_guest_free_pages(struct page *page, int numpages)
{
	struct free_page_cfg cfg;
	int ret = 0;

	cfg.start_gfn = page_to_pfn(page);
	cfg.numpages = numpages;
	ret = kvm_hypercall3(KVM_HC_SC, HC_SET_FREED_PAGE, (unsigned long)__pa(&cfg), sizeof(cfg));

	return ret;
}
EXPORT_SYMBOL_GPL(sc_guest_free_pages);

bool sc_guest_is_in_sc(void)
{
	return current->ept_viewid != 0;
}
EXPORT_SYMBOL_GPL(sc_guest_is_in_sc);

int sc_guest_create_ept_view(unsigned long clusterid)
{
	struct view_cfg cfg;
	struct page *page;
	struct pt_regs *regs = current_pt_regs();
	int ret;

	ret = get_user_pages_fast(regs->ip, 1, 0, &page);
	if (ret < 0) {
		printk(KERN_ERR "SC_GUEST: cannot setup first page for create view. ret = %d\n", ret);
		return ret;
	}

	cfg.first_pfn = page_to_pfn(page);
	cfg.enable_cluster = (clusterid != 0) ? 1 : 0;
	cfg.cluster_id = clusterid;

	return kvm_hypercall3(KVM_HC_SC, HC_CREATE_VIEW, (unsigned long)__pa(&cfg), sizeof(cfg));
}
EXPORT_SYMBOL_GPL(sc_guest_create_ept_view);

static int __init sc_guest_init(void)
{
	struct sc_cfg cfg;
	const struct vdso_image *image = &vdso_image_64;
	int i = 0;
	int ret;

	memset(&cfg, 0, sizeof(struct sc_cfg));
	if (sizeof(long) == 4)
		cfg.is_x32 = 1;

	cfg.total_npages = max_pfn;

	cfg.kernel_text_start = __pa(_stext);
	cfg.kernel_text_end = __pa(_etext);

	BUG_ON(image->size % PAGE_SIZE != 0);
	cfg.vdso_start = __pa(image->data);
	cfg.vdso_end = __pa(image->data + image->size);
	cfg.vvar_start = __pa_symbol(&__vvar_page);
	cfg.vvar_end = __pa_symbol(&__vvar_page + PAGE_SIZE);

	cfg.zero_start = __pa_symbol(empty_zero_page);
	cfg.zero_end = __pa_symbol(empty_zero_page  + PAGE_SIZE);

	cfg.user_vrange_max = TASK_SIZE_MAX;
	cfg.kernel_vrange_start = __START_KERNEL_map;
	cfg.kernel_vrange_end = MODULES_VADDR;
	cfg.module_vrange_start = MODULES_VADDR;
	cfg.module_vrange_end = MODULES_END;

	cfg.task_cfg.smp_cpu = nr_cpu_ids;
	cfg.task_cfg.task_size = sizeof(struct task_struct);
	cfg.task_cfg.task2pid_off = offsetof(struct task_struct, pid);
	cfg.task_cfg.task2viewid_off = offsetof(struct task_struct, ept_viewid);
	cfg.task_cfg.task2comm_off = offsetof(struct task_struct, comm);
	cfg.task_cfg.task2thread_off = offsetof(struct task_struct, thread);
	for_each_possible_cpu(i) {
		if (unlikely(i >= MAX_CPU)) {
			printk(KERN_ERR "SC_GUEST: cpu number exceeds MAX_CPU\n");
			return -1;
		}
		cfg.task_cfg.percpu_task[i] = (uint64_t)__pa(&per_cpu(current_task, i));
	}

	cfg.pv_cfg.phys_base = phys_base;
	cfg.pv_cfg.start_kernel_map = __START_KERNEL_map;
	cfg.pv_cfg.page_offset = PAGE_OFFSET;
	cfg.erase_freed_page = 0;
	printk(KERN_INFO "SC_GUEST: init sc with below parameters:\n"
			"is_x32: %u\n"
			"total_npages: %lu\n"
			"kernel_text_start: 0x%lx\n"
			"kernel_text_end: 0x%lx\n"
			"vdso_start: 0x%lx\n"
			"vdso_end: 0x%lx\n"
			"vvar_start: 0x%lx\n"
			"vvar_end: 0x%lx\n"
			"zero_start: 0x%lx\n"
			"zero_end: 0x%lx\n"
			"user_vrange_max: 0x%lx\n"
			"kernel_vrange_start: 0x%lx\n"
			"kernel_vrange_end: 0x%lx\n"
			"module_vrange_start: 0x%lx\n"
			"module_vrange_end: 0x%lx\n"
			"task:\n"
			"\t smp_cpu: %u\n"
			"\t percpu_task[0]: 0x%lx\n"
			"\t task_size: %u\n"
			"\t task2pid_off: %u\n"
			"\t task2viewid_off: %u\n"
			"\t task2viewid_comm: %u\n"
			"pv:\n"
			"\t phys_base: 0x%lx\n"
			"\t start_kernel_map: 0x%lx\n"
			"\t page_offset: 0x%lx\n"
			"erase_freed_page: %u\n",
			cfg.is_x32,
			(unsigned long)cfg.total_npages,
			(unsigned long)cfg.kernel_text_start,
			(unsigned long)cfg.kernel_text_end,
			(unsigned long)cfg.vdso_start,
			(unsigned long)cfg.vdso_end,
			(unsigned long)cfg.vvar_start,
			(unsigned long)cfg.vvar_end,
			(unsigned long)cfg.zero_start,
			(unsigned long)cfg.zero_end,
			(unsigned long)cfg.user_vrange_max,
			(unsigned long)cfg.kernel_vrange_start,
			(unsigned long)cfg.kernel_vrange_end,
			(unsigned long)cfg.module_vrange_start,
			(unsigned long)cfg.module_vrange_end,
			cfg.task_cfg.smp_cpu,
			(unsigned long)cfg.task_cfg.percpu_task[0],
			cfg.task_cfg.task_size,
			cfg.task_cfg.task2pid_off,
			cfg.task_cfg.task2viewid_off,
			cfg.task_cfg.task2comm_off,
			(unsigned long)cfg.pv_cfg.phys_base,
			(unsigned long)cfg.pv_cfg.start_kernel_map,
			(unsigned long)cfg.pv_cfg.page_offset,
			cfg.erase_freed_page);

	ret = kvm_hypercall3(KVM_HC_SC, HC_INIT_SC, (unsigned long)__pa(&cfg), sizeof(cfg));
	if (ret) {
		printk(KERN_ERR "SC_GUEST: HC_INIT_SC failed\n");
		return -1;
	}

	return 0;
}

postcore_initcall(sc_guest_init);
