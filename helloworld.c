#include <linux/syscalls.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("l-a-geller");
MODULE_DESCRIPTION("Linux kernel module printing some kernel structures for educational purposes");
MODULE_VERSION("1.0");

#define PROC_FILE_NAME "os_lab2"
#define BUF_SIZE 256

#define BPF_MESSAGE "bpf_map_memory params:\n pages: %d\n: "

#define PAGE_EXTENDED_MESSAGE "Page virtual adress: 0x%lx, \n" \
			"Page physical adress: 0x%lx, \n" \
			"CONFIG_PGTABLE_LEVELS: %d, \n" \
			"PAGE_SIZE: %ld, \n" \
			"flags: %u l, \n" \
			"refcount: %u \n" 


static struct proc_dir_entry *out;
static char proc_read_buffer[BUF_SIZE];
static bool bpf_selected = false;
static bool page_selected = false;
static struct mutex lock;

static int get_bpf_map_memory(struct bpf_map_memory* mem) {

	struct bpf_insn prog[] = {
		BPF_ALU64_IMM(BPF_MOV, BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	};

	union bpf_attr attr = {0};
	attr.prog_type = BPF_PROG_TYPE_SCHED_CLS;
	attr.insn_cnt = 2;
	attr.insns = (__u64)(unsigned long)(prog);
	attr.license = (__u64)(unsigned long)("");
	attr.key_size = 4;
	attr.value_size = 4;
	attr.max_entries = 1;
	attr.map_flags = 0;

	struct bpf_map mp;
	bpf_map_init_from_attr(&mp, &attr);
	*mem = mp.memory;
}

static unsigned long get_page_phys_addr(unsigned long vaddr, struct page* my_beloved_page) {

    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    unsigned long paddr = 0;
    unsigned long page_addr = 0;
    unsigned long page_offset = 0;

    pgd = pgd_offset(current->mm, vaddr);
    pr_info("pgd_val = 0x%lx\n", pgd_val(*pgd));
    pr_info("pgd_index = %lu\n", pgd_index(vaddr));
    if (pgd_none(*pgd)) {
        pr_notice("Not mapped in pgd\n");
        return -1;
    }

    p4d = p4d_offset(pgd, vaddr);
    pr_info("p4d_val = 0x%lx\n", p4d_val(*p4d));
    pr_info("pgd_index = %lu\n", p4d_index(vaddr));
    if (p4d_none(*p4d) || p4d_bad(*p4d)) {
        pr_notice("Not mapped in p4d\n");
        return -1;
    }

    pud = pud_offset(p4d, vaddr);
    pr_info("pud_val = 0x%lx\n", pud_val(*pud));
    pr_info("pud_index = %lu\n", pud_index(vaddr));
    if (pud_none(*pud)) {
        pr_notice("Not mapped in pud\n");
        return -1;
    }

    pmd = pmd_offset(pud, vaddr);
    pr_info("pmd_val = 0x%lxn", pmd_val(*pmd));
    pr_info("pmd_index = %lun", pmd_index(vaddr));
    if (pmd_none(*pmd)) {
        pr_notice("Not mapped in pmd\n");
        return -1;
    }

    pte = pte_offset_kernel(pmd, vaddr);
    pr_info("pte_val = 0x%lx\n", pte_val(*pte));
    pr_info("pte_index = %lu\n", pte_index(vaddr));
    if (pte_none(*pte)) {
        pr_notice("Not mapped in pte\n");
        return -1;
    }

    page_addr = pte_val(*pte) & PAGE_MASK;
    page_offset = vaddr & ~PAGE_MASK;
    paddr = page_addr | page_offset;
    printk("page_addr = %lx, page_offset = %lx\n", page_addr, page_offset);
    printk("vaddr = %lx, paddr = %lx\n", vaddr, paddr);
    my_beloved_page = pte_page(*pte);
    printk("Page flags = %lx\n", my_beloved_page -> flags);

    return paddr;
}

static void get_page_info(void) {
	unsigned long vaddr = __get_free_page(GFP_KERNEL);
	// Allocate a single page and return a virtual address
        if (vaddr == 0) {
        	pr_notice("__get_free_page failed\n");	
		    sprintf(proc_read_buffer, "__get_free_page failed\n");
        } else {
            struct page my_beloved_page = {0};
            sprintf(proc_read_buffer,
                    PAGE_EXTENDED_MESSAGE,
                    vaddr,
                    get_page_phys_addr(vaddr, &my_beloved_page),
                    CONFIG_PGTABLE_LEVELS,
                    PAGE_SIZE,
                    my_beloved_page.flags,
                    my_beloved_page._refcount.counter
            );
            free_page(vaddr);
	}
}

static ssize_t struct2proc(struct file* filp, char __user* buffer, size_t length, loff_t *offset) {
    mutex_lock(&lock);
    if (*offset > 0) {
        return 0;
    }
    if (length < BUF_SIZE) {
        pr_notice("Not enough buffer size\n");
        return 0;
    }
    if (bpf_selected) {
	    struct bpf_map_memory bpf = {0};
        pr_info("BPF_map_memory requested\n");
	    sprintf(proc_read_buffer, BPF_MESSAGE, bpf.pages);
	    strcat(proc_read_buffer, "\n");
    }
    if (page_selected) {
        pr_info("Page requested\n");
	    get_page_info();
    }
    bpf_selected = false;
    page_selected = false;
    length = strlen(proc_read_buffer) + 1;
    *offset += length;
    if (copy_to_user(buffer, proc_read_buffer, length)) {
        pr_info("Copy_to_user on buffer message failed\n");
        return -EFAULT;
    }
    mutex_unlock(&lock);
    return *offset;
}

static const struct proc_ops proc_file_fops = {
    .proc_read = struct2proc
};


SYSCALL_DEFINE1( helloworld, int, struct_to_print_type ) {
    pr_info("I am... Ghoul.\n");
    if (NULL == out) out = proc_create(PROC_FILE_NAME, 0, NULL, &proc_file_fops);
    if (struct_to_print_type == 0) {
        pr_info("BPF map memory structure selected");
	    bpf_selected = true;
    } else if (struct_to_print_type == 1) {
	    pr_info("Page structure selected");
	    page_selected = true;
    } else {
	    pr_notice("Invalid option selected");
    }
    return 0;
}

