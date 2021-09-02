#include<linux/module.h>
#include<linux/version.h>
#include<linux/kernel.h>
#include<linux/init.h>
#include<linux/kprobes.h>
#include<net/ip.h>

MODULE_LICENSE("GPL");
MODULE_ALIAS("kprobe_simple");

//Bringing this back just so that this can compile and I can see things.
//export 函数可外连，就能被检测
#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]

#define NIPQUAD_FMT "%u.%u.%u.%u"

static struct kprobe kp = {
	.symbol_name = "ip_rcv",//被探测函数的名字
};

/* kprobe pre_handler: called just before the probed instruction is executed */
static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
        printk(KERN_INFO "pre_handler: p->addr = 0x%p, ip = %lx,"
                        " flags = 0x%lx\n",
                p->addr, regs->ip, regs->flags);

        /* A dump_stack() here will give a stack backtrace */

	//dump_stack(); //above is proven :-)

        return 0;
}

/* kprobe post_handler: called after the probed instruction is executed */
static void handler_post(struct kprobe *p, struct pt_regs *regs,
                                unsigned long flags)
{
        printk(KERN_INFO "post_handler: p->addr = 0x%p, flags = 0x%lx\n",
                p->addr, regs->flags);
}

/*
 * fault_handler: this is called if an exception is generated for any
 * instruction within the pre- or post-handler, or when Kprobes
 * single-steps the probed instruction.
 */
static int handler_fault(struct kprobe *p, struct pt_regs *regs, int trapnr)
{
        printk(KERN_INFO "fault_handler: p->addr = 0x%p, trap #%dn",
                p->addr, trapnr);
        /* Return 0 because we don't handle the fault. */
        return 0;
}

static int __init myinit(void)
{

    int ret;

    printk("module inserted\n ");

    //my_probe.kp.addr = (kprobe_opcode_t *)0xffffffff81570830;
    //cat /proc/kallsyms | grep ip_rcv gets you ffffffff8156b770 T ip_rcv

    kp.pre_handler = handler_pre;
    kp.post_handler = handler_post;
    kp.fault_handler = handler_fault;

    ret = register_kprobe(&kp);
    if (ret < 0) {
    	printk(KERN_INFO "register_kprobe failed, returned %d\n", ret);
    	return ret;
    }

    printk(KERN_INFO "Planted kprobe at %p\n", kp.addr);
    return 0;
}

static void __exit myexit(void)
{
    unregister_kprobe(&kp);

    printk(KERN_INFO "kprobe at %p unregistered\n", kp.addr);

    printk("module removed\n ");
}


module_init(myinit);
module_exit(myexit);
