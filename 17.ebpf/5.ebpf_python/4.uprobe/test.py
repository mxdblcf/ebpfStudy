#!/usr/bin/env python

from bcc import BPF
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <uapi/linux/limits.h>
int get_fname(struct pt_regs *ctx) {
 bpf_trace_printk("Hello, World!\\n");
 return 0;
};
"""
b = BPF(text=bpf_text)
b.attach_uprobe(name="c", sym="printf", fn_name="get_fname")

print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "MESSAGE"))
while True:
        try:
                (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        except ValueError:
                continue
        print("%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))

