#!/usr/bin/env python

from bcc import BPF

prog="""
int hello(void *ctx) {
        bpf_trace_printk("Hello, World!\\n");
        return 0;
}
"""

b = BPF(text=prog)
execve_function = b.get_syscall_fnname("execve")
b.attach_kprobe(event=execve_function, fn_name="hello") #do_sys_open

print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "MESSAGE"))
while True:
        try:
                (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        except ValueError:
                continue
        print("%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))
