#!/usr/bin/env python

from bcc import BPF

bpf_source = """
int trace_bpf_prog_load(void *ctx) {
  char comm[16];
  bpf_get_current_comm(&comm, sizeof(comm));

  bpf_trace_printk("%s is loading a BPF program", comm);
  return 0;
}
"""

bpf = BPF(text = bpf_source)
#/sys/kernel/debug/tracing/events/task/task_newtask
bpf.attach_tracepoint(tp = "task:task_newtask", fn_name = "trace_bpf_prog_load")
bpf.trace_print()
