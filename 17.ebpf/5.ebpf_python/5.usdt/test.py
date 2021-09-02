#!/usr/bin/env python


import sys
reload(sys)
sys.setdefaultencoding('utf8')

from bcc import BPF, USDT
import sys

bpf_src = """
int trace_udst(struct pt_regs *ctx) {
    u32 idx;
    bpf_usdt_readarg(1, ctx, &idx);
    bpf_trace_printk("test_idx=%d tracepoint cachted\\n", idx);
    return 0;
};
"""
procid = 12925
u = USDT(pid=procid)
u.enable_probe(probe="test_idx", fn_name="trace_udst")

b = BPF(text=bpf_src, usdt_contexts=[u])
print("Start USDT tracing")
b.trace_print()