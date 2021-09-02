#!/usr/bin/env python
import sys
import signal
from time import sleep

from bcc import BPF


def signal_ignore(signal, frame):
    print()


bpf_source = """
#include <uapi/linux/ptrace.h>

BPF_HASH(cache, u64, u64);
BPF_HISTOGRAM(histogram);

int trace_execve_start(void *ctx) {
  u64 pid = bpf_get_current_pid_tgid();
  u64 start_time_ns = bpf_ktime_get_ns();
  cache.update(&pid, &start_time_ns);
  return 0;
}
"""

bpf_source += """
int trace_execve_return(void *ctx) {
  u64 *start_time_ns, delta;
  u64 pid = bpf_get_current_pid_tgid();
  start_time_ns = cache.lookup(&pid);
  if (start_time_ns == 0)
    return 0;

  delta = bpf_ktime_get_ns() - *start_time_ns;
  histogram.increment(bpf_log2l(delta));
  return 0;
}
"""

bpf = BPF(text=bpf_source)
execve_function = bpf.get_syscall_fnname("execve")
bpf.attach_kprobe(event=execve_function, fn_name="trace_execve_start")
bpf.attach_kretprobe(event=execve_function,
                     fn_name="trace_execve_return")


try:
    sleep(10)
except KeyboardInterrupt:
    signal.signal(signal.SIGINT, signal_ignore)

bpf["histogram"].print_log2_hist("msecs")
