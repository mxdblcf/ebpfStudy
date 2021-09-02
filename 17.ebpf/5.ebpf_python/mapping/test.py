#!/usr/bin/env python

from bcc import BPF
from time import sleep

bpf_text = """
BPF_TABLE("array",u32,u32,stats,1);
int hello_world(void *ctx) {
 u32 key=0,value=0,*val;
 val=stats.lookup_or_init(&key,&value);
 lock_xadd(val,1);
 return 0;
};
"""
b = BPF(text=bpf_text)

stats_map=b.get_table("stats")
execve_function = b.get_syscall_fnname("execve")
b.attach_kprobe(event=execve_function, fn_name="hello_world")

while True:
	stats_map[stats_map.Key(0)]=stats_map.Leaf(0)
	sleep(1)
	print("Total sys_clone per second =",stats_map[stats_map.Key(0)].value)
