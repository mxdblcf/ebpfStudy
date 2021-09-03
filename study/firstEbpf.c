//
// Created by mxd on 2021/9/3.
//
#include <linux/bpf.h>
//告诉bpf虚拟机如何用SEC运行程序，当检测到execve系统调用更总店被执行时，bpf程序将执行。
//跟踪点是内核二进制代码中的静态标记，

//clang -O2 -target bpf -c firstEbpf.c -o firstEbpf.o

//我们还需要加载bpf到内核中运行，使用内核帮助函数load_bpf_file ,
#define SEC(NAME) __attribute__((section(NAME),used))

SEC("tracepoint/syscalls/sys_enter_execve")
int bpf_prog(void *ctx){
    char msg[]="hello mxd!";
    //在、sys/kernel/debug/tracing/trace_pipe中能看到代码被打印
            bpf_trace_printk(msg,sizeof(msg));
    return 0;
}
//加入许可证

char  _licence[] SEC("license") = "GPL";