//
// Created by mxd on 2021/9/2.
//

#include <linux/bpf.h>

#define  SEC(NAME) _attribute_((section(NAME),used))

//给elf添加Section信息
SEC("xdp")
int xdp_drop_the_world(struct xdp_md *ctx){

    return XDP_DROP;
}

//许可证声明 , 给 内核看的   ，需要被检验
//程序没有main入口  ，执行入口可以由 elf文件的section指定 在elf的 。text标识下，函数放在这里面
char  _licence[] SEC("license") = "GPL";