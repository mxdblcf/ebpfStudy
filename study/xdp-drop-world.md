#### 执行
clang -O2 -target bpf -c xdp-drop-world.c -o xdp-drop-world.o

1. 查看生成的elf格式的可执行文件的相关信息
2. 能看到上文提到的Section信息
> readelf -a xdp-drop-world.o

####加载到内核hook点
> ip link set dev [device name] xdp obj xdp-drop-world.o sec [section name]

1. sec [section name]通过Section来指定程序入口
2. device name是本机某个网卡设备的名称
#### 链接到网卡
3. ip link set dev enp0s8 xdp obj xdp-drop-world.o sec xdp verbose

此时就会ping不同网卡地址，因为所有流量都被丢弃

4.卸载这个xdp

> ip link set dev enp0s8 xdp obj xdp-drop-world.o sec xdp verbose

