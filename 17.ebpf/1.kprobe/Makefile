#kernel source
KERNEL_SRC=/usr/src/linux-headers-5.0.0-37-generic

#current directory
PWD = $(shell pwd)

#kernel module
obj-m += kprobe_simple.o

all:
	make -C $(KERNEL_SRC) M=$(PWD) modules
clean:
	rm -f *.ko *.o *.symvers *.cmd *.cmd.o *.mod.* *.order

