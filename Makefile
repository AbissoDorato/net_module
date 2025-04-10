obj-m += fib_info.o

EXTRA_CFLAGS += -std=gnu11

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
