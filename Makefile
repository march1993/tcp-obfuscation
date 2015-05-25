obj-m = \
	tcp-obfuscation-ipv4.o \
	tcp-obfuscation-ipv6.o \
	tcp-obfuscation-service.o

KVERSION = $(shell uname -r)

all:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) clean

insmod:
	insmod tcp-obfuscation-service.ko
	insmod tcp-obfuscation-ipv4.ko
	insmod tcp-obfuscation-ipv6.ko

rmmod:
	rmmod tcp-obfuscation-ipv6
	rmmod tcp-obfuscation-ipv4
	rmmod tcp-obfuscation-service
