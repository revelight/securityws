
# == Definitions
TARGET = firewall
# SRCS = hw2secws.c
# OBJS = $(SRCS:.c=.o)
OBJS = \
fw.o \
env_kernel.o env_program.o env_err_tools_kernel.o \
fw_standards.o net_netfilter_handler.o \
cd_chardevices_env.o cd_chardevices_handler.o cd_logs.o cd_rules.o cd_conntab.o \
fw_traffic_man.o fw_rules.o \
fw_logs_env.o fw_logs.o fw_logs_datastruct_filo_circarray.o \
fw_conntable.o \
fw_filter_stateless.o fw_filter_ids.o fw_filter_stateful.o \
fw_userclient_protocol.o


# == Kbuild Targets
# add relevant files in dir to "kbuild" "obj-m" var
# kbuild will search for targets accordingly
obj-m += $(TARGET).o
#obj-m += hw2secws.o


# == Kbuild c standard
ccflags-y := -std=gnu99 -Wno-declaration-after-statement


# == Module 
# enable other than sourcefile kernel module name 
 $(TARGET)-y = $(OBJS)
#secwsmodule-y = hw2secws.o


# == Make 
#  target: modules, default to build ext modules
#  option: M=$(PWD) M tells kbuild we are building an ext module, 
#          given abs path to location of this Makefile 
#  option: -C <path> path for kernel source, using $() for kernel version 
#

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
