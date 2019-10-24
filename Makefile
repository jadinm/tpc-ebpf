SRC=$(wildcard *.c)
OBJ=$(SRC:.c=.o)
CFLAGS=-fno-stack-protector 

all: $(SRC) $(OBJ)

$(OBJ): %.o

%.o: %.c
	clang $(CFLAGS) -O1 -D__KERNEL__ -D__ASM_SYSREG_H -Wno-unused-value -Wno-pointer-sign -g \
		-Wno-compare-distinct-pointer-types -I/root/ebpf_hhf_kernel/include -I /root/ebpf_hhf_kernel/arch/x86/include/ -emit-llvm -c $< -o - | llc -march=bpf -filetype=obj -o $@

clean:
	rm -rf *.o

.PHONY: %.o
