SRC=$(wildcard *.c)
OBJ=$(SRC:.c=.o)
CFLAGS=-fno-stack-protector 

all: $(SRC) $(OBJ)

$(OBJ): %.o

%.o: %.c
	clang $(CFLAGS) -O2 -D__KERNEL__ -D__ASM_SYSREG_H -Wno-unused-value -Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types -I/home/fab/linux/include -I /home/fab/linux/arch/x86/include/ -emit-llvm -c $< -o - | llc -march=bpf -filetype=obj -o $@

clean:
	rm -rf *.o

.PHONY: %.o
