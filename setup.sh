#!/bin/bash

# mount the bpf FS
mount -t bpf none /sys/fs/bpf

mount -o remount,rw /sys/fs/cgroup/
mkdir /sys/fs/cgroup/unified 
mount -t cgroup2 none /sys/fs/cgroup/unified

# create a test cgroup2
mkdir /sys/fs/cgroup/unified/test.slice

# loading the program
./bpftool prog load ./ebpf_hhf.o /sys/fs/bpf/hhf_acc type cgroup/skb
./bpftool prog load ./ebpf_socks_hhf.o /sys/fs/bpf/hhf_socks type sockops 
#./bpftool prog load ./tcp_basertt_kern.o /sys/fs/bpf/prog type sockops 

# attaching th program to the egress path of the cgroup FIXME id
./bpftool cgroup attach /sys/fs/cgroup/unified/test.slice/ egress id 3 multi
#./bpftool cgroup attach /sys/fs/cgroup/unified/test.slice/ sock_ops id 3 multi
./bpftool cgroup attach /sys/fs/cgroup/unified/test.slice/ sock_ops id 6 multi

