#!/bin/bash

# mount the bpf FS
mount -t bpf none /sys/fs/bpf

# create a test cgroup2
mkdir /sys/fs/cgroup/unified/test.slice

# loading the program
bpftool prog load ./ebpf_hhf.o /sys/fs/bpf/prog type cgroup/skb

# attaching th program to the egress path of the cgroup FIXME id
bpftool cgroup attach /sys/fs/cgroup/unified/test.slice/ egress id 13 multi

