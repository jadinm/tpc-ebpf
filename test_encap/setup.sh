#!/bin/bash

set -e

sh TestBPFEncap.topo.sh
ip netns exec a tc qdisc add dev a-0 root fq
ip netns exec a tc qdisc add dev a-0 clsact
ip netns exec a tc filter add dev a-0 egress bpf da obj bpf_seg6_encap_test.o sec encap_srh
ip netns exec a ping6 -m 42 fc00:2:0:6::1 -c 5 -w 6

if [[ $? -eq 0 ]]; then
	echo "Success."
else
	echo "Failure."
fi

set +e

ip netns del a
ip netns del b
ip netns del c
ip netns del d
ip netns del e
ip netns del f
