# a loop: fc00:2:0:1::1/64
# c loop: fc00:2:0:2::1/64
# b loop: fc00:2:0:3::1/64
# e loop: fc00:2:0:4::1/64
# d loop: fc00:2:0:5::1/64
# f loop: fc00:2:0:6::1/64

ip netns add a
ip netns add c
ip netns add b
ip netns add e
ip netns add d
ip netns add f
ip link add name a-0 type veth peer name b-0
ip link set a-0 netns a
ip link set b-0 netns b
ip link add name b-1 type veth peer name c-0
ip link set b-1 netns b
ip link set c-0 netns c
ip link add name c-1 type veth peer name d-0
ip link set c-1 netns c
ip link set d-0 netns d
ip link add name d-1 type veth peer name e-0
ip link set d-1 netns d
ip link set e-0 netns e
ip link add name e-1 type veth peer name f-0
ip link set e-1 netns e
ip link set f-0 netns f
ip netns exec a bash -c 'ifconfig lo up; ip -6 ad ad fc00:2:0:1::1/64 dev lo; sysctl net.ipv6.conf.all.forwarding=1; sysctl net.ipv6.conf.all.seg6_enabled=1; ifconfig a-0 add fc00:42:0:1::1/64 up; sysctl net.ipv6.conf.a-0.seg6_enabled=1; ip -6 ro ad fc00:2:0:3::1/64 via fc00:42:0:1::2 metric 1 src fc00:2:0:1::1; ip -6 ro ad fc00:2:0:6::1/64 via fc00:42:0:1::2 metric 5 src fc00:2:0:1::1; ip -6 ro ad fc00:2:0:5::1/64 via fc00:42:0:1::2 metric 3 src fc00:2:0:1::1; ip -6 ro ad fc00:2:0:2::1/64 via fc00:42:0:1::2 metric 2 src fc00:2:0:1::1; ip -6 ro ad fc00:2:0:4::1/64 via fc00:42:0:1::2 metric 4 src fc00:2:0:1::1'
ip netns exec c bash -c 'ifconfig lo up; ip -6 ad ad fc00:2:0:2::1/64 dev lo; sysctl net.ipv6.conf.all.forwarding=1; sysctl net.ipv6.conf.all.seg6_enabled=1; ifconfig c-0 add fc00:42:0:2::2/64 up; sysctl net.ipv6.conf.c-0.seg6_enabled=1; ifconfig c-1 add fc00:42:0:3::1/64 up; sysctl net.ipv6.conf.c-1.seg6_enabled=1; ip -6 ro ad fc00:2:0:3::1/64 via fc00:42:0:2::1 metric 1 src fc00:2:0:2::1; ip -6 ro ad fc00:2:0:6::1/64 via fc00:42:0:3::2 metric 3 src fc00:2:0:2::1; ip -6 ro ad fc00:2:0:5::1/64 via fc00:42:0:3::2 metric 1 src fc00:2:0:2::1; ip -6 ro ad fc00:2:0:1::1/64 via fc00:42:0:2::1 metric 2 src fc00:2:0:2::1; ip -6 ro ad fc00:2:0:4::1/64 via fc00:42:0:3::2 metric 2 src fc00:2:0:2::1'
ip netns exec b bash -c 'ifconfig lo up; ip -6 ad ad fc00:2:0:3::1/64 dev lo; sysctl net.ipv6.conf.all.forwarding=1; sysctl net.ipv6.conf.all.seg6_enabled=1; ifconfig b-0 add fc00:42:0:1::2/64 up; sysctl net.ipv6.conf.b-0.seg6_enabled=1; ifconfig b-1 add fc00:42:0:2::1/64 up; sysctl net.ipv6.conf.b-1.seg6_enabled=1; ip -6 ro ad fc00:2:0:6::1/64 via fc00:42:0:2::2 metric 4 src fc00:2:0:3::1; ip -6 ro ad fc00:2:0:5::1/64 via fc00:42:0:2::2 metric 2 src fc00:2:0:3::1; ip -6 ro ad fc00:2:0:2::1/64 via fc00:42:0:2::2 metric 1 src fc00:2:0:3::1; ip -6 ro ad fc00:2:0:1::1/64 via fc00:42:0:1::1 metric 1 src fc00:2:0:3::1; ip -6 ro ad fc00:2:0:4::1/64 via fc00:42:0:2::2 metric 3 src fc00:2:0:3::1'
ip netns exec e bash -c 'ifconfig lo up; ip -6 ad ad fc00:2:0:4::1/64 dev lo; sysctl net.ipv6.conf.all.forwarding=1; sysctl net.ipv6.conf.all.seg6_enabled=1; ifconfig e-0 add fc00:42:0:4::2/64 up; sysctl net.ipv6.conf.e-0.seg6_enabled=1; ifconfig e-1 add fc00:42:0:5::1/64 up; sysctl net.ipv6.conf.e-1.seg6_enabled=1; ip -6 ro ad fc00:2:0:3::1/64 via fc00:42:0:4::1 metric 3 src fc00:2:0:4::1; ip -6 ro ad fc00:2:0:6::1/64 via fc00:42:0:5::2 metric 1 src fc00:2:0:4::1; ip -6 ro ad fc00:2:0:5::1/64 via fc00:42:0:4::1 metric 1 src fc00:2:0:4::1; ip -6 ro ad fc00:2:0:2::1/64 via fc00:42:0:4::1 metric 2 src fc00:2:0:4::1; ip -6 ro ad fc00:2:0:1::1/64 via fc00:42:0:4::1 metric 4 src fc00:2:0:4::1'
ip netns exec d bash -c 'ifconfig lo up; ip -6 ad ad fc00:2:0:5::1/64 dev lo; sysctl net.ipv6.conf.all.forwarding=1; sysctl net.ipv6.conf.all.seg6_enabled=1; ifconfig d-0 add fc00:42:0:3::2/64 up; sysctl net.ipv6.conf.d-0.seg6_enabled=1; ifconfig d-1 add fc00:42:0:4::1/64 up; sysctl net.ipv6.conf.d-1.seg6_enabled=1; ip -6 ro ad fc00:2:0:3::1/64 via fc00:42:0:3::1 metric 2 src fc00:2:0:5::1; ip -6 ro ad fc00:2:0:6::1/64 via fc00:42:0:4::2 metric 2 src fc00:2:0:5::1; ip -6 ro ad fc00:2:0:2::1/64 via fc00:42:0:3::1 metric 1 src fc00:2:0:5::1; ip -6 ro ad fc00:2:0:1::1/64 via fc00:42:0:3::1 metric 3 src fc00:2:0:5::1; ip -6 ro ad fc00:2:0:4::1/64 via fc00:42:0:4::2 metric 1 src fc00:2:0:5::1'
ip netns exec f bash -c 'ifconfig lo up; ip -6 ad ad fc00:2:0:6::1/64 dev lo; sysctl net.ipv6.conf.all.forwarding=1; sysctl net.ipv6.conf.all.seg6_enabled=1; ifconfig f-0 add fc00:42:0:5::2/64 up; sysctl net.ipv6.conf.f-0.seg6_enabled=1; ip -6 ro ad fc00:2:0:3::1/64 via fc00:42:0:5::1 metric 4 src fc00:2:0:6::1; ip -6 ro ad fc00:2:0:5::1/64 via fc00:42:0:5::1 metric 2 src fc00:2:0:6::1; ip -6 ro ad fc00:2:0:2::1/64 via fc00:42:0:5::1 metric 3 src fc00:2:0:6::1; ip -6 ro ad fc00:2:0:1::1/64 via fc00:42:0:5::1 metric 5 src fc00:2:0:6::1; ip -6 ro ad fc00:2:0:4::1/64 via fc00:42:0:5::1 metric 1 src fc00:2:0:6::1'
