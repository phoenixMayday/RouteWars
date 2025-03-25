#!/bin/bash

# 1. Create network namespaces
sudo ip netns add ns1
sudo ip netns add ns2

# 2. Create virtual ethernet (veth) pairs
sudo ip link add veth0 type veth peer name veth1

# 3. Assign the veths to namespaces
sudo ip link set veth0 netns ns1
sudo ip link set veth1 netns ns2

# 4. Assign IPs and bring up interfaces
sudo ip netns exec ns1 ip addr add 192.168.1.1/24 dev veth0
sudo ip netns exec ns2 ip addr add 192.168.1.2/24 dev veth1

sudo ip netns exec ns1 ip link set veth0 up
sudo ip netns exec ns2 ip link set veth1 up

sudo ip netns exec ns1 ip link set lo up
sudo ip netns exec ns2 ip link set lo up

# 5. Set up input rule
sudo ip netns exec ns2 iptables -A INPUT -j ACCEPT 
sudo ip netns exec ns2 iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
