# 1. Create Network Namespaces
sudo ip netns add ns1
sudo ip netns add ns2
sudo ip netns add router

# 2. Create virtual ethernet (veth) pairs
sudo ip link add veth0 type veth peer name veth0-rtr
sudo ip link add veth1 type veth peer name veth1-rtr

# 3. Assign the veths to namespaces
sudo ip link set veth0 netns ns1
sudo ip link set veth1 netns ns2

sudo ip link set veth0-rtr netns router
sudo ip link set veth1-rtr netns router

# 4. Assign IPs and bring up interfaces
sudo ip netns exec ns1 ip addr add 192.168.1.1/24 dev veth0
sudo ip netns exec ns2 ip addr add 192.168.2.1/24 dev veth1
sudo ip netns exec router ip addr add 192.168.1.100/24 dev veth0-rtr
sudo ip netns exec router ip addr add 192.168.2.100/24 dev veth1-rtr

sudo ip netns exec ns1 ip link set veth0 up
sudo ip netns exec ns2 ip link set veth1 up
sudo ip netns exec router ip link set veth0-rtr up
sudo ip netns exec router ip link set veth1-rtr up

sudo ip netns exec ns1 ip link set lo up
sudo ip netns exec ns2 ip link set lo up

# 5. Update default routes in namespaces
sudo ip netns exec ns1 ip route add default via 192.168.1.100 dev veth0
#sudo ip netns exec ns2 ip route add default via 192.168.2.100 dev veth1 #not needed maybe?

# 6. Set up forwarding rules
sudo ip netns exec router iptables -A FORWARD -i veth0-rtr -o veth1-rtr -j NFQUEUE --queue-num 0
sudo ip netns exec router iptables -A FORWARD -i veth1-rtr -o veth0-rtr -m state --state ESTABLISHED,RELATED -j NFQUEUE --queue-num 0
