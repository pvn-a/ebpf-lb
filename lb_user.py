from bcc import BPF
import socket
import struct
import ctypes

def ip_to_int(ip_str):
    """Convert dotted IP string to a custom format."""
    packed_ip = socket.inet_aton(ip_str)  # Convert to packed binary format
    reversed_ip = struct.unpack("<I", packed_ip)[0]  # Unpack in little-endian order
    return reversed_ip

def mac_to_int(mac_str):
    """Convert MAC address string to a 64-bit integer."""
    mac_parts = mac_str.split(":")
    mac_bytes = bytes(int(part, 16) for part in mac_parts)
    return int.from_bytes(mac_bytes, byteorder="little")

# Load the eBPF program
bpf = BPF(src_file="lb_kern.c")
fn = bpf.load_func("xdp_load_balancer", BPF.XDP)

# Attach the eBPF program to the load balancer interface
iface = "lo" #put lo if lo or use veth-lb
bpf.attach_xdp(dev=iface, fn=fn, flags=0)

# Populate backend IPs
backend_ips = bpf["backend_ips"]
backend_ips[0] = ctypes.c_uint(ip_to_int("172.17.0.2"))  # b1 IP
backend_ips[1] = ctypes.c_uint(ip_to_int("172.17.0.3"))  # b2 IP

# Populate backend MACs
backend_macs = bpf["backend_macs"]
# backend_macs[0] = ctypes.c_ulong(mac_to_int("02:42:ac:11:00:02"))  # b1 MAC
# backend_macs[1] = ctypes.c_ulong(mac_to_int("02:42:ac:11:00:03"))  # b2 MAC
backend_macs[0] = ctypes.c_ulong(mac_to_int("00:00:00:00:00:00"))  # b1 MAC in case of lo
backend_macs[1] = ctypes.c_ulong(mac_to_int("00:00:00:00:00:00"))  # b2 MAC incase of lo

client_lb_ips = bpf["client_lb_ips"]
client_lb_ips[0] = ctypes.c_uint(ip_to_int("172.17.0.4")) #client ip
client_lb_ips[1] = ctypes.c_uint(ip_to_int("172.17.0.5")) #lb ip

# Populate backend MACs
client_lb_macs = bpf["client_lb_macs"]
# client_lb_macs[0] = ctypes.c_ulong(mac_to_int("02:42:ac:11:00:04"))  # client MAC
# client_lb_macs[1] = ctypes.c_ulong(mac_to_int("02:42:ac:11:00:05"))  # lb MAC
client_lb_macs[0] = ctypes.c_ulong(mac_to_int("00:00:00:00:00:00"))  # client MAC incase of lo
client_lb_macs[1] = ctypes.c_ulong(mac_to_int("00:00:00:00:00:00"))  # lb MAC incase of lo

dev_map = bpf["dev_map"]
dev_map[0] = ctypes.c_uint(7) #veth-b1-br
dev_map[1] = ctypes.c_uint(9) #veth-b2-br
dev_map[2] = ctypes.c_uint(3) #veth-client-br


# Initialize round-robin index
rr_index = bpf["rr_index"]
rr_index[0] = ctypes.c_uint(0)  # Round-robin starts at 0

print("eBPF load balancer running. Press Ctrl+C to exit.")
try:
    while True:
        pass
except KeyboardInterrupt:
    print("Detaching program...")
    bpf.remove_xdp(dev=iface, flags=0)





#++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#please use this setup
""" MAIN NETWORK SETUP 1, ALL VETHS IN SAME NAMESPACE, attach to lo, mac addresses all are 00, check for ifindexes

#------------------- TRY 4 ---------

sudo ip netns add lb-ns
sudo ip netns exec lb-ns ip link add br0 type bridge
sudo ip netns exec lb-ns ip link set br0 up

# Client
sudo ip netns exec lb-ns ip link add veth-client type veth peer name veth-client-br
sudo ip netns exec lb-ns ip link set veth-client-br master br0
sudo ip netns exec lb-ns ip link set veth-client up
sudo ip netns exec lb-ns ip link set veth-client-br up

# Load Balancer
sudo ip netns exec lb-ns ip link add veth-lb type veth peer name veth-lb-br
sudo ip netns exec lb-ns ip link set veth-lb-br master br0
sudo ip netns exec lb-ns ip link set veth-lb up
sudo ip netns exec lb-ns ip link set veth-lb-br up

# Backend 1
sudo ip netns exec lb-ns ip link add veth-b1 type veth peer name veth-b1-br
sudo ip netns exec lb-ns ip link set veth-b1-br master br0
sudo ip netns exec lb-ns ip link set veth-b1 up
sudo ip netns exec lb-ns ip link set veth-b1-br up

# Backend 2
sudo ip netns exec lb-ns ip link add veth-b2 type veth peer name veth-b2-br
sudo ip netns exec lb-ns ip link set veth-b2-br master br0
sudo ip netns exec lb-ns ip link set veth-b2 up
sudo ip netns exec lb-ns ip link set veth-b2-br up


# Client
sudo ip netns exec lb-ns ip link set dev veth-client address 02:42:ac:11:00:04
sudo ip netns exec lb-ns ip addr add 172.17.0.4/24 dev veth-client

# LB
sudo ip netns exec lb-ns ip link set dev veth-lb address 02:42:ac:11:00:05
sudo ip netns exec lb-ns ip addr add 172.17.0.5/24 dev veth-lb

# Backend 1
sudo ip netns exec lb-ns ip link set dev veth-b1 address 02:42:ac:11:00:02
sudo ip netns exec lb-ns ip addr add 172.17.0.2/24 dev veth-b1

# Backend 2
sudo ip netns exec lb-ns ip link set dev veth-b2 address 02:42:ac:11:00:03
sudo ip netns exec lb-ns ip addr add 172.17.0.3/24 dev veth-b2


sudo ip netns exec lb-ns ip link set veth-client up
sudo ip netns exec lb-ns ip link set veth-lb up
sudo ip netns exec lb-ns ip link set veth-b1 up
sudo ip netns exec lb-ns ip link set veth-b2 up

sudo ip netns exec lb-ns ip route add default via 172.17.0.5 dev veth-client
sudo ip netns exec lb-ns ip link set lo up

#Cleanup commands
sudo ip netns exec lb-ns ip link del br0
sudo ip netns exec lb-ns ip link del veth-b1
sudo ip netns exec lb-ns ip link del veth-b1-br
sudo ip netns exec lb-ns ip link del veth-b2
sudo ip netns exec lb-ns ip link del veth-b2-br
sudo ip netns exec lb-ns ip link del veth-client
sudo ip netns exec lb-ns ip link del veth-client-br
sudo ip netns del lb-ns

"""