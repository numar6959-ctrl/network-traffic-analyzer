import sys
from collections import Counter
from scapy.all import rdpcap, TCP, UDP, ICMP, IP, DNS, DNSQR

# Check whether the user provided a capture file
if len(sys.argv) != 2:
    print("Usage: python analyzer.py <capture.pcap>")
    sys.exit(1)

# Get the capture file name
pcap_file = sys.argv[1]

# Read the network packets
packets = rdpcap(pcap_file)

# Display the result
print(f"Loaded {len(packets)} packets from {pcap_file}")

# Count different network protocols
protocol_counts = {
    "TCP": 0,
    "UDP": 0,
    "ICMP": 0,
    "Other": 0
}

# Examine each captured packet
for packet in packets:
    if packet.haslayer(TCP):
        protocol_counts["TCP"] += 1
    elif packet.haslayer(UDP):
        protocol_counts["UDP"] += 1
    elif packet.haslayer(ICMP):
        protocol_counts["ICMP"] += 1
    else:
        protocol_counts["Other"] += 1

# Display the results
print("\nProtocol Breakdown:")

for protocol, count in protocol_counts.items():
    print(f"{protocol}: {count}")
# Store the number of packets for each IP address
source_ips = {}
destination_ips = {}

# Examine every packet
for packet in packets:
    if packet.haslayer(IP):

        src = packet[IP].src
        dst = packet[IP].dst

        # Count source IP addresses
        source_ips[src] = source_ips.get(src, 0) + 1

        # Count destination IP addresses
        destination_ips[dst] = destination_ips.get(dst, 0) + 1

# Display source IP addresses
print("\nSource IP Addresses:")

for ip, count in source_ips.items():
    print(f"{ip}: {count} packets")

# Display destination IP addresses
print("\nDestination IP Addresses:")

for ip, count in destination_ips.items():
    print(f"{ip}: {count} packets")

# Count destination TCP and UDP ports
destination_ports = Counter()

# Examine each packet
for packet in packets:

    if packet.haslayer(TCP):
        port = packet[TCP].dport
        destination_ports[("TCP", port)] += 1

    elif packet.haslayer(UDP):
        port = packet[UDP].dport
        destination_ports[("UDP", port)] += 1

# Display the 10 most common destination ports
print("\nTop 10 Destination Ports:")

for (protocol, port), count in destination_ports.most_common(10):
    print(f"{protocol} Port {port}: {count} packets")

# Count DNS queries
dns_queries = Counter()

# Examine each packet
for packet in packets:

    # Check whether the packet contains a DNS query
    if packet.haslayer(DNS) and packet.haslayer(DNSQR):

        # Only examine DNS requests, not responses
        if packet[DNS].qr == 0:

            # Extract the requested domain name
            domain = packet[DNSQR].qname.decode(
                "utf-8", errors="replace"
            ).rstrip(".")

            # Count the domain
            dns_queries[domain] += 1

# Display DNS results
print("\nTop 10 DNS Queries:")

if dns_queries:
    for domain, count in dns_queries.most_common(10):
        print(f"{domain}: {count} queries")
else:
    print("No DNS queries found.")

# Calculate network traffic statistics
total_bytes = sum(len(packet) for packet in packets)

# Calculate average packet size
if len(packets) > 0:
    average_packet_size = total_bytes / len(packets)
else:
    average_packet_size = 0

# Display traffic statistics
print("\nNetwork Traffic Statistics:")
print(f"Total Packets: {len(packets)}")
print(f"Total Bytes: {total_bytes:,}")
print(f"Average Packet Size: {average_packet_size:.2f} bytes")

# Count initial TCP SYN packets
syn_count = 0

# Examine each packet
for packet in packets:

    if packet.haslayer(TCP):

        # Get the TCP flags
        flags = int(packet[TCP].flags)

        # Check for SYN without ACK
        if (flags & 0x02) and not (flags & 0x10):
            syn_count += 1

# Display the results
print("\nTCP Connection Analysis:")
print(f"Initial TCP SYN Packets: {syn_count}")

