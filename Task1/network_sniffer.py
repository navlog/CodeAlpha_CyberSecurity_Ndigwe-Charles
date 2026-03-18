from scapy.all import sniff, wrpcap, IP, TCP, UDP, ICMP, Raw

packets = []  # List to store captured packets

def analyze_and_capture(pkt):
    # Append to list for later saving
    packets.append(pkt)
    
    # Only process packets with IP layer (skip pure ARP, etc.)
    if IP in pkt:
        ip_layer = pkt[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto_num = ip_layer.proto
        
        # Map common protocol numbers to names
        if proto_num == 1:
            proto = "ICMP"
        elif proto_num == 6:
            proto = "TCP"
        elif proto_num == 17:
            proto = "UDP"
        else:
            proto = f"Other ({proto_num})"
        
        # Prepare output lines
        output = []
        output.append("═══════════════════════════════════════════════")
        output.append(f"Packet captured at: {pkt.time:.2f}")
        output.append(f"Source IP     : {src_ip}")
        output.append(f"Destination IP: {dst_ip}")
        output.append(f"Protocol      : {proto}")
        
        # Add transport layer details
        if TCP in pkt:
            tcp = pkt[TCP]
            output.append(f"TCP Source Port   : {tcp.sport}")
            output.append(f"TCP Dest Port     : {tcp.dport}")
            output.append(f"TCP Flags         : {tcp.flags}")
        
        elif UDP in pkt:
            udp = pkt[UDP]
            output.append(f"UDP Source Port   : {udp.sport}")
            output.append(f"UDP Dest Port     : {udp.dport}")
        
        elif ICMP in pkt:
            icmp = pkt[ICMP]
            output.append(f"ICMP Type         : {icmp.type}")
            output.append(f"ICMP Code         : {icmp.code}")
        
        # Show payload if present (try as text, otherwise note binary size)
        if Raw in pkt:
            payload = pkt[Raw].load
            try:
                # Decode as UTF-8, ignore errors, limit to first 120 chars
                text_payload = payload.decode('utf-8', errors='ignore').strip()[:120]
                if text_payload:
                    output.append(f"Payload (text)    : {text_payload} ...")
                else:
                    output.append(f"Payload (text)    : [empty or non-printable]")
            except:
                output.append(f"Payload           : Binary/non-text ({len(payload)} bytes)")
        
        # Print the formatted output
        print("\n".join(output))
        print("═══════════════════════════════════════════════\n")

# Start sniffing (adjust interface if needed: eth0, wlan0, en0, etc.)
print("Starting packet capture on eth0... Press Ctrl+C to stop early.")
sniff(iface="eth0", prn=analyze_and_capture, count=200, store=True)

# After capture finishes (or Ctrl+C)
print(f"\nCaptured {len(packets)} packets.")

# Save to pcap file (can open in Wireshark later)
output_file = "network_sniffer_capture.pcap"
wrpcap(output_file, packets)
print(f"Saved to {output_file}")
print("You can now open this .pcap file in Wireshark for deeper visual analysis!")
