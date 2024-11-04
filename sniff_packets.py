from scapy.all import sniff

def packet_callback(packet):
    if packet.haslayer("Raw"):
        try:
            data = packet.getlayer("Raw").load.decode('utf-8')
            print(f"Intercepted data: {data}")
        except UnicodeDecodeError:
            pass

# Sniffing packetsad
print("Starting packet capture...")
sniff(iface="eth0", prn=packet_callback, filter="tcp port 80", store=0)