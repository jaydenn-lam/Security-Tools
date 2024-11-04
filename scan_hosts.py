from scapy.all import ARP, Ether, srp
import ipaddress

def scan_network(target_network="192.168.0.0/24"):
    # Convert target network to IP range
    ip_network = ipaddress.ip_network(target_network, strict=False)
    
    # Create ARP request packet
    arp_request = ARP(pdst=str(ip_network))
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    
    # Send request and receive responses
    answered, unanswered = srp(arp_request_broadcast, timeout=1, verbose=False)
    
    devices = []
    for sent, received in answered:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    
    return devices

# Run the scan and print results
devices = scan_network()
print("Devices found on the network:")
for device in devices:
    print(f"IP: {device['ip']} - MAC: {device['mac']}")