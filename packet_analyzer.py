from ast import arg
import subprocess
import sys
import argparse
import textwrap
import copy

from collections import Counter
from prettytable import PrettyTable
from tabulate import tabulate

from scapy.all import *
import pyshark

import pandas as pd

# Define runtime flags
parser = argparse.ArgumentParser()

parser.add_argument("--file", help="PCAP Filename and location")
parser.add_argument("-n", type=int, help="Number of IPs to parse")
parser.add_argument("--dests", help="Top n destination addresses",action="store_true")
parser.add_argument("--sources", help="Top n source addresses", action="store_true")
parser.add_argument("--protocols",help="List network protocols used", action="store_true")
parser.add_argument("--contx", help="List number of successful TCP connections", action="store_true")
parser.add_argument("--top_talkers", help="List the top talkers (src-dest) pairs in a TCP connection", action='store_true')
parser.add_argument("--evasive", help="List suspicious connections", action="store_true")
parser.add_argument("--windows", help="List Windows hosts", action="store_true")

osi_layers = pd.read_csv('osi_layers.csv')

# Extract source and destination IPs
def extractIP(num):
    ip_src = []
    ip_dst = []
    connections = []

    for frame in extraction:
       flag = IP in frame
       if IP in frame:
           ip_src.append(frame[IP].src)
           ip_dst.append(frame[IP].dst)
           
           talk = (frame[IP].src, frame[IP].dst)
           
           connections.append(talk)

    ip_src_x = Counter(ip_src).most_common(num)
    ip_dst_x = Counter(ip_dst).most_common(num)

    talkers = Counter(connections).most_common(num)

    return ip_src_x, ip_dst_x, talkers


# Pretty print IPs
def prettyIPs(liste, kes):
    if(kes):
        keys = "Source"
    else:
        keys = "Destination"
    t = PrettyTable(["IPs", "Frequency"])
    t.title = ("Top " + str(args.n) + " " + keys +" IPs")
    for addr in liste:
        ip_1, cnt = addr
        t.add_row([ip_1, cnt])
    print(t)

# Pretty print top talkers
def prettyTalkers(talking):
    t = PrettyTable(["Talkers", "Frequency"])
    t.title = ("Top " + str(args.n) + " Talkers")
    for talks in talking:
        talk, cnt = talks
        ip_1, ip_2 = talk
        t.add_row([ip_1 + " -> " + ip_2, cnt])
    print(t)


# Pyshark assumes values and is able to parse protocols more effectively here, but significantly slower
def extractProtos(fileN):
    # Make empty protos with 6 layers representing osi model Layer 2+
    with pyshark.FileCapture(fileN) as packet:
        for i, pkt in enumerate(packet):
            try:
                for i, lay in enumerate(pkt.layers):
                    if pkt.layers[i].layer_name in osi_layers.Protocols.values:
                        osi_layers.loc[osi_layers['Protocols'] == pkt.layers[i].layer_name, 'Count'] += 1
            except AttributeError as ex:
                print(ex)
    return osi_layers

def prettyProtos(proto_list):
    layersz = proto_list.loc[~(proto_list['Count'] == 0)].copy(deep=True)
    print(tabulate(layersz, headers='keys', showindex=False, tablefmt='psql'))

def listSuccess():
    # A successful TCP session consists of a SYN from client, SYN-ACK from server (back and forth), ACK from client
    # If you can capture successful SYN-ACK from server -> client, it is indicative of a successful connection
    # as it is in the middle of the two systems sharing information
    cnt = 0
    for pkt in extraction:
        if TCP in pkt:
            if pkt[TCP].flags.SA:
                cnt += 1
    print("Number of successful TCP connections: " + str(cnt))

def listSuspicious(fileN):
    # Pyshark used due to cleaner protocol handling
    # Suspicious HTTP/HTTPS are on non-standard ports of !80/443
    # Assuming is above the transport layer
    suspicious_packets = []
    with pyshark.FileCapture(fileN) as packets:
        for i, pkt in enumerate(packets):
            try:
                if pkt.transport_layer:
                    if ((int(pkt[pkt.transport_layer].srcport) not in osi_layers.Port.values) and (int(pkt[pkt.transport_layer].srcport) not in osi_layers.Alternate.values)) and ((int(pkt[pkt.transport_layer].dstport) not in osi_layers.Port.values) and (int(pkt[pkt.transport_layer].dstport) not in osi_layers.Alternate.values)):
                        suspicious_packets.append(pkt)
            except AttributeError as ex:
                print(ex)
    return suspicious_packets

def displaySuspicious(packets):
    t = PrettyTable(["Addresses", "Protocols"])
    t.title = ("Suspicious Connections")
    for pkt in packets:
        try:
            ip_1 = pkt.ip.src
            ip_2 = pkt.ip.dst
            src_port = pkt[pkt.transport_layer].srcport
            dst_port = pkt[pkt.transport_layer].dstport
            protocol = pkt.highest_layer
            # Removing DATA-TEXT-LINES or whatever from being highest layer
            if 'HTTP' in pkt:
                protocol  = 'HTTP'
        
            t.add_row([ip_1 + ":" + src_port + " -> " + ip_2 + ":" + dst_port, protocol])
        except:
            pass

    print(t)

def troublesomeHTTP(listed):
    t = PrettyTable(["Host/Browser", "URL/Type"])
    t.title = ("Suspicious HTTP Connections")
    t.align = 'l'
    for pkt in listed:
        try:
            if 'HTTP' in pkt:
                    ip_1 = pkt.ip.src
                    ip_2 = pkt.ip.dst
                    src_port = pkt[pkt.transport_layer].srcport
                    dst_port = pkt[pkt.transport_layer].dstport
                    protocol = pkt.highest_layer
                    host = pkt.http.host
                    url = pkt.http.host + pkt.http.request_uri

                    wrapped_url = textwrap.wrap(url, width=40)
                    split_row = ["--" * x for x in [40,8]]
                    t.add_row([ip_1 + ":" + src_port + " -> " + ip_2 + ":" + dst_port, protocol])
                    t.add_row(["HOST: " + host, "On Port: " + dst_port])
                    for i, val in enumerate(wrapped_url):
                        if i == 0:
                            t.add_row(["URL: " + val, "URL"])
                        else:
                            t.add_row([val, "URL"])
                    if pkt.http.user_agent:
                        browser = pkt.http.user_agent
                        wrapped_browser = textwrap.wrap(browser, width=40)
                        for i, brow in enumerate(wrapped_browser):
                            if i == 0 and i != len(wrapped_browser):
                                t.add_row(["BROWSER: " + brow, "BROWSER"])#"TYPE: " + content) 
                            else:
                                t.add_row([brow, "BROWSER"])
                            
                    else:
                        t.add_row(["BROWSER: NOT DETECTED", "BROWSER"])
                        

                    # Cannot parse content_type from packets so ignored...
                    #content = pkt.http.content_type
                    #if pkt.http.content_type:
                    #    t.add_row(["Content type: " + pkt.http.content_type, "TYPE"])

                    t.add_row(["-----------------------------------------------","----------------"])
        except:
            pass
    print(t)

def findWindows(fileN):
    windowMachine = []
    dhcp_ips = []
    dhcp_hostnames = []
    dhcp_workgroups  = []
    t = PrettyTable(["Windows Hosts"])
    t.align = 'l'
    with pyshark.FileCapture(fileN) as packets:
        for pkt in packets:
            try:
                if ('dhcp' in pkt) and (pkt.dhcp.option_hostname not in dhcp_hostnames):
                    if pkt.ip.src == '0.0.0.0':
                        dhcp_ips.append(pkt.dhcp.option_requested_ip_address)
                    else:
                        dhcp_ips.append(pkt.ip.src)
                    dhcp_hostnames.append(pkt.dhcp.option_hostname)
                    # Assume domain name is synonymous with Windows Workgroup (not sure)
                    dhcp_workgroups.append(pkt.dhcp.option_netbios_over_tcpip_name_server)
                elif 'http' in pkt:
                    if 'Windows' in pkt.http.user_agent and pkt.ip.src not in windowMachine:
                        windowMachine.append(pkt.ip.src)
                        t.add_row(["IP Address: " + pkt.ip.src])
                        t.add_row(["MAC Address: " + pkt.eth.src])
                        if 'NT 5.1' in pkt.http.user_agent:
                            t.add_row(["OS: Windows XP"])
                        elif 'NT 6.0' in pkt.http.user_agent:
                            t.add_row(["OS: Windows Vista"])
                        elif 'NT 6.1' in pkt.http.user_agent:
                            t.add_row(["OS: Windows 7"])
                        elif 'NT 6.2' in pkt.http.user_agent:
                            t.add_row(["OS: Windows 8"])
                        elif 'NT 6.3' in pkt.http.user_agent:
                            t.add_row(["OS: Windows 8.1"])
                        elif 'NT 10.0' in pkt.http.user_agent:
                            t.add_row(["OS: Windows 10"])
                        else:
                            t.add_row(["OS: UNKNOWN"])

                        for i,val in enumerate(dhcp_ips):
                            if val == pkt.ip.src:
                                hostname = dhcp_hostnames[i]
                                t.add_row(["Hostname: " + hostname])
                                # Not working...
                                #t.add_row(["Workgroup: " + dhcp_workgroups[i]])
                        t.add_row(['--------------------------------'])
            except:
                pass
    print(t)

# Main run area
args = parser.parse_args()
extraction = rdpcap(args.file)

if args.sources or args.dests:
    srcs, dests, talkers = extractIP(args.n)
    if(args.sources):
        prettyIPs(srcs, True)
    if(args.dests):
        prettyIPs(dests, False)

if(args.protocols):
    protosa = extractProtos(args.file)
    prettyProtos(protosa)

if(args.contx):
    listSuccess()

if(args.top_talkers):
    srcs, dests, talkers = extractIP(args.n)
    prettyTalkers(talkers)

if(args.evasive):
    packets = listSuspicious(args.file)
    displaySuspicious(packets)
    troublesomeHTTP(packets)

if(args.windows):
    findWindows(args.file)

    