#!/usr/bin/env python

from scapy.all import conf, sendp, ARP, Ether, ETHER_BROADCAST, IP
from scapy.contrib.igmp import IGMP


class IGMPMembership(object):
    """This thread is used to discover clients on the network by sending IGMP general queries."""

    _IGMP_MULTICAST = "224.0.0.1"
    """str: Multicast address used to send IGMP general queries."""
    _SLEEP = 60
    """int: Time to wait before sending packets anew."""
    _IGMP_GENERAL_QUERY = 0x11
    """int: Value of type Field for IGMP general queries."""
    _TTL = 1
    """int: Value for TTL for IP packet."""

    def __init__(self, gateway, network, ip, src_mac, dst_mac, mrtime):
        """Initialises the thread.
 
        Args:
            gateway (str): The gateway's IP address.
            network (str): The network IP address.
            mac (str): MAC address of this device.
            ip (str): IP address of this device.
 
        """
        self.gateway = gateway
        self.network = network
        self.src_mac = src_mac
        self.ip = ip
        self.dst_mac = dst_mac
        self.mrtime = mrtime

    def run(self):
        """Sends IGMP general query packets using the multicast address 224.0.0.1.
        Received replies are processed by a SniffThread.
        """

        # create IGMP general query packet
        ether_part = Ether(src=self.src_mac)
        ip_part = IP(ttl=self._TTL, src=self.ip, dst=self._IGMP_MULTICAST)
        igmp_part = IGMP(type=self._IGMP_GENERAL_QUERY)

        # Called to explicitely fixup associated IP and Ethernet headers
        igmp_part.mrtime = self.mrtime
        igmp_part.igmpize(ether=ether_part, ip=ip_part)
        ether_part.dst = self.dst_mac


        sendp(ether_part / ip_part / igmp_part)

if __name__ == '__main__':
    # send to all VMs
    igmp = IGMPMembership(None, None, '0.0.0.0', '00:00:00:00:00:00', '01:00:5e:00:00:01', 1)
    # send to specify VM
    # igmp = IGMPMembership(None, None, '0.0.0.0', '00:00:00:00:00:00', '5a:ea:c8:7c:07:aa', 1)
    igmp.run()