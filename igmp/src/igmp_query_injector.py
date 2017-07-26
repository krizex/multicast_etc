#!/usr/bin/env python
import argparse
import socket
import subprocess
from contextlib import contextmanager
from select import EPOLLIN, epoll

import time


class ERRNO(object):
    SUCC = 0
    XENSTORE_WATCH_TIMEOUT = 1


class XenstoreUtil(object):
    @staticmethod
    def read(path):
        return subprocess.check_output(['xenstore-read', path]).strip()

    @staticmethod
    def vif_mac_path(domid, vifid):
        return '/local/domain/%d/device/vif/%d/mac' % (domid, vifid)

    @staticmethod
    def vif_state_path(domid, vifid):
        return '/local/domain/%d/device/vif/%d/state' % (domid, vifid)


class XenstoreWatcher(object):
    def __init__(self, watch_path):
        self._watch_path = watch_path
        self.p = None

    def start(self):
        self.p = subprocess.Popen(['xenstore-watch', self._watch_path], stdout=subprocess.PIPE)

    def terminate(self):
        self.p.terminate()

    def readline(self):
        return self.stdout.readline()

    @property
    def stdout(self):
        return self.p.stdout


class XenstoreInspector(object):
    def __init__(self, watch_path, expect_val, timeout):
        """
        :param watch_path: xenstore key path
        :param expect_val: expected value of corresponding xenstore key path
        :param timeout: timeout value in seconds
        """
        self._watcher = XenstoreWatcher(watch_path)
        self._watch_path = watch_path
        self._expect_val = expect_val
        self._timeout = timeout

    @contextmanager
    def __start_watch(self):
        self._watcher.start()
        poll = epoll()
        # add level trigger for input
        poll.register(self._watcher.stdout, EPOLLIN)
        yield poll
        self._watcher.terminate()
        poll.close()

    def inspect(self):
        with self.__start_watch() as poll:
            remain_timeout = self._timeout
            while remain_timeout > 0:
                start = time.time()
                events = poll.poll(remain_timeout)
                if not events:
                    break

                print self._watcher.readline()
                # check the value
                val = XenstoreUtil.read(self._watch_path)
                print 'real val', val
                if val == self._expect_val:
                    return ERRNO.SUCC

                remain_timeout = remain_timeout - (time.time() - start)

            return ERRNO.XENSTORE_WATCH_TIMEOUT


class IGMPQueryGenerator(object):
    """IGMP Query generator.
    Generate IGMP Query packet with/without vlan
    """
    def __init__(self, dst_mac, vlanid):
        self.src_mac = '00:00:00:00:00:00'
        self.dst_mac = dst_mac
        self.vlanid = vlanid

    def parse_mac_address(self, mac):
        ret = []
        for x in mac.split(':'):
            ret.append(int(x, 16))

        return ret

    def create_ether_layer(self):
        ret = []
        for mac in (self.dst_mac, self.src_mac):
            ret.extend(self.parse_mac_address(mac))

        if self.vlanid == 0:
            type_field = [0x08, 0x00]
        else:
            type_field = [0x81, 0x00]

        ret.extend(type_field)
        return ret

    def create_vlan_layer(self):
        if self.vlanid == 0:
            return []
        else:
            return [0x20 | (self.vlanid >> 8), self.vlanid & 0xff, 0x08, 0x00]

    def create_ip_layer(self):
        """
        IP Type: IPv4 (0x0800)
        Version: 4
        Total length: 32
        TTL: 1
        Source IP: 0.0.0.0
        Destination IP: 224.0.0.1 (e0:00:00:01)
        """
        return [
            0x46, 0x00, 0x00, 0x20, 0x00, 0x01,
            0x00, 0x00, 0x01, 0x02, 0x44, 0xd6,
            0x00, 0x00, 0x00, 0x00, 0xe0, 0x00,
            0x00, 0x01, 0x94, 0x04, 0x00, 0x00,
        ]

    def create_igmp_layer(self):
        """
        IGMP Version: 2
        IGMP Type: IGMP Query (0x11)
        Max Resp Time: 0.1 second (0x01)
        Multicast Address: 0.0.0.0
        """
        return [
            0x11, 0x01, 0xee, 0xfe,
            0x00, 0x00, 0x00, 0x00,
        ]

    def generate(self):
        ether_layer = self.create_ether_layer()
        vlan_layer = self.create_vlan_layer()
        ip_layer = self.create_ip_layer()
        igmp_layer = self.create_igmp_layer()
        packet = ether_layer + vlan_layer + ip_layer + igmp_layer
        return "".join(map(chr, packet))


def build_parser():
    parser = argparse.ArgumentParser(prog='igmp_query_injector.py', description=
                                     'Tool for injecting IGMP query packet')

    subparsers = parser.add_subparsers()
    to_vif_parser = subparsers.add_parser('vif', help='Inject query to vifs',
                                          description='Inject query to vifs')
    to_vif_parser.add_argument('vif_name', metavar='vif_name', nargs='+', help='Vif interface name in Dom0')
    to_vif_parser.add_argument('--wait-vif-connected', dest='wait_vif_connected', action='store_true',
                        help='Toggle of wait for vif connected')

    to_bridge_parser = subparsers.add_parser('bridge', help='Inject query to vifs on the bridge',
                                             description='Inject query to vifs on the bridge')
    to_bridge_parser.add_argument('bridge_name', metavar='bridge_name', nargs='+', help='Bridge name of OVS')
    to_bridge_parser.add_argument('--only-to-running-port', dest='only_to_running_port', action='store_true',
                        help='Toggle of only injecting to the port that multicast lives by inspecting IGMP snooping table')

    return parser


def inject_query_packet(interface, packet):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0)
    s.bind((interface, 0))
    s.send(packet)
    s.close()


if __name__ == '__main__':
    parser = build_parser()
    print parser.parse_args()
    # args = parser.parse_args()
    # print args
    # inspector = XenstoreInspector('/local/1/2/3', '4', 10)
    # ret = inspector.inspect()
