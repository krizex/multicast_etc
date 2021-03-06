#!/usr/bin/env python
import argparse
import os
import socket
import subprocess
from abc import ABCMeta, abstractmethod
from collections import namedtuple
from select import EPOLLIN, epoll
import logging
import signal
import xcp.logger as log
import time
import sys
import re

__DEBUG = True
if __DEBUG:
    logging_lvl = logging.DEBUG
else:
    logging_lvl = logging.INFO


class Singleton(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]


class SubprocessAutoClean(object):
    __metaclass__ = Singleton
    """Ensure all subprocess are terminated when the main process exits
    """
    CATCH_SIGNALS = [signal.SIGTERM, signal.SIGINT]

    def __init__(self):
        self.subprocess_lst = []

    def add_subprocess(self, p):
        self.subprocess_lst.append(p)

    def del_subprocess(self, p):
        self.subprocess_lst.remove(p)

    def kill_all_subprocess(self):
        if not self.subprocess_lst:
            return

        log.info('kill all sub process')
        for p in self.subprocess_lst:
            p.terminate()

        self.subprocess_lst = []

    def __enter__(self):
        self._set_signal_handler(self.CATCH_SIGNALS, self._kill_all_subprocess_and_exit)

    def __exit__(self, exc_type, exc_value, traceback):
        self.kill_all_subprocess()

    def _set_signal_handler(self, signals, f):
        for s in signals:
            signal.signal(s, f)

    def _kill_all_subprocess_and_exit(self, signum, frame):
        log.critical('Catch signal %d, kill all subprocess' % signum)
        self.kill_all_subprocess()
        sys.exit(1)


class ERRNO(object):
    SUCC = 0
    SNOOPING_IS_OFF = 1


class XenstoreUtil(object):
    """Utilities for access xenstore
    """
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
    """Tool for watching xenstore
    """
    def __init__(self, watch_path):
        self._watch_path = watch_path
        self.p = None

    def start(self):
        self.p = subprocess.Popen(['xenstore-watch', self._watch_path], stdout=subprocess.PIPE)
        SubprocessAutoClean().add_subprocess(self.p)

    def terminate(self):
        self.p.terminate()
        SubprocessAutoClean().del_subprocess(self.p)

    def readline(self):
        return self.stdout.readline()

    @property
    def stdout(self):
        return self.p.stdout


class XenstoreInspector(object):
    """Watch xenstore until value beed expected or timeout
    """
    def __init__(self, watch_path, expect_val):
        """
        :param watch_path: xenstore key path
        :param expect_val: expected value of corresponding xenstore key path
        """
        self._watcher = XenstoreWatcher(watch_path)
        self.watch_path = watch_path
        self.expect_val = expect_val

    @property
    def stdout(self):
        return self._watcher.stdout

    def read_and_check(self):
        self._watcher.readline()
        val = XenstoreUtil.read(self.watch_path)
        if val == self.expect_val:
            return True
        else:
            return False

    def start(self):
        self._watcher.start()

    def terminate(self):
        self._watcher.terminate()


class Vif(object):
    def __init__(self, vif):
        self.vif_name = vif
        ids = self.vif_name.split('vif')[1].split('.')
        self._domid = int(ids[0])
        self._vifid = int(ids[1])
        self.mac = XenstoreUtil.read(self._mac_address_path())
        self.state_path = self._vif_state_path()

    def _mac_address_path(self):
        return XenstoreUtil.vif_mac_path(self._domid, self._vifid)

    def _vif_state_path(self):
        return XenstoreUtil.vif_state_path(self._domid, self._vifid)


class VifInspectorTask(object):
    def __init__(self, vif, expect_state):
        self._vif = Vif(vif)
        self.expect_state = expect_state

    def get_vif_obj(self):
        return self._vif

    @property
    def vif(self):
        return self._vif.vif_name

    @property
    def mac(self):
        return self._vif.mac

    @property
    def vif_state_path(self):
        return self._vif.state_path


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


class IGMPQueryInjector(object):
    __metaclass__ = ABCMeta

    def __init__(self):
        pass

    def inject_to_vif(self, vif, mac):
        log.info('Inject IGMP query to vif:%s, mac:%s' % (vif, mac))
        packet = IGMPQueryGenerator(mac, 0).generate()
        inject_query_packet(vif, packet)

    def inject_to_vifs(self, vifs):
        for vif in vifs:
            _vif = Vif(vif)
            self.inject_to_vif(_vif.vif_name, _vif.mac)

    @abstractmethod
    def inject(self):
        pass


class IGMPQueryInjectorPerVif(IGMPQueryInjector):
    def __init__(self, vifs, vif_connected_timeout=0):
        super(IGMPQueryInjectorPerVif, self).__init__()
        self.vifs = vifs
        self.vif_connected_timeout = vif_connected_timeout

    def inject(self):
        if self.vif_connected_timeout > 0:
            # should check connection state
            log.info('Inject IGMP query with connection state check')
            self._inject_with_connection_state_check()
        else:
            log.info('Inject IGMP query without connection state check')
            self._inject_without_connection_state_check()

    def _inject_with_connection_state_check(self):
        TaskInspectorPair = namedtuple('TaskInspectorPair', ['task', 'inspector'])
        tasks = map(lambda vif: VifInspectorTask(vif, '4'), self.vifs)
        task_inspector_pair_list = map(lambda x: TaskInspectorPair(x, XenstoreInspector(x.vif_state_path, x.expect_state)),
                                       tasks)
        fdmap = {}
        poll = epoll()
        for x in task_inspector_pair_list:
            x.inspector.start()
            fd = x.inspector.stdout.fileno()
            fdmap[fd] = x
            poll.register(fd, EPOLLIN)

        remain_timeout = self.vif_connected_timeout
        while remain_timeout > 0:
            start = time.time()
            events = poll.poll(remain_timeout)
            if not events:
                break

            for fd, _ in events:
                task, inspector = fdmap[fd]
                if inspector.read_and_check():
                    # value change to expected, so inject query
                    self.inject_to_vif(task.vif, task.mac)
                    inspector.terminate()
                    poll.unregister(fd)
                    del fdmap[fd]

            if not fdmap:
                break

            remain_timeout = remain_timeout - (time.time() - start)

        poll.close()
        for task, inspector in fdmap.itervalues():
            log.warning("Value of '%s' not change to '%s' in %d seconds." %
                        (task.vif_state_path, task.expect_state, self.vif_connected_timeout))
            log.warning("Won't inject IGMP query to vif: %s, mac: %s" % (task.vif, task.mac))
            inspector.terminate()

    def _inject_without_connection_state_check(self):
        self.inject_to_vifs(self.vifs)


class IGMPQueryInjectorPerBridge(IGMPQueryInjector):
    RE_VIF = re.compile(r'^vif\d+\.\d+$')

    def __init__(self, bridges):
        super(IGMPQueryInjectorPerBridge, self).__init__()
        self.bridges = bridges

    def get_vifs_on_bridge(self, bridge):
        ret = []
        outs = subprocess.check_output(['ovs-vsctl', 'list-ports', bridge]).strip()
        for line in outs.split('\n'):
            if self.RE_VIF.match(line):
                ret.append(line)

        return ret

    def inject(self):
        for bridge in self.bridges:
            log.info('Inject IGMP query to bridge:%s' % bridge)
            vifs = self.get_vifs_on_bridge(bridge)
            self.inject_to_vifs(vifs)


def inject_per_vif(args):
    log.info('Entry point: Inject IGMP query per pif')
    injector = IGMPQueryInjectorPerVif(args.vifs, args.vif_connected_timeout)
    return injector.inject()


def inject_per_bridge(args):
    log.info('Entry point: Inject IGMP query per bridge')
    injector = IGMPQueryInjectorPerBridge(args.bridges)
    return injector.inject()


def build_parser():
    parser = argparse.ArgumentParser(prog='igmp_query_injector.py', description=
                                     'Tool for injecting IGMP query packet')
    parser.add_argument('--detach', dest='detach', required=False, action='store_true',
                        help='execute this tool as a daemon')
    parser.add_argument('--check-snooping-toggle', dest='check_snooping_toggle', required=False, action='store_true',
                        help='inject query only when IGMP snooping toggle is enabled')

    subparsers = parser.add_subparsers()
    to_vif_parser = subparsers.add_parser('vif', help='inject query to vifs',
                                          description='Inject query to vifs')
    to_vif_parser.set_defaults(func=inject_per_vif)
    to_vif_parser.add_argument('vifs', metavar='vif_name', nargs='+', help='vif interface name in Dom0')
    to_vif_parser.add_argument('--wait-vif-connected', dest='vif_connected_timeout', metavar='timeout', type=int,
                               default=0, help='timeout value for waiting vif connected')

    to_bridge_parser = subparsers.add_parser('bridge', help='inject query to vifs on the bridge',
                                             description='Inject query to vifs on the bridge')
    to_bridge_parser.set_defaults(func=inject_per_bridge)
    to_bridge_parser.add_argument('bridges', metavar='bridge_name', nargs='+', help='bridge name of OVS')

    return parser


def inject_query_packet(interface, packet):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0)
    s.bind((interface, 0))
    s.send(packet)
    s.close()


def _detach():
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError as e:
        sys.stderr.write("fork failed: %d (%s)\n" % (e.errno, e.strerror))
        sys.exit(1)


def toggle_of_IGMP_snooping_is_enabled():
    pool_uuid = subprocess.check_output(['xe', 'pool-list', '--minimal']).strip()
    toggle_state = subprocess.check_output(
        ['xe', 'pool-param-get', 'uuid=%s' % pool_uuid, 'param-name=igmp_snooping_enabled']).strip()
    if toggle_state == 'true':
        return True
    else:
        return False


def main():
    # Ensure kill subprocess when exception catches
    with SubprocessAutoClean():
        log.logToSyslog(level=logging_lvl)
        parser = build_parser()
        args = parser.parse_args()

        if args.detach:
            _detach()

        if args.check_snooping_toggle and (not toggle_of_IGMP_snooping_is_enabled()):
            return ERRNO.SNOOPING_IS_OFF

        args.func(args)


if __name__ == '__main__':
    main()
