#!/usr/bin/env python
import argparse
import subprocess
import threading
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


class XenStoreWatcherThread(threading.Thread):
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
        super(XenStoreWatcherThread, self).__init__()

    @contextmanager
    def __start_watch(self):
        self._watcher.start()
        poll = epoll()
        # add level trigger for input
        poll.register(self._watcher.stdout, EPOLLIN)
        yield poll
        self._watcher.terminate()
        poll.close()

    def run(self):
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


def build_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('--interface', dest='interface', metavar='interface', required=True, help='Vif interface name in dom0')
    parser.add_argument('--domid', dest='domid', metavar='domid', required=True, type=int, help='Dom ID of the VM')
    parser.add_argument('--vifid', dest='vifid', metavar='vifid', required=True, type=int, help='Vif ID of the vif in the VM')
    parser.add_argument('--wait-vif-connected', dest='wait_vif_connected', action='store_true',
                        help='Toggle of wait for vif connected')
    return parser


if __name__ == '__main__':
    parser = build_parser()
    # parser.parse_args()
    watcher_thread = XenStoreWatcherThread('/local/1/2/3', '4', 10)
    watcher_thread.start()
    watcher_thread.join()