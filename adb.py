#!/usr/bin/env python3

__author__ = 'Chariton Karamitas <huku@census-labs.com>'


import subprocess

import logger


class ADB(object):

    def __init__(self, serial=None):
        super(ADB, self).__init__()
        self._logger = logger.get_logger(self.__class__.__name__)
        self.serial = serial

    def __str__(self):
        return '<ADB serial=%s>' % self.serial


    def _run(self, args, check=True):

        if self.serial is not None:
            args = ['adb', '-s', self.serial] + args
        else:
            args = ['adb'] + args

        proc = subprocess.run(args, check=check, capture_output=True, text=True)
        return proc.stdout.rstrip()


    def shell(self, args, check=True):
        return self._run(['shell'] + args, check=check)

    def push(self, src_path, dst_path):
        return self._run(['push', src_path, dst_path])

    def pull(self, src_path, dst_path):
        return self._run(['pull', src_path, dst_path])

    def forward(self, protocol, host_endpoint, dev_endpoint):
        return self._run(['forward', '%s:%s' % (protocol, host_endpoint),
            '%s:%s' % (protocol, dev_endpoint)])

    def reverse(self, protocol, dev_endpoint, host_endpoint):
        return self._run(['reverse', '%s:%s' % (protocol, dev_endpoint),
            '%s:%s' % (protocol, host_endpoint)])



class ADBAbstractions(ADB):

    def __init__(self, serial=None):
        super(ADBAbstractions, self).__init__(serial)

    def __str__(self):
        return '<ADBAbstractions serial=%s>' % self.serial

    def su(self, args, check=True):
        return self.shell(['su', '-c'] + args, check=check)

    def is_rooted(self):

        out = self.su(['id', '-u'])

        try:
            rooted = int(out) == 0
        except ValueError:
            rooted = False

        return rooted

    def getprop(self, name):
        return self.shell(['getprop', name])

    def setprop(self, name, value):
        return self.shell(['setprop', name, value])

