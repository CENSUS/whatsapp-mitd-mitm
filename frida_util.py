#!/usr/bin/env python3

__author__ = 'Chariton Karamitas <huku@census-labs.com>'


import sys
import os
import collections
import random
import time
import multiprocessing
import re
import xml.dom.minidom


try:
    import frida
except ImportError:
    sys.exit('Please install frida-python and run again')

import common
import logger
import adb


import getopt


FridaInstance = collections.namedtuple('FrindaInstance', ['pid', 'address', 'port'])


class FridaServer(object):

    def __init__(self, serial=None, frida_path=None):
        super(FridaServer, self).__init__()
        self._adb = adb.ADBAbstractions(serial)
        self._logger = logger.get_logger(self.__class__.__name__)

        if frida_path is None:
            self._frida_path = self._get_frida_path()
        else:
            self._frida_path = frida_path

        self._frida_instance = None
        self._frida_process = None



    def __str__(self):
        return '<%s serial=%s>' % (self.__class__.__name__, self._adb.serial)



    def _get_listen_address(self, cmdline):

        options, _ = getopt.gnu_getopt(cmdline[1:], 'd:hl:vD',
            ['directory=', 'help', 'listen=', 'verbose', 'daemonize', 'version'])

        address = '0.0.0.0'
        port = '27042'

        for o, v in options:
            if o in ['-l', '--listen']:
                if ':' in v:
                    address, port = v.split(':')
                else:
                    address = v

        return address, port



    def _get_running_instance(self):

        instance = None

        basename = os.path.basename(self._frida_path)

        #
        # Enumerate all system processes and look for Frida servers running as
        # root and using the same ABI.
        #
        for line in self._adb.su(['ps', '-A', '-w', '-o', 'PID,UID,GID,BIT,NAME,CMDLINE']).splitlines()[1:]:

            pid, uid, gid, bits, name, cmdline = re.split('\s+', line.strip(), 5)

            if name == basename and uid == '0' and gid == '0' and bits == str(self.bits):
                address, port = self._get_listen_address(cmdline)

                self._logger.debug('Found Frida server instance pid=%s uid=%s, gid=%s, bits=%s at %s:%s',
                    pid, uid, gid, bits, address, port)

                instance = FridaInstance(pid=pid, address=address, port=port)

        return instance



    def start(self):

        if self._frida_instance is None:

            #
            # Enumerate Frida server instances.
            #
            instance = self._get_running_instance()
            process = None

            #
            # If no Frida server is currently running, attempt to spawn a new
            # instance.
            #
            if instance is None:
                self._logger.info('Attempting to spawn a new Frida server instance')
                process = multiprocessing.Process(target=self._adb.su, args=([self._frida_path],))
                process.start()

                time.sleep(2)
                instance = self._get_running_instance()

            #
            # Still no running instance? Means we failed to start the server.
            #
            if instance is None:
                raise RuntimeError('Frida server is not running and failed to spawn a new instance')

            self._frida_instance = instance
            self._frida_process = process



    def stop(self):

        if self._frida_process is not None:
            self._frida_process.terminate()
            self._frida_process.join()



class FridaServer64(FridaServer):

    def __init__(self, serial=None, frida_path=None):
        super(FridaServer64, self).__init__(serial=serial, frida_path=frida_path)
        self.bits = 64

    def _get_frida_path(self):

        frida_path = None
        for abi in self._adb.getprop('ro.product.cpu.abilist64').split(','):
            if abi.startswith('x86_64'):
                frida_path = '%s/frida-server-*-android-x86_64' % common.TMPDIR
            elif abi.startswith('arm64'):
                frida_path = '%s/frida-server-*-android-arm64' % common.TMPDIR

        if frida_path is None:
            raise RuntimeError('Unknown 64-bit ABIs')

        frida_path = self._adb.shell(['echo', '-n', frida_path])

        if '*' in frida_path:
            raise RuntimeError('Frida server for 64-bit not found at "%s"' % frida_path)

        self._logger.info('Auto detected Frida server for 64-bit at "%s"', frida_path)

        return frida_path



class FridaServer32(FridaServer):

    def __init__(self, serial=None, frida_path=None):
        super(FridaServer32, self).__init__(serial=serial, frida_path=frida_path)
        self.bits = 32

    def _get_frida_path(self):

        frida_path = None
        for abi in self._adb.getprop('ro.product.cpu.abilist32').split(','):
            if abi.startswith('x86'):
                frida_path = '%s/frida-server-*-android-x86' % common.TMPDIR
            elif abi.startswith('arm'):
                frida_path = '%s/frida-server-*-android-arm' % common.TMPDIR

        if frida_path is None:
            raise RuntimeError('Unknown 32-bit ABIs')

        frida_path = self._adb.shell(['echo', '-n', frida_path])

        if '*' in frida_path:
            raise RuntimeError('Frida server for 32-bit not found at "%s"' % frida_path)

        self._logger.info('Auto detected Frida server for 32-bit at "%s"', frida_path)

        return frida_path



#
# A class implementing the factory design pattern for returning both 32-bit and
# 64-bit instances of Frida server, based on the ABI of the process that needs
# to be instrumented.
#
class FridaServerFactory(object):

    def __init__(self, serial=None):
        super(FridaServerFactory, self).__init__()
        self._logger = logger.get_logger(self.__class__.__name__)
        self._adb = adb.ADBAbstractions(serial)
        self._serial = serial
        self._frida_server32 = None
        self._frida_server64 = None

    def __str__(self):
        return '<FridaServerFactory serial=%s>' % self._serial


    def _get_frida_server64(self):

        if self._frida_server64 is None:
            self._logger.debug('Creating 64-bit Frida server instance')
            self._frida_server64 = FridaServer64(serial=self._serial)
        else:
            self._logger.debug('Returning existing 64-bit Frida server instance')

        return self._frida_server64


    def _get_frida_server32(self):

        if self._frida_server32 is None:
            self._logger.debug('Creating 32-bit Frida server instance')
            self._frida_server32 = FridaServer32(serial=self._serial)
        else:
            self._logger.debug('Returning existing 32-bit Frida server instance')

        return self._frida_server32


    def get_frida_server(self, process):

        server = None

        #
        # Enumerate all system processes and match `process' against the PID or
        # name of each item. We are only interested in determining the ABI, so,
        # we break on the first match.
        #
        for line in self._adb.su(['ps', '-A', '-w', '-o', 'PID,BIT,NAME']).splitlines()[1:]:
            pid, bits, name = re.split('\s+', line.strip(), 2)
            if pid == process or name == process:
                self._logger.debug('Matched %s-bit process "%s" (%s)', bits, name, pid)
                if bits == '64':
                    server = self._get_frida_server64()
                elif bits == '32':
                    server = self._get_frida_server32()
                break

        #
        # If `process' does not match the PID or name of a currently running
        # process, assume it's a package name and look it up in the package
        # database.
        #
        if server is None:
            data = self._adb.su(['cat', '/data/system/packages.xml'])

            dom = xml.dom.minidom.parseString(data)

            for package in dom.getElementsByTagName('package'):

                name = None
                if package.hasAttribute('name'):
                    name = package.attributes['name'].value

                if name == process and package.hasAttribute('primaryCpuAbi'):
                    abi = package.attributes['primaryCpuAbi'].value
                    self._logger.debug('Matched package "%s" ABI "%s"', name, abi)
                    if abi.startswith('arm64') or abi.startswith('x86_64'):
                        server = self._get_frida_server64()
                    elif abi.startswith('arm') or abi.startswith('x86'):
                        server = self._get_frida_server32()
                    break

        #
        # Looks like `process' matches neither a running process nor a package
        # name. We can do nothing.
        #
        if server is None:
            raise RuntimeError('No such process or package "%s"' % process)

        return server



class Frida(object):

    def __init__(self, serial=None):
        super(Frida, self).__init__()
        self._logger = logger.get_logger(self.__class__.__name__)
        self._frida_server_factory = FridaServerFactory(serial=serial)
        self._serial = serial
        self._frida_server = None
        self._device = None
        self._session = None

        found = False
        while not found:
            try:
                if serial is not None:
                    self._logger.info('Frida using device with serial "%s"', serial)
                    device = frida.get_device_manager().get_device(serial)
                else:
                    self._logger.info('No device serial given; using default USB device')
                    device = frida.get_device_manager().get_usb_device()

                found = True

            except frida.InvalidArgumentError as exception:
                self._logger.info('Frida exception "%s"; retrying in 2 secs.', str(exception))
                time.sleep(2)

        self._logger.info('Found device "%s" (%s) over %s' , device.name, device.id, device.type.upper())
        self._device = device


    def _receive_message(self, message, data):

        message_type = message['type']
        if message_type == 'error':
            self._logger.error('Frida error: %s (%s:%d)' % \
                (message['description'], message['fileName'], message['lineNumber']))
        elif message_type == 'send':
            self._logger.info(message['payload'])


    def load_script_file(self, filename):

        self._logger.info('Loading script %s', filename)

        script = None
        with open(filename) as fp:
            script = self._session.create_script(fp.read())
            script.on('message', self._receive_message)
            script.load()

        return script


    def load_script(self, script):

        self._logger.info('Loading script')
        script = self._session.create_script(script)
        script.on('message', self._receive_message)
        script.load()

        return script


    def unload_script(self, script):
        self._logger.info('Unloading script %s', str(script))
        script.unload()


    def attach(self, process):
        self._logger.debug('Preparing Frida server')
        self._frida_server = self._frida_server_factory.get_frida_server(process)
        self._frida_server.start()

        self._logger.debug('Attaching to process %s', str(process))
        self._session = self._device.attach(process)

        try:
            self._pid = int(process)
        except ValueError:
            self._pid = self._device.get_process(process).pid

        self._logger.debug('Attached to PID %d', self._pid)


    def spawn(self, name):
        self._logger.debug('Preparing Frida server')
        self._frida_server = self._frida_server_factory.get_frida_server(name)
        self._frida_server.start()

        self._logger.debug('Killing any previous instances of %s', name)
        try:
            self._device.kill(name)
        except frida.ProcessNotFoundError:
            self._logger.debug('No previous instances found')

        self._logger.debug('Spawning %s', name)
        self._pid = self._device.spawn(name)

        self._logger.debug('Attaching to PID %d', self._pid)
        self._session = self._device.attach(self._pid)


    def resume(self):
        self._logger.debug('Resuming PID %d', self._pid)
        self._device.resume(self._pid)


    def detach(self):
        self._logger.debug('Detaching from session %s', str(self._session))
        self._session.detach()
        self._session = None
        self._frida_server.stop()
        self._frida_server = None
        self._pid = None

