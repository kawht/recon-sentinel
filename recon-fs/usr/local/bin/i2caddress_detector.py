#!/usr/bin/python
#Copyright 2017 Cybersecurity Defense Soltions. ALL RIGHTS RESERVED
#DETECT i2c address for LCD Displauy
#v1.0
import sys
import os
from subprocess import PIPE, Popen


def cmdline(command):
    process = Popen(
        args=command,
        stdout=PIPE,
        shell=True
    )
    return process.communicate()[0]


def probe_address(bus, line):
    cmd = "/usr/sbin/i2cdetect -y %s | /bin/grep [0-9a-f][0-9a-f] | /usr/bin/awk {' print $%s '} | /bin/grep [0-9a-f][0-9a-f]" % (bus, line)
    address = cmdline(cmd)
    if address:
        return address
    else:
        return False






line = 2
bus = 1

while (line <= 17):
    addy = probe_address(bus, line)
    if addy:
        addy = addy.rstrip()
        addy = "0x%s" % addy
        fhandle = open("/usr/local/etc/display_address", "w")
        fhandle.truncate()
        fhandle.write(addy)
        #print addy
        fhandle.close()
        sys.exit(0)
    else:
        line = line + 1

