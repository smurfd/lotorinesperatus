#!/usr/bin/env python3
# Auth: smurfd, 2025; 2 space indent; 150 with;                                                                                                     #
# ------------------------------------------------------------------------------------------------------------------------------------------------- #
from typing import List, Tuple
import binascii
# TODO: READ
# https://en.wikipedia.org/wiki/Mach-O
# https://medium.com/@andrewss112/reverse-engineering-mach-o-arm64-d33f6373ed85
# https://valsamaras.medium.com/arm-64-assembly-series-basic-definitions-and-registers-ec8cc1334e40
# https://book.hacktricks.wiki/en/macos-hardening/macos-security-and-privilege-escalation/macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.html
# https://formats.kaitai.io/mach_o/python.html
# https://oliviagallucci.com/the-anatomy-of-a-mach-o-structure-code-signing-and-pac/
# https://yossarian.net/res/pub/macho-internals/macho-internals.pdf
class Arm64_macho:
  def __init__(self, fn) -> None:
    self.header, self.command, self.loader, self.data, self.segment, self.fn = [], [], [], [], [], fn
    hl, ll, sl = self.get_lengths()
    with open(self.fn, 'rb') as f:
      self.h = f.read(hl)
      self.c, self.l, self.s, self.d = f.read(int(f'{binascii.hexlify(self.get_big(self.h[20:24])).decode()}', 16)), f.read(ll), f.read(sl), f.read()
    #with open(self.fn, 'rb') as f: self.h, self.c, self.l, self.s, self.d = f.read(hl), f.read(cl), f.read(ll), f.read(sl), f.read()
  def get_big(self, s) -> List: return s[::-1]
  def get_lengths(self) -> Tuple:
    return 32, 72, 80                              # Lenght of header, loader, segment
  def get_header(self) -> List:                    # [::-1] for big endian
    self.header.append(self.h[0:4])                # Magic number
    self.header.append(self.h[4:8])                # CPU type
    self.header.append(self.h[8:12])               # CPU subtype
    self.header.append(self.h[12:16])              # Filetype
    self.header.append(self.h[16:20])              # Number of load commands
    self.header.append(self.h[20:24])              # Size of load commands
    self.header.append(self.h[24:28])              # Flags
    self.header.append(self.h[28:32])              # Reserved. 64bit only
    return self.header
  def get_command(self) -> List:
    p1, p2 = 0, 4
    # TODO: dont just print, save to variables
    # TODO: make into functions
    for i in range(int(f'{binascii.hexlify(self.get_big(self.h[16:20])).decode()}', 16)):
      nr = self.get_big(self.c[p1:p2])
      nrr = int(f'{binascii.hexlify(nr).decode()}', 16)
      nsec = 0
      if (nrr == 25): #0x19
        loa = self.get_loader(p1)
        nsec = int(f'{binascii.hexlify(self.get_big(loa[9])).decode()}', 16)
        print(f'cmd loa {i}: {loa}')
        print(f'cmd loa {i}: SECs {nsec}')
        s1 = p1 + 72  # 72 for size of loader
        print('------')
        for j in range(nsec):
          sec = self.get_segment(s1+(j * 80))
          print(f'cmd loa sec {i} {j}: {sec}')
          pos = self.get_big(sec[4])
          siz = self.get_big(sec[3])
          print(f'cmd loa sec {i} {j}: {pos} {siz}')
          pos = int(f'{binascii.hexlify(pos).decode()}', 16)
          siz = int(f'{binascii.hexlify(siz).decode()}', 16)
          print(f'cmd loa sec {i} {j}: {pos} {siz}')
          with open(self.fn, 'rb') as f: # TODO: read this in __init__?
            f.seek(pos)  # find position for data in file
            d = f.read(siz)  # read data size
            print(f'cmd loa data {i} {j}: {d}')
        print('------')
      p1, p2 = p1 + 4, p2 + 4
      sz = self.get_big(self.c[p1:p2])
      sz = int(f'{binascii.hexlify(sz).decode()}', 16)
      print(f'cmd {i}: {nr}')
      print(f'cmd {i}: {sz}')  # size (including the 4 + 4)
      p1, p2 = p2, p2 + sz - 8
      print(f'cmd {i}: {self.c[p1:p2]}')
      p1, p2 = p2, p2 + 4
  def get_loader(self, c) -> List:
    self.loader = []
    self.loader.append(self.c[c + 0:c + 4])        # Command type
    self.loader.append(self.c[c + 4:c + 8])        # Command size
    self.loader.append(self.c[c + 8:c + 24])       # Segment name
    self.loader.append(self.c[c + 24:c + 32])      # Address
    self.loader.append(self.c[c + 32:c + 40])      # Address size
    self.loader.append(self.c[c + 40:c + 48])      # File offset
    self.loader.append(self.c[c + 48:c + 56])      # Size (bytes from file offset)
    self.loader.append(self.c[c + 56:c + 60])      # Maximum virtual memory protection
    self.loader.append(self.c[c + 60:c + 64])      # Initial virtual memory protection
    self.loader.append(self.c[c + 64:c + 68])      # Number of sections
    self.loader.append(self.c[c + 68:c + 72])      # Flags32
    return self.loader
  def get_segment(self, c) -> List:
    self.segment = []
    self.segment.append(self.c[c + 0:c + 16])              # Section name
    self.segment.append(self.c[c + 16:c + 32])             # Segment name
    self.segment.append(self.c[c + 32:c + 40])             # Section address
    self.segment.append(self.c[c + 40:c + 48])             # Section size
    self.segment.append(self.c[c + 48:c + 52])             # Section file offset
    self.segment.append(self.c[c + 52:c + 56])             # Alignment
    self.segment.append(self.c[c + 56:c + 60])             # Relocations file offset
    self.segment.append(self.c[c + 60:c + 64])             # Number of relocations0
    self.segment.append(self.c[c + 64:c + 68])             # Flag/type
    self.segment.append(self.c[c + 68:c + 72])             # Reserved1
    self.segment.append(self.c[c + 72:c + 76])             # Reserved2
    self.segment.append(self.c[c + 76:c + 80])             # Reserved3
    return self.segment
  def get_data(self) -> bytes:
    self.data = self.d
    return self.data
"""
$ otool -tvV ./hello_arm64_macho.bin
./hello_arm64_macho.bin:
(__TEXT,__text) section
_main:
0000000100000460	stp	x29, x30, [sp, #-0x10]!
0000000100000464	mov	x29, sp
0000000100000468	adrp	x0, 0 ; 0x100000000
000000010000046c	add	x0, x0, #0x490 ; literal pool for: "hello world"
0000000100000470	bl	0x100000480 ; symbol stub for: _puts
0000000100000474	mov	w0, #0x0
0000000100000478	ldp	x29, x30, [sp], #0x10
000000010000047c	ret
"""
