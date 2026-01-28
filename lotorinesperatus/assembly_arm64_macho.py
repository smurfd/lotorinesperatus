#!/usr/bin/env python3
# Auth: smurfd, 2025; 2 space indent; 150 width;                                                                                                    #
# ------------------------------------------------------------------------------------------------------------------------------------------------- #
from typing import List, Tuple, Literal
import binascii
# TODO: READ
# https://en.wikipedia.org/wiki/Mach-O
# https://medium.com/@andrewss112/reverse-engineering-mach-o-arm64-d33f6373ed85
# https://valsamaras.medium.com/arm-64-assembly-series-basic-definitions-and-registers-ec8cc1334e40
# https://book.hacktricks.wiki/en/macos-hardening/macos-security-and-privilege-escalation/macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.html
# https://formats.kaitai.io/mach_o/python.html
# https://oliviagallucci.com/the-anatomy-of-a-mach-o-structure-code-signing-and-pac/
# https://yossarian.net/res/pub/macho-internals/macho-internals.pdf

# Arm Architecture Reference Manual
# https://developer.arm.com/documentation/ddi0487/lb/


class Arm64_macho:
  def __init__(self, fn) -> None:
    self.header, self.command, self.loader, self.data, self.segment, self.sections, self.sections_data, self.fn = [], [], [], [], [], [], [], fn
    hl, ll, sl = self.get_lengths()
    with open(self.fn, 'rb') as f:
      self.file = f.read(); p1, p2 = 0, hl
      self.h = self.file[p1:p2]; p1, p2 = hl, hl + int(f'{binascii.hexlify(self.get_big(self.h[20:24])).decode()}', 16)
      self.c = self.file[p1:p2]; p1, p2 = p2, p2 + ll
      self.l = self.file[p1:p2]; p1, p2 = p2, p2 + sl
      self.s = self.file[p1:p2]; p1, p2 = p2, p2
      self.d = self.file[p1:]
  def get_big(self, s) -> List: return s[::-1]
  def get_lengths(self) -> Tuple:
    return 32, 72, 80                              # Lenght of header, loader, segment
  def get_header(self) -> List:                    # [::-1] for big endian
    self.header.append(self.h[ 0: 4])              # Magic number
    self.header.append(self.h[ 4: 8])              # CPU type
    self.header.append(self.h[ 8:12])              # CPU subtype
    self.header.append(self.h[12:16])              # Filetype
    self.header.append(self.h[16:20])              # Number of load commands
    self.header.append(self.h[20:24])              # Size of load commands
    self.header.append(self.h[24:28])              # Flags
    self.header.append(self.h[28:32])              # Reserved. 64bit only
    return self.header
  def get_command(self) -> List:
    nr = self.get_big(self.c[0:4])
    nrr, nsec, sec = int(f'{binascii.hexlify(nr).decode()}', 16), 0, []
    if (nrr == 25): #0x19, meaning it has sections
      loa, s1 = self.get_loader(0), 72  # 72 is the size of the loader
      sec, sec1 = self.get_sections(int(f'{binascii.hexlify(self.get_big(loa[9])).decode()}', 16), s1)
    sz = int(f'{binascii.hexlify(self.get_big(self.c[4:8])).decode()}', 16)
    return sec[0]
  def get_loader(self, c) -> List:
    self.loader = []
    self.loader.append(self.c[c +  0:c +  4])      # Command type
    self.loader.append(self.c[c +  4:c +  8])      # Command size
    self.loader.append(self.c[c +  8:c + 24])      # Segment name
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
    self.segment.append(self.c[c +  0:c + 16])     # Section name
    self.segment.append(self.c[c + 16:c + 32])     # Segment name
    self.segment.append(self.c[c + 32:c + 40])     # Section address
    self.segment.append(self.c[c + 40:c + 48])     # Section size
    self.segment.append(self.c[c + 48:c + 52])     # Section file offset
    self.segment.append(self.c[c + 52:c + 56])     # Alignment
    self.segment.append(self.c[c + 56:c + 60])     # Relocations file offset
    self.segment.append(self.c[c + 60:c + 64])     # Number of relocations0
    self.segment.append(self.c[c + 64:c + 68])     # Flag/type
    self.segment.append(self.c[c + 68:c + 72])     # Reserved1
    self.segment.append(self.c[c + 72:c + 76])     # Reserved2
    self.segment.append(self.c[c + 76:c + 80])     # Reserved3
    return self.segment
  def get_instructions(self, i) -> Literal:
    if   i[:20] == '0b100100010000000001': return f'add x29, sp, #0x10'
    elif i[:19] == '0b10010001000000001': return f'add sp, sp, #0x20'
    elif i[:19] == '0b10010001000000000': return f'mov x{int(i[29:34], 2)}, sp'
    elif i[:14] == '0b100100010001': return f'add x{int(i[29:34], 2)}, x{int(i[19:24], 2)}, '
    elif i[:14] == '0b100100010000': return f'mov x{int(i[29:34], 2)}, sp'
    elif i[:13] == '0b10010000000': return f'adrp x{int(i[29:34], 2)}, 0x100000xxx <'
    elif i[:13] == '0b10010100000': return f'bl 0x100000xxx <'
    elif i[:13] == '0b10100101000': return f'mov w{int(i[29:34], 2)}, #0x0'
    elif i[:13] == '0b10101000110': return f'ldp x{int(i[29:34], 2)}, x{int(i[19:24], 2)}, [sp], #0x10'
    elif i[:13] == '0b11010110010': return f'ret'
    elif i[:13] == '0b11111001010': return f'ldr x{int(i[29:34], 2)}, [x16]'
    elif i[:13] == '0b11010110000': return f'br x{int(i[24:29], 2)}'
    elif i[:13] == '0b10101001101': return f'stp x{int(i[29:34], 2)}, x{int(i[19:24], 2)} [sp, #-0x10]'
    elif i[:13] == '0b11010001000': return f'sub sp, sp, #0x20'
    elif i[:13] == '0b11111001000': return f'str x0, [sp, #0x8]'
    elif i[:13] == '0b10111001000': return f'str wzr, [sp, #0x1c]'
    elif i[:13] == '0b10100000000': return f'b 0x10000048c <_func+0x2c>'
    elif i[:13] == '0b10111001100': return f'ldrsw x0, [sp, #0x1c]'
    elif i[:13] == '0b10001011000': return f'add x0, x1, x0'
    elif i[:13] == '0b10111001010': return f'ldr w0, [sp, #0x1c]'
    elif i[:13] == '0b10001000000': return f'add w0, w0, #0x1'
    elif i[:13] == '0b11100010000': return f'cmp w0, #0x13'
    elif i[:13] == '0b10101001111': return f'b.le  0x100000470 <_func+0x10>'
    elif i[:13] == '0b11010001000': return f'b.le  0x100000470 <_func+0x10>'
    elif i[:13] == '0b10101001000': return f'stp x29, x30, [sp, #0x10]'
    elif i[:13] == '0b11010010100': return f'mov x0, #0x64'
    elif i[:13] == '0b10010111111': return f'bl  0x100000460 <_func>'
    elif i[:13] == '0b10101001010': return f'ldp x29, x30, [sp, #0x10]'
    elif i      != '0b0': return f'NOOP'  # catch all
  def get_assembly(self) -> List:  # Hex, binary, instruction, bytes
    # https://gist.github.com/jemo07/ef2f0be8ed12e1e4f181ab522cd66889
    # https://stackoverflow.com/questions/11785973/converting-very-simple-arm-instructions-to-binary-hex
    # https://medium.com/@mohamad.aerabi/arm-binary-analysis-part7-613d1dc9b9e2
    p = int.from_bytes(self.header[5][::-1]) + 64  # 1120 = 0x460 = sizeof load commands + 64
    i, ins, hx, bi, b = 0, [], [], [], []  # TODO: does this actually work for other binaries?
    while (instr := self.get_instructions(bin(int.from_bytes(self.file[p + i:p + i + 4][::-1])))) != None and self.file[p + i:p + i + 4][::-1] != b'':
      ins.append(instr)
      byt = self.file[p + i:p + i + 4][::-1]
      hx.append(hex(int.from_bytes(byt)))
      bi.append(bin(int.from_bytes(byt)))
      b.append(byt)
      i += 4
    return hx, bi, ins, b
  def get_sections(self, nr, p) -> List:
    self.sections = self.get_segment(p + 80)
    pos, siz = int(f'{binascii.hexlify(self.get_big(self.sections[4])).decode()}', 16), int(f'{binascii.hexlify(self.get_big(self.sections[3])).decode()}', 16)
    self.sections_data.append(self.file[pos:pos + siz])
    return self.sections, self.sections_data
  def get_data(self) -> bytes:
    self.data = self.d
    return self.data

