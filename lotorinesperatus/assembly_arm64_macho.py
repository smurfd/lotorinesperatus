#!/usr/bin/env python3
# Auth: smurfd, 2025; 2 space indent; 150 with;                                                                                                     #
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
    if   i[:13] == '0b10101001101': return f'stp x{int(i[29:34], 2)}, x{int(i[19:24], 2)} [sp, #-0x10]'
    elif i[:14] == '0b100100010000': return f'mov x{int(i[29:34], 2)}, sp'
    elif i[:13] == '0b10010000000': return f'adrp x{int(i[29:34], 2)}, 0x100000xxx <'
    elif i[:14] == '0b100100010001': return f'add x{int(i[29:34], 2)}, x{int(i[19:24], 2)}, '
    elif i[:13] == '0b10010100000': return f'bl 0x100000xxx <'
    elif i[:13] == '0b10100101000': return f'mov w{int(i[29:34], 2)}, #0x0'
    elif i[:13] == '0b10101000110': return f'ldp x{int(i[29:34], 2)}, x{int(i[19:24], 2)}, [sp], #0x10'
    elif i[:13] == '0b11010110010': return f'ret'
    elif i[:13] == '0b11111001010': return f'ldr x{int(i[29:34], 2)}, [x16]'
    elif i[:13] == '0b11010110000': return f'br x{int(i[24:29], 2)}'
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
"""
$ objdump -d lotorinesperatus/test/examples/hello_arm64_macho.bin
lotorinesperatus/test/examples/hello_arm64_macho.bin:	file format mach-o arm64

Disassembly of section __TEXT,__text:

0000000100000460 <_main>:
100000460: a9bf7bfd    	stp	x29, x30, [sp, #-0x10]!
100000464: 910003fd    	mov	x29, sp
100000468: 90000000    	adrp	x0, 0x100000000 <_puts+0x100000000>
10000046c: 91124000    	add	x0, x0, #0x490
100000470: 94000004    	bl	0x100000480 <_puts+0x100000480>
100000474: 52800000    	mov	w0, #0x0                ; =0
100000478: a8c17bfd    	ldp	x29, x30, [sp], #0x10
10000047c: d65f03c0    	ret

Disassembly of section __TEXT,__stubs:

0000000100000480 <__stubs>:
100000480: 90000030    	adrp	x16, 0x100004000 <_puts+0x100004000>
100000484: f9400210    	ldr	x16, [x16]
100000488: d61f0200    	br	x16

# ---------------- My asm ------------------ #
Arm Asm: 0xa9bf7bfd 0b10101001101111110111101111111101 stp x29, x30 [sp, #-0x10]
Arm Asm: 0x910003fd 0b10010001000000000000001111111101 mov x29, sp
Arm Asm: 0x90000000 0b10010000000000000000000000000000 adrp x0, 0x100000xxx <
Arm Asm: 0x91124000 0b10010001000100100100000000000000 add x0, x16, 
Arm Asm: 0x94000004 0b10010100000000000000000000000100 bl 0x100000xxx <
Arm Asm: 0x52800000 0b1010010100000000000000000000000 mov w0, #0x0
Arm Asm: 0xa8c17bfd 0b10101000110000010111101111111101 ldp x29, x30, [sp], #0x10
Arm Asm: 0xd65f03c0 0b11010110010111110000001111000000 ret
Arm Asm: 0x90000030 0b10010000000000000000000000110000 adrp x16, 0x100000xxx <
Arm Asm: 0xf9400210 0b11111001010000000000001000010000 ldr x16, [x16]
Arm Asm: 0xd61f0200 0b11010110000111110000001000000000 br x16
"""
