#!/usr/bin/env python3
# Auth: smurfd, 2025; 2 space indent; 150 width;                                                                                                    #
# ------------------------------------------------------------------------------------------------------------------------------------------------- #
from typing import List, Tuple, Literal
# TODO: READ
# https://en.wikipedia.org/wiki/Executable_and_Linkable_Format
# https://gabi.xinuos.com/v42/elf.pdf
# https://web.archive.org/web/20250628070854/http://skyfree.org/linux/references/ELF_Format.pdf

# https://notes.eatonphil.com/emulating-amd64-starting-with-elf.html
# https://wiki.osdev.org/X86-64_Instruction_Encoding#Registers
# http://ref.x86asm.net/coder64.html << ---
# https://stackoverflow.com/questions/15352547/get-elf-sections-offsets # this helped me understand what i had done wrong

class Amd64_elf:
  def __init__(self, fn) -> None:
    self.header, self.proghd, self.secthd, self.data, self.file, self.fn = [], [], [], [], [], fn
    hl, ll, sl = self.get_lengths()
    with open(self.fn, 'rb') as f: self.file = f.read()
    p1, p2 = 0, hl
    self.h = self.file[p1:p2]; p1, p2 = hl, hl + ll
    self.p = self.file[p1:p2]; p1, p2 = p2, p2 + sl + 3
    self.s = self.file[p1:p2]
    self.d = self.file[p2:]
  def get_lengths(self) -> Tuple:
    return 64, 56, 65                              # Length of header, proghd, secthd
  def get_header(self) -> List:                    # [::-1] for big endian
    self.header.append(self.h[ 0: 4])              # Magic number
    self.header.append(self.h[ 4: 5])              # 32bit or 64bit
    self.header.append(self.h[ 5: 6])              # Endianess
    self.header.append(self.h[ 6: 7])              # Version
    self.header.append(self.h[ 7: 8])              # Target system ABI
    self.header.append(self.h[ 8: 9])              # ABI version
    self.header.append(self.h[ 9:16])              # Padding, should be zeros
    self.header.append(self.h[16:18])              # Object filetype
    self.header.append(self.h[18:20])              # Target instruction set arch
    self.header.append(self.h[20:24])              # Version
    self.header.append(self.h[24:32])              # Memory address from where execution starts
    self.header.append(self.h[32:40])              # Memory address for Program offset
    self.header.append(self.h[40:48])              # Points to the start of the section header table
    self.header.append(self.h[48:52])              # Flags
    self.header.append(self.h[52:54])              # This header size, 64 for 64bit
    self.header.append(self.h[54:56])              # Program header size, 56 for 64bit
    self.header.append(self.h[56:58])              # Program header number of entries
    self.header.append(self.h[58:60])              # Section header size, 64 for 64bit
    self.header.append(self.h[60:62])              # Section header number of entries
    self.header.append(self.h[62:64])              # Section header index
    return self.header
  def get_header_program(self) -> List:
    self.proghd.append(self.p[ 0: 4])              # Segment type
    self.proghd.append(self.p[ 4: 8])              # Segment-dependent flags
    self.proghd.append(self.p[ 8:16])              # Segment offset in the file image
    self.proghd.append(self.p[16:24])              # Virtual Address of the segment in memory
    self.proghd.append(self.p[24:32])              # Segments physical address
    self.proghd.append(self.p[32:40])              # Size in bytes of the segment in file image
    self.proghd.append(self.p[40:48])              # Size in bytes of the segment in memory
    self.proghd.append(self.p[48:56])              # Alignment
    return self.proghd
  def get_header_section(self) -> List:
    self.secthd.append(self.s[ 0: 4])              # Offset to name string
    self.secthd.append(self.s[ 4: 8])              # Type of header
    self.secthd.append(self.s[ 8:16])              # Flags
    self.secthd.append(self.s[16:24])              # Virtual address of the section in memory
    self.secthd.append(self.s[24:32])              # Section offset in the file image
    self.secthd.append(self.s[32:40])              # Section size in bytes
    self.secthd.append(self.s[40:44])              # Section index
    self.secthd.append(self.s[44:48])              # Section information
    self.secthd.append(self.s[48:56])              # Section alignment
    self.secthd.append(self.s[56:64])              # Section entry size
    return self.secthd
  def get_data(self) -> bytes:
    self.data = self.d
    return self.data
  def get_register(self, b, ins, nr, d = 0):
    reg, d = [['101', f'%rsp'], ['011', f'%rsp'], ['010', f'%rbp'], ['001', f'%rbx'], ['000', f'%rax']], 0
    if   len(b) > 33 and len(b) < 56: j = 2  # jump steps between instructions
    elif len(b) > 56 and len(b) < 65: j = 0
    elif len(b) == 65: j = 3
    else: j = 0
    if   ins == 'pushq': i = 0 + (nr * 3)
    elif ins == 'movq':  # if d == 1, means we cant move from one register to the same register
      if j:
        i = (len(b)//2)-5 + (nr * 3) - (j+(2-nr)) - int(not nr)
        if len(b) == 65 and not nr: [d := 1 if k[0] in b[i+2:i+5] else None for k in reg]
      else:
        if   len(b) == 33 and nr: i = (len(b)//2)-5 + (nr * 3) - nr
        elif len(b) == 33 and not nr: i = (len(b)//2)-5 + (nr * 3) + int(not(nr))
        elif len(b) == 57:
          i = (len(b)//2)-5 + (nr * 3) + (len(b)//5)-4
          if b[i+2:i+5] == b[i+5:i+8]: d = 1
        else: i = (len(b)//2)-5 + (nr * 3)
    elif ins == 'decq': i = (len(b)//2)+2 + (nr * 3)
    elif ins == 'incq': i = (len(b)//2)+2 + (nr * 3)
    elif ins == 'jmpq': i = (len(b)//2)-1 + (nr * 3)
    if   d == 0 and b[5+i:8+i] == '101': return f'%rsp'  # d for duplicate
    elif d == 0 and b[5+i:8+i] == '011': return f'%rsp'
    elif d == 1 and b[5+i:8+i] == '010': return f'%rsp'
    elif d == 0 and b[5+i:8+i] == '010': return f'%rbp'
    elif d == 1 and b[5+i:8+i] == '101': return f'%rbp'
    elif d == 0 and b[5+i:8+i] == '001': return f'%rbx'
    elif d == 0 and b[5+i:8+i] == '000': return f'%rax'
  def rx(self, p, i): return hex(int.from_bytes(self.file[p:p + i]))  # Return hex
  def get_assembly_correctly(self) -> List:
    reg = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']
    byt, co, p = b'', 0, 1192  # 1192 = 0x4004a8 - 0x4a8
    hx, bi, ins, b = [], [], [], []
    while p + co < len(self.file) and co < 910:  # TODO: how to find the 910 programaticly?
      bit16, bit64, cond, chk, byt, px = False, False, False, False, self.file[p + co:p + co + 1], ''
      # TODO: movq instead of mov, for 64bit, movl for 32bit etc...
      if   int.from_bytes(byt) == 0x48: co += 1; bit64 = True; byt = self.file[p + co:p + co + 1]                                                   # 64bit op
      elif int.from_bytes(byt) == 0x66: co += 1; bit16 = True; byt = self.file[p+co:p+co+1]                                                         # 16bit op
      elif int.from_bytes(byt) == 0x49: co += 1; cond = True; byt = self.file[p+co:p+co+1]                                                          # Conditional
      elif int.from_bytes(byt) == 0x41: co += 1; cond = True; byt = self.file[p+co:p+co+1]                                                          # Conditional
      elif int.from_bytes(byt) == 0x4c: co += 1; byt = self.file[p+co:p+co+1]                                                                       # Check
      elif int.from_bytes(byt) == 0x4d: co += 1; chk = True; byt = self.file[p+co:p+co+1]                                                           # Check
      if bit16:
        x = int.from_bytes(self.file[p+co+1:p+co+2]); y = int.from_bytes(self.file[p+co+2:p+co+3])
        if   int.from_bytes(byt) == 0x90: co += 1; ins.append(f'nop')                                                                               # Nop
        elif int.from_bytes(byt) == 0x0f and (0xf0 & x) == 0x10 and (0xf0 & y) == 0x40: px = 'l'; ins.append(f'nop{px} {self.rx(p + co, 2)}'); co += 2  # Nopl, read 2
        elif int.from_bytes(byt) == 0x66 or int.from_bytes(byt) == 0x2e:
          co += 1;
          while int.from_bytes(self.file[p+co:p+co+1]) == 0x66: co += 1;
          ins.append(f'nop{px} {self.rx(p + co, 8)}'); co += 8
        else: ins.append(f'noop')                                                                                                                   # No operation found
      elif chk:
        if   int.from_bytes(byt) == 0x8b: ins.append(f'mov{px} {self.rx(p + co, 3)}'); co += 3                                                      # Mov, read 3
        elif int.from_bytes(byt) == 0x39: ins.append(f'cmp{px} {self.rx(p + co, 2)}'); co += 2                                                      # Cmp, read 2
      elif int.from_bytes(byt) == 0x83:  # Add / Sub / Cmp
        co += 1; x = int.from_bytes(self.file[p+co:p+co+1])
        if   (0xf0 & x) == 0xe0: ins.append(f'sub{px} {self.rx(p + co, 2)}'); co += 2                                                               # Sub, read 2
        elif (0xf0 & x) == 0x40: ins.append(f'add{px} {self.rx(p + co, 3)}'); co += 3                                                               # Add, read 4
        elif (0xf0 & x) == 0xc0: ins.append(f'add{px} {self.rx(p + co, 2)}'); co += 2                                                               # Add, read 2
        elif (0xf0 & x) == 0xf0: ins.append(f'cmp{px} {self.rx(p + co, 2)}'); co += 2                                                               # Cmp, read 2
        elif (0xf0 & x) == 0xd0: ins.append(f'adc{px} {self.rx(p + co, 2)}'); co += 2                                                               # Adc, read 2
        elif (0xf0 & x) == 0x70: ins.append(f'cmp{px} {self.rx(p + co, 3)}'); co += 3                                                               # Cmp, read 3
        elif (0xf0 & x) == 0x30: ins.append(f'cmp{px} {self.rx(p + co, 6)}'); co += 6                                                               # Cmp, read 6
        elif (0xf0 & x) == 0x80: ins.append(f'mov{px} {self.rx(p + co, 2)}'); co += 2                                                               # Mov, read 2
      elif int.from_bytes(byt) == 0xff:
        if   int.from_bytes(self.file[p+co+1:p+co+2]) == 0x25: ins.append(f'jmp{px} {self.rx(p + co, 6)}'); co += 6                                 # Jmp
        elif int.from_bytes(self.file[p+co+1:p+co+2]) == 0x35: ins.append(f'push{px} {self.rx(p + co, 6)}'); co += 6                                # Push
        elif int.from_bytes(self.file[p+co+1:p+co+2]) == 0x55: ins.append(f'call{px} {self.rx(p + co, 2)}'); co += 2                                # Call
        elif int.from_bytes(self.file[p+co+1:p+co+2]) == 0xe0: ins.append(f'jmp{px} {self.rx(p + co, 2)}'); co += 2                                 # Call
        elif int.from_bytes(self.file[p+co+1:p+co+2]) == 0xd0: ins.append(f'call{px} {self.rx(p + co, 2)}'); co += 2                                # Call
        elif int.from_bytes(self.file[p+co+1:p+co+2]) == 0xc0: ins.append(f'incq{px} {self.rx(p + co, 2)}'); co += 2                                # Incq
        elif int.from_bytes(self.file[p+co+1:p+co+2]) == 0xcb: ins.append(f'decq{px} {self.rx(p + co, 2)}'); co += 2                                # Decq
        elif int.from_bytes(self.file[p+co+1:p+co+2]) == 0xc5: ins.append(f'incq{px} {self.rx(p + co, 2)}'); co += 2                                # Incq
        else: co += 1
      elif int.from_bytes(byt) == 0x45:
        if   int.from_bytes(self.file[p+co+1:p+co+2]) == 0x31: ins.append(f'xor{px} {self.rx(p + co, 2)}'); co += 2                                 # xor
        elif int.from_bytes(self.file[p+co+1:p+co+2]) == 0x85: ins.append(f'test{px} {self.rx(p + co, 2)}'); co += 2                                # test
        else: co += 1
      elif int.from_bytes(byt) == 0x89 and bit64:
        co += 1; x = int.from_bytes(self.file[p+co:p+co+1])
        if   (0xf0 & x) == 0xd0: ins.append(f'mov{px} {self.rx(p + co, 1)}'); co += 1                                                               # Mov, read 1
        elif (0xf0 & x) == 0xe0: ins.append(f'mov{px} {self.rx(p + co, 1)}'); co += 1                                                               # Mov, read 1
        elif (0xf0 & x) == 0xf0: ins.append(f'mov{px} {self.rx(p + co, 1)}'); co += 1                                                               # Mov, read 1
        elif (0xf0 & x) == 0x50: ins.append(f'mov{px} {self.rx(p + co, 2)}'); co += 2                                                               # Mov, read 2
        elif (0xf0 & x) == 0x70: ins.append(f'mov{px} {self.rx(p + co, 2)}'); co += 2                                                               # Mov, read 2
        elif (0xf0 & x) == 0x10: ins.append(f'mov{px} {self.rx(p + co, 5)}'); co += 5                                                               # Mov, read 5
        elif (0xf0 & x) == 0x0:  ins.append(f'mov{px} {self.rx(p + co, 5)}'); co += 5                                                               # Mov, read 5
      elif int.from_bytes(byt) == 0x89 and cond:
        co += 1; x = int.from_bytes(self.file[p+co:p+co+1]);
        if   (0xf0 & x) == 0x0:  ins.append(f'mov{px} {self.rx(p + co, 2)}'); co += 2                                                               # Mov, read 2
        elif (0xf0 & x) == 0xf0: ins.append(f'mov{px} {self.rx(p + co, 1)}'); co += 1                                                               # Mov, read 1
      elif int.from_bytes(byt) == 0x0f:
        co += 1; x = int.from_bytes(self.file[p+co:p+co+1]); y = int.from_bytes(self.file[p+co+1:p+co+2])
        if   (0xf0 & x) == 0x10 and (0xf0 & y) == 0x40: ins.append(f'nopl{px} {self.rx(p + co, 2)}'); co += 2                                       # Nopl, read 2
        elif (0xf0 & x) == 0x10 and (0xf0 & y) == 0x80: ins.append(f'nopl{px} {self.rx(p + co, 5)}'); co += 5                                       # Nopl, read 5
        elif (0xf0 & x) == 0x10 and (0xf0 & y) == 0x0:  ins.append(f'nopl{px} {self.rx(p + co, 1)}'); co += 1                                       # Nopl, read 1
        elif (0xf0 & x) == 0xb0: ins.append(f'movzbl{px} {self.rx(p + co, 3)}'); co += 3                                                            # Mov, read 3
        elif (0xf0 & x) == 0xa0: ins.append(f'cpuid{px} {self.rx(p + co, 1)}'); co += 1                                                             # cpuid, read 1
      elif int.from_bytes(byt) == 0x81 and (cond or bit64):
        co += 1; x = int.from_bytes(self.file[p+co:p+co+1])
        if   (0xf0 & x) == 0xf0: ins.append(f'cmp{px} {self.rx(p + co, 5)}'); co += 5                                                               # Cmp, read 5
      elif int.from_bytes(byt) == 0x8d and bit64:
        co += 1; x = int.from_bytes(self.file[p+co:p+co+1])
        if   (0xf0 & x) == 0x10: ins.append(f'leaq{px} {self.rx(p + co, 2)}'); co += 2                                                              # leaq, read 2
        elif (0xf0 & x) == 0x00: ins.append(f'leaq{px} {self.rx(p + co, 5)}'); co += 5                                                              # leaq, read 5
        elif (0xf0 & x) == 0x30: ins.append(f'leaq{px} {self.rx(p + co, 5)}'); co += 5                                                              # leaq, read 5
      elif int.from_bytes(byt) == 0xc1:
        co += 1; x = int.from_bytes(self.file[p+co:p+co+1])
        if   (0xf0 & x) == 0xe0: ins.append(f'shr{px} {self.rx(p + co, 3)}'); co += 2                                                               # Shr
        elif (0xf0 & x) == 0xf0: ins.append(f'sar{px} {self.rx(p + co, 3)}'); co += 2                                                               # Sar
      elif int.from_bytes(byt) == 0xcc: ins.append(f'int13{px} {self.rx(p + co, 1)}'); co += 1                                                      # Int13
      elif int.from_bytes(byt) == 0xc3: ins.append(f'retq{px} {self.rx(p + co, 1)}'); co += 1                                                       # Retq
      elif int.from_bytes(byt) == 0x98: ins.append(f'cltq{px} {self.rx(p + co, 1)}'); co += 1                                                       # Retq
      elif int.from_bytes(byt) == 0x39: ins.append(f'cmpq{px} {self.rx(p + co, 2)}'); co += 2                                                       # Cmpq
      elif int.from_bytes(byt) == 0xe8: ins.append(f'call{px} {self.rx(p + co, 5)}'); co += 5                                                       # Call
      elif int.from_bytes(byt) == 0x85: ins.append(f'test{px} {self.rx(p + co, 2)}'); co += 2                                                       # Test
      elif int.from_bytes(byt) == 0x29: ins.append(f'sub{px} {self.rx(p + co, 2)}'); co += 2                                                        # Sub
      elif int.from_bytes(byt) == 0xd1: ins.append(f'sar{px} {self.rx(p + co, 2)}'); co += 2                                                        # Sar
      elif int.from_bytes(byt) == 0x45: ins.append(f'xor{px} {self.rx(p + co, 3)}'); co += 3                                                        # Xor
      elif int.from_bytes(byt) == 0xe9: ins.append(f'jmp{px} {self.rx(p + co, 5)}'); co += 5                                                        # Jmp
      elif int.from_bytes(byt) == 0xbb: ins.append(f'mov{px} {self.rx(p + co, 5)}'); co += 5                                                        # Mov
      elif int.from_bytes(byt) == 0x01: ins.append(f'add{px} {self.rx(p + co, 3)}'); co += 3                                                        # Mov
      elif int.from_bytes(byt) == 0xb9: ins.append(f'mov{px} {self.rx(p + co, 5)}'); co += 5                                                        # Mov
      elif int.from_bytes(byt) == 0xeb: ins.append(f'jmp{px} {self.rx(p + co, 2)}'); co += 2                                                        # Jmp
      elif int.from_bytes(byt) == 0x89: ins.append(f'mov{px} {self.rx(p + co, 2)}'); co += 2                                                        # Mov
      elif int.from_bytes(byt) == 0x8b: ins.append(f'mov{px} {self.rx(p + co, 3)}'); co += 3                                                        # Mov
      elif int.from_bytes(byt) == 0x63: ins.append(f'mov{px} {self.rx(p + co, 2)}'); co += 2                                                        # Mov
      elif int.from_bytes(byt) == 0x75: ins.append(f'jne{px} {self.rx(p + co, 2)}'); co += 2                                                        # Jne
      elif int.from_bytes(byt) == 0x7e: ins.append(f'jle{px} {self.rx(p + co, 2)}'); co += 2                                                        # Jle
      elif int.from_bytes(byt) == 0x73: ins.append(f'jae{px} {self.rx(p + co, 2)}'); co += 2                                                        # Jae
      elif int.from_bytes(byt) == 0x31: ins.append(f'xor{px} {self.rx(p + co, 2)}'); co += 2                                                        # Xor
      elif int.from_bytes(byt) == 0x80: ins.append(f'cmp{px} {self.rx(p + co, 7)}'); co += 7                                                        # Jb
      elif int.from_bytes(byt) == 0xc6: ins.append(f'mov{px} {self.rx(p + co, 7)}'); co += 7                                                        # Jb
      elif int.from_bytes(byt) == 0xc7: ins.append(f'mov{px} {self.rx(p + co, 7)}'); co += 7                                                        # Jb
      elif int.from_bytes(byt) == 0x74: ins.append(f'je{px} {self.rx(p + co, 2)}'); co += 2                                                         # Je
      elif int.from_bytes(byt) == 0x72: ins.append(f'jb{px} {self.rx(p + co, 2)}'); co += 2                                                         # Jb
      elif int.from_bytes(byt) >= 0xb0 and int.from_bytes(byt) < 0xb8: ins.append(f'mov{px} {self.rx(p + co, 4)}'); co += 4                         # Mov 32bit
      elif int.from_bytes(byt) >= 0xb8 and int.from_bytes(byt) < 0xc0: ins.append(f'mov{px} {self.rx(p + co, 4)}'); co += 4                         # Mov 64bit
      elif int.from_bytes(byt) >= 0x54 and int.from_bytes(byt) < 0x58 and cond: ins.append(f'push{px} {reg[int.from_bytes(byt) - 0x48]}'); co += 1  # Push
      elif int.from_bytes(byt) >= 0x50 and int.from_bytes(byt) < 0x56: ins.append(f'push{px} {reg[int.from_bytes(byt) - 0x50]}'); co += 1           # Push
      elif int.from_bytes(byt) >= 0x5c and int.from_bytes(byt) <= 0x5f: ins.append(f'pop{px} {reg[int.from_bytes(byt) - 0x50]}'); co += 1           # Pop
      elif int.from_bytes(byt) == 0x68 and int.from_bytes(self.file[p+co+1:p+co+2]) >= 0x00 and int.from_bytes(self.file[p+co+1:p+co+2]) < 0x0f:
        ins.append(f'push{px} {self.rx(p + co, 2)}'); co += 2                                                                                       # Push
        while int.from_bytes(self.file[p+co:p+co+1]) == 0: co += 1;
      elif int.from_bytes(byt) >= 0x58 and int.from_bytes(byt) < 0x60: ins.append(f'pop{px} {reg[int.from_bytes(byt) - 0x58]}'); co += 1            # Pop
      elif int.from_bytes(byt) == 0x0f and int.from_bytes(self.file[p+co+1:p+co+2]) == 0x1f:                                                        # Nopl
        ins.append(f'nop{px} {self.rx(1)}'); co += 2
        while int.from_bytes(self.file[p+co+1:p+co+2]) == 0x00: co += 1
      elif int.from_bytes(byt) == 0x90: ins.append(f'nop {self.rx(p + co, 1)}'); co += 1                                                            # Nop
      elif bit64: ins.append(f'noop')
      else: co = co + 1
      #ins.append(self.get_instructions(bin(int.from_bytes(byt))))
      #hx.append(hex(int.from_bytes(byt)))
      #bi.append(bin(int.from_bytes(byt)))
      #b.append(byt)
    return ins  # TODO: return hex, binary, asm. byte

