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
    self.asm_init, self.asm_end, self.asm_data, self.file_counter = 0, 0, b'', 0
    hl, ll, sl = self.get_lengths()
    with open(self.fn, 'rb') as f: self.file = f.read()
    p1, p2 = 0, hl
    self.h = self.file[p1:p2]; p1, p2 = hl, hl + ll
    self.p = self.file[p1:p2]; p1, p2 = p2, p2 + sl + 3
    self.s = self.file[p1:p2]
    self.d = self.file[p2:]
  def get_lengths(self) -> Tuple:
# ------------------------------------------------------------------------------------------------------------------------------------------------- #
    return 64, 56, 65                                                                                                                               # Length of header, proghd, secthd
  def get_header(self) -> List:                                                                                                                     # [::-1] for big endian
    self.header.append(self.h[ 0: 4])                                                                                                               # Magic number
    self.header.append(self.h[ 4: 5])                                                                                                               # 32bit or 64bit
    self.header.append(self.h[ 5: 6])                                                                                                               # Endianess
    self.header.append(self.h[ 6: 7])                                                                                                               # Version
    self.header.append(self.h[ 7: 8])                                                                                                               # Target system ABI
    self.header.append(self.h[ 8: 9])                                                                                                               # ABI version
    self.header.append(self.h[ 9:16])                                                                                                               # Padding, should be zeros
    self.header.append(self.h[16:18])                                                                                                               # Object filetype
    self.header.append(self.h[18:20])                                                                                                               # Target instruction set arch
    self.header.append(self.h[20:24])                                                                                                               # Version
    self.header.append(self.h[24:32])                                                                                                               # Memory address from where execution starts
    self.header.append(self.h[32:40])                                                                                                               # Memory address for Program offset
    self.header.append(self.h[40:48])                                                                                                               # Points to the start of the section header table
    self.header.append(self.h[48:52])                                                                                                               # Flags
    self.header.append(self.h[52:54])                                                                                                               # This header size, 64 for 64bit
    self.header.append(self.h[54:56])                                                                                                               # Program header size, 56 for 64bit
    self.header.append(self.h[56:58])                                                                                                               # Program header number of entries
    self.header.append(self.h[58:60])                                                                                                               # Section header size, 64 for 64bit
    self.header.append(self.h[60:62])                                                                                                               # Section header number of entries
    self.header.append(self.h[62:64])                                                                                                               # Section header index
    return self.header
  def get_header_program(self) -> List:
    self.proghd.append(self.p[ 0: 4])                                                                                                               # Segment type
    self.proghd.append(self.p[ 4: 8])                                                                                                               # Segment-dependent flags
    self.proghd.append(self.p[ 8:16])                                                                                                               # Segment offset in the file image
    self.proghd.append(self.p[16:24])                                                                                                               # Virtual Address of the segment in memory
    self.proghd.append(self.p[24:32])                                                                                                               # Segments physical address
    self.proghd.append(self.p[32:40])                                                                                                               # Size in bytes of the segment in file image
    self.proghd.append(self.p[40:48])                                                                                                               # Size in bytes of the segment in memory
    self.proghd.append(self.p[48:56])                                                                                                               # Alignment
    return self.proghd
  def get_header_section(self) -> List:
    self.secthd.append(self.s[ 0: 4])                                                                                                               # Offset to name string
    self.secthd.append(self.s[ 4: 8])                                                                                                               # Type of header
    self.secthd.append(self.s[ 8:16])                                                                                                               # Flags
    self.secthd.append(self.s[16:24])                                                                                                               # Virtual address of the section in memory
    self.secthd.append(self.s[24:32])                                                                                                               # Section offset in the file image
    self.secthd.append(self.s[32:40])                                                                                                               # Section size in bytes
    self.secthd.append(self.s[40:44])                                                                                                               # Section index
    self.secthd.append(self.s[44:48])                                                                                                               # Section information
    self.secthd.append(self.s[48:56])                                                                                                               # Section alignment
    self.secthd.append(self.s[56:64])                                                                                                               # Section entry size
    return self.secthd
  def get_data(self) -> bytes:
    self.data = self.d
    return self.data
  def get_register(self, ins, b, nr, d = 0):
    reg, d = [['101', f'%rsp'], ['011', f'%rsp'], ['010', f'%rbp'], ['001', f'%rbx'], ['000', f'%rax']], 0
    b, i = bin(int.from_bytes(b)), 0
    if   len(b) > 33 and len(b) < 56: j = 2  # jump steps between instructions
    elif len(b) > 56 and len(b) < 65: j = 0
    elif len(b) == 65: j = 3
    else: j = 0
    if   ins == 'pushq': i = 0 + (nr * 3)
    elif ins == 'movq':  # if d == 1, means we cant move from one register to the same register
      if j:
        i = (len(b) // 2) - 5 + (nr * 3) - (j + (2 - nr)) - int(not nr)
        if len(b) == 65 and not nr: [d := 1 if k[0] in b[i + 2:i + 5] else None for k in reg]
      else:
        if   len(b) == 33 and nr: i = (len(b) // 2) - 5 + (nr * 3) - nr
        elif len(b) == 33 and not nr: i = (len(b) // 2) - 5 + (nr * 3) + int(not(nr))
        elif len(b) == 57:
          i = (len(b) // 2) - 5 + (nr * 3) + (len(b) // 5) - 4
          if b[i + 2:i + 5] == b[i + 5:i + 8]: d = 1
        else: i = (len(b) // 2) - 5 + (nr * 3)
    elif ins == 'decq': i = (len(b) // 2) + 2 + (nr * 3)
    elif ins == 'incq': i = (len(b) // 2) + 2 + (nr * 3)
    elif ins == 'jmpq': i = (len(b) // 2) - 1 + (nr * 3)
    if   d == 0 and b[5 + i:8 + i] == '101': return f'%rsp'  # d for duplicate
    elif d == 0 and b[5 + i:8 + i] == '011': return f'%rsp'
    elif d == 1 and b[5 + i:8 + i] == '010': return f'%rsp'
    elif d == 0 and b[5 + i:8 + i] == '010': return f'%rbp'
    elif d == 1 and b[5 + i:8 + i] == '101': return f'%rbp'
    elif d == 0 and b[5 + i:8 + i] == '001': return f'%rbx'
    elif d == 0 and b[5 + i:8 + i] == '000': return f'%rax'
  def rx(self, p, i, file=None): [file := self.file if not file else file]; return hex(int.from_bytes(file[p:p + i]))  # Return hex
  def rr(self, ins, asm, l):  # Return register
    asm.append(f'{ins} {hex(int.from_bytes(self.asm_data[self.asm_init + self.file_counter:self.asm_init + self.file_counter + l]))}')
    self.file_counter += l
    return asm
  def get_assembly(self, start, end, data=None) -> List:
    reg = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']
    byt, self.file_counter, p, maxco, f, hx, bi, ins, b = b'', 0, start, end, self.file, [], [], [], []
    if data: maxco, p, f = len(data), 0, data
    self.asm_init, self.asm_end, self.asm_data = p, maxco, f
    while self.file_counter + p < maxco:
      bit16, bit64, cond, chk, byt, px = False, False, False, False, f[p + self.file_counter:p + self.file_counter + 1], ''
      # TODO: movq instead of mov, for 64bit, movl for 32bit etc...
      if   int.from_bytes(byt) == 0x48: self.file_counter += 1; bit64 = True; byt = f[p + self.file_counter:p + self.file_counter + 1]              # 64bit op
      elif int.from_bytes(byt) == 0x66: self.file_counter += 1; bit16 = True; byt = f[p + self.file_counter:p + self.file_counter + 1]              # 16bit op
      elif int.from_bytes(byt) == 0x49: self.file_counter += 1; cond = True; byt = f[p + self.file_counter:p + self.file_counter + 1]               # Conditional
      elif int.from_bytes(byt) == 0x41: self.file_counter += 1; cond = True; byt = f[p + self.file_counter:p + self.file_counter + 1]               # Conditional
      elif int.from_bytes(byt) == 0x4c: self.file_counter += 1; byt = f[p + self.file_counter:p + self.file_counter + 1]                            # Check
      elif int.from_bytes(byt) == 0x4d: self.file_counter += 1; chk = True; byt = f[p + self.file_counter:p + self.file_counter + 1]                # Check
      if bit16:
        x = int.from_bytes(f[p + self.file_counter + 1:p + self.file_counter + 2])
        y = int.from_bytes(f[p + self.file_counter + 2:p + self.file_counter + 3])
        if   int.from_bytes(byt) == 0x90: self.file_counter += 1; ins.append(f'nop')                                                                # Nop
        elif int.from_bytes(byt) == 0x0f and (0xf0 & x) == 0x10 and (0xf0 & y) == 0x40:
          px = 'l'; ins = self.rr(f'nop{px}', ins, 2)                                                                                               # Nopl, read 2
        elif int.from_bytes(byt) == 0x66 or int.from_bytes(byt) == 0x2e:
          self.file_counter += 1;
          while int.from_bytes(f[p + self.file_counter:p + self.file_counter + 1]) == 0x66: self.file_counter += 1;
          ins = self.rr(f'nop{px}', ins, 8)
        else: ins.append(f'noop')                                                                                                                   # No operation found
      elif chk:
        if   int.from_bytes(byt) == 0x8b: ins = self.rr(f'mov{px}', ins, 3)                                                                         # Mov, read 3
        elif int.from_bytes(byt) == 0x39: ins = self.rr(f'cmp{px}', ins, 2)                                                                         # Cmp, read 2
      elif int.from_bytes(byt) == 0x83:  # Add / Sub / Cmp
        self.file_counter += 1; x = int.from_bytes(f[p + self.file_counter:p + self.file_counter + 1])
        if   (0xf0 & x) == 0xe0: ins = self.rr(f'sub{px}', ins, 2)                                                                                  # Sub, read 2
        elif (0xf0 & x) == 0x40: ins = self.rr(f'add{px}', ins, 3)                                                                                  # Add, read 4
        elif (0xf0 & x) == 0xc0: ins = self.rr(f'add{px}', ins, 2)                                                                                  # Add, read 2
        elif (0xf0 & x) == 0xf0: ins = self.rr(f'cmp{px}', ins, 2)                                                                                  # Cmp, read 2
        elif (0xf0 & x) == 0xd0: ins = self.rr(f'adc{px}', ins, 2)                                                                                  # Adc, read 2
        elif (0xf0 & x) == 0x70: ins = self.rr(f'cmp{px}', ins, 3)                                                                                  # Cmp, read 3
        elif (0xf0 & x) == 0x30: ins = self.rr(f'cmp{px}', ins, 6)                                                                                  # Cmp, read 6
        elif (0xf0 & x) == 0x80: ins = self.rr(f'mov{px}', ins, 2)                                                                                  # Mov, read 2
      elif int.from_bytes(byt) == 0xff:
        if   int.from_bytes(f[p + self.file_counter + 1:p + self.file_counter + 2]) == 0x35: ins = self.rr(f'push{px}', ins, 6)                     # Push
        elif int.from_bytes(f[p + self.file_counter + 1:p + self.file_counter + 2]) == 0x55: ins = self.rr(f'call{px}', ins, 2)                     # Call
        elif int.from_bytes(f[p + self.file_counter + 1:p + self.file_counter + 2]) == 0xd0: ins = self.rr(f'call{px}', ins, 2)                     # Call
        elif int.from_bytes(f[p + self.file_counter + 1:p + self.file_counter + 2]) == 0x25: ins = self.rr(f'jmp{px}', ins, 6)                      # Jmp
        elif int.from_bytes(f[p + self.file_counter + 1:p + self.file_counter + 2]) == 0xe0: ins = self.rr(f'jmp{px}', ins, 2)                      # Jmp
        elif int.from_bytes(f[p + self.file_counter + 1:p + self.file_counter + 2]) == 0xc0: ins = self.rr(f'inc{px}', ins, 2)                      # Incq
        elif int.from_bytes(f[p + self.file_counter + 1:p + self.file_counter + 2]) == 0xcb: ins = self.rr(f'dec{px}', ins, 2)                      # Decq
        elif int.from_bytes(f[p + self.file_counter + 1:p + self.file_counter + 2]) == 0xc5: ins = self.rr(f'inc{px}', ins, 2)                      # Incq
        else: self.file_counter += 1
      elif int.from_bytes(byt) == 0x45:
        if   int.from_bytes(f[p + self.file_counter + 1:p + self.file_counter + 2]) == 0x31: ins = self.rr(f'xor{px}', ins, 2)                      # Xor
        elif int.from_bytes(f[p + self.file_counter + 1:p + self.file_counter + 2]) == 0x85: ins = self.rr(f'test{px}', ins, 2)                     # Test
        else: self.file_counter += 1
      elif int.from_bytes(byt) == 0x89 and bit64:
        self.file_counter += 1; x = int.from_bytes(f[p + self.file_counter:p + self.file_counter + 1])
        if   (0xf0 & x) == 0xd0: ins = self.rr(f'mov{px}', ins, 1)                                                                                  # Mov, read 1
        elif (0xf0 & x) == 0xe0: ins = self.rr(f'mov{px}', ins, 1)                                                                                  # Mov, read 1
        elif (0xf0 & x) == 0xf0: ins = self.rr(f'mov{px}', ins, 1)                                                                                  # Mov, read 1
        elif (0xf0 & x) == 0x50: ins = self.rr(f'mov{px}', ins, 2)                                                                                  # Mov, read 2
        elif (0xf0 & x) == 0x70: ins = self.rr(f'mov{px}', ins, 2)                                                                                  # Mov, read 2
        elif (0xf0 & x) == 0x10: ins = self.rr(f'mov{px}', ins, 5)                                                                                  # Mov, read 5
        elif (0xf0 & x) == 0x0:  ins = self.rr(f'mov{px}', ins, 5)                                                                                  # Mov, read 5
      elif int.from_bytes(byt) == 0x89 and cond:
        self.file_counter += 1; x = int.from_bytes(f[p + self.file_counter:p + self.file_counter + 1]);
        if   (0xf0 & x) == 0x0:  ins = self.rr(f'mov{px}', ins, 2)                                                                                  # Mov, read 2
        elif (0xf0 & x) == 0xf0: ins = self.rr(f'mov{px}', ins, 1)                                                                                  # Mov, read 1
      elif int.from_bytes(byt) == 0x0f:
        self.file_counter += 1
        x = int.from_bytes(f[p + self.file_counter:p + self.file_counter + 1]); y = int.from_bytes(f[p + self.file_counter + 1:p + self.file_counter + 2])
        if   (0xf0 & x) == 0x10 and (0xf0 & y) == 0x40: ins = self.rr(f'nopl{px}', ins, 2)                                                          # Nopl, read 2
        elif (0xf0 & x) == 0x10 and (0xf0 & y) == 0x80: ins = self.rr(f'nopl{px}', ins, 5)                                                          # Nopl, read 5
        elif (0xf0 & x) == 0x10 and (0xf0 & y) == 0x0:  ins = self.rr(f'nopl{px}', ins, 1)                                                          # Nopl, read 1
        elif (0xf0 & x) == 0xb0: ins = self.rr(f'movzbl{px}', ins, 3)                                                                               # Mov, read 3
        elif (0xf0 & x) == 0xa0: ins = self.rr(f'cpuid{px}', ins, 1)                                                                                # cpuid, read 1
      elif int.from_bytes(byt) == 0x81 and (cond or bit64):
        self.file_counter += 1; x = int.from_bytes(f[p + self.file_counter:p + self.file_counter + 1])
        if   (0xf0 & x) == 0xf0: ins = self.rr(f'cmp{px}', ins, 5)                                                                                  # Cmp, read 5
      elif int.from_bytes(byt) == 0x8d and bit64:
        self.file_counter += 1; x = int.from_bytes(f[p + self.file_counter:p + self.file_counter + 1])
        if   (0xf0 & x) == 0x10: ins = self.rr(f'leaq{px}', ins, 2)                                                                                 # leaq, read 2
        elif (0xf0 & x) == 0x00: ins = self.rr(f'leaq{px}', ins, 5)                                                                                 # leaq, read 5
        elif (0xf0 & x) == 0x30: ins = self.rr(f'leaq{px}', ins, 5)                                                                                 # leaq, read 5
      elif int.from_bytes(byt) == 0xc1:
        self.file_counter += 1; x = int.from_bytes(f[p + self.file_counter:p + self.file_counter + 1])
        if   (0xf0 & x) == 0xe0: ins = self.rr(f'shr{px}', ins, 3); self.file_counter -= 1                                                          # Shr
        elif (0xf0 & x) == 0xf0: ins = self.rr(f'sar{px}', ins, 3); self.file_counter -= 1                                                          # Sar
      elif int.from_bytes(byt) == 0xcc: ins = self.rr(f'int13{px}', ins, 1)                                                                         # Int13
      elif int.from_bytes(byt) == 0xc3: ins = self.rr(f'retq{px}', ins, 1)                                                                          # Retq
      elif int.from_bytes(byt) == 0x98: ins = self.rr(f'cltq{px}', ins, 1)                                                                          # Retq
      elif int.from_bytes(byt) == 0x39: ins = self.rr(f'cmpq{px}', ins, 2)                                                                          # Cmpq
      elif int.from_bytes(byt) == 0xe8: ins = self.rr(f'call{px}', ins, 5)                                                                          # Call
      elif int.from_bytes(byt) == 0x85: ins = self.rr(f'test{px}', ins, 2)                                                                          # Test
      elif int.from_bytes(byt) == 0x29: ins = self.rr(f'sub{px}', ins, 2)                                                                           # Sub
      elif int.from_bytes(byt) == 0xd1: ins = self.rr(f'sar{px}', ins, 2)                                                                           # Sar
      elif int.from_bytes(byt) == 0x45: ins = self.rr(f'xor{px}', ins, 3)                                                                           # Xor
      elif int.from_bytes(byt) == 0xe9: ins = self.rr(f'jmp{px}', ins, 5)                                                                           # Jmp
      elif int.from_bytes(byt) == 0xbb: ins = self.rr(f'mov{px}', ins, 5)                                                                           # Mov
      elif int.from_bytes(byt) == 0x01: ins = self.rr(f'add{px}', ins, 3)                                                                           # Mov
      elif int.from_bytes(byt) == 0xb9: ins = self.rr(f'mov{px}', ins, 5)                                                                           # Mov
      elif int.from_bytes(byt) == 0xeb: ins = self.rr(f'jmp{px}', ins, 2)                                                                           # Jmp
      elif int.from_bytes(byt) == 0x89: ins = self.rr(f'mov{px}', ins, 2)                                                                           # Mov
      elif int.from_bytes(byt) == 0x8b: ins = self.rr(f'mov{px}', ins, 3)                                                                           # Mov
      elif int.from_bytes(byt) == 0x63: ins = self.rr(f'mov{px}', ins, 2)                                                                           # Mov
      elif int.from_bytes(byt) == 0x75: ins = self.rr(f'jne{px}', ins, 2)                                                                           # Jne
      elif int.from_bytes(byt) == 0x7e: ins = self.rr(f'jle{px}', ins, 2)                                                                           # Jle
      elif int.from_bytes(byt) == 0x73: ins = self.rr(f'jae{px}', ins, 2)                                                                           # Jae
      elif int.from_bytes(byt) == 0x31: ins = self.rr(f'xor{px}', ins, 2)                                                                           # Xor
      elif int.from_bytes(byt) == 0x80: ins = self.rr(f'cmp{px}', ins, 7)                                                                           # Jb
      elif int.from_bytes(byt) == 0xc6: ins = self.rr(f'mov{px}', ins, 7)                                                                           # Jb
      elif int.from_bytes(byt) == 0xc7: ins = self.rr(f'mov{px}', ins, 7)                                                                           # Jb
      elif int.from_bytes(byt) == 0x74: ins = self.rr(f'je{px}', ins, 2)                                                                            # Je
      elif int.from_bytes(byt) == 0x72: ins = self.rr(f'jb{px}', ins, 2)                                                                            # Jb
      elif int.from_bytes(byt) >= 0xb0 and int.from_bytes(byt) < 0xb8: ins = self.rr(f'mov{px}', ins, 4)                                            # Mov 32bit
      elif int.from_bytes(byt) >= 0xb8 and int.from_bytes(byt) < 0xc0: ins = self.rr(f'mov{px}', ins, 4)                                            # Mov 64bit
      elif int.from_bytes(byt) >= 0x54 and int.from_bytes(byt) < 0x58 and cond: ins.append(f'push{px} {reg[int.from_bytes(byt) - 0x48]}'); self.file_counter += 1  # Push
      elif int.from_bytes(byt) >= 0x50 and int.from_bytes(byt) < 0x56: ins.append(f'push{px} {reg[int.from_bytes(byt) - 0x50]}'); self.file_counter += 1           # Push
      elif int.from_bytes(byt) >= 0x5c and int.from_bytes(byt) <= 0x5f: ins.append(f'pop{px} {reg[int.from_bytes(byt) - 0x50]}'); self.file_counter += 1           # Pop
      elif int.from_bytes(byt) == 0x68 and int.from_bytes(f[p + self.file_counter + 1:p + self.file_counter + 2]) >= 0x00 and int.from_bytes(f[p + self.file_counter + 1:p + self.file_counter + 2]) < 0x0f:
        ins = self.rr(f'push{px}', ins, 2)                                                                                                          # Push
        while int.from_bytes(f[p + self.file_counter:p + self.file_counter + 1]) == 0: self.file_counter += 1;
      elif int.from_bytes(byt) >= 0x58 and int.from_bytes(byt) < 0x60: ins.append(f'pop{px} {reg[int.from_bytes(byt) - 0x58]}'); self.file_counter += 1            # Pop
      elif int.from_bytes(byt) == 0x0f and int.from_bytes(f[p + self.file_counter + 1:p + self.file_counter + 2]) == 0x1f:                          # Nopl
        ins = self.rr(f'nop{px}', ins, 2)
        while int.from_bytes(f[p + self.file_counter + 1:p + self.file_counter + 2]) == 0x00: self.file_counter += 1
      elif int.from_bytes(byt) == 0x90: ins = self.rr(f'nop{px}', ins, 1)                                                                           # Nop
      elif bit64: ins.append(f'noop')
      else: self.file_counter += 1
      hx.append(hex(int.from_bytes(byt)))
      bi.append(bin(int.from_bytes(byt)))
      b.append(byt)
    return hx, bi, ins, b                                                                                                                           # return hex, binary, asm, bytes
  def get_segment_positions(self):
    header = self.file[:64]
    e_shoff = int.from_bytes(header[40:47][::-1])
    e_shentsize = int.from_bytes(header[58:59][::-1])
    e_shnum = int.from_bytes(header[60:61][::-1])
    shdr = list(range(e_shentsize))
    for i,j in enumerate(range(e_shoff, e_shoff + (e_shnum * e_shentsize), e_shentsize)): shdr[i] = self.file[j:j + (e_shentsize - 1)]
    strs, i, d, soff = 0, 0, b'', int.from_bytes(shdr[e_shnum-1][24:31][::-1])
    while strs < e_shnum:
      d += self.file[soff+i:soff+i+1]
      if d[-1].to_bytes() == b'\x00': strs += 1 # find end of string, increase number of strings
      i += 1
    names, nr = d.decode().split('\x00'), list(range(e_shnum))
    for i in range(e_shnum): nr[i] = (int.from_bytes(shdr[i][0:3][::-1]), int.from_bytes(shdr[i][24:31][::-1]))
    return sorted(nr)[names.index('.init') + 1][1], sorted(nr)[names.index('.fini') + 1][1], sorted(nr)[names.index('.rodata') + 1][1]
