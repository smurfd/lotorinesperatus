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


class Amd64_elf:
  def __init__(self, fn) -> None:
    self.header, self.proghd, self.secthd, self.data, self.file, self.fn = [], [], [], [], [], fn
    self.hhh = []
    hl, ll, sl = self.get_lengths()
    with open(self.fn, 'rb') as f:
      self.file = f.read(); p1, p2 = 0, hl
      self.h = self.file[p1:p2]; p1, p2 = hl, hl + ll
      self.p = self.file[p1:p2]; p1, p2 = p2, p2 + sl + 3
      self.s = self.file[p1:p2]
      self.d = self.file[p2:]
      self.hhh = self.file[:1192]
  def get_hhh(self): return self.hhh
  def get_lengths(self) -> Tuple:
    return 64, 72, 65                              # Length of header, proghd, secthd
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
    self.proghd.append(self.p[56:64])              # Size in bytes of the segment in memory
    self.proghd.append(self.p[64:72])              # Alignment
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
  def get_instructions(self, i) -> Literal:
    if   i[:23] == '0b100100111000001111111': return f'sarq ${hex(int(i[29:34], 2))}, %r{int(i[2:7], 2):x}'
    elif i[:23] == '0b100100110000011111111': return f'cmpq ${hex(int(i[29:34], 2))}, %r{int(i[2:7], 2):x}'
    elif i[:23] == '0b100100110000011110101': return f'adcq ${hex(int(i[29:34], 2))}, %r{int(i[2:7], 2):x}'
    elif i[:22] == '0b10010001000110100000': return f'leaq {hex(int(i[36:41], 2))}{int(i[25:33], 2):x}(%rip), %rdi'
    elif i[:22] == '0b10010001111111111001': return f'decq {self.get_register(i, "decq", 0)}'
    elif i[:22] == '0b10010001111111111000': return f'incq {self.get_register(i, "incq", 0)}'
    elif i[:21] == '0b1001000100000111110': return f'subq ${hex(int(i[29:34], 2))}, %rsp'
    elif i[:21] == '0b1001000100000111100': return f'addq ${hex(int(i[28:34], 2))}, %rsp'
    elif i[:21] == '0b1001000100000111111': return f'cmpq ${hex(int(i[29:34], 2))}, %rax'
    elif i[:21] == '0b1001000110000011110': return f'shrq ${hex(int(i[27:34], 2))}, %rsi'
    elif i[:21] == '0b1001000110000011111': return f'sarq ${hex(int(i[29:34], 2))}, %rax'
    elif i[:20] == '0b100100010001101001': return f'leaq {hex(int(i[36:41], 2))}{int(i[25:33], 2):x}(%rip), %rdi'
    elif i[:20] == '0b100100010001101000': return f'leaq (%rdi,%rax,8), %rbx'
    elif i[:20] == '0b100010100110001111': return f'xorl %r{int(i[2:7], 2)+2:x}d, %r{int(i[2:7], 2)+2:x}d'
    elif i[:20] == '0b100100111111111110': return f'incq %r{int(i[2:7], 2)+1:x}'
    elif i[:20] == '0b100110100111001111': return f'cmpq %r{int(i[2:7], 2):x}, %r{int(i[8:13], 2)-1:x}'
    elif i[:19] == '0b10010010010100111': return f'subq %rax, %r{int(i[2:7], 2):x}'
    elif i[:18] == '0b1001000100000110': return f'cmpq {hex(int(i[41:46], 2))}, {hex(int(i[36:41], 2))}{int(i[25:33], 2):x}(%rip)'
    elif i[:18] == '0b1111111111100000': return f'jmpq *{self.get_register(i, "jmpq", 0)}'
    elif i[:17] == '0b111010100010111': return f'jne 0x400xxx <'
    elif i[:17] == '0b111010000111111': return f'callq 0x400xxx <>'
    elif i[:17] == '0b111010000000000': return f'callq 0x400xxx <'
    elif i[:17] == '0b100100110000011': return f'addq ${hex(int(i[28:34], 2))}, %r14'
    elif i[:16] == '0b10010001000000': return f'cmpq $0x401xxx, %rbx'
    elif i[:16] == '0b10000011111110': return f'cmpl ${hex(int(i[20:26], 2))}, %ecx'
    elif i[:16] == '0b10000011011111': return f'cmpl ${hex(int(i[20:26], 2))}, %ecx'
    elif i[:16] == '0b10000011111111': return f'callq *x{int(i[28:33], 2):x}(%r13)'
    elif i[:16] == '0b10010001000001': return f'addq {hex(int(i[28:33], 2))}, %rbx'
    elif i[:16] == '0b11101000100001': return f'callq 0x400xxx <'
    elif i[:18] == '0b1110100000100100': return f'callq 0x400xxx <'
    elif i[:17] == '0b111010000010010': return f'je 0x400xxx'
    elif i[:17] == '0b111010000010101': return f'je 0x400xxx'
    elif i[:17] == '0b111010000001001': return f'je 0x400xxx'
    elif i[:17] == '0b111010000010100': return f'je 0x400xxx'
    elif i[:17] == '0b111010000001000': return f'je 0x400xxx'
    elif i[:17] == '0b111010000011011': return f'je 0x400xxx'
    elif i[:15] == '0b1110100111000': return f'jmp 0x400xxx <'
    elif i[:15] == '0b1110100111010': return f'jmp 0x400xxx <'
    elif i[:15] == '0b1110100111011': return f'je 0x400xxx <'
    elif i[:16] == '0b10111111001100': return f'movl $0x401xxx, %edi'
    elif i[:16] == '0b11101000110000': return f'callq 0x400xxx'
    elif i[:16] == '0b10010001101000': return f'sarq %rsi'
    elif i[:16] == '0b11101011100011': return f'jmp 0x400xxx'
    elif i[:16] == '0b10010101000101': return f'movq 0x401xxx(,%r13,8), {self.get_register(i, "movq", 3)}'
    elif i[:15] == '0b1000000000111': return f'cmpb {hex(int(i[16:17], 2))}, ${hex(int(i[29:34], 2))}{int(i[18:26], 2):02x}(%rip)'
    elif i[:15] == '0b1001000001010': return f'subq %rdi, %rsi'
    elif i[:15] == '0b1001000000000': return f'addq %rax, %rsi'
    elif i[:15] == '0b1110100000001': return f'callq 0x400xxx <'
    elif i[:15] == '0b1000001010101': return f'pushq %r{12+int(i[15:17], 2)}'
    elif i[:15] == '0b1000001010111': return f'popq %r{12+int(i[15:17], 2)}'
    elif i[:15] == '0b0010001000001': return f'cmpq ${hex(int(i[29:34], 2))}, %rax'
    elif i[:15] == '0b1110101111100': return f'jne 0x400xxx <'
    elif i[:15] == '0b1110101110001': return f'jne 0x400xxx <'
    elif i[:14] == '0b111010001110': return f'callq 0x400xxx <'
    elif i[:14] == '0b111010000001': return f'callq 0x400xxx <'
    elif i[:14] == '0b111010000010': return f'callq 0x400xxx <'
    elif i[:14] == '0b111010000011': return f'callq 0x400xxx <'
    elif i[:14] == '0b111010001100': return f'callq 0x400xxx'
    elif i[:14] == '0b111010111011': return f'jmp 0x400xxx <'
    elif i[:14] == '0b111111110011': return f'pushq *{hex(int(i[29:34], 2))}{int(i[18:26], 2):x}(%rip)'
    elif i[:14] == '0b101111110011': return f'pushq *{hex(int(i[29:34], 2))}{int(i[18:26], 2):x}(%rip)'
    elif i[:14] == '0b111111110010': return f'jmpq *{hex(int(i[29:34], 2))}{int(i[18:26], 2):x}(%rip)'
    elif i[:14] == '0b110100000000': return f'pushq ${hex(int(i[15:17], 2))}'
    elif i[:14] == '0b100000110100': return f'addl $0x1, -0x4(%rbp)'
    elif i[:14] == '0b111010010000': return f'jmp 0x400864 <_fini>'
    elif i[:14] == '0b110001110100': return f'movl $0x0, -0x4(%rbp)'
    elif i[:14] == '0b100010110100': return f'movl -0x4(%rbp), %eax'
    elif i[:14] == '0b100100010011': return f'cltq'
    elif i[:14] == '0b111111011101': return f'jle 0x400823 <func+0x11>'
    elif i[:14] == '0b101111110110': return f'movl $0xxxxx, %edi'
    elif i[:14] == '0b111100011111': return f'nopl (%rax)'
    elif i[:14] == '0b100100000101': return f'subq %rdi, %rsi'
    elif i[:14] == '0b100100000000': return f'addq %rax, %rsi'
    elif i[:14] == '0b100000110001': return f'movl %edi, %r15d'
    elif i[:14] == '0b100100110001': return f'movq %rsi, %r14'
    elif i[:14] == '0b100100010001': return f'movq {self.get_register(i, "movq", 1)}, {self.get_register(i, "movq", 0)}'
    elif i[:14] == '0b100110110001': return f'movq (%r{int(i[2:7], 2):x}), %r{int(i[2:7], 2)-1:x}'
    elif i[:14] == '0b100100010000': return f'testq %rax, %rax'
    elif i[:14] == '0b100100010110': return f'sarq %rsi'
    elif i[:14] == '0b111010111000': return f'jmp 0x400xxx'
    elif i[:14] == '0b100100110000': return f'cmpq $0x401xxx, %r12'
    elif i[:14] == '0b111001101001': return f'jae 0x400xxx'
    elif i[:14] == '0b100010010001': return f'movl %r15d, %edi'
    elif i[:14] == '0b100110010001': return f'movq %r14, %rsi'
    elif i[:14] == '0b100100110000': return f'cmpq $0x401xxx, %r12'
    elif i[:14] == '0b101110001100': return f'movl $0x401xxx, %eax'
    elif i[:14] == '0b111110110110': return f'movzbl -{hex(int(i[29:34], 2))}(%rax), %ecx'
    elif i[:14] == '0b100000110000': return f'cmpl ${hex(int(i[35:41], 2))}, {hex(int(i[29:33], 2))}(%r13)'
    elif i[:14] == '0b100100000111': return f'cmpq %rdi, %rax'
    elif i[:14] == '0b111110100010': return f'cpuid'
    elif i[:14] == '0b100100101100': return f'movslq %r15d, %rax'
    elif i[:14] == '0b100010110000': return f'testl %r15d, %r15d'
    elif i[:14] == '0b100001011100': return f'testl %ecx, %ecx'
    elif i[:14] == '0b111010001101': return f'callq 0x400xxx'
    elif i[:14] == '0b101111110001': return f'movl $0x401xxx, %edi'
    elif i[:14] == '0b100000110111': return f'movl $0x401xxx, %r12d'
    elif i[:13] == '0b11101000000': return f'je 0x400xxx <'
    elif i[:13] == '0b11101011000': return f'jmp 0x400xxx <'
    elif i[:13] == '0b10001001110': return f'movl %eax, %edi'
    elif i[:13] == '0b10010001111': return f'decq %rbx'
    elif i[:12] == '0b1110101111': return f'jmp 0x400xxx'
    elif i[:12] == '0b1111111111': return f'callq *%rax'
    elif i[:12] == '0b1110010111': return f'jb 0x400xxx'
    elif i[:12] == '0b1100011100': return f'xorl %ecx, %ecx'
    elif i[:12] == '0b1111110001': return f'jle 0x400xxx'
    elif i[:12] == '0b1110010000': return f'jb 0x400xxx'
    elif i[:12] == '0b1110100000': return f'je 0x400xxx'
    elif i[:12] == '0b1110100001': return f'je 0x400xxx'
    elif i[:12] == '0b1100110001': return f'nopw (%rax,%rax)'
    elif i[:12] == '0b1100110000': return f'nopw (%rax,%rax)'
    elif i[:12] == '0b1100110011': return f'nopw %cs:(%rax,%rax)'
    elif i[:11] == '0b110001100': return f'movb {hex(int(i[15:16], 2))}, ${hex(int(i[29:34], 2))}{int(i[18:26], 2):02x}(%rip)'
    elif i[:11] == '0b111010011': return f'jmp 0x4004c0 <.plt>'
    elif i[:11] == '0b111010001': return f'je 0x400xxx'
    elif i[:11] == '0b111010000': return f'callq 0x400xxx'
    elif i[:10] == '0b11001101': return f'nop'
    elif i[:10] == '0b10010000': return f'nop'
    elif i[:10] == '0b11000011': return f'retq'
    elif i      == '0b1010101': return f'pushq {self.get_register(i, "pushq", 0)}'
    elif i      == '0b1011101': return f'popq %rpb'
    elif i[:9]  == '0b1011101': return f'movl $0x401xxx, %ebx'
    elif i[:9]  == '0b1011100': return f'movl {hex(int(i[29:34], 2))}, %eax'
    elif i[:9]  == '0b1011011': return f'popq %rbx'
    elif i[:9]  == '0b1110101': return f'jne 0x400xxx'
    elif i[:9]  == '0b1010011': return f'pushq {self.get_register(i, "pushq", 0)}'
    elif i[:9]  == '0b1010000': return f'pushq {self.get_register(i, "pushq", 0)}'
    elif i      == '0b11001100': return f'int3'
    elif i      != '0b0': return f'NOOP'  # catch all
  def get_assembly(self, n) -> List:  # Hex, binary, instruction, bytes
    i, ins, hx, bi, b, co, p = 0, [], [], [], [], 0, 1192  # 1192 = 0x4004a8 - 0x4a8
    # TODO: How do we get these programmaticly?!?! manually fetched from objdump file
    if n == 1:  # Hello example
      op_bytes = [
      4, 4, 1,
      15,
      6, 6, 4,
      6, 5, 5,
      6, 5, 5,
      6, 5, 5,
      6, 5, 5,
      1, 3, 2, 2, 2, 2, 1, 1, 3, 3, 3, 4, 4, 8, 2, 7, 4, 3, 2, 3, 3, 2, 15, 7, 3, 4, 3, 2, 2, 2, 5, 3, 2, 4, 6, 2, 3, 4, 7, # belongs to below
        2, 5, 2, 2, 2, 2, 2, 5, 5, 3, 2, 2, 5, 2, 5, 2, 4, 2, 4, 4, 2, 3, 5, 2, 5, 4, 3, 3, 3, 5, 3, 3, 3, 5, 2, 5, 15,     #
      5, 3, 2, 1, 1, 3, 2, 2, 2, 2, 1, 1, 3, 3, 3, 5, 5, 6, 7, 2, 5, 3, 4, 4, 4, 3, 2, 12, 3, 3, 2, 8, 4, 2, 3, 3, 3, 2,    # belongs to below
        2, 5, 6, 7, 2, 5, 3, 4, 4, 4, 3, 2, 3, 3, 2, 8, 4, 2, 3, 3, 3, 2, 2, 4, 1, 2, 2, 2, 2, 1, 1, 14,                    #
      1, 3, 1, 1, 5, 7, 2, 5, 3, 4, 2, 14, 3, 2, 8, 4, 2, 2, 2, 4, 1, 1, 5, 1, 1, 10, 2,
      7, 7, 3, 2, 7, 3, 2, 2, 7, 1, 7,
      7, 7, 3, 3, 4, 4, 3, 3, 2, 7, 3, 2, 2, 6, 1, 7,
      7, 2, 1, 3, 5, 7, 1, 1, 5, 1, 11, 4,
      2,
      1, 3, 5, 5, 5, 1, 1, 1,
      4, 4, 1]
    elif n == 2:  # Func example
      op_bytes = [
      4, 4, 1,
      15,
      6, 6, 4,
      6, 5, 5,
      6, 5, 5,
      6, 5, 5,
      6, 5, 5,
      1, 3, 2, 2, 2, 2, 1, 1, 3, 3, 3, 4, 4, 8, 2, 7, 4, 3, 2, 3, 3, 2, 15, 7, 3, 4, 3, 2, 2, 2, 5, 3, 2, 4, 6, 2, 3, 4, 7, # belongs to below
        2, 5, 2, 2, 2, 2, 2, 5, 5, 3, 2, 2, 5, 2, 5, 2, 4, 2, 4, 4, 2, 3, 5, 2, 5, 4, 3, 3, 3, 5, 3, 3, 3, 5, 2, 5, 15,     #
      5, 3, 2, 1, 1, 3, 2, 2, 2, 2, 1, 1, 3, 3, 3, 5, 5, 6, 7, 2, 5, 3, 4, 4, 4, 3, 2, 12, 3, 3, 2, 8, 4, 2, 3, 3, 3, 2,    # belongs to below
        2, 5, 6, 7, 2, 5, 3, 4, 4, 4, 3, 2, 3, 3, 2, 8, 4, 2, 3, 3, 3, 2, 2, 4, 1, 2, 2, 2, 2, 1, 1, 14,                    #
      1, 3, 1, 1, 5, 7, 2, 5, 3, 4, 2, 14, 3, 2, 8, 4, 2, 2, 2, 4, 1, 1, 5, 1, 1, 10, 2,
      7, 7, 3, 2, 7, 3, 2, 2, 7, 1, 7,
      7, 7, 3, 3, 4, 4, 3, 3, 2, 7, 3, 2, 2, 6, 1, 7,
      7, 2, 1, 3, 5, 7, 1, 1, 5, 1, 11, 4,
      2,
      1, 3, 4, 7, 2, 3, 2, 4, 4, 4, 2, 4, 1, 1,
      1, 3, 5, 5, 2, 5, 5, 5, 5, 1, 1, 2,
      4, 4, 1]
    for j, i in enumerate(op_bytes):
      byt = self.file[p + co:p + co + i]
      ins.append(self.get_instructions(bin(int.from_bytes(byt))))
      hx.append(hex(int.from_bytes(byt)))
      bi.append(bin(int.from_bytes(byt)))
      b.append(byt)
      co += i
    return hx, bi, ins, b
  def get_assembly_correctly(self) -> List:
    reg = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']
    byt, co, p = b'', 0, 1192  # 1192 = 0x4004a8 - 0x4a8
    while p + co < len(self.file) and co < 910:  # TODO: how to find the 910 programaticly?
      bit16, bit64, cond, chk, byt = False, False, False, False, self.file[p + co:p + co + 1]
      # TODO: when we know this works, remove prints
      # TODO: movq instead of mov, for 64bit, movl for 32bit etc...
      if   int.from_bytes(byt) == 0x48: print(f'64bit op size ', end=''); co += 1; bit64 = True; byt = self.file[p + co:p + co + 1]  # 64bit op
      elif int.from_bytes(byt) == 0x66: print(f'16bit op size ', end=''); co += 1; bit16 = True; byt = self.file[p+co:p+co+1]        # 16bit op
      elif int.from_bytes(byt) == 0x49: print(f'Conditional ', end=''); co += 1; cond = True; byt = self.file[p+co:p+co+1]           # Conditional
      elif int.from_bytes(byt) == 0x41: print(f'Conditional ', end=''); co += 1; cond = True; byt = self.file[p+co:p+co+1]           # Conditional
      elif int.from_bytes(byt) == 0x4c: print(f'4c ', end=''); co += 1; byt = self.file[p+co:p+co+1]                                 # Check
      elif int.from_bytes(byt) == 0x4d: print(f'4d ', end=''); co += 1; chk = True; byt = self.file[p+co:p+co+1]                     # Check

      if bit16:
        x = int.from_bytes(self.file[p+co+1:p+co+2]); y = int.from_bytes(self.file[p+co+2:p+co+3])
        if int.from_bytes(byt) == 0x90: print(f'nop'); co += 1;  # Nop
        elif  int.from_bytes(byt) == 0x0f and (0xf0 & x) == 0x10 and (0xf0 & y) == 0x40: print(f'nopl {hex(int.from_bytes(self.file[p+co:p+co+2]))}'); co += 2;        # Nopl, read 2
        elif int.from_bytes(byt) == 0x66 or int.from_bytes(byt) == 0x2e:
          co += 1;
          while int.from_bytes(self.file[p+co:p+co+1]) == 0x66: co += 1;
          print(f'nopw {self.file[p+co:p+co+8]}'); co += 8;
        else: print(f'noop')
      elif chk:
        if   int.from_bytes(byt) == 0x8b: print(f'mov {hex(int.from_bytes(self.file[p+co:p+co+3]))}'); co += 3;  # Mov, read 3
        elif int.from_bytes(byt) == 0x39: print(f'cmp {hex(int.from_bytes(self.file[p+co:p+co+2]))}'); co += 2;  # Cmp, read 2

      elif int.from_bytes(byt) == 0x83:  # Add / Sub / Cmp
        co += 1; x = int.from_bytes(self.file[p+co:p+co+1])
        if   (0xf0 & x) == 0xe0: print(f'sub {hex(int.from_bytes(self.file[p+co:p+co+2]))}'); co += 2;         # Sub, read 2
        elif (0xf0 & x) == 0x40: print(f'add {hex(int.from_bytes(self.file[p+co:p+co+4]))}'); co += 4;         # Add, read 4
        elif (0xf0 & x) == 0xc0: print(f'add {hex(int.from_bytes(self.file[p+co:p+co+2]))}'); co += 2;         # Add, read 2
        elif (0xf0 & x) == 0xf0: print(f'cmp {hex(int.from_bytes(self.file[p+co:p+co+2]))}'); co += 2;         # Cmp, read 2
        elif (0xf0 & x) == 0xd0: print(f'adc {hex(int.from_bytes(self.file[p+co:p+co+2]))}'); co += 2;         # Adc, read 2
        elif (0xf0 & x) == 0x70: print(f'cmp {hex(int.from_bytes(self.file[p+co:p+co+3]))}'); co += 3;         # Cmp, read 3
        elif (0xf0 & x) == 0x30: print(f'cmp {hex(int.from_bytes(self.file[p+co:p+co+6]))}'); co += 6;         # Cmp, read 6
        elif (0xf0 & x) == 0x80: print(f'mov {hex(int.from_bytes(self.file[p+co:p+co+2]))}'); co += 2;         # Mov, read 2
      elif int.from_bytes(byt) == 0xff:
        if   int.from_bytes(self.file[p+co+1:p+co+2]) == 0x25: print(f'jmp'); co += 6;                         # Jmp
        elif int.from_bytes(self.file[p+co+1:p+co+2]) == 0x35: print(f'push'); co += 6;                        # Push
        elif int.from_bytes(self.file[p+co+1:p+co+2]) == 0x55: print(f'call'); co += 2;                        # Call
        elif int.from_bytes(self.file[p+co+1:p+co+2]) == 0xe0: print(f'jmp'); co += 2;                        # Call
        elif int.from_bytes(self.file[p+co+1:p+co+2]) == 0xd0: print(f'call'); co += 2;                        # Call
        elif int.from_bytes(self.file[p+co+1:p+co+2]) == 0xc0: print(f'incq'); co += 2;                        # Incq
        elif int.from_bytes(self.file[p+co+1:p+co+2]) == 0xcb: print(f'decq'); co += 2;                        # Incq
        elif int.from_bytes(self.file[p+co+1:p+co+2]) == 0xc5: print(f'incq'); co += 2;                        # Incq
        else: co += 1
      elif int.from_bytes(byt) == 0x45:
        if   int.from_bytes(self.file[p+co+1:p+co+2]) == 0x31: print(f'xor'); co += 2;                         # Jmp
        elif int.from_bytes(self.file[p+co+1:p+co+2]) == 0x85: print(f'test'); co += 2;                        # Push
        else: co += 1
      elif int.from_bytes(byt) == 0x89 and bit64:
        co += 1; x = int.from_bytes(self.file[p+co:p+co+1])
        if   (0xf0 & x) == 0xd0: print(f'mov {hex(int.from_bytes(self.file[p+co:p+co+1]))}'); co += 1;         # Mov, read 1
        elif (0xf0 & x) == 0xe0: print(f'mov {hex(int.from_bytes(self.file[p+co:p+co+1]))}'); co += 1;         # Mov, read 1
        elif (0xf0 & x) == 0xf0: print(f'mov {hex(int.from_bytes(self.file[p+co:p+co+1]))}'); co += 1;         # Mov, read 1
        elif (0xf0 & x) == 0x50: print(f'mov {hex(int.from_bytes(self.file[p+co:p+co+2]))}'); co += 2;         # Mov, read 2
        elif (0xf0 & x) == 0x10: print(f'mov {hex(int.from_bytes(self.file[p+co:p+co+5]))}'); co += 5;         # Mov, read 5
        elif (0xf0 & x) == 0x0:  print(f'mov {hex(int.from_bytes(self.file[p+co:p+co+5]))}'); co += 5;         # Mov, read 5
      elif int.from_bytes(byt) == 0x89 and cond:
        co += 1; x = int.from_bytes(self.file[p+co:p+co+1]);
        if   (0xf0 & x) == 0x0: print(f'mov {hex(int.from_bytes(self.file[p+co:p+co+2]))}'); co += 2;          # Mov, read 1
        elif (0xf0 & x) == 0xf0: print(f'mov {hex(int.from_bytes(self.file[p+co:p+co+1]))}'); co += 1;          # Mov, read 1
      elif int.from_bytes(byt) == 0x0f:
        co += 1; x = int.from_bytes(self.file[p+co:p+co+1]); y = int.from_bytes(self.file[p+co+1:p+co+2])
        if   (0xf0 & x) == 0x10 and (0xf0 & y) == 0x40: print(f'nopl {hex(int.from_bytes(self.file[p+co:p+co+2]))}'); co += 2;        # Nopl, read 2
        elif (0xf0 & x) == 0x10 and (0xf0 & y) == 0x80: print(f'nopl {hex(int.from_bytes(self.file[p+co:p+co+5]))}'); co += 5;        # Nopl, read 2
        elif (0xf0 & x) == 0x10 and (0xf0 & y) == 0x0: print(f'nopl {hex(int.from_bytes(self.file[p+co:p+co+1]))}'); co += 1;        # Nopl, read 2
        elif (0xf0 & x) == 0xb0: print(f'movzbl {hex(int.from_bytes(self.file[p+co:p+co+3]))}'); co += 3;      # Mov, read 3
        elif (0xf0 & x) == 0xa0: print(f'cpuid {hex(int.from_bytes(self.file[p+co:p+co+1]))}'); co += 1;       # cpuid, read 1
      elif int.from_bytes(byt) == 0x81 and (cond or bit64):
        co += 1; x = int.from_bytes(self.file[p+co:p+co+1])
        if   (0xf0 & x) == 0xf0: print(f'cmp {hex(int.from_bytes(self.file[p+co:p+co+5]))}'); co += 5;         # Cmp, read 5
      elif int.from_bytes(byt) == 0x8d and bit64:
        co += 1; x = int.from_bytes(self.file[p+co:p+co+1])
        if   (0xf0 & x) == 0x10: print(f'leaq {hex(int.from_bytes(self.file[p+co:p+co+2]))}'); co += 2;        # Nopl, read 2
        elif (0xf0 & x) == 0x00: print(f'leaq {hex(int.from_bytes(self.file[p+co:p+co+5]))}'); co += 5;        # Nopl, read 2
        elif (0xf0 & x) == 0x30: print(f'leaq {hex(int.from_bytes(self.file[p+co:p+co+5]))}'); co += 5;        # Nopl, read 2


      elif int.from_bytes(byt) == 0xcc: print(f'int13 {self.file[p+co+0:p+co+1]}'); co += 1                    # Int13
      elif int.from_bytes(byt) == 0xc3: print(f'retq {self.file[p+co+0:p+co+1]}'); co += 1                     # Retq
      elif int.from_bytes(byt) == 0x39: print(f'cmpq {self.file[p+co+1:p+co+2]}'); co += 2                     # Leaq
      elif int.from_bytes(byt) == 0xe8: print(f'call {self.file[p+co+1:p+co+5]}'); co += 5                     # Call
      elif int.from_bytes(byt) == 0x85: print(f'test {self.file[p+co+1:p+co+2]}'); co += 2                     # Test

      elif int.from_bytes(byt) == 0x29: print(f'sub {self.file[p+co+1:p+co+2]}'); co += 2                      # Sub
      elif int.from_bytes(byt) == 0xc1: print(f'sar {self.file[p+co+1:p+co+3]}'); co += 3                      # Sar
      elif int.from_bytes(byt) == 0xd1: print(f'sar {self.file[p+co+1:p+co+2]}'); co += 2                      # Sar
      elif int.from_bytes(byt) == 0x45: print(f'xor {self.file[p+co+1:p+co+3]}'); co += 3                      # Xor

      elif int.from_bytes(byt) == 0xe9: print(f'jmp {self.file[p+co+1:p+co+5]}'); co += 5                      # Jmp
      elif int.from_bytes(byt) == 0xbb: print(f'mov {self.file[p+co+1:p+co+5]}'); co += 5                      # Mov
      elif int.from_bytes(byt) == 0x01: print(f'add {self.file[p+co+1:p+co+2]}'); co += 2                      # Mov
      elif int.from_bytes(byt) == 0xb9: print(f'mov {self.file[p+co+1:p+co+5]}'); co += 5                      # Mov
      elif int.from_bytes(byt) == 0xeb: print(f'jmp {self.file[p+co+1:p+co+2]}'); co += 2                      # Jmp
      elif int.from_bytes(byt) == 0x89: print(f'mov {self.file[p+co+1:p+co+2]}'); co += 2                      # Mov
      elif int.from_bytes(byt) == 0x8b: print(f'mov {self.file[p+co+1:p+co+2]}'); co += 2                      # Mov
      elif int.from_bytes(byt) == 0x63: print(f'mov {self.file[p+co+1:p+co+2]}'); co += 2                      # Mov
      elif int.from_bytes(byt) == 0x75: print(f'jne {self.file[p+co+1:p+co+2]}'); co += 2                      # Jne
      elif int.from_bytes(byt) == 0x7e: print(f'jle {self.file[p+co+1:p+co+2]}'); co += 2                      # Jle
      elif int.from_bytes(byt) == 0x73: print(f'jae {self.file[p+co+1:p+co+2]}'); co += 2                      # Jae
      elif int.from_bytes(byt) == 0x31: print(f'xor {self.file[p+co+1:p+co+2]}'); co += 2                      # Xor
      elif int.from_bytes(byt) == 0x80: print(f'cmp {self.file[p+co+1:p+co+7]}'); co += 7                       # Jb
      elif int.from_bytes(byt) == 0xc6: print(f'mov {self.file[p+co+1:p+co+7]}'); co += 7                       # Jb
      elif int.from_bytes(byt) == 0x74: print(f'je {self.file[p+co+1:p+co+2]}'); co += 2                       # Je
      elif int.from_bytes(byt) == 0x72: print(f'jb {self.file[p+co+1:p+co+2]}'); co += 2                       # Jb

      elif int.from_bytes(byt) >= 0xb0 and int.from_bytes(byt) < 0xb8: print(f'mov {self.file[p+co+1:p+co+4]}'); co += 4                    # Mov 32bit
      elif int.from_bytes(byt) >= 0xb8 and int.from_bytes(byt) < 0xc0: print(f'mov {self.file[p+co+1:p+co+4]}'); co += 4                    # Mov 64bit

      elif int.from_bytes(byt) >= 0x54 and int.from_bytes(byt) < 0x58 and cond: print(f'push {reg[int.from_bytes(byt) - 0x48]}'); co += 1;  # Push
      elif int.from_bytes(byt) >= 0x50 and int.from_bytes(byt) < 0x56: print(f'push {reg[int.from_bytes(byt) - 0x50]}'); co += 1;           # Push
      elif int.from_bytes(byt) >= 0x5c and int.from_bytes(byt) <= 0x5f: print(f'pop {reg[int.from_bytes(byt) - 0x50]}'); co += 1;           # Pop
      elif int.from_bytes(byt) == 0x68 and int.from_bytes(self.file[p+co+1:p+co+2]) >= 0x00 and int.from_bytes(self.file[p+co+1:p+co+2]) < 0x0f:
          print(f'push {hex(int.from_bytes(self.file[p+co+1:p+co+2]))}'); co += 2;
          while int.from_bytes(self.file[p+co:p+co+1]) == 0: co += 1;
      elif int.from_bytes(byt) >= 0x58 and int.from_bytes(byt) < 0x60: print(f'Pop {reg[int.from_bytes(byt) - 0x58]}'); co += 1;            # Pop
      elif int.from_bytes(byt) == 0x0f and int.from_bytes(self.file[p+co+1:p+co+2]) == 0x1f:                   # Nopl
        print(f'nopl'); co += 2;
        while int.from_bytes(self.file[p+co+1:p+co+2]) == 0x00: co += 1
      elif int.from_bytes(byt) == 0x90: print(f'nop'); co += 1;                                                # Nop
      elif bit64: print(f'Noop')
      else: co = co + 1
    return byt


"""
$ objdump -d lotorinesperatus/test/examples/hello_amd64_elf.bin

lotorinesperatus/test/examples/hello_amd64_elf.bin:	file format elf64-x86-64

Disassembly of section .init:

00000000004004a8 <_init>:
  4004a8: 48 83 ec 08                  	subq	$0x8, %rsp
  4004ac: 48 83 c4 08                  	addq	$0x8, %rsp
  4004b0: c3                           	retq

Disassembly of section .plt:

00000000004004c0 <.plt>:
  4004c0: ff 35 fa 15 00 00            	pushq	0x15fa(%rip)            # 0x401ac0 <_GLOBAL_OFFSET_TABLE_+0x8>
  4004c6: ff 25 fc 15 00 00            	jmpq	*0x15fc(%rip)           # 0x401ac8 <_GLOBAL_OFFSET_TABLE_+0x10>
  4004cc: 0f 1f 40 00                  	nopl	(%rax)

00000000004004d0 <atexit@plt>:
  4004d0: ff 25 fa 15 00 00            	jmpq	*0x15fa(%rip)           # 0x401ad0 <_GLOBAL_OFFSET_TABLE_+0x18>
  4004d6: 68 00 00 00 00               	pushq	$0x0
  4004db: e9 e0 ff ff ff               	jmp	0x4004c0 <.plt>

00000000004004e0 <puts@plt>:
  4004e0: ff 25 f2 15 00 00            	jmpq	*0x15f2(%rip)           # 0x401ad8 <_GLOBAL_OFFSET_TABLE_+0x20>
  4004e6: 68 01 00 00 00               	pushq	$0x1
  4004eb: e9 d0 ff ff ff               	jmp	0x4004c0 <.plt>

00000000004004f0 <exit@plt>:
  4004f0: ff 25 ea 15 00 00            	jmpq	*0x15ea(%rip)           # 0x401ae0 <_GLOBAL_OFFSET_TABLE_+0x28>
  4004f6: 68 02 00 00 00               	pushq	$0x2
  4004fb: e9 c0 ff ff ff               	jmp	0x4004c0 <.plt>

0000000000400500 <_init_tls@plt>:
  400500: ff 25 e2 15 00 00            	jmpq	*0x15e2(%rip)           # 0x401ae8 <_GLOBAL_OFFSET_TABLE_+0x30>
  400506: 68 03 00 00 00               	pushq	$0x3
  40050b: e9 b0 ff ff ff               	jmp	0x4004c0 <.plt>

Disassembly of section .text:

0000000000400510 <_start>:
  400510: 55                           	pushq	%rbp
  400511: 48 89 e5                     	movq	%rsp, %rbp
  400514: 41 57                        	pushq	%r15
  400516: 41 56                        	pushq	%r14
  400518: 41 55                        	pushq	%r13
  40051a: 41 54                        	pushq	%r12
  40051c: 53                           	pushq	%rbx
  40051d: 50                           	pushq	%rax
  40051e: 49 89 fe                     	movq	%rdi, %r14
  400521: 4c 8b 3f                     	movq	(%rdi), %r15
  400524: 49 63 c7                     	movslq	%r15d, %rax
  400527: 48 8d 1c c7                  	leaq	(%rdi,%rax,8), %rbx
  40052b: 48 83 c3 10                  	addq	$0x10, %rbx
  40052f: 48 83 3d c9 15 00 00 00      	cmpq	$0x0, 0x15c9(%rip)      # 0x401b00 <environ>
  400537: 75 07                        	jne	0x400540 <_start+0x30>
  400539: 48 89 1d c0 15 00 00         	movq	%rbx, 0x15c0(%rip)      # 0x401b00 <environ>
  400540: 49 83 c6 08                  	addq	$0x8, %r14
  400544: 45 85 ff                     	testl	%r15d, %r15d
  400547: 7e 2e                        	jle	0x400577 <_start+0x67>
  400549: 49 8b 06                     	movq	(%r14), %rax
  40054c: 48 85 c0                     	testq	%rax, %rax
  40054f: 74 26                        	je	0x400577 <_start+0x67>
  400551: 66 66 66 66 66 66 2e 0f 1f 84 00 00 00 00 00 	nopw	%cs:(%rax,%rax)
  400560: 48 89 05 89 15 00 00         	movq	%rax, 0x1589(%rip)      # 0x401af0 <__progname>
  400567: 48 ff c0                     	incq	%rax
  40056a: 0f b6 48 ff                  	movzbl	-0x1(%rax), %ecx
  40056e: 83 f9 2f                     	cmpl	$0x2f, %ecx
  400571: 74 ed                        	je	0x400560 <_start+0x50>
  400573: 85 c9                        	testl	%ecx, %ecx
  400575: 75 f0                        	jne	0x400567 <_start+0x57>
  400577: b8 d8 18 40 00               	movl	$0x4018d8, %eax         # imm = 0x4018D8
  40057c: 48 85 c0                     	testq	%rax, %rax
  40057f: 75 5a                        	jne	0x4005db <_start+0xcb>
  400581: 48 89 5d d0                  	movq	%rbx, -0x30(%rbp)
  400585: 41 bd a8 04 40 00            	movl	$0x4004a8, %r13d        # imm = 0x4004A8
  40058b: eb 07                        	jmp	0x400594 <_start+0x84>
  40058d: 0f 1f 00                     	nopl	(%rax)
  400590: 49 83 c5 18                  	addq	$0x18, %r13
  400594: 49 81 fd a8 04 40 00         	cmpq	$0x4004a8, %r13         # imm = 0x4004A8
  40059b: 73 48                        	jae	0x4005e5 <_start+0xd5>
  40059d: b8 01 00 00 00               	movl	$0x1, %eax
  4005a2: 0f a2                        	cpuid
  4005a4: 89 d7                        	movl	%edx, %edi
  4005a6: 89 ce                        	movl	%ecx, %esi
  4005a8: 31 c0                        	xorl	%eax, %eax
  4005aa: 0f a2                        	cpuid
  4005ac: bb 00 00 00 00               	movl	$0x0, %ebx
  4005b1: b9 00 00 00 00               	movl	$0x0, %ecx
  4005b6: 83 f8 07                     	cmpl	$0x7, %eax
  4005b9: 72 09                        	jb	0x4005c4 <_start+0xb4>
  4005bb: 31 c9                        	xorl	%ecx, %ecx
  4005bd: b8 07 00 00 00               	movl	$0x7, %eax
  4005c2: 0f a2                        	cpuid
  4005c4: 41 83 7d 08 25               	cmpl	$0x25, 0x8(%r13)
  4005c9: 75 c5                        	jne	0x400590 <_start+0x80>
  4005cb: 4d 8b 65 00                  	movq	(%r13), %r12
  4005cf: 89 da                        	movl	%ebx, %edx
  4005d1: 41 ff 55 10                  	callq	*0x10(%r13)
  4005d5: 49 89 04 24                  	movq	%rax, (%r12)
  4005d9: eb b5                        	jmp	0x400590 <_start+0x80>
  4005db: 48 89 f7                     	movq	%rsi, %rdi
  4005de: e8 ed fe ff ff               	callq	0x4004d0 <atexit@plt>
  4005e3: eb 09                        	jmp	0x4005ee <_start+0xde>
  4005e5: e8 16 ff ff ff               	callq	0x400500 <_init_tls@plt>
  4005ea: 48 8b 5d d0                  	movq	-0x30(%rbp), %rbx
  4005ee: 44 89 ff                     	movl	%r15d, %edi
  4005f1: 4c 89 f6                     	movq	%r14, %rsi
  4005f4: 48 89 da                     	movq	%rbx, %rdx
  4005f7: e8 24 00 00 00               	callq	0x400620 <handle_static_init>
  4005fc: 44 89 ff                     	movl	%r15d, %edi
  4005ff: 4c 89 f6                     	movq	%r14, %rsi
  400602: 48 89 da                     	movq	%rbx, %rdx
  400605: e8 08 02 00 00               	callq	0x400812 <main>
  40060a: 89 c7                        	movl	%eax, %edi
  40060c: e8 df fe ff ff               	callq	0x4004f0 <exit@plt>
  400611: 66 66 66 66 66 66 2e 0f 1f 84 00 00 00 00 00 	nopw	%cs:(%rax,%rax)

0000000000400620 <handle_static_init>:
  400620: b8 d8 18 40 00               	movl	$0x4018d8, %eax         # imm = 0x4018D8
  400625: 48 85 c0                     	testq	%rax, %rax
  400628: 74 01                        	je	0x40062b <handle_static_init+0xb>
  40062a: c3                           	retq
  40062b: 55                           	pushq	%rbp
  40062c: 48 89 e5                     	movq	%rsp, %rbp
  40062f: 41 57                        	pushq	%r15
  400631: 41 56                        	pushq	%r14
  400633: 41 55                        	pushq	%r13
  400635: 41 54                        	pushq	%r12
  400637: 53                           	pushq	%rbx
  400638: 50                           	pushq	%rax
  400639: 48 89 d3                     	movq	%rdx, %rbx
  40063c: 49 89 f6                     	movq	%rsi, %r14
  40063f: 41 89 ff                     	movl	%edi, %r15d
  400642: bf 10 07 40 00               	movl	$0x400710, %edi         # imm = 0x400710
  400647: e8 84 fe ff ff               	callq	0x4004d0 <atexit@plt>
  40064c: 41 bc c4 18 40 00            	movl	$0x4018c4, %r12d        # imm = 0x4018C4
  400652: 49 81 fc c4 18 40 00         	cmpq	$0x4018c4, %r12         # imm = 0x4018C4
  400659: 74 48                        	je	0x4006a3 <handle_static_init+0x83>
  40065b: b8 c4 18 40 00               	movl	$0x4018c4, %eax         # imm = 0x4018C4
  400660: 49 29 c4                     	subq	%rax, %r12
  400663: 49 c1 fc 03                  	sarq	$0x3, %r12
  400667: 49 83 fc 01                  	cmpq	$0x1, %r12
  40066b: 49 83 d4 00                  	adcq	$0x0, %r12
  40066f: 45 31 ed                     	xorl	%r13d, %r13d
  400672: eb 14                        	jmp	0x400688 <handle_static_init+0x68>
  400674: 66 66 66 2e 0f 1f 84 00 00 00 00 00  	nopw	%cs:(%rax,%rax)
  400680: 49 ff c5                     	incq	%r13
  400683: 4d 39 ec                     	cmpq	%r13, %r12
  400686: 74 1b                        	je	0x4006a3 <handle_static_init+0x83>
  400688: 4a 8b 04 ed c4 18 40 00      	movq	0x4018c4(,%r13,8), %rax
  400690: 48 83 f8 02                  	cmpq	$0x2, %rax
  400694: 72 ea                        	jb	0x400680 <handle_static_init+0x60>
  400696: 44 89 ff                     	movl	%r15d, %edi
  400699: 4c 89 f6                     	movq	%r14, %rsi
  40069c: 48 89 da                     	movq	%rbx, %rdx
  40069f: ff d0                        	callq	*%rax
  4006a1: eb dd                        	jmp	0x400680 <handle_static_init+0x60>
  4006a3: e8 00 fe ff ff               	callq	0x4004a8 <_init>
  4006a8: 41 bc d0 18 40 00            	movl	$0x4018d0, %r12d        # imm = 0x4018D0
  4006ae: 49 81 fc c8 18 40 00         	cmpq	$0x4018c8, %r12         # imm = 0x4018C8
  4006b5: 74 3c                        	je	0x4006f3 <handle_static_init+0xd3>
  4006b7: b8 c8 18 40 00               	movl	$0x4018c8, %eax         # imm = 0x4018C8
  4006bc: 49 29 c4                     	subq	%rax, %r12
  4006bf: 49 c1 fc 03                  	sarq	$0x3, %r12
  4006c3: 49 83 fc 01                  	cmpq	$0x1, %r12
  4006c7: 49 83 d4 00                  	adcq	$0x0, %r12
  4006cb: 45 31 ed                     	xorl	%r13d, %r13d
  4006ce: eb 08                        	jmp	0x4006d8 <handle_static_init+0xb8>
  4006d0: 49 ff c5                     	incq	%r13
  4006d3: 4d 39 ec                     	cmpq	%r13, %r12
  4006d6: 74 1b                        	je	0x4006f3 <handle_static_init+0xd3>
  4006d8: 4a 8b 04 ed c8 18 40 00      	movq	0x4018c8(,%r13,8), %rax
  4006e0: 48 83 f8 02                  	cmpq	$0x2, %rax
  4006e4: 72 ea                        	jb	0x4006d0 <handle_static_init+0xb0>
  4006e6: 44 89 ff                     	movl	%r15d, %edi
  4006e9: 4c 89 f6                     	movq	%r14, %rsi
  4006ec: 48 89 da                     	movq	%rbx, %rdx
  4006ef: ff d0                        	callq	*%rax
  4006f1: eb dd                        	jmp	0x4006d0 <handle_static_init+0xb0>
  4006f3: 48 83 c4 08                  	addq	$0x8, %rsp
  4006f7: 5b                           	popq	%rbx
  4006f8: 41 5c                        	popq	%r12
  4006fa: 41 5d                        	popq	%r13
  4006fc: 41 5e                        	popq	%r14
  4006fe: 41 5f                        	popq	%r15
  400700: 5d                           	popq	%rbp
  400701: c3                           	retq
  400702: 66 66 66 66 66 2e 0f 1f 84 00 00 00 00 00    	nopw	%cs:(%rax,%rax)

0000000000400710 <finalizer>:
  400710: 55                           	pushq	%rbp
  400711: 48 89 e5                     	movq	%rsp, %rbp
  400714: 53                           	pushq	%rbx
  400715: 50                           	pushq	%rax
  400716: bb d8 18 40 00               	movl	$0x4018d8, %ebx         # imm = 0x4018D8
  40071b: 48 81 fb d0 18 40 00         	cmpq	$0x4018d0, %rbx         # imm = 0x4018D0
  400722: 74 33                        	je	0x400757 <finalizer+0x47>
  400724: b8 d0 18 40 00               	movl	$0x4018d0, %eax         # imm = 0x4018D0
  400729: 48 29 c3                     	subq	%rax, %rbx
  40072c: 48 c1 fb 03                  	sarq	$0x3, %rbx
  400730: eb 13                        	jmp	0x400745 <finalizer+0x35>
  400732: 66 66 66 66 66 2e 0f 1f 84 00 00 00 00 00    	nopw	%cs:(%rax,%rax)
  400740: 48 ff cb                     	decq	%rbx
  400743: 74 12                        	je	0x400757 <finalizer+0x47>
  400745: 48 8b 04 dd c8 18 40 00      	movq	0x4018c8(,%rbx,8), %rax
  40074d: 48 83 f8 02                  	cmpq	$0x2, %rax
  400751: 72 ed                        	jb	0x400740 <finalizer+0x30>
  400753: ff d0                        	callq	*%rax
  400755: eb e9                        	jmp	0x400740 <finalizer+0x30>
  400757: 48 83 c4 08                  	addq	$0x8, %rsp
  40075b: 5b                           	popq	%rbx
  40075c: 5d                           	popq	%rbp
  40075d: e9 c6 00 00 00               	jmp	0x400828 <_fini>
  400762: cc                           	int3
  400763: cc                           	int3
  400764: 66 2e 0f 1f 84 00 00 00 00 00	nopw	%cs:(%rax,%rax)
  40076e: 66 90                        	nop

0000000000400770 <deregister_tm_clones>:
  400770: 48 8d 3d 89 13 00 00         	leaq	0x1389(%rip), %rdi      # 0x401b00 <environ>
  400777: 48 8d 05 82 13 00 00         	leaq	0x1382(%rip), %rax      # 0x401b00 <environ>
  40077e: 48 39 f8                     	cmpq	%rdi, %rax
  400781: 74 15                        	je	0x400798 <deregister_tm_clones+0x28>
  400783: 48 8b 05 1e 13 00 00         	movq	0x131e(%rip), %rax      # 0x401aa8 <puts@FBSD_1.0+0x401aa8>
  40078a: 48 85 c0                     	testq	%rax, %rax
  40078d: 74 09                        	je	0x400798 <deregister_tm_clones+0x28>
  40078f: ff e0                        	jmpq	*%rax
  400791: 0f 1f 80 00 00 00 00         	nopl	(%rax)
  400798: c3                           	retq
  400799: 0f 1f 80 00 00 00 00         	nopl	(%rax)

00000000004007a0 <register_tm_clones>:
  4007a0: 48 8d 3d 59 13 00 00         	leaq	0x1359(%rip), %rdi      # 0x401b00 <environ>
  4007a7: 48 8d 35 52 13 00 00         	leaq	0x1352(%rip), %rsi      # 0x401b00 <environ>
  4007ae: 48 29 fe                     	subq	%rdi, %rsi
  4007b1: 48 89 f0                     	movq	%rsi, %rax
  4007b4: 48 c1 ee 3f                  	shrq	$0x3f, %rsi
  4007b8: 48 c1 f8 03                  	sarq	$0x3, %rax
  4007bc: 48 01 c6                     	addq	%rax, %rsi
  4007bf: 48 d1 fe                     	sarq	%rsi
  4007c2: 74 14                        	je	0x4007d8 <register_tm_clones+0x38>
  4007c4: 48 8b 05 e5 12 00 00         	movq	0x12e5(%rip), %rax      # 0x401ab0 <puts@FBSD_1.0+0x401ab0>
  4007cb: 48 85 c0                     	testq	%rax, %rax
  4007ce: 74 08                        	je	0x4007d8 <register_tm_clones+0x38>
  4007d0: ff e0                        	jmpq	*%rax
  4007d2: 66 0f 1f 44 00 00            	nopw	(%rax,%rax)
  4007d8: c3                           	retq
  4007d9: 0f 1f 80 00 00 00 00         	nopl	(%rax)

00000000004007e0 <__do_global_dtors_aux>:
  4007e0: 80 3d 21 13 00 00 00         	cmpb	$0x0, 0x1321(%rip)      # 0x401b08 <completed.0>
  4007e7: 75 17                        	jne	0x400800 <__do_global_dtors_aux+0x20>
  4007e9: 55                           	pushq	%rbp
  4007ea: 48 89 e5                     	movq	%rsp, %rbp
  4007ed: e8 7e ff ff ff               	callq	0x400770 <deregister_tm_clones>
  4007f2: c6 05 0f 13 00 00 01         	movb	$0x1, 0x130f(%rip)      # 0x401b08 <completed.0>
  4007f9: 5d                           	popq	%rbp
  4007fa: c3                           	retq
  4007fb: 0f 1f 44 00 00               	nopl	(%rax,%rax)
  400800: c3                           	retq
  400801: 66 66 2e 0f 1f 84 00 00 00 00 00     	nopw	%cs:(%rax,%rax)
  40080c: 0f 1f 40 00                  	nopl	(%rax)

0000000000400810 <frame_dummy>:
  400810: eb 8e                        	jmp	0x4007a0 <register_tm_clones>

0000000000400812 <main>:
  400812: 55                           	pushq	%rbp
  400813: 48 89 e5                     	movq	%rsp, %rbp
  400816: bf 32 08 40 00               	movl	$0x400832, %edi         # imm = 0x400832
  40081b: e8 c0 fc ff ff               	callq	0x4004e0 <puts@plt>
  400820: b8 00 00 00 00               	movl	$0x0, %eax
  400825: 5d                           	popq	%rbp
  400826: c3                           	retq
  400827: 90                           	nop

Disassembly of section .fini:

0000000000400828 <_fini>:
  400828: 48 83 ec 08                  	subq	$0x8, %rsp
  40082c: 48 83 c4 08                  	addq	$0x8, %rsp
  400830: c3                           	retq

# ---------------- My asm ------------------ #
Amd Asm: 0x4883ec08 0b1001000100000111110110000001000 subq $0x8, %rsp
Amd Asm: 0x4883c408 0b1001000100000111100010000001000 addq $0x8, %rsp
Amd Asm: 0xc3 0b11000011 retq
Amd Asm: 0xff35fa150000 0b111111110011010111111010000101010000000000000000 pushq *0x15fa(%rip)
Amd Asm: 0xff25fc150000 0b111111110010010111111100000101010000000000000000 jmpq *0x15fc(%rip)
Amd Asm: 0xf1f4000 0b1111000111110100000000000000 nopl (%rax)
Amd Asm: 0xff25fa150000 0b111111110010010111111010000101010000000000000000 jmpq *0x15fa(%rip)
Amd Asm: 0x6800000000 0b110100000000000000000000000000000000000 pushq $0x0
Amd Asm: 0xe9e0ffffff 0b1110100111100000111111111111111111111111 jmp 0x4004c0 <.plt>
Amd Asm: 0xff25f2150000 0b111111110010010111110010000101010000000000000000 jmpq *0x15f2(%rip)
Amd Asm: 0x6801000000 0b110100000000001000000000000000000000000 pushq $0x1
Amd Asm: 0xe9d0ffffff 0b1110100111010000111111111111111111111111 jmp 0x4004c0 <.plt>
Amd Asm: 0xff25ea150000 0b111111110010010111101010000101010000000000000000 jmpq *0x15ea(%rip)
Amd Asm: 0x6802000000 0b110100000000010000000000000000000000000 pushq $0x2
Amd Asm: 0xe9c0ffffff 0b1110100111000000111111111111111111111111 jmp 0x4004c0 <.plt>
Amd Asm: 0xff25e2150000 0b111111110010010111100010000101010000000000000000 jmpq *0x15e2(%rip)
Amd Asm: 0x6803000000 0b110100000000011000000000000000000000000 pushq $0x3
Amd Asm: 0xe9b0ffffff 0b1110100110110000111111111111111111111111 jmp 0x4004c0 <.plt>
Amd Asm: 0x55 0b1010101 pushq %rbp
Amd Asm: 0x4889e5 0b10010001000100111100101 movq %rsp, %rbp
Amd Asm: 0x4157 0b100000101010111 pushq %r15
Amd Asm: 0x4156 0b100000101010110 pushq %r14
Amd Asm: 0x4155 0b100000101010101 pushq %r13
Amd Asm: 0x4154 0b100000101010100 pushq %r12
Amd Asm: 0x53 0b1010011 pushq %rbx
Amd Asm: 0x50 0b1010000 pushq %rax
Amd Asm: 0x4989fe 0b10010011000100111111110 movq %rsi, %r14
Amd Asm: 0x4c8b3f 0b10011001000101100111111 movq %r14, %rsi
Amd Asm: 0x4963c7 0b10010010110001111000111 movslq %r15d, %rax
Amd Asm: 0x488d1cc7 0b1001000100011010001110011000111 leaq (%rdi,%rax,8), %rbx
Amd Asm: 0x4883c310 0b1001000100000111100001100010000 addq $0x10, %rsp
Amd Asm: 0x48833dc915000000 0b100100010000011001111011100100100010101000000000000000000000000 cmpq 0x0, 0x15c9(%rip)
Amd Asm: 0x7507 0b111010100000111 jne 0x400xxx
Amd Asm: 0x48891dc0150000 0b1001000100010010001110111000000000101010000000000000000 movq %rsp, %rbp
Amd Asm: 0x4983c608 0b1001001100000111100011000001000 addq $0x8, %r14
Amd Asm: 0x4585ff 0b10001011000010111111111 testl %r15d, %r15d
Amd Asm: 0x7e2e 0b111111000101110 jle 0x400xxx
Amd Asm: 0x498b06 0b10010011000101100000110 movq %rsi, %r14
Amd Asm: 0x4885c0 0b10010001000010111000000 testq %rax, %rax
Amd Asm: 0x7426 0b111010000100110 je 0x400xxx
Amd Asm: 0x6666666666662e0f1f840000000000 0b11001100110011001100110011001100110011001100110001011100000111100011111100001000000000000000000000000000000000000000000 nopw %cs:(%rax,%rax)
Amd Asm: 0x48890589150000 0b1001000100010010000010110001001000101010000000000000000 movq %rsp, %rbp
Amd Asm: 0x48ffc0 0b10010001111111111000000 incq %rax
Amd Asm: 0xfb648ff 0b1111101101100100100011111111 movzbl -0x1(%rax), %ecx
Amd Asm: 0x83f92f 0b100000111111100100101111 cmpl $0x2f, %ecx
Amd Asm: 0x74ed 0b111010011101101 jmp 0x4004c0 <.plt>
Amd Asm: 0x85c9 0b1000010111001001 testl %ecx, %ecx
Amd Asm: 0x75f0 0b111010111110000 jne 0x400xxx <
Amd Asm: 0xb8d8184000 0b1011100011011000000110000100000000000000 movl 0x0, %eax
Amd Asm: 0x4885c0 0b10010001000010111000000 testq %rax, %rax
Amd Asm: 0x755a 0b111010101011010 jne 0x400xxx
Amd Asm: 0x48895dd0 0b1001000100010010101110111010000 movq %rsp, %rbp
Amd Asm: 0x41bda8044000 0b10000011011110110101000000001000100000000000000 movl $0x401xxx, %r12d
Amd Asm: 0xeb07 0b1110101100000111 jmp 0x400xxx <
Amd Asm: 0xf1f00 0b11110001111100000000 nopl (%rax)
Amd Asm: 0x4983c518 0b1001001100000111100010100011000 addq $0x18, %r14
Amd Asm: 0x4981fda8044000 0b1001001100000011111110110101000000001000100000000000000 cmpq $0x401xxx, %r12
Amd Asm: 0x7348 0b111001101001000 jae 0x400xxx
Amd Asm: 0xb801000000 0b1011100000000001000000000000000000000000 movl 0x0, %eax
Amd Asm: 0xfa2 0b111110100010 cpuid
Amd Asm: 0x89d7 0b1000100111010111 movl %eax, %edi
Amd Asm: 0x89ce 0b1000100111001110 movl %eax, %edi
Amd Asm: 0x31c0 0b11000111000000 xorl %ecx, %ecx
Amd Asm: 0xfa2 0b111110100010 cpuid
Amd Asm: 0xbb00000000 0b1011101100000000000000000000000000000000 movl $0x401xxx, %ebx
Amd Asm: 0xb900000000 0b1011100100000000000000000000000000000000 movl 0x0, %eax
Amd Asm: 0x83f807 0b100000111111100000000111 cmpl $0x7, %ecx
Amd Asm: 0x7209 0b111001000001001 jb 0x400xxx
Amd Asm: 0x31c9 0b11000111001001 xorl %ecx, %ecx
Amd Asm: 0xb807000000 0b1011100000000111000000000000000000000000 movl 0x0, %eax
Amd Asm: 0xfa2 0b111110100010 cpuid
Amd Asm: 0x41837d0825 0b100000110000011011111010000100000100101 cmpl $0x25, 0x8(%r13)
Amd Asm: 0x75c5 0b111010111000101 jne 0x400xxx <
Amd Asm: 0x4d8b6500 0b1001101100010110110010100000000 movq (%r13), %r12
Amd Asm: 0x89da 0b1000100111011010 movl %eax, %edi
Amd Asm: 0x41ff5510 0b1000001111111110101010100010000 callq *x10(%r13)
Amd Asm: 0x49890424 0b1001001100010010000010000100100 movq %rsi, %r14
Amd Asm: 0xebb5 0b1110101110110101 jmp 0x400xxx <
Amd Asm: 0x4889f7 0b10010001000100111110111 movq %rsp, %rbp
Amd Asm: 0xe8edfeffff 0b1110100011101101111111101111111111111111 callq 0x400xxx <
Amd Asm: 0xeb09 0b1110101100001001 jmp 0x400xxx <
Amd Asm: 0xe816ffffff 0b1110100000010110111111111111111111111111 callq 0x400xxx <
Amd Asm: 0x488b5dd0 0b1001000100010110101110111010000 movq %rsp, %rbp
Amd Asm: 0x4489ff 0b10001001000100111111111 movl %r15d, %edi
Amd Asm: 0x4c89f6 0b10011001000100111110110 movq %r14, %rsi
Amd Asm: 0x4889da 0b10010001000100111011010 movq %rsp, %rbp
Amd Asm: 0xe824000000 0b1110100000100100000000000000000000000000 callq 0x400xxx <
Amd Asm: 0x4489ff 0b10001001000100111111111 movl %r15d, %edi
Amd Asm: 0x4c89f6 0b10011001000100111110110 movq %r14, %rsi
Amd Asm: 0x4889da 0b10010001000100111011010 movq %rsp, %rbp
Amd Asm: 0xe808020000 0b1110100000001000000000100000000000000000 callq 0x400xxx <
Amd Asm: 0x89c7 0b1000100111000111 movl %eax, %edi
Amd Asm: 0xe8dffeffff 0b1110100011011111111111101111111111111111 callq 0x400xxx
Amd Asm: 0x6666666666662e0f1f840000000000 0b11001100110011001100110011001100110011001100110001011100000111100011111100001000000000000000000000000000000000000000000 nopw %cs:(%rax,%rax)
Amd Asm: 0xb8d8184000 0b1011100011011000000110000100000000000000 movl 0x0, %eax
Amd Asm: 0x4885c0 0b10010001000010111000000 testq %rax, %rax
Amd Asm: 0x7401 0b111010000000001 je 0x400xxx <
Amd Asm: 0xc3 0b11000011 retq
Amd Asm: 0x55 0b1010101 pushq %rbp
Amd Asm: 0x4889e5 0b10010001000100111100101 movq %rsp, %rbp
Amd Asm: 0x4157 0b100000101010111 pushq %r15
Amd Asm: 0x4156 0b100000101010110 pushq %r14
Amd Asm: 0x4155 0b100000101010101 pushq %r13
Amd Asm: 0x4154 0b100000101010100 pushq %r12
Amd Asm: 0x53 0b1010011 pushq %rbx
Amd Asm: 0x50 0b1010000 pushq %rax
Amd Asm: 0x4889d3 0b10010001000100111010011 movq %rsp, %rbp
Amd Asm: 0x4989f6 0b10010011000100111110110 movq %rsi, %r14
Amd Asm: 0x4189ff 0b10000011000100111111111 movl %edi, %r15d
Amd Asm: 0xbf10074000 0b1011111100010000000001110100000000000000 movl $0x401xxx, %edi
Amd Asm: 0xe884feffff 0b1110100010000100111111101111111111111111 callq 0x400xxx <
Amd Asm: 0x41bcc4184000 0b10000011011110011000100000110000100000000000000 movl $0x401xxx, %r12d
Amd Asm: 0x4981fcc4184000 0b1001001100000011111110011000100000110000100000000000000 cmpq $0x401xxx, %r12
Amd Asm: 0x7448 0b111010001001000 je 0x400xxx
Amd Asm: 0xb8c4184000 0b1011100011000100000110000100000000000000 movl $0x401xxx, %eax
Amd Asm: 0x4929c4 0b10010010010100111000100 subq %rax, %r12
Amd Asm: 0x49c1fc03 0b1001001110000011111110000000011 sarq $0x3, %r12
Amd Asm: 0x4983fc01 0b1001001100000111111110000000001 cmpq $0x1, %r12
Amd Asm: 0x4983d400 0b1001001100000111101010000000000 adcq $0x0, %r12
Amd Asm: 0x4531ed 0b10001010011000111101101 xorl %r13d, %r13d
Amd Asm: 0xeb14 0b1110101100010100 jmp 0x400xxx <
Amd Asm: 0x6666662e0f1f840000000000 0b11001100110011001100110001011100000111100011111100001000000000000000000000000000000000000000000 nopw %cs:(%rax,%rax)
Amd Asm: 0x49ffc5 0b10010011111111111000101 incq %r13
Amd Asm: 0x4d39ec 0b10011010011100111101100 cmpq %r13, %r12
Amd Asm: 0x741b 0b111010000011011 je 0x400xxx
Amd Asm: 0x4a8b04edc4184000 0b100101010001011000001001110110111000100000110000100000000000000 movq 0x401xxx(,%r13,8), %rax
Amd Asm: 0x4883f802 0b1001000100000111111100000000010 cmpq $0x2, %rax
Amd Asm: 0x72ea 0b111001011101010 jb 0x400xxx
Amd Asm: 0x4489ff 0b10001001000100111111111 movl %r15d, %edi
Amd Asm: 0x4c89f6 0b10011001000100111110110 movq %r14, %rsi
Amd Asm: 0x4889da 0b10010001000100111011010 movq %rsp, %rbp
Amd Asm: 0xffd0 0b1111111111010000 callq *%rax
Amd Asm: 0xebdd 0b1110101111011101 jmp 0x400xxx
Amd Asm: 0xe800feffff 0b1110100000000000111111101111111111111111 callq 0x400xxx <
Amd Asm: 0x41bcd0184000 0b10000011011110011010000000110000100000000000000 movl $0x401xxx, %r12d
Amd Asm: 0x4981fcc8184000 0b1001001100000011111110011001000000110000100000000000000 cmpq $0x401xxx, %r12
Amd Asm: 0x743c 0b111010000111100 je 0x400xxx
Amd Asm: 0xb8c8184000 0b1011100011001000000110000100000000000000 movl $0x401xxx, %eax
Amd Asm: 0x4929c4 0b10010010010100111000100 subq %rax, %r12
Amd Asm: 0x49c1fc03 0b1001001110000011111110000000011 sarq $0x3, %r12
Amd Asm: 0x4983fc01 0b1001001100000111111110000000001 cmpq $0x1, %r12
Amd Asm: 0x4983d400 0b1001001100000111101010000000000 adcq $0x0, %r12
Amd Asm: 0x4531ed 0b10001010011000111101101 xorl %r13d, %r13d
Amd Asm: 0xeb08 0b1110101100001000 jmp 0x400xxx <
Amd Asm: 0x49ffc5 0b10010011111111111000101 incq %r13
Amd Asm: 0x4d39ec 0b10011010011100111101100 cmpq %r13, %r12
Amd Asm: 0x741b 0b111010000011011 je 0x400xxx
Amd Asm: 0x4a8b04edc8184000 0b100101010001011000001001110110111001000000110000100000000000000 movq 0x401xxx(,%r13,8), %rax
Amd Asm: 0x4883f802 0b1001000100000111111100000000010 cmpq $0x2, %rax
Amd Asm: 0x72ea 0b111001011101010 jb 0x400xxx
Amd Asm: 0x4489ff 0b10001001000100111111111 movl %r15d, %edi
Amd Asm: 0x4c89f6 0b10011001000100111110110 movq %r14, %rsi
Amd Asm: 0x4889da 0b10010001000100111011010 movq %rsp, %rbp
Amd Asm: 0xffd0 0b1111111111010000 callq *%rax
Amd Asm: 0xebdd 0b1110101111011101 jmp 0x400xxx
Amd Asm: 0x4883c408 0b1001000100000111100010000001000 addq $0x8, %rsp
Amd Asm: 0x5b 0b1011011 popq %rbx
Amd Asm: 0x415c 0b100000101011100 popq %r12
Amd Asm: 0x415d 0b100000101011101 popq %r13
Amd Asm: 0x415e 0b100000101011110 popq %r14
Amd Asm: 0x415f 0b100000101011111 popq %r15
Amd Asm: 0x5d 0b1011101 popq %rpb
Amd Asm: 0xc3 0b11000011 retq
Amd Asm: 0x66666666662e0f1f840000000000 0b110011001100110011001100110011001100110001011100000111100011111100001000000000000000000000000000000000000000000 nopw %cs:(%rax,%rax)
Amd Asm: 0x55 0b1010101 pushq %rbp
Amd Asm: 0x4889e5 0b10010001000100111100101 movq %rsp, %rbp
Amd Asm: 0x53 0b1010011 pushq %rbx
Amd Asm: 0x50 0b1010000 pushq %rax
Amd Asm: 0xbbd8184000 0b1011101111011000000110000100000000000000 movl $0x401xxx, %ebx
Amd Asm: 0x4881fbd0184000 0b1001000100000011111101111010000000110000100000000000000 cmpq $0x401xxx, %rbx
Amd Asm: 0x7433 0b111010000110011 je 0x400xxx
Amd Asm: 0xb8d0184000 0b1011100011010000000110000100000000000000 movl 0x0, %eax
Amd Asm: 0x4829c3 0b10010000010100111000011 subq %rdi, %rsi
Amd Asm: 0x48c1fb03 0b1001000110000011111101100000011 sarq $0x3, %rax
Amd Asm: 0xeb13 0b1110101100010011 jmp 0x400xxx <
Amd Asm: 0x66666666662e0f1f840000000000 0b110011001100110011001100110011001100110001011100000111100011111100001000000000000000000000000000000000000000000 nopw %cs:(%rax,%rax)
Amd Asm: 0x48ffcb 0b10010001111111111001011 decq %rbx
Amd Asm: 0x7412 0b111010000010010 callq 0x400xxx <
Amd Asm: 0x488b04ddc8184000 0b100100010001011000001001101110111001000000110000100000000000000 movq %rsp, %rbp
Amd Asm: 0x4883f802 0b1001000100000111111100000000010 cmpq $0x2, %rax
Amd Asm: 0x72ed 0b111001011101101 jb 0x400xxx
Amd Asm: 0xffd0 0b1111111111010000 callq *%rax
Amd Asm: 0xebe9 0b1110101111101001 jmp 0x400xxx
Amd Asm: 0x4883c408 0b1001000100000111100010000001000 addq $0x8, %rsp
Amd Asm: 0x5b 0b1011011 popq %rbx
Amd Asm: 0x5d 0b1011101 popq %rpb
Amd Asm: 0xe9c6000000 0b1110100111000110000000000000000000000000 jmp 0x4004c0 <.plt>
Amd Asm: 0xcc 0b11001100 int3
Amd Asm: 0xcc 0b11001100 int3
Amd Asm: 0x662e0f1f840000000000 0b1100110001011100000111100011111100001000000000000000000000000000000000000000000 nopw (%rax,%rax)
Amd Asm: 0x6690 0b110011010010000 nop
Amd Asm: 0x488d3d89130000 0b1001000100011010011110110001001000100110000000000000000 leaq 0x1389(%rip), %rdi
Amd Asm: 0x488d0582130000 0b1001000100011010000010110000010000100110000000000000000 leaq 0x1382(%rip), %rdi
Amd Asm: 0x4839f8 0b10010000011100111111000 cmpq %rdi, %rax
Amd Asm: 0x7415 0b111010000010101 callq 0x400xxx <
Amd Asm: 0x488b051e130000 0b1001000100010110000010100011110000100110000000000000000 movq %rsp, %rbp
Amd Asm: 0x4885c0 0b10010001000010111000000 testq %rax, %rax
Amd Asm: 0x7409 0b111010000001001 callq 0x400xxx <
Amd Asm: 0xffe0 0b1111111111100000 jmpq *%rax
Amd Asm: 0xf1f8000000000 0b1111000111111000000000000000000000000000000000000000 nopl (%rax)
Amd Asm: 0xc3 0b11000011 retq
Amd Asm: 0xf1f8000000000 0b1111000111111000000000000000000000000000000000000000 nopl (%rax)
Amd Asm: 0x488d3d59130000 0b1001000100011010011110101011001000100110000000000000000 leaq 0x1359(%rip), %rdi
Amd Asm: 0x488d3552130000 0b1001000100011010011010101010010000100110000000000000000 leaq 0x1352(%rip), %rdi
Amd Asm: 0x4829fe 0b10010000010100111111110 subq %rdi, %rsi
Amd Asm: 0x4889f0 0b10010001000100111110000 movq %rsp, %rbp
Amd Asm: 0x48c1ee3f 0b1001000110000011110111000111111 shrq $0x3f, %rsi
Amd Asm: 0x48c1f803 0b1001000110000011111100000000011 sarq $0x3, %rax
Amd Asm: 0x4801c6 0b10010000000000111000110 addq %rax, %rsi
Amd Asm: 0x48d1fe 0b10010001101000111111110 sarq %rsi
Amd Asm: 0x7414 0b111010000010100 callq 0x400xxx <
Amd Asm: 0x488b05e5120000 0b1001000100010110000010111100101000100100000000000000000 movq %rsp, %rbp
Amd Asm: 0x4885c0 0b10010001000010111000000 testq %rax, %rax
Amd Asm: 0x7408 0b111010000001000 callq 0x400xxx <
Amd Asm: 0xffe0 0b1111111111100000 jmpq *%rax
Amd Asm: 0x660f1f440000 0b11001100000111100011111010001000000000000000000 nopw (%rax,%rax)
Amd Asm: 0xc3 0b11000011 retq
Amd Asm: 0xf1f8000000000 0b1111000111111000000000000000000000000000000000000000 nopl (%rax)
Amd Asm: 0x803d2113000000 0b10000000001111010010000100010011000000000000000000000000 cmpb 0x0, $0x1321(%rip)
Amd Asm: 0x7517 0b111010100010111 jne 0x400xxx
Amd Asm: 0x55 0b1010101 pushq %rbp
Amd Asm: 0x4889e5 0b10010001000100111100101 movq %rsp, %rbp
Amd Asm: 0xe87effffff 0b1110100001111110111111111111111111111111 callq 0x400xxx <>
Amd Asm: 0xc6050f13000001 0b11000110000001010000111100010011000000000000000000000001 movb 0x1, $0x130f(%rip)
Amd Asm: 0x5d 0b1011101 popq %rpb
Amd Asm: 0xc3 0b11000011 retq
Amd Asm: 0xf1f440000 0b111100011111010001000000000000000000 nopl (%rax)
Amd Asm: 0xc3 0b11000011 retq
Amd Asm: 0x66662e0f1f840000000000 0b110011001100110001011100000111100011111100001000000000000000000000000000000000000000000 nopw %cs:(%rax,%rax)
Amd Asm: 0xf1f4000 0b1111000111110100000000000000 nopl (%rax)
Amd Asm: 0xeb8e 0b1110101110001110 jne 0x400xxx <
Amd Asm: 0x55 0b1010101 pushq %rbp
Amd Asm: 0x4889e5 0b10010001000100111100101 movq %rsp, %rbp
Amd Asm: 0xbf32084000 0b1011111100110010000010000100000000000000 movl $0x401xxx, %edi
Amd Asm: 0xe8c0fcffff 0b1110100011000000111111001111111111111111 callq 0x400xxx
Amd Asm: 0xb800000000 0b1011100000000000000000000000000000000000 movl 0x0, %eax
Amd Asm: 0x5d 0b1011101 popq %rpb
Amd Asm: 0xc3 0b11000011 retq
Amd Asm: 0x90 0b10010000 nop
Amd Asm: 0x4883ec08 0b1001000100000111110110000001000 subq $0x8, %rsp
Amd Asm: 0x4883c408 0b1001000100000111100010000001000 addq $0x8, %rsp
Amd Asm: 0xc3 0b11000011 retq
"""
