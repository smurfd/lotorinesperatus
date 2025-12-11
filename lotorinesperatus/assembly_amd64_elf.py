#!/usr/bin/env python3
# Auth: smurfd, 2025; 2 space indent; 150 with;                                                                                                     #
# ------------------------------------------------------------------------------------------------------------------------------------------------- #
from typing import List, Tuple, Literal
# TODO: READ
# https://en.wikipedia.org/wiki/Executable_and_Linkable_Format
# https://gabi.xinuos.com/v42/elf.pdf
# https://web.archive.org/web/20250628070854/http://skyfree.org/linux/references/ELF_Format.pdf
class Amd64_elf:
  def __init__(self, fn) -> None:
    self.header, self.proghd, self.secthd, self.data, self.file, self.fn = [], [], [], [], [], fn
    hl, ll, sl = self.get_lengths()
    with open(self.fn, 'rb') as f:
      self.file = f.read(); p1, p2 = 0, hl
      self.h = self.file[p1:p2]; p1, p2 = hl, hl + ll  #hl + int(f'{binascii.hexlify(self.get_big(self.h[20:24])).decode()}', 16)
      #self.c = self.file[p1:p2]; p1, p2 = p2, p2 + sl
      self.p = self.file[p1:p2]; p1, p2 = p2, p2 + sl + 3
      self.s = self.file[p1:p2]
      self.d = self.file[p2:]

    #self.header, self.proghd, self.secthd, self.data, self.fn = [], [], [], [], fn
    #hl, ll, sl = self.get_lengths()
    #with open(self.fn, 'rb') as f: self.h, self.p, self.s, _, self.d = f.read(hl), f.read(ll), f.read(sl), f.read(3), f.read()
  def get_lengths(self) -> Tuple:
    return 64, 72, 65                              # Length of header, proghd, secthd
  def get_header(self) -> List:                    # [::-1] for big endian
    self.header.append(self.h[0:4])                # Magic number
    self.header.append(self.h[4:5])                # 32bit or 64bit
    self.header.append(self.h[5:6])                # Endianess
    self.header.append(self.h[6:7])                # Version
    self.header.append(self.h[7:8])                # Target system ABI
    self.header.append(self.h[8:9])                # ABI version
    self.header.append(self.h[9:16])               # Padding, should be zeros
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
    self.proghd.append(self.p[0:4])                # Segment type
    self.proghd.append(self.p[4:8])                # Segment-dependent flags
    self.proghd.append(self.p[8:16])               # Segment offset in the file image
    self.proghd.append(self.p[16:24])              # Virtual Address of the segment in memory
    self.proghd.append(self.p[24:32])              # Segments physical address
    self.proghd.append(self.p[32:40])              # Size in bytes of the segment in file image
    self.proghd.append(self.p[56:64])              # Size in bytes of the segment in memory
    self.proghd.append(self.p[64:72])              # Alignment
    return self.proghd
  def get_header_section(self) -> List:
    self.secthd.append(self.s[0:4])                # Offset to name string 
    self.secthd.append(self.s[4:8])                # Type of header
    self.secthd.append(self.s[8:16])               # Flags
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
  def get_instructions(self, i) -> Literal:
    if i[5:14]:  # TODO: check same positions and length?
      if   i[5:14] == '100010000' and i[17:25] == '11101100': return f'subq ${hex(int(i[29:34], 2))}, %rsp'
      elif i[5:14] == '100010000' and i[17:25] == '11000100': return f'addq ${hex(int(i[29:34], 2))}, %rsp'
      elif i[2:10] == '11000011': return f'retq'
      elif i[5:14] == '111110011': return f'pushq *{hex(int(i[29:34], 2))}{int(i[18:26], 2):x}(%rip)'
      elif i[5:14] == '111110010': return f'jmpq *{hex(int(i[29:34], 2))}{int(i[18:26], 2):x}(%rip)'
      elif i[2:11] == '110001100': return f'movb {hex(int(i[15:16], 2))}, ${hex(int(i[29:34], 2))}{int(i[18:26], 2):02x}(%rip)'
      elif i[2:15] == '1000000000111': return f'cmpb {hex(int(i[16:17], 2))}, ${hex(int(i[29:34], 2))}{int(i[18:26], 2):02x}(%rip)'
      elif i[5:14] == '100011111': return f'nopl (%rax)'
      elif i[5:14] == '100000000': return f'pushq ${hex(int(i[15:17], 2))}'
      elif i[2:9]  == '1010101': return f'pushq %rbp'
      elif i[8:15] == '1010101': return f'pushq %r{12+int(i[15:17], 2)}'
      elif i[8:15] == '1010111': return f'popq %r{12+int(i[15:17], 2)}'
      elif i[5:11] == '010011': return f'jmp 0x4004c0 <.plt>'  # TODO: fix
      elif i[2:9]  == '1011100': return f'movl {hex(int(i[29:34], 2))}, %eax'
      elif i[2:11] == '111010111': return f'jmp 0x400xxx'
      elif i[2:18] == '1111111111100000': return f'jmpq *%rax'
      elif i[2:17] == '111010100010111': return f'jne 0x400xxx'
      elif i[2:17] == '111010000001000': return f'je 0x400xxx'
      elif i[2:10] == '11101000': return f'callq 0x400xxx'
      elif i[2:14] == '100100010001': return f'movq %rsp, %rbp'
      elif i[2:9]  == '1011101': return f'popq %rpb'
      elif i[2:10] == '10010000': return f'nop'
      elif i[2:10] == '11001100': return f'int3'
  def get_assembly(self) -> List:
    i, ins, hx, bi, co, p = 0, [], [], [], 0, 1192  # 1192 = 0x4004a8 - 0x4a8
    #ins.append(self.get_instructions(bin(int.from_bytes(self.file[p + i:p + i + 4][::-1]))))
    #hx.append(hex(int.from_bytes(self.file[p + i:p + i + 4][::-1])))
    #bi.append(bin(int.from_bytes(self.file[p + i:p + i + 4][::-1])))
    op_bytes = [
      4, 4, 1, # TODO how to get these programmaticly
      6, 6, 4,
      6, 5, 5,
      6, 5, 5,
      6, 5, 5,
      6, 5, 5,
      1, 3, 2, 2, 2, 2, 1, 1, 3, 3, 3, 4, 4, 8, 2, 7, 4, 3, 2, 3, 3, 2, 15, 7, 3, 4, 3, 2, 2, 2, 5, 3, 2, 4, 6, 2, 3, 4, 7, # belong to below
        2, 5, 2, 2, 2, 2, 2, 5, 5, 3, 2, 2, 5, 2, 5, 2, 4, 2, 4, 4, 2, 3, 5, 2, 5, 4, 3, 3, 5, 3, 3, 3, 5, 2, 5, 15,        #
      5, 3, 2, 1, 1, 3, 2, 2, 2, 2, 1, 1, 3, 3, 3, 5, 5, 6, 7, 2, 5, 3, 4, 4, 4, 3, 2, 12, 3, 3, 2, 8, 4, 2, 3, 3, 3, 2,    # belong to below
        2, 5, 6, 7, 2, 5, 3, 4, 4, 4, 3, 2, 3, 3, 2, 8, 4, 2, 3, 3, 3, 2, 2, 4, 1, 2, 2, 2, 2, 1, 1, 14,                    #
      1, 3, 1, 1, 5, 7, 2, 5, 3, 4, 2, 14, 3, 2, 8, 4, 2, 2, 2, 4, 1, 1, 5, 1, 1, 10, 2,
      7, 7, 3, 2, 7, 3, 2, 2, 7, 1, 7,
      7, 7, 3, 3, 4, 4, 3, 3, 2, 7, 3, 2, 2, 6, 1, 7,
      7, 2, 1, 3, 5, 7, 1, 1, 5, 1, 11, 4,
      2,
      1, 3, 5, 5, 5, 1, 1, 1,
      4, 4, 1]
    for j, i in enumerate(op_bytes):
      print(f'{hex(int.from_bytes(self.file[p + co:p + co + i]))}'\
        f' {bin(int.from_bytes(self.file[p + co:p + co + i]))}'\
        f' {self.get_instructions(bin(int.from_bytes(self.file[p + co:p + co + i])))}')
      co += i
      if j in [2, 5, 8, 11, 14, 17, 92, 162, 189, 200, 216, 228, 229, 237, 241]: print('\n')  # to get a new line between sections
      if j == 2: co = 24
      if j == 84: co += 3
    return hx, bi, ins

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
"""
