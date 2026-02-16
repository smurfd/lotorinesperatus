#!/usr/bin/env python3
# Auth: smurfd, 2025; 2 space indent; 150 width;                                                                                                    #
# ------------------------------------------------------------------------------------------------------------------------------------------------- #
from lotorinesperatus.assembly import Assembly, Objdump
import platform, sys, os

def read_arm_macho_hello() -> None:
  print('--- arm64 macho header ---')
  arm = Assembly(f'{os.path.dirname(os.path.realpath(__file__))}/examples/hello_arm64_macho.bin', arch='arm64', flavour='arm64', binfmt='macho')
  arm_header  = arm.asm.get_header()
  arm_command = arm.asm.get_command()
  arm_loader  = arm.asm.get_loader(0)
  arm_segment = arm.asm.get_segment(80)
  arm_data    = arm.asm.get_data()
  arm.print_hex(arm.bytes2hex(arm_header))
  arm.print_hex(arm.bytes2hex(arm_loader))
  arm.print_hex(arm.bytes2hex(arm_segment))
  arm.print_hex(arm.bytes2hex(arm_data))
  [print(f'Header {arm.hex2str(arm_header[i])}') for i in range(len(arm_header))]
  [print(f'Loader {arm.hex2str(arm_loader[i])}') for i in range(len(arm_loader))]
  [print(f'Segment {arm.hex2str(arm_segment[i])}') for i in range(len(arm_segment))]
  h, bi, a, b = arm.asm.get_assembly()
  [print(f'Arm Asm hello: {h[i]} {bi[i]} {a[i]}') for i in range(len(h))]
  print('--- arm64 macho header ---')
def read_amd_elf_hello() -> None:
  print('--- amd64 elf header ---')
  amd = Assembly(f'{os.path.dirname(os.path.realpath(__file__))}/examples/hello_amd64_elf.bin', arch='amd64', flavour='amd64', binfmt='elf')
  amd_header         = amd.asm.get_header()
  amd_header_program = amd.asm.get_header_program()
  amd_header_section = amd.asm.get_header_section()
  amd_data           = amd.asm.get_data()
  amd.print_hex(amd.bytes2hex(amd_header))
  amd.print_hex(amd.bytes2hex(amd_header_program))
  amd.print_hex(amd.bytes2hex(amd_header_section))
  amd.print_hex(amd.bytes2hex(amd_data))
  [print(f'Header {amd.hex2str(amd_header[i])}') for i in range(len(amd_header))]
  [print(f'Program {amd.hex2str(amd_header_program[i])}') for i in range(len(amd_header_program))]
  [print(f'Section {amd.hex2str(amd_header_section[i])}') for i in range(len(amd_header_section))]
  print(f'{amd.asm.get_assembly_correctly()}')
  print('--- amd64 elf header ---')
def read_arm_macho_func() -> None:
  print('--- arm64 macho header ---')
  arm = Assembly(f'{os.path.dirname(os.path.realpath(__file__))}/examples/func_arm64_macho.bin', arch='arm64', flavour='arm64', binfmt='macho')
  arm_header  = arm.asm.get_header()
  arm_command = arm.asm.get_command()
  arm_loader  = arm.asm.get_loader(0)
  arm_segment = arm.asm.get_segment(80)
  arm_data    = arm.asm.get_data()
  arm.print_hex(arm.bytes2hex(arm_header))
  arm.print_hex(arm.bytes2hex(arm_loader))
  arm.print_hex(arm.bytes2hex(arm_segment))
  arm.print_hex(arm.bytes2hex(arm_data))
  [print(f'Header {arm.hex2str(arm_header[i])}') for i in range(len(arm_header))]
  [print(f'Loader {arm.hex2str(arm_loader[i])}') for i in range(len(arm_loader))]
  [print(f'Segment {arm.hex2str(arm_segment[i])}') for i in range(len(arm_segment))]
  h, bi, a, b = arm.asm.get_assembly()
  [print(f'Arm Asm func: {h[i]} {bi[i]} {a[i]}') for i in range(len(h))]
  print('--- arm64 macho header ---')
def read_amd_elf_func() -> None:
  print('--- amd64 elf header ---')
  amd = Assembly(f'{os.path.dirname(os.path.realpath(__file__))}/examples/func_amd64_elf.bin', arch='amd64', flavour='amd64', binfmt='elf')
  amd_header         = amd.asm.get_header()
  amd_header_program = amd.asm.get_header_program()
  amd_header_section = amd.asm.get_header_section()
  amd_data           = amd.asm.get_data()
  amd.print_hex(amd.bytes2hex(amd_header))
  amd.print_hex(amd.bytes2hex(amd_header_program))
  amd.print_hex(amd.bytes2hex(amd_header_section))
  amd.print_hex(amd.bytes2hex(amd_data))
  [print(f'Header {amd.hex2str(amd_header[i])}') for i in range(len(amd_header))]
  [print(f'Program {amd.hex2str(amd_header_program[i])}') for i in range(len(amd_header_program))]
  [print(f'Section {amd.hex2str(amd_header_section[i])}') for i in range(len(amd_header_section))]
  print(f'{amd.asm.get_assembly_correctly()}')
  print('--- amd64 elf header ---')
def read_helloamd_objdump() -> None:
  hamd = Objdump('lotorinesperatus/test/examples/hello_amd64_elf.objdump').get()
  amd = Assembly(f'{os.path.dirname(os.path.realpath(__file__))}/examples/hello_amd64_elf.bin', arch='amd64', flavour='amd64', binfmt='elf')
  amd_header         = amd.asm.get_header()
  amd_header_program = amd.asm.get_header_program()
  amd_header_section = amd.asm.get_header_section()
  amd_data           = amd.asm.get_data()
  asmc = amd.asm.get_assembly_correctly()
  for i,f in enumerate(hamd):
    if f[0] == 'file format elf64-x86-64': continue
    assert f[0][:3] == asmc[i - 1].split(' ')[0][:3]  # Read first 3 letters in op since we have not figured out the sufix, like movQ, movL etc.
def read_helloarm_objdump() -> None:
  harm = Objdump('lotorinesperatus/test/examples/hello_arm64_macho.objdump').get()
  arm = Assembly(f'{os.path.dirname(os.path.realpath(__file__))}/examples/hello_arm64_macho.bin', arch='arm64', flavour='arm64', binfmt='macho')
  arm_header  = arm.asm.get_header()
  arm_command = arm.asm.get_command()
  arm_loader  = arm.asm.get_loader(0)
  arm_segment = arm.asm.get_segment(80)
  arm_data    = arm.asm.get_data()
  h, bi, a, b = arm.asm.get_assembly()
  for i,f in enumerate(harm[1:]): assert f[0] == a[i].split(' ')[0]
def read_funcamd_objdump() -> None:
  famd = Objdump('lotorinesperatus/test/examples/func_amd64_elf.objdump').get()
  amd = Assembly(f'{os.path.dirname(os.path.realpath(__file__))}/examples/func_amd64_elf.bin', arch='amd64', flavour='amd64', binfmt='elf')
  amd_header         = amd.asm.get_header()
  amd_header_program = amd.asm.get_header_program()
  amd_header_section = amd.asm.get_header_section()
  amd_data           = amd.asm.get_data()
  asmc = amd.asm.get_assembly_correctly()  # TODO: fetch all data
  for i,f in enumerate(famd):
    if f[0] == 'file format elf64-x86-64': continue
    if i > len(asmc): break  # We dont fetch enough
    assert f[0][:3] == asmc[i - 1].split(' ')[0][:3]  # Read first 3 letters in op since we have not figured out the sufix, like movQ, movL etc.
def read_funcarm_objdump() -> None:
  farm = Objdump('lotorinesperatus/test/examples/func_arm64_macho.objdump').get()
  arm = Assembly(f'{os.path.dirname(os.path.realpath(__file__))}/examples/func_arm64_macho.bin', arch='arm64', flavour='arm64', binfmt='macho')
  arm_header  = arm.asm.get_header()
  arm_command = arm.asm.get_command()
  arm_loader  = arm.asm.get_loader(0)
  arm_segment = arm.asm.get_segment(80)
  arm_data    = arm.asm.get_data()
  h, bi, a, b = arm.asm.get_assembly()
  for i,f in enumerate(farm[1:]): assert f[0] == a[i].split(' ')[0]
def rx1(p, i, file): return hex(int.from_bytes(file[p:p + i]))  # Return hex
def get_assembly_correctly1(file, start, end, data=None):
    reg = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']
    byt, co, p, maxco = b'', 0, start, end
    hx, bi, ins, b = [], [], [], []
    if data: maxco, p, file = len(data), 0, data
    while p + co < len(file) and co < maxco:
      bit16, bit64, cond, chk, byt, px = False, False, False, False, file[p + co:p + co + 1], ''
      # TODO: movq instead of mov, for 64bit, movl for 32bit etc...
      if   int.from_bytes(byt) == 0x48: co += 1; bit64 = True; byt = file[p + co:p + co + 1];                                                  # 64bit op
      elif int.from_bytes(byt) == 0x66: co += 1; bit16 = True; byt = file[p+co:p+co+1]                                                         # 16bit op
      elif int.from_bytes(byt) == 0x49: co += 1; cond = True; byt = file[p+co:p+co+1]                                                          # Conditional
      elif int.from_bytes(byt) == 0x41: co += 1; cond = True; byt = file[p+co:p+co+1]                                                          # Conditional
      elif int.from_bytes(byt) == 0x4c: co += 1; byt = file[p+co:p+co+1]                                                                       # Check
      elif int.from_bytes(byt) == 0x4d: co += 1; chk = True; byt = file[p+co:p+co+1]                                                           # Check
      if bit16:
        x = int.from_bytes(file[p+co+1:p+co+2]); y = int.from_bytes(file[p+co+2:p+co+3])
        if   int.from_bytes(byt) == 0x90: co += 1; ins.append(f'nop')                                                                               # Nop
        elif int.from_bytes(byt) == 0x0f and (0xf0 & x) == 0x10 and (0xf0 & y) == 0x40: px = 'l'; ins.append(f'nop{px} {rx1(p + co, 2, file)}'); co += 2  # Nopl, read 2
        elif int.from_bytes(byt) == 0x66 or int.from_bytes(byt) == 0x2e:
          co += 1;
          while int.from_bytes(file[p+co:p+co+1]) == 0x66: co += 1;
          ins.append(f'nop{px} {rx1(p + co, 8, file)}'); co += 8
        else: ins.append(f'noop')                                                                                                                   # No operation found
      elif chk:
        if   int.from_bytes(byt) == 0x8b: ins.append(f'mov{px} {rx1(p + co, 3, file)}'); co += 3                                                      # Mov, read 3
        elif int.from_bytes(byt) == 0x39: ins.append(f'cmp{px} {rx1(p + co, 2, file)}'); co += 2                                                      # Cmp, read 2
      elif int.from_bytes(byt) == 0x83:  # Add / Sub / Cmp
        co += 1; x = int.from_bytes(file[p+co:p+co+1])
        if   (0xf0 & x) == 0xe0: ins.append(f'sub{px} {rx1(p + co, 2, file)}'); co += 2                                                               # Sub, read 2
        elif (0xf0 & x) == 0x40: ins.append(f'add{px} {rx1(p + co, 3, file)}'); co += 3                                                               # Add, read 4
        elif (0xf0 & x) == 0xc0: ins.append(f'add{px} {rx1(p + co, 2, file)}'); co += 2                                                               # Add, read 2
        elif (0xf0 & x) == 0xf0: ins.append(f'cmp{px} {rx1(p + co, 2, file)}'); co += 2                                                               # Cmp, read 2
        elif (0xf0 & x) == 0xd0: ins.append(f'adc{px} {rx1(p + co, 2, file)}'); co += 2                                                               # Adc, read 2
        elif (0xf0 & x) == 0x70: ins.append(f'cmp{px} {rx1(p + co, 3, file)}'); co += 3                                                               # Cmp, read 3
        elif (0xf0 & x) == 0x30: ins.append(f'cmp{px} {rx1(p + co, 6, file)}'); co += 6                                                               # Cmp, read 6
        elif (0xf0 & x) == 0x80: ins.append(f'mov{px} {rx1(p + co, 2, file)}'); co += 2                                                               # Mov, read 2
      elif int.from_bytes(byt) == 0xff:
        if   int.from_bytes(file[p+co+1:p+co+2]) == 0x25: ins.append(f'jmp{px} {rx1(p + co, 6, file)}'); co += 6                                 # Jmp
        elif int.from_bytes(file[p+co+1:p+co+2]) == 0x35: ins.append(f'push{px} {rx1(p + co, 6, file)}'); co += 6                                # Push
        elif int.from_bytes(file[p+co+1:p+co+2]) == 0x55: ins.append(f'call{px} {rx1(p + co, 2, file)}'); co += 2                                # Call
        elif int.from_bytes(file[p+co+1:p+co+2]) == 0xe0: ins.append(f'jmp{px} {rx1(p + co, 2, file)}'); co += 2                                 # Call
        elif int.from_bytes(file[p+co+1:p+co+2]) == 0xd0: ins.append(f'call{px} {rx1(p + co, 2, file)}'); co += 2                                # Call
        elif int.from_bytes(file[p+co+1:p+co+2]) == 0xc0: ins.append(f'incq{px} {rx1(p + co, 2, file)}'); co += 2                                # Incq
        elif int.from_bytes(file[p+co+1:p+co+2]) == 0xcb: ins.append(f'decq{px} {rx1(p + co, 2, file)}'); co += 2                                # Decq
        elif int.from_bytes(file[p+co+1:p+co+2]) == 0xc5: ins.append(f'incq{px} {rx1(p + co, 2, file)}'); co += 2                                # Incq
        else: co += 1
      elif int.from_bytes(byt) == 0x45:
        if   int.from_bytes(file[p+co+1:p+co+2]) == 0x31: ins.append(f'xor{px} {rx1(p + co, 2, file)}'); co += 2                                 # xor
        elif int.from_bytes(file[p+co+1:p+co+2]) == 0x85: ins.append(f'test{px} {rx1(p + co, 2, file)}'); co += 2                                # test
        else: co += 1
      elif int.from_bytes(byt) == 0x89 and bit64:
        co += 1; x = int.from_bytes(file[p+co:p+co+1])
        if   (0xf0 & x) == 0xd0: ins.append(f'mov{px} {rx1(p + co, 1, file)}'); co += 1                                                               # Mov, read 1
        elif (0xf0 & x) == 0xe0: ins.append(f'mov{px} {rx1(p + co, 1, file)}'); co += 1                                                               # Mov, read 1
        elif (0xf0 & x) == 0xf0: ins.append(f'mov{px} {rx1(p + co, 1, file)}'); co += 1                                                               # Mov, read 1
        elif (0xf0 & x) == 0x50: ins.append(f'mov{px} {rx1(p + co, 2, file)}'); co += 2                                                               # Mov, read 2
        elif (0xf0 & x) == 0x70: ins.append(f'mov{px} {rx1(p + co, 2, file)}'); co += 2                                                               # Mov, read 2
        elif (0xf0 & x) == 0x10: ins.append(f'mov{px} {rx1(p + co, 5, file)}'); co += 5                                                               # Mov, read 5
        elif (0xf0 & x) == 0x0:  ins.append(f'mov{px} {rx1(p + co, 5, file)}'); co += 5                                                               # Mov, read 5
      elif int.from_bytes(byt) == 0x89 and cond:
        co += 1; x = int.from_bytes(file[p+co:p+co+1]);
        if   (0xf0 & x) == 0x0:  ins.append(f'mov{px} {rx1(p + co, 2, file)}'); co += 2                                                               # Mov, read 2
        elif (0xf0 & x) == 0xf0: ins.append(f'mov{px} {rx1(p + co, 1, file)}'); co += 1                                                               # Mov, read 1
      elif int.from_bytes(byt) == 0x0f:
        co += 1; x = int.from_bytes(file[p+co:p+co+1]); y = int.from_bytes(file[p+co+1:p+co+2])
        if   (0xf0 & x) == 0x10 and (0xf0 & y) == 0x40: ins.append(f'nopl{px} {rx1(p + co, 2, file)}'); co += 2                                       # Nopl, read 2
        elif (0xf0 & x) == 0x10 and (0xf0 & y) == 0x80: ins.append(f'nopl{px} {rx1(p + co, 5, file)}'); co += 5                                       # Nopl, read 5
        elif (0xf0 & x) == 0x10 and (0xf0 & y) == 0x0:  ins.append(f'nopl{px} {rx1(p + co, 1, file)}'); co += 1                                       # Nopl, read 1
        elif (0xf0 & x) == 0xb0: ins.append(f'movzbl{px} {rx1(p + co, 3, file)}'); co += 3                                                            # Mov, read 3
        elif (0xf0 & x) == 0xa0: ins.append(f'cpuid{px} {rx1(p + co, 1, file)}'); co += 1                                                             # cpuid, read 1
      elif int.from_bytes(byt) == 0x81 and (cond or bit64):
        co += 1; x = int.from_bytes(file[p+co:p+co+1])
        if   (0xf0 & x) == 0xf0: ins.append(f'cmp{px} {rx1(p + co, 5, file)}'); co += 5                                                               # Cmp, read 5
      elif int.from_bytes(byt) == 0x8d and bit64:
        co += 1; x = int.from_bytes(file[p+co:p+co+1])
        if   (0xf0 & x) == 0x10: ins.append(f'leaq{px} {rx1(p + co, 2, file)}'); co += 2                                                              # leaq, read 2
        elif (0xf0 & x) == 0x00: ins.append(f'leaq{px} {rx1(p + co, 5, file)}'); co += 5                                                              # leaq, read 5
        elif (0xf0 & x) == 0x30: ins.append(f'leaq{px} {rx1(p + co, 5, file)}'); co += 5                                                              # leaq, read 5
      elif int.from_bytes(byt) == 0xc1:
        co += 1; x = int.from_bytes(file[p+co:p+co+1])
        if   (0xf0 & x) == 0xe0: ins.append(f'shr{px} {rx1(p + co, 3, file)}'); co += 2                                                               # Shr
        elif (0xf0 & x) == 0xf0: ins.append(f'sar{px} {rx1(p + co, 3, file)}'); co += 2                                                               # Sar
      elif int.from_bytes(byt) == 0xcc: ins.append(f'int13{px} {rx1(p + co, 1, file)}'); co += 1                                                      # Int13
      elif int.from_bytes(byt) == 0xc3: ins.append(f'retq{px} {rx1(p + co, 1, file)}'); co += 1                                                       # Retq
      elif int.from_bytes(byt) == 0x98: ins.append(f'cltq{px} {rx1(p + co, 1, file)}'); co += 1                                                       # Retq
      elif int.from_bytes(byt) == 0x39: ins.append(f'cmpq{px} {rx1(p + co, 2, file)}'); co += 2                                                       # Cmpq
      elif int.from_bytes(byt) == 0xe8: ins.append(f'call{px} {rx1(p + co, 5, file)}'); co += 5                                                       # Call
      elif int.from_bytes(byt) == 0x85: ins.append(f'test{px} {rx1(p + co, 2, file)}'); co += 2                                                       # Test
      elif int.from_bytes(byt) == 0x29: ins.append(f'sub{px} {rx1(p + co, 2, file)}'); co += 2                                                        # Sub
      elif int.from_bytes(byt) == 0xd1: ins.append(f'sar{px} {rx1(p + co, 2, file)}'); co += 2                                                        # Sar
      elif int.from_bytes(byt) == 0x45: ins.append(f'xor{px} {rx1(p + co, 3, file)}'); co += 3                                                        # Xor
      elif int.from_bytes(byt) == 0xe9: ins.append(f'jmp{px} {rx1(p + co, 5, file)}'); co += 5                                                        # Jmp
      elif int.from_bytes(byt) == 0xbb: ins.append(f'mov{px} {rx1(p + co, 5, file)}'); co += 5                                                        # Mov
      elif int.from_bytes(byt) == 0x01: ins.append(f'add{px} {rx1(p + co, 3, file)}'); co += 3                                                        # Mov
      elif int.from_bytes(byt) == 0xb9: ins.append(f'mov{px} {rx1(p + co, 5, file)}'); co += 5                                                        # Mov
      elif int.from_bytes(byt) == 0xeb: ins.append(f'jmp{px} {rx1(p + co, 2, file)}'); co += 2                                                        # Jmp
      elif int.from_bytes(byt) == 0x89: ins.append(f'mov{px} {rx1(p + co, 2, file)}'); co += 2                                                        # Mov
      elif int.from_bytes(byt) == 0x8b: ins.append(f'mov{px} {rx1(p + co, 3, file)}'); co += 3                                                        # Mov
      elif int.from_bytes(byt) == 0x63: ins.append(f'mov{px} {rx1(p + co, 2, file)}'); co += 2                                                        # Mov
      elif int.from_bytes(byt) == 0x75: ins.append(f'jne{px} {rx1(p + co, 2, file)}'); co += 2                                                        # Jne
      elif int.from_bytes(byt) == 0x7e: ins.append(f'jle{px} {rx1(p + co, 2, file)}'); co += 2                                                        # Jle
      elif int.from_bytes(byt) == 0x73: ins.append(f'jae{px} {rx1(p + co, 2, file)}'); co += 2                                                        # Jae
      elif int.from_bytes(byt) == 0x31: ins.append(f'xor{px} {rx1(p + co, 2, file)}'); co += 2                                                        # Xor
      elif int.from_bytes(byt) == 0x80: ins.append(f'cmp{px} {rx1(p + co, 7, file)}'); co += 7                                                        # Jb
      elif int.from_bytes(byt) == 0xc6: ins.append(f'mov{px} {rx1(p + co, 7, file)}'); co += 7                                                        # Jb
      elif int.from_bytes(byt) == 0xc7: ins.append(f'mov{px} {rx1(p + co, 7, file)}'); co += 7                                                        # Jb
      elif int.from_bytes(byt) == 0x74: ins.append(f'je{px} {rx1(p + co, 2, file)}'); co += 2                                                         # Je
      elif int.from_bytes(byt) == 0x72: ins.append(f'jb{px} {rx1(p + co, 2, file)}'); co += 2                                                         # Jb
      elif int.from_bytes(byt) >= 0xb0 and int.from_bytes(byt) < 0xb8: ins.append(f'mov{px} {rx1(p + co, 4, file)}'); co += 4                         # Mov 32bit
      elif int.from_bytes(byt) >= 0xb8 and int.from_bytes(byt) < 0xc0: ins.append(f'mov{px} {rx1(p + co, 4, file)}'); co += 4                         # Mov 64bit
      elif int.from_bytes(byt) >= 0x54 and int.from_bytes(byt) < 0x58 and cond: ins.append(f'push{px} {reg[int.from_bytes(byt) - 0x48]}'); co += 1  # Push
      elif int.from_bytes(byt) >= 0x50 and int.from_bytes(byt) < 0x56: ins.append(f'push{px} {reg[int.from_bytes(byt) - 0x50]}'); co += 1           # Push
      elif int.from_bytes(byt) >= 0x5c and int.from_bytes(byt) <= 0x5f: ins.append(f'pop{px} {reg[int.from_bytes(byt) - 0x50]}'); co += 1           # Pop
      elif int.from_bytes(byt) == 0x68 and int.from_bytes(file[p+co+1:p+co+2]) >= 0x00 and int.from_bytes(file[p+co+1:p+co+2]) < 0x0f:
        ins.append(f'push{px} {rx1(p + co, 2, file)}'); co += 2                                                                                       # Push
        while int.from_bytes(file[p+co:p+co+1]) == 0: co += 1;
      elif int.from_bytes(byt) >= 0x58 and int.from_bytes(byt) < 0x60: ins.append(f'pop{px} {reg[int.from_bytes(byt) - 0x58]}'); co += 1            # Pop
      elif int.from_bytes(byt) == 0x0f and int.from_bytes(file[p+co+1:p+co+2]) == 0x1f:                                                        # Nopl
        ins.append(f'nop{px} {rx1(1)}'); co += 2
        while int.from_bytes(file[p+co+1:p+co+2]) == 0x00: co += 1
      elif int.from_bytes(byt) == 0x90: ins.append(f'nop {rx1(p + co, 1, file)}'); co += 1                                                            # Nop
      elif bit64: ins.append(f'noop')
      else: co = co + 1
      hx.append(hex(int.from_bytes(byt)))
      bi.append(bin(int.from_bytes(byt)))
      b.append(byt)
    return hx, bi, ins, b  # return hex, binary, asm, bytes
def get_segment_positions(shdr, shnum, data):
  strs, i, d, soff = 0, 0, b'', int.from_bytes(shdr[shnum-1][24:31][::-1])
  while strs < shnum:
    d += data[soff+i:soff+i+1]
    if d[-1].to_bytes() == b'\x00': strs += 1 # end of string, one more string
    i += 1
  names, nr = d.decode().split('\x00'), list(range(shnum))
  for i in range(shnum): nr[i] = (int.from_bytes(shdr[i][0:3][::-1]), int.from_bytes(shdr[i][24:31][::-1]))
  return sorted(nr)[names.index('.init') + 1][1], sorted(nr)[names.index('.fini') + 1][1], sorted(nr)[names.index('.rodata') + 1][1]
def read_amd_elf_hello_tmp():
  with open(f'{os.path.dirname(os.path.realpath(__file__))}/examples/hello_amd64_elf.bin', 'rb') as f:
    file = f.read()
    header = file[:64]
    e_shoff = int.from_bytes(header[40:47][::-1])
    e_shentsize = int.from_bytes(header[58:59][::-1])
    e_shnum = int.from_bytes(header[60:61][::-1])
    shdr = list(range(e_shentsize))
    for i,j in enumerate(range(e_shoff, e_shoff + (e_shnum * e_shentsize), e_shentsize)): shdr[i] = file[j:j + (e_shentsize - 1)]
    init, fini, rodata = get_segment_positions(shdr, e_shnum, file)
    print(f'start reading here {init}\nlast section here {fini}\nstop reading here {rodata}')
    hx, bi, asm, by = get_assembly_correctly1(file, init, rodata, data=file[init:rodata])
    print(asm)


if __name__ == '__main__':
  read_arm_macho_hello()
  read_arm_macho_func()
  read_amd_elf_hello()
  read_amd_elf_func()
  read_helloamd_objdump()
  read_helloarm_objdump()
  read_funcamd_objdump()
  read_funcarm_objdump()
  read_amd_elf_hello_tmp()
  print('OK')
