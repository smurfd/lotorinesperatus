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
  amd.print_hex(amd.bytes2hex(amd.asm.get_hhh()))
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


if __name__ == '__main__':
  read_arm_macho_hello()
  read_arm_macho_func()
  read_amd_elf_hello()
  read_amd_elf_func()
  read_helloamd_objdump()
  read_helloarm_objdump()
  read_funcamd_objdump()
  read_funcarm_objdump()
  print('OK')
