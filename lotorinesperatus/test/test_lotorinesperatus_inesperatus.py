#!/usr/bin/env python3
# Auth: smurfd, 2025; 2 space indent; 150 with;                                                                                                     #
# ------------------------------------------------------------------------------------------------------------------------------------------------- #
from lotorinesperatus.assembly import Assembly
import platform, curses, sys, os


def read_arm_macho() -> None:
  print('--- arm64 macho header ---')
  arm = Assembly(os.path.dirname(os.path.realpath(__file__)) + '/examples/hello_arm64_macho.bin', arch='arm64', flavour='arm64', binfmt='macho')
  arm_header = arm.asm.get_header()
  arm_command= arm.asm.get_command()
  """
  arm_loader = arm.asm.get_loader()
  arm_segment= arm.asm.get_segment()
  arm_data   = arm.asm.get_data()
  arm.print_hex(arm.bytes2hex(arm_header))
  arm.print_hex(arm.bytes2hex(arm_loader))
  arm.print_hex(arm.bytes2hex(arm_segment))
  arm.print_hex(arm.bytes2hex(arm_data))
  for i in range(len(arm_header)): print(f'Header {arm.hex2str(arm_header[i])}')
  for i in range(len(arm_loader)): print(f'Loader {arm.hex2str(arm_loader[i])}')
  for i in range(len(arm_segment)): print(f'Segment {arm.hex2str(arm_segment[i])}')
  """
  print('--- arm64 macho header ---')
def read_amd_elf() -> None:
  print('--- amd64 elf header ---')
  amd = Assembly(os.path.dirname(os.path.realpath(__file__)) + '/examples/hello_amd64_elf.bin', arch='amd64', flavour='amd64', binfmt='elf')
  amd_header         = amd.asm.get_header()
  amd_header_program = amd.asm.get_header_program()
  amd_header_section = amd.asm.get_header_section()
  amd_data           = amd.asm.get_data()
  amd.print_hex(amd.bytes2hex(amd_header))
  amd.print_hex(amd.bytes2hex(amd_header_program))
  amd.print_hex(amd.bytes2hex(amd_header_section))
  amd.print_hex(amd.bytes2hex(amd_data))
  for i in range(len(amd_header)): print(f'Header {amd.hex2str(amd_header[i])}')
  for i in range(len(amd_header_program)): print(f'Program {amd.hex2str(amd_header_program[i])}')
  for i in range(len(amd_header_section)): print(f'Section {amd.hex2str(amd_header_section[i])}')
  print('--- amd64 elf header ---')


if __name__ == '__main__':
  read_arm_macho()
  #read_amd_elf()
  print('OK')
