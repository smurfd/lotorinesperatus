#!/usr/bin/env python3
from lotorinesperatus.lotorinesperatus import LotorInesperatus
from lotorinesperatus.assembly import Assembly, Format
import platform, capstone, curses, sys, os


def test_lotorinesperatus_arm() -> None:
  l = LotorInesperatus(os.path.dirname(os.path.realpath(__file__)) + '/examples/hello_arm64_macho.bin')
  bind, _ = l.get_binary()
  lb, ll = l.get_disassembly(bind, test=True)
  with open(os.path.dirname(os.path.realpath(__file__)) + '/examples/hello_arm64_macho.capstone', 'r') as f:
    genb = f.read()
    genl = len(genb)
  assert(genl == ll)
  assert(genb == lb)
def test_lotorinesperatus_amd() -> None:
  l = LotorInesperatus(os.path.dirname(os.path.realpath(__file__)) + '/examples/hello_amd64_elf.bin')
  bind, _ = l.get_binary()
  lb, ll = l.get_disassembly(bind, test=True)
  print(lb)
  with open(os.path.dirname(os.path.realpath(__file__)) + '/examples/hello_amd64_elf.capstone', 'r') as f:
    genb = f.read()
    genl = len(genb)
  assert(genl == ll)
  assert(genb == lb)
def curses_lotorinesperatus(pth) -> None: curses.wrapper(LotorInesperatus(pth).cwin)
def print_asm(pth) -> None:
  l = LotorInesperatus(pth)
  bind, _ = l.get_binary()
  lb, ll = l.get_disassembly(bind)
  Format().print(lb)

if __name__ == '__main__':
  if len(sys.argv) >= 2 and sys.argv[1] == 'gui':
    curses_lotorinesperatus(os.path.dirname(os.path.realpath(__file__)) + '/examples/hello_arm64_macho.bin')  # Cursor ui
  print_asm(os.path.dirname(os.path.realpath(__file__)) + '/examples/hello_arm64_macho.bin')                  # just print the asm
  # Read our own assembly
  print('--- arm64 macho header ---')
  arm = Assembly(os.path.dirname(os.path.realpath(__file__)) + '/examples/hello_arm64_macho.bin', arch='arm64', flavour='arm64', binfmt='macho')
  arm_header = arm.asm.get_header()
  arm_loader = arm.asm.get_loader()
  print(arm_header)
  print(arm_loader)
  print('--- amd64 elf header ---')
  amd = Assembly(os.path.dirname(os.path.realpath(__file__)) + '/examples/hello_amd64_elf.bin', arch='amd64', flavour='amd64', binfmt='elf')
  amd_header = amd.asm.get_header()
  amd_header_program = amd.asm.get_header_program()
  amd_header_section = amd.asm.get_header_section()
  print(amd_header)
  print(amd_header_program)
  print(amd_header_section)
  print('OK')

