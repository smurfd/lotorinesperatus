#!/usr/bin/env python3
# Auth: smurfd, 2025; 2 space indent; 150 with;                                                                                                     #
# ------------------------------------------------------------------------------------------------------------------------------------------------- #
from lotorinesperatus.lotorinesperatus import LotorInesperatus
from lotorinesperatus.assembly import Format
import platform, curses, sys, os


def test_lotorinesperatus_arm() -> None:
  l = LotorInesperatus(f'{os.path.dirname(os.path.realpath(__file__))}/examples/hello_arm64_macho.bin')
  bind, _ = l.get_binary()
  lb, ll = l.get_disassembly(bind, test=True)
  with open(f'{os.path.dirname(os.path.realpath(__file__))}/examples/hello_arm64_macho.capstone', 'r') as f:
    genb = f.read()
    genl = len(genb)
  assert(genl == ll)
  assert(genb == lb)
def test_lotorinesperatus_amd() -> None:
  l = LotorInesperatus(f'{os.path.dirname(os.path.realpath(__file__))}/examples/hello_amd64_elf.bin')
  bind, _ = l.get_binary()
  lb, ll = l.get_disassembly(bind, test=True)
  print(lb)
  with open(f'{os.path.dirname(os.path.realpath(__file__))}/examples/hello_amd64_elf.capstone', 'r') as f:
    genb = f.read()
    genl = len(genb)
  assert(genl == ll)
  assert(genb == lb)
def curses_lotorinesperatus(pth) -> None: curses.wrapper(LotorInesperatus(pth).cwin)


if __name__ == '__main__':
  if len(sys.argv) >= 2 and sys.argv[1] == 'gui':
    curses_lotorinesperatus(f'{os.path.dirname(os.path.realpath(__file__))}/examples/hello_arm64_macho.bin')  # Cursor UI
  print('OK')
