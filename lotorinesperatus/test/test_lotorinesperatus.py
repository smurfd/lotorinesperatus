#!/usr/bin/env python3
from lotorinesperatus.lotorinesperatus import LotorInesperatus, FormatAsm
import platform, capstone, curses, sys, os


def test_lotorinesperatus() -> None:
  l = LotorInesperatus(os.path.dirname(os.path.realpath(__file__)) + '/examples/hello.bin')
  bind, _ = l.get_binary()
  lb, ll = l.get_disassembly(bind, test=True)
  with open(os.path.dirname(os.path.realpath(__file__)) + '/examples/hello.genasm', 'r') as f:
    genb = f.read()
    genl = len(genb)
  assert(genl == ll)
  assert(genb == lb)

def curses_lotorinesperatus(pth) -> None:
  curses.wrapper(LotorInesperatus(pth).cwin)

def print_asm(pth) -> None:
  l = LotorInesperatus(pth)
  bind, _ = l.get_binary()
  lb, ll = l.get_disassembly(bind)
  FormatAsm().print(lb)

if __name__ == '__main__':
  curses_lotorinesperatus(os.path.dirname(os.path.realpath(__file__)) + '/examples/hello.bin')  # Cursor ui
  print_asm(os.path.dirname(os.path.realpath(__file__)) + '/examples/hello.bin')                # just print the asm
  print('OK')
