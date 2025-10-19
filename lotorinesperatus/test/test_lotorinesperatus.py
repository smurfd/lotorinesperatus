#!/usr/bin/env python3
from lotorinesperatus.lotorinesperatus import LotorInesperatus
import platform, capstone, curses, sys, os


def curses_lotorinesperatus() -> None:
  curses.wrapper(LotorInesperatus(os.path.dirname(os.path.realpath(__file__)) + '/examples/hello.bin').cwin)

def test_lotorinesperatus() -> None:
  l = LotorInesperatus(os.path.dirname(os.path.realpath(__file__)) + '/examples/hello.bin')
  bind, _ = l.get_binary()
  lb, ll = l.get_disassembly(bind)
  with open(os.path.dirname(os.path.realpath(__file__)) + '/examples/hello.genasm', 'r') as f:
    genb = f.read()
    genl = len(genb)
  assert(genl == ll)
  assert(genb == lb)

if __name__ == '__main__':
  curses_lotorinesperatus()
  print('OK')
