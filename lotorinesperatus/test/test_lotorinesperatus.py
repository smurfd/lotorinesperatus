#!/usr/bin/env python3
from lotorinesperatus.lotorinesperatus import LotorInesperatus
import platform, capstone, curses, sys, os


def test_lotorinesperatus() -> None:
  curses.wrapper(LotorInesperatus(os.path.dirname(os.path.realpath(__file__)) + '/examples/hello.bin').cwin)

def test_t():
  l = LotorInesperatus(os.path.dirname(os.path.realpath(__file__)) + '/examples/hello.bin')
  lb, ll = l.get_dis(l.get_bin())
  print(lb)
  print(ll)

if __name__ == '__main__':
  test_lotorinesperatus()
  test_t()
  print('OK')
