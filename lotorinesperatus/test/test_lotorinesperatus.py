#!/usr/bin/env python3
from lotorinesperatus.lotorinesperatus import LotorInesperatus
import curses, os


def test_lotorinesperatus() -> None:
  l = LotorInesperatus(os.path.dirname(os.path.realpath(__file__)) + '/examples/hello.bin')
  curses.wrapper(l.cwin)


if __name__ == '__main__':
  test_lotorinesperatus()
  print('OK')
