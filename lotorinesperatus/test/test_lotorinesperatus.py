#!/usr/bin/env python3
from lotorinesperatus.lotorinesperatus import LotorInesperatus
import curses, os


def test_lotorinesperatus() -> None:
  curses.wrapper(LotorInesperatus(os.path.dirname(os.path.realpath(__file__)) + '/examples/hello.bin').cwin)


if __name__ == '__main__':
  test_lotorinesperatus()
  print('OK')
