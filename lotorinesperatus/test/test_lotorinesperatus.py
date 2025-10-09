#!/usr/bin/env python3
from lotorinesperatus.lotorinesperatus import LotorInesperatus
from typing import Any
import sys, time, os, curses


def test_lotorinesperatus() -> None:
  t = time.perf_counter()
  l = LotorInesperatus(os.path.dirname(os.path.realpath(__file__)) + '/examples/hello.bin')
  print('time {:.4f}'.format(time.perf_counter() - t))

def test_color2() -> None:
  class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
  print(f"{bcolors.WARNING}Warning: No active frommets remain. Continue?{bcolors.ENDC}")
  print(f'{bcolors.FAIL}[{bcolors.ENDC}stuff here{bcolors.OKBLUE}]{bcolors.ENDC}')

def cmain(win):
    win.nodelay(True)
    win.clear()                
    win.addstr("Detected key:")
    while True:          
        try:                 
           key = win.getkey()         
           win.clear()                
           #win.addstr("Detected key:")
           win.addstr(str(key)) 
           if key == os.linesep:
              break           
        except Exception as e:
           # No input   
           pass         


if __name__ == '__main__':
  test_lotorinesperatus()
  test_color2()
  curses.wrapper(cmain)
  print('OK')
