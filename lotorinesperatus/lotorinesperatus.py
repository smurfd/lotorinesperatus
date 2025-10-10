#!/usr/bin/env python3
from typing import List
import curses, os

class LotorInesperatus:
  def __init__(self, fn):
    self.chunks = []
    self.fn = fn
    self.nr = 0
    with open(self.fn, 'rb') as f:
      while True:
        chunk = f.read(4)
        if not chunk: break
        self.chunks.append(chunk)
        self.nr+=1

  def get_binary(self) -> List:
    return self.chunks

  def curses_setup(self, curses, stdscr):
    curses.noecho()
    curses.cbreak()
    curses.curs_set(False)
    if curses.has_colors(): curses.start_color()
    curses.use_default_colors()
    curses.mousemask(curses.ALL_MOUSE_EVENTS | curses.REPORT_MOUSE_POSITION)
    curses.flushinp()
    stdscr.keypad(True)
    curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_RED)
    curses.init_pair(2, curses.COLOR_BLUE, curses.COLOR_WHITE)

  def curses_teardown(self, curses, stdscr):
    curses.nocbreak()
    curses.echo()
    curses.curs_set(True)
    stdscr.keypad(False)

  def cwin(self, stdscr):
    bindat = self.get_binary()
    self.curses_setup(curses, stdscr)
    try:
      index, start = 0, 0
      stdscr.addstr(curses.LINES - 1, 0, 'Press Q to quit, any other key to alternate')
      stdscr.refresh()
      while True:
        infowin = curses.newwin(10, 12, 14, 3) # hight, width, starty, startx
        hexwin = curses.newwin(10, 80, 3, 3)
        infowin.bkgd(' ', curses.color_pair(1))
        hexwin.bkgd(' ', curses.color_pair(2))
        infowin.border(0)
        hexwin.border(0)
      
        for i in range(start + 1, start + 9):
          s0 = []
          for j in range(7):
            s0.append('0x{:08x}'.format(int.from_bytes(bindat[((i * 4) - 4) + j])))
            hexwin.addstr(i - start, 2 + (11 * j), s0[j])
        infowin.addstr(1, 1, '0x{:08x}'.format(int.from_bytes(bindat[(start * 4)])))
        infowin.box()
        hexwin.box()
        infowin.refresh()
        hexwin.refresh()
        stdscr.addstr(0, 0, f'Iteration [{str(index)}] :: {start} / {self.nr}')
        stdscr.refresh()
        ch = stdscr.getch()
        if ch == ord('Q') or ch == ord('q'): break
        elif ch == curses.KEY_DOWN: start += 1
        elif ch == curses.KEY_UP and start > 0: start -= 1
        if ch == curses.KEY_MOUSE:
          if index % 2: curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_GREEN)
          else: curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_RED)
        stdscr.refresh()
        index += 1

    except Exception as err: print(f'Got error(s) [{str(err)}]')
    self.curses_teardown(curses, stdscr)

