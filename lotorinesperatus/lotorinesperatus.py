#!/usr/bin/env python3
from typing import List
import curses, os

class LotorInesperatus:
  def __init__(self, fn):
    self.chunks = []
    self.fn = fn
    with open(self.fn, 'rb') as f:
      while True:
        chunk = f.read(4)
        if not chunk: break
        self.chunks.append(chunk)

  def get_binary(self) -> List:
    return self.chunks

  def cwin(self, stdscr):
    bindat = self.get_binary()
    curses.noecho()
    curses.cbreak()
    curses.curs_set(False)
    if curses.has_colors(): curses.start_color()
    curses.use_default_colors()
    curses.mousemask(curses.ALL_MOUSE_EVENTS | curses.REPORT_MOUSE_POSITION)
    curses.flushinp()
    stdscr.keypad(True)
    try:
      index, start = 0, 0
      curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_RED)
      curses.init_pair(2, curses.COLOR_BLUE, curses.COLOR_WHITE)
      stdscr.addstr(curses.LINES - 1, 0, 'Press Q to quit, any other key to alternate')
      stdscr.refresh()
      while True: #not done:
        mainWindow1 = curses.newwin(10, 12, 14, 3) # hight, width, starty, startx
        mainWindow2 = curses.newwin(10, 80, 3, 3)
        mainWindow1.bkgd(' ', curses.color_pair(1))
        mainWindow2.bkgd(' ', curses.color_pair(2))
        mainWindow1.border(0)
        mainWindow2.border(0)
      
        for i in range(start + 1, start + 9):
          s0 = []
          for j in range(7):
            s0.append('0x{:08x}'.format(int.from_bytes(bindat[((i * 4) - 4) + j])))
            mainWindow2.addstr(i - start, 2 + (11 * j), s0[j])
        mainWindow1.addstr(1, 1, '0x{:08x}'.format(int.from_bytes(bindat[(start * 4)])))
        mainWindow1.box()
        mainWindow2.box()
        mainWindow1.refresh()
        mainWindow2.refresh()
        stdscr.addstr(0, 0, f'Iteration [{str(index)}]')
        stdscr.refresh()
        ch = stdscr.getch()
        if ch == ord('Q') or ch == ord('q'): break #done = True
        elif ch == curses.KEY_DOWN: start += 1
        elif ch == curses.KEY_UP and start > 0: start -= 1
        if ch == curses.KEY_MOUSE:
          if index % 2: curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_GREEN)
          else: curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_RED)
        stdscr.refresh()
        index += 1

    except Exception as err: print(f'Got error(s) [{str(err)}]')
    curses.nocbreak()
    curses.echo()
    curses.curs_set(True)
    stdscr.keypad(False)

