#!/usr/bin/env python3
from typing import List, Tuple
import subprocess, curses, os

class LotorInesperatus:
  def __init__(self, fn) -> None:
    self.chunks = []
    self.disasm = []
    self.fn = fn
    self.nr = 0
    with open(self.fn, 'rb') as f:
      while True:
        chunk = f.read(4)
        if not chunk: break
        self.chunks.append(chunk)
        self.nr+=1
    result = subprocess.run(['objdump', '-d', fn], capture_output=True, text=True)
    self.disasm = result.stdout

  def get_binary(self) -> List:
    return self.chunks

  def get_disassembly(self) -> List:
    return [s for s in self.disasm.splitlines()]

  def curses_setup(self, curses, stdscr) -> None:
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

  def curses_teardown(self, curses, stdscr) -> None:
    curses.nocbreak()
    curses.echo()
    curses.curs_set(True)
    stdscr.keypad(False)

  def curses_refresh(self, infowin, hexwin, diswin, stdscr) -> None:
    infowin.box()
    hexwin.box()
    diswin.box()
    infowin.refresh()
    hexwin.refresh()
    diswin.refresh()
    stdscr.refresh()

  def curses_keymanage(self, curses, stdscr, start, index) -> Tuple:
    stop = False
    ch = stdscr.getch()
    if ch == ord('Q') or ch == ord('q'): stop = True
    elif ch == curses.KEY_DOWN: start += 1
    elif ch == curses.KEY_UP and start > 0: start -= 1
    if ch == curses.KEY_MOUSE:
      if index % 2: curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_GREEN)
      else: curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_RED)
    return start, stop, index

  def curses_progress(self, curses, stdscr, progress, pmax) -> None:
    curses.init_pair(3, curses.COLOR_RED, curses.COLOR_WHITE)
    width = 83
    filled = int(width * progress / pmax)
    prgstr = '{:03}'.format(progress * 100 // pmax)
    stdscr.addstr(2, 3, '[' + '-' * filled + ' ' * (width - filled) + ']' +  f' {prgstr}%', curses.color_pair(3))

  def curses_menu(self) -> None: # TODO if needed
    menu_items = ["Option 1", "Option 2", "Option 3"]
    selected = 0
    while True:
      stdscr.clear()
      for i, item in enumerate(menu_items):
        if i == selected: stdscr.addstr(i, 0, f"> {item}", curses.A_REVERSE)
        else: stdscr.addstr(i, 0, item)
      key = stdscr.getch()
      if key == curses.KEY_UP and selected > 0:
        selected -= 1
      elif key == curses.KEY_DOWN and selected < len(menu_items) - 1:
        selected += 1
      elif key == 10:  # Enter key
        stdscr.addstr(len(menu_items) + 1, 0, f"You selected: {menu_items[selected]}")
        stdscr.refresh()
        stdscr.getch()
        break


  def cwin(self, stdscr) -> None:
    bindat = self.get_binary()
    asmdat = self.get_disassembly()
    self.curses_setup(curses, stdscr)
    try:
      index, start = 0, 0
      stdscr.addstr(curses.LINES - 1, 0, 'Press Q to quit, any other key to alternate')
      stdscr.refresh()
      while True:
        infwin = curses.newwin(10, 12, 14, 3) # hight, width, starty, startx
        hexwin = curses.newwin(10, 90, 3, 3)
        diswin = curses.newwin(30, 77, 14, 16)
        infwin.bkgd(' ', curses.color_pair(1))
        hexwin.bkgd(' ', curses.color_pair(2))
        diswin.bkgd(' ', curses.color_pair(2))
        infwin.border(0)
        hexwin.border(0)
        diswin.border(0)
        for i in range(start + 1, start + 9):
          s0 = []
          for j in range(7):
            s0.append('0x{:08x}'.format(int.from_bytes(bindat[((i * 4) - 4) + j])))
            hexwin.addstr(i - start, 2, '0x{:04x}'.format(i))
            hexwin.addstr(i - start, 10 + (11 * j), s0[j])
        infwin.addstr(1, 1, '0x{:08x}'.format(int.from_bytes(bindat[(start * 4)])))
        stdscr.addstr(0, 0, f'Iteration [{str(index)}] :: {start} / {self.nr}')
        s1 = []
        for i in range(21):
          s1.append(asmdat[i])
          diswin.addstr(i, 1, s1[i])
        self.curses_progress(curses, stdscr, start, self.nr)
        self.curses_refresh(infwin, hexwin, diswin, stdscr)
        start, stop, index = self.curses_keymanage(curses, stdscr, start, index)
        if stop: break
        index += 1
    except Exception as err: print(f'Got error(s) [{str(err)}]')
    self.curses_teardown(curses, stdscr)

