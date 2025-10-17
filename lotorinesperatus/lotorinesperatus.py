#!/usr/bin/env python3
from typing import List, Tuple
import platform, subprocess, capstone, curses, sys, os

class LotorInesperatus:
  def __init__(self, fn) -> None:
    self.chunks, self.disasm = [], []
    self.bin, self.fn, self.nr = b'', fn, 0
    with open(self.fn, 'rb') as f:
      self.bin = f.read()
      self.nr = len(self.bin) // 4

  def get_binary(self) -> bytes:
    return self.bin

  def get_disassembly(self, code) -> Tuple:
    if pm := platform.machine() == 'arm64': cs = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    elif pm == 'amd64': cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    cs.skipdata = True
    ret = ''
    for instr in cs.disasm(code, 0): ret += f'{instr.address:#08x}: {instr.mnemonic}\t{instr.op_str}\n'
    return ret, len(ret)

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

  def curses_keymanage(self, curses, stdscr, start, astart, index, asmlen) -> Tuple:
    stop = False
    ch = stdscr.getch()
    if ch == ord('Q') or ch == ord('q'): stop = True
    elif ch == curses.KEY_DOWN:
      start += 1
      if astart < asmlen: astart += 1
    elif ch == curses.KEY_UP and start > 0:
      if start > 0: start -= 1
      if astart > 0: astart -= 1
    if ch == curses.KEY_MOUSE:
      if index % 2: curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_GREEN)
      else: curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_RED)
    return start, stop, index, astart

  def curses_progress(self, curses, stdscr, progress, pmax) -> None:
    curses.init_pair(3, curses.COLOR_RED, curses.COLOR_WHITE)
    filled = int(83 * progress / pmax) # 83 == width
    prgstr = '{:03}'.format(progress * 100 // pmax)
    stdscr.addstr(2, 3, '[' + '-' * filled + ' ' * (83 - filled) + ']' +  f' {prgstr}%', curses.color_pair(3))

  def curses_menu(self) -> None: # TODO if needed
    menu_items = ['Option 1', 'Option 2', 'Option 3']
    selected = 0
    while True:
      stdscr.clear()
      for i, item in enumerate(menu_items):
        if i == selected: stdscr.addstr(i, 0, f'> {item}', curses.A_REVERSE)
        else: stdscr.addstr(i, 0, item)
      key = stdscr.getch()
      if key == curses.KEY_UP and selected > 0: selected -= 1
      elif key == curses.KEY_DOWN and selected < len(menu_items) - 1: selected += 1
      elif key == 10:  # Enter key
        stdscr.addstr(len(menu_items) + 1, 0, f'You selected: {menu_items[selected]}')
        stdscr.refresh()
        stdscr.getch()
        break


  def cwin(self, stdscr) -> None:
    bind = self.get_binary()
    asmdat, asmlen = self.get_disassembly(bind)
    self.curses_setup(curses, stdscr)
    try:
      index, start, astart = 0, 0, 0
      stdscr.addstr(curses.LINES - 1, 0, 'Press Q to quit, any other key to alternate')
      stdscr.refresh()
      while True:
        hexwin = curses.newwin(10, 90, 3, 3) # hight, width, starty, startx
        infwin = curses.newwin(10, 12, 14, 3)
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
            s0.append('0x{:08x}'.format(bind[((i * 4) - 4) + j]))
            hexwin.addstr(i - start, 2, '0x{:04x}'.format(i))
            hexwin.addstr(i - start, 10 + (11 * j), s0[j])
        infwin.addstr(1, 1, '0x{:08x}'.format(bind[(start * 4)]))
        stdscr.addstr(0, 0, f'Iteration [{str(index)}] :: {start} / {self.nr}')
        s1 = []
        if asmlen < 11:
          for i in range(asmlen):
            s1.append(asmdat.splitlines()[i])
            diswin.addstr(i, 1, s1[i])
        else:
          for i in range(0 + astart, 10 + astart):
            s1.append(asmdat.splitlines()[i])
            diswin.addstr(i - astart, 1, s1[i - astart])
        self.curses_progress(curses, stdscr, start, self.nr)
        self.curses_refresh(infwin, hexwin, diswin, stdscr)
        start, stop, index, astart = self.curses_keymanage(curses, stdscr, start, astart, index, asmlen - 10)
        if stop: break
        index += 1
    except Exception as err: print(f'Got error(s) [{str(err)}]')
    self.curses_teardown(curses, stdscr)

