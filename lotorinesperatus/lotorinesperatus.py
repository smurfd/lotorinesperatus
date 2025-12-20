#!/usr/bin/env python3
# Auth: smurfd, 2025; 2 space indent; 150 with;                                                                                                     #
# ------------------------------------------------------------------------------------------------------------------------------------------------- #
from lotorinesperatus.assembly import Assembly
from typing import List, Tuple
import platform, subprocess, curses, sys, os


class LotorInesperatus:
  def __init__(self, fn) -> None:
    self.chunks, self.disasm = [], []
    self.bin, self.fn, self.nr = b'', fn, 0
    with open(self.fn, 'rb') as f:
      self.bin = f.read()
      self.nr = len(self.bin) // 4
  def get_binary(self) -> Tuple: return self.bin, len(self.bin)
  #def get_disassembly(self, code, test=False) -> Tuple:
  #  if pm := platform.machine() == 'arm64': cs = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
  #  elif pm == 'amd64': cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
  #  cs.skipdata, ret = True, ''
  #  # TODO: this logic should be in format, but probably we skip capstone, so dont move for now
  #  if test: [ret := ret + f'{ins.address:#08x}: {ins.mnemonic}\t{ins.op_str}\n' for ins in cs.disasm(code, 0)]
  #  else: [ret := ret + f'{ins.address:#08x}|{ins.mnemonic+(" " * (5 - len(ins.mnemonic)))}|{"|".join(str(y) for y in ins.op_str.split(", "))}\n'
  #    .replace('|', '\t') for ins in cs.disasm(code, 0)]
  #  return ret, len(ret)
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
  def curses_keymanage(self, curses, stdscr, start, astart, index, blen, asmlen) -> Tuple:
    ch, stop = stdscr.getch(), False
    if ch == ord('Q') or ch == ord('q'): stop = True
    elif ch == curses.KEY_DOWN:
      if start < blen: start += 1
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
    filled, prgstr = int(83 * progress / pmax), '{:03}'.format(progress * 100 // pmax)
    stdscr.addstr(2, 3, '[' + '-' * filled + ' ' * (83 - filled) + ']' +  f' {prgstr}%', curses.color_pair(3))
  def cwin(self, stdscr) -> None:
    asm = Assembly(os.path.dirname(os.path.realpath(__file__)) + '/test/examples/hello_arm64_macho.bin', arch='arm64', flavour='arm64', binfmt='macho')
    arm_header, arm_command, arm_loader, arm_segment = asm.asm.get_header(), asm.asm.get_command(), asm.asm.get_loader(0), asm.asm.get_segment(80)
    h, b, a, bb = asm.asm.get_assembly()
    d = asm.asm.d #asm.asm.get_data()
    asmdat, asmlen, bind, binlen = a, len(a), b, len(b)
    self.curses_setup(curses, stdscr)
    if len(d) < 11: blen = len(d)
    elif len(d) == 0: blen = 10
    else: blen = 10
    try:
      index, start, astart, stop, alen = 0, 0, 0, 0, 0
      stdscr.addstr(curses.LINES - 1, 0, 'Press Q to quit, any other key to alternate')
      stdscr.refresh()
      while True:
        hexwin, infwin, diswin = curses.newwin(10, 90, 3, 3), curses.newwin(10, 12, 14, 3), curses.newwin(30, 77, 14, 16)  # h, w, y, x
        infwin.bkgd(' ', curses.color_pair(1))
        hexwin.bkgd(' ', curses.color_pair(2))
        diswin.bkgd(' ', curses.color_pair(2))
        infwin.border(0)
        hexwin.border(0)
        diswin.border(0)
        #if len(d) < 11: blen = len(d)
        #elif len(d) == 0: blen = 10
        #else: blen = 10
        for i in range(start + 1, start + blen):
          s0 = []
          for j in range(2):
            s0.append('0x{:08x}'.format(d[((i * 4) - 4) + j]))
            hexwin.addstr(i - start, 3, '0x{:04x}'.format(i))
            s0.append('{:08x}'.format(d[i])) #f'{d[i]}')
            s0.append(d[start * 4])
            #s0.append(h[0])
            #hexwin.addstr(i - start, 0, str(blen))
            #hexwin.addstr(i - start, 9, str(j))
            #hexwin.addstr(i - start, 12, str(len(asm.asm.file)))
            #hexwin.addstr(i - start, 18, str(len(asm.asm.d)))
            #hexwin.addstr(i - start, 25, str(len(asm.asm.data)))
            hexwin.addstr(i - start, blen + ((blen + 1) * j), s0[j])
            #hexwin.addstr(i - start, len(b) + ((len(b) + 1) * j), s0[j])
        #infwin.addstr(1, 1, '0x{:08x}'.format(len(h)))
        #infwin.addstr(1, 1, '0x{:08x}'.format(h[(start * 4)]))
        stdscr.addstr(0, 0, f'Iteration [{str(index)}] :: {start} / {self.nr}')
        s1 = []
        if asmlen < 11: alen = asmlen
        else: alen = 10
        for i in range(astart + 0, astart + alen):
          s1.append(asmdat[i])
          diswin.addstr(i - astart, 1, s1[i - astart])
        self.curses_progress(curses, stdscr, start, self.nr)
        self.curses_refresh(infwin, hexwin, diswin, stdscr)
        start, stop, index, astart = self.curses_keymanage(curses, stdscr, start, astart, index, binlen, asmlen - 10)
        if stop: break
        index += 1
    except Exception as err: print(f'Got error(s) [{str(err)}]')
    self.curses_teardown(curses, stdscr)
    # TODO: return value to figure out
