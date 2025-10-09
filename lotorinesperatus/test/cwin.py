import curses
import struct
import math
import sys

def cwin(stdscr):
  bindat = [struct.pack(">Q", i) for i in range(1000)]
  curses.noecho()
  curses.cbreak()
  curses.curs_set(False)
  if curses.has_colors(): curses.start_color()
  curses.use_default_colors()
  curses.mousemask(curses.ALL_MOUSE_EVENTS | curses.REPORT_MOUSE_POSITION)
  curses.flushinp()
  stdscr.keypad(True)
  try:
    curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_RED)
    curses.init_pair(2, curses.COLOR_BLUE, curses.COLOR_WHITE)
    stdscr.addstr(curses.LINES - 1, 0, 'Press Q to quit, any other key to alternate')
    stdscr.refresh()

    index, start = 0, 0
    done = False
    items = [f'Item {i}' for i in range(1, 101)]
    while not done:
      mainWindow1 = curses.newwin(10, 12, 14, 3) # hight, width, starty, startx
      mainWindow2 = curses.newwin(10, 80, 3, 3)
      mainWindow1.bkgd(' ', curses.color_pair(1))
      mainWindow2.bkgd(' ', curses.color_pair(2))
      mainWindow1.border(0)
      mainWindow2.border(0)
      
      for i in range(start + 1, start + 9):
        s0 = "0x{:08x}".format(int.from_bytes(bindat[((i * 4) - 4) + 0]))
        s1 = "0x{:08x}".format(int.from_bytes(bindat[((i * 4) - 4) + 1]))
        s2 = "0x{:08x}".format(int.from_bytes(bindat[((i * 4) - 4) + 2]))
        s3 = "0x{:08x}".format(int.from_bytes(bindat[((i * 4) - 4) + 3]))
        mainWindow2.addstr(i - start,  1, s0)
        mainWindow2.addstr(i - start, 12, s1)
        mainWindow2.addstr(i - start, 23, s2)
        mainWindow2.addstr(i - start, 34, s3)
      mainWindow1.addstr(1, 1, "0x{:08x}".format(int.from_bytes(bindat[(start * 4)])))

      mainWindow1.box()
      mainWindow2.box()
      mainWindow1.refresh()
      mainWindow2.refresh()

      stdscr.addstr(0, 0, f'Iteration [{str(index)}]')
      stdscr.refresh()
      ch = stdscr.getch()
      if ch == ord('Q') or ch == ord('q'): done = True
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


if __name__ == '__main__':
  curses.wrapper(cwin)

