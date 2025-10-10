import curses


def main(stdscr):
    progress = 0
    curses.noecho()
    curses.cbreak()
    curses.curs_set(False)
    if curses.has_colors(): curses.start_color()
    curses.use_default_colors()
    curses.init_pair(1, curses.COLOR_RED, curses.COLOR_WHITE)
    while progress < 100:
        stdscr.clear()
        bar_width = 40
        filled_width = int(bar_width * progress / 100)
        stdscr.addstr(0, 0, "[" + "-" * filled_width + " " * (bar_width - filled_width) + "]" +  f" {progress}%", curses.color_pair(1))
        stdscr.refresh()
        progress += 1
        curses.napms(100)


curses.wrapper(main)
