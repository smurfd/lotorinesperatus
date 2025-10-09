import curses


def main(stdscr):
    progress = 0
    while progress < 100:
        stdscr.clear()
        bar_width = 40
        filled_width = int(bar_width * progress / 100)
        #stdscr.addstr(0, 0, "[" + "#" * filled_width + " " * (bar_width - filled_width) + "]")
        stdscr.addstr(0, 0, "[" + "#" * filled_width + " " * (bar_width - filled_width) + "]" +  f" {progress}%")
        #stdscr.addstr(1, 0, f"{progress}%")
        stdscr.refresh()
        progress += 1
        curses.napms(100)


curses.wrapper(main)
