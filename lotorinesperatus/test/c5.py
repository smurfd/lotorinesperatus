import curses


def main(stdscr):
    menu_items = ["Option 1", "Option 2", "Option 3"]
    selected = 0

    while True:
        stdscr.clear()
        for i, item in enumerate(menu_items):
            if i == selected:
                stdscr.addstr(i, 0, f"> {item}", curses.A_REVERSE)
            else:
                stdscr.addstr(i, 0, item)

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

        stdscr.refresh()


curses.wrapper(main)
