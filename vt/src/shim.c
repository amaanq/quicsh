// The calls into libghostty-vt, written in C so that the compiler checks
// every struct and enum against the library's own header.

#include <ghostty/vt.h>

// How many bytes of an unfinished escape sequence the terminal keeps, so
// that qvt_continuation can give them back.
#define CONTINUATION_LIMIT 4096

// How much memory the history may take, whatever its row count.
#define HISTORY_BYTES ((size_t)32 << 20)

GhosttyTerminal qvt_new(uint16_t columns, uint16_t rows, size_t history) {
  GhosttyTerminal terminal;
  size_t kept = CONTINUATION_LIMIT;
  size_t bytes = HISTORY_BYTES;

  if (ghostty_terminal_new(NULL, &terminal, columns, rows) != GHOSTTY_SUCCESS) {
    return NULL;
  }

  ghostty_terminal_set(terminal, GHOSTTY_TERMINAL_OPT_SCROLLBACK_MAX_BYTES, &bytes);
  ghostty_terminal_set(terminal, GHOSTTY_TERMINAL_OPT_SCROLLBACK_MAX_LINES, &history);
  ghostty_terminal_set(terminal, GHOSTTY_TERMINAL_OPT_CONTINUATION_MAX_BYTES, &kept);

  return terminal;
}

void qvt_free(GhosttyTerminal terminal) {
  ghostty_terminal_free(terminal);
}

void qvt_write(GhosttyTerminal terminal, const uint8_t* bytes, size_t length) {
  ghostty_terminal_vt_write(terminal, bytes, length);
}

bool qvt_resize(GhosttyTerminal terminal, uint16_t columns, uint16_t rows) {
  return ghostty_terminal_resize(terminal, columns, rows, 0, 0) == GHOSTTY_SUCCESS;
}

bool qvt_alternate(GhosttyTerminal terminal) {
  GhosttyTerminalScreen screen = GHOSTTY_TERMINAL_SCREEN_PRIMARY;

  ghostty_terminal_get(terminal, GHOSTTY_TERMINAL_DATA_ACTIVE_SCREEN, &screen);
  return screen == GHOSTTY_TERMINAL_SCREEN_ALTERNATE;
}

size_t qvt_history(GhosttyTerminal terminal) {
  size_t rows = 0;

  ghostty_terminal_get(terminal, GHOSTTY_TERMINAL_DATA_SCROLLBACK_ROWS, &rows);
  return rows;
}

// Where the rows start that `part` names, and where they end.
static bool span(GhosttyTerminal terminal, GhosttyPointTag part, GhosttySelection* selection) {
  uint16_t columns = 0;
  size_t rows = 0;
  uint16_t shown = 0;

  ghostty_terminal_get(terminal, GHOSTTY_TERMINAL_DATA_COLS, &columns);
  ghostty_terminal_get(terminal, GHOSTTY_TERMINAL_DATA_ROWS, &shown);
  ghostty_terminal_get(terminal, GHOSTTY_TERMINAL_DATA_SCROLLBACK_ROWS, &rows);

  if (part == GHOSTTY_POINT_TAG_ACTIVE) {
    rows = shown;
  }

  if (columns == 0 || rows == 0) {
    return false;
  }

  GhosttyPoint first = {.tag = part, .value = {.coordinate = {.x = 0, .y = 0}}};
  GhosttyPoint last = {
      .tag = part,
      .value = {.coordinate = {.x = columns - 1, .y = (uint32_t)(rows - 1)}},
  };

  selection->start = GHOSTTY_INIT_SIZED(GhosttyGridRef);
  selection->end = GHOSTTY_INIT_SIZED(GhosttyGridRef);

  return ghostty_terminal_grid_ref(terminal, first, &selection->start) == GHOSTTY_SUCCESS &&
         ghostty_terminal_grid_ref(terminal, last, &selection->end) == GHOSTTY_SUCCESS;
}

// Writes the escape sequences that draw the screen, or the plain styled
// rows of the history above it, into a buffer for qvt_release.
bool qvt_format(GhosttyTerminal terminal, bool history, uint8_t** out, size_t* length) {
  GhosttySelection selection = GHOSTTY_INIT_SIZED(GhosttySelection);
  GhosttyFormatterTerminalOptions options = GHOSTTY_INIT_SIZED(GhosttyFormatterTerminalOptions);
  GhosttyFormatter formatter;

  *out = NULL;
  *length = 0;

  if (!span(terminal, history ? GHOSTTY_POINT_TAG_HISTORY : GHOSTTY_POINT_TAG_ACTIVE, &selection)) {
    return history;
  }

  options.emit = GHOSTTY_FORMATTER_FORMAT_VT;
  options.selection = &selection;
  options.extra.size = sizeof(options.extra);
  options.extra.screen.size = sizeof(options.extra.screen);

  if (!history) {
    options.extra.modes = true;
    options.extra.scrolling_region = true;
    options.extra.keyboard = true;
    options.extra.screen.cursor = true;
    options.extra.screen.style = true;
    options.extra.screen.hyperlink = true;
    options.extra.screen.protection = true;
    options.extra.screen.kitty_keyboard = true;
    options.extra.screen.charsets = true;
  }

  if (ghostty_formatter_terminal_new(NULL, &formatter, terminal, options) != GHOSTTY_SUCCESS) {
    return false;
  }

  GhosttyResult result = ghostty_formatter_format_alloc(formatter, NULL, out, length);

  ghostty_formatter_free(formatter);
  return result == GHOSTTY_SUCCESS;
}

// Writes the unfinished escape sequence the terminal is in the middle of,
// which is empty between sequences, into a buffer for qvt_release.
bool qvt_continuation(GhosttyTerminal terminal, uint8_t** out, size_t* length) {
  *out = NULL;
  *length = 0;

  return ghostty_terminal_continuation_alloc(terminal, NULL, out, length) == GHOSTTY_SUCCESS;
}

void qvt_release(uint8_t* bytes, size_t length) {
  ghostty_free(NULL, bytes, length);
}
