# Server-side terminal state and frame coalescing

A design note on making an interactive session feel faster than raw SSH, by
moving the terminal emulator to the server and sending screen state instead of
the raw PTY byte stream. quicsh does not do this today. This records the
architecture, the three speed mechanisms, and what adopting it would cost.

## Why raw PTY forwarding leaves speed on the table

quicsh forwards a pseudo-terminal byte for byte. The remote program writes
escape sequences to its PTY, the holder reads them, and the bytes travel to the
client terminal unchanged. SSH does the same. The client terminal is the only
thing that holds screen state.

That design pays three costs on an interactive session.

- A full-screen redraw ships every byte. A `vim` scroll or a `tmux` repaint
  emits kilobytes of cursor moves and SGR runs. All of it crosses the wire even
  though the end state is one screen.
- A fast writer ships every intermediate frame. `yes`, a build log, or a
  progress bar at 200 updates per second sends 200 screens. The user sees only
  the last one. The other 199 are latency the client must drain before it
  catches up.
- Reattach replays bytes. To restore the screen after a reconnect, the only
  record is the byte history, so the server replays scrollback and the client
  re-renders it. The more scrollback, the longer the catch-up.

## The model

Run the terminal emulator on the server and keep the authoritative cell grid
there. The client becomes a thin renderer that receives screen state.

The shape below is recovered from a shipping implementation's binary. Symbol
names in backticks are real exports, so each claim is checkable. Provenance is
marked, confirmed from a decompiled function or inferred from structure.

- The server links a terminal emulator as a C library and feeds the program's
  PTY output into it. The emulator holds the grid, cursor, styles, and
  scrollback. `cell_get` and `cell_get_multi` read cells back out. Confirmed.
- A render state tracks per-row dirtiness. `render_state_begin_update` opens a
  cycle, `render_state_row_iterator_next_dirty` walks only the rows that
  changed, `render_state_row_cells_get` reads their cells, and
  `render_state_end_update` plus `render_state_clean` close the cycle and reset
  the dirty flags. Confirmed.
- A cell-style differ emits minimal styling. A `StyleDiff` routine computes the
  SGR change from one cell to the next, so an unchanged attribute costs no
  bytes. Confirmed.
- A multiplexer fans out to attached clients. `mux.(*Client)` is the per-client
  handle, with `ground`, `memory`, `chunk`, `compress`, `pause`, `park` source
  files for the stages. Inferred, the stage functions did not survive as
  symbols.
- A separate formatter serves one-shot capture, not the live stream. The
  decompiled `FormatReq.formatterFormat` only validates a format kind string and
  routes to a dump. It is the `capture screen and scrollback` path. Confirmed.

Live output flow on the server:

```
program --PTY bytes--> emulator (grid + dirty rows) --dirty-row encode--> mux --compress--> client
```

The client never sees the program's raw bytes. It sees the dirty rows the
emulator settled in the last update cycle.

## Three mechanisms that beat raw forwarding

1. Coalescing per update cycle. The emulator applies every write immediately
   into the grid and marks rows dirty. One update cycle emits the net dirty
   rows, then `render_state_clean` resets the flags. Writes that land between
   cycles collapse, so 200 intermediate frames of a fast log become one
   send. Confirmed by the begin_update, next_dirty, end_update, clean cycle.

2. Row-level diffing. `row_iterator_next_dirty` yields only changed rows, and
   `StyleDiff` trims each row to the styling that actually changed. A one-line
   status update is a short run, not a full-screen repaint. Confirmed.

3. Compression on settled output. The dirty-row stream is regular and already
   small, and a general-purpose compressor runs on the chunk stream. The
   snapshot path compresses scrollback history separately through
   `SnapshotDecoder.SetCompressHistory`. Confirmed symbol, compressor not named.

## Reattach as a snapshot

A reconnecting client gets one serialized grid snapshot, not a scrollback
replay. `Terminal.Snapshot` and `SnapshotWriteTo` serialize the live grid plus
scrollback, and the client restores it through `NewSnapshotDecoder`. The decoder
has knobs for `SetCompressHistory`, `SetKittyImageStorageLimit`, and
`SetRetainContinuation`, so the snapshot carries compressed history, bounded
inline images, and wrapped-line continuation. Catch-up time is bounded by the
snapshot size, not by how long the session ran. Confirmed.

A terminal keeps about 64 MiB of scrollback, roughly 100,000 lines, and drops
the oldest lines past that cap. The alternate screen keeps no scrollback. These
bounds size the snapshot and the per-terminal memory. From the shipped docs.

## Interaction with the QUIC transport

The transport and the terminal model are independent and compound.

- Coalescing cuts the bytes QUIC must pace, so a lossy path recovers faster
  because there is less in flight to retransmit.
- A snapshot reattach fits the roaming model already in quicsh. After a network
  move, the client decodes a fresh grid snapshot instead of resyncing a byte
  position.
- Graphics stay a special case. Kitty and sixel images are not cells. The
  snapshot decoder bounds them through `SetKittyImageStorageLimit`, and the
  binary keeps a separate `kitty_rewrite` stage so image data bypasses the cell
  diff.

## What quicsh would have to change

Large. The holder currently owns a PTY and a byte pipe. This model needs a
terminal emulator in the holder, per-row dirty tracking, and an update
scheduler.

- Add an emulator. Either link one as a C library or write a grid in Rust. The
  grid must track cells, styles, cursor, scrollback, and modes.
- Change the holder from a byte relay to a grid owner. It feeds PTY output into
  the emulator and never forwards raw bytes to clients.
- Add per-row dirty tracking and a row encoder that emits only dirty rows,
  trimmed to the styling that changed against the last sent cell.
- Add an update scheduler that decides when to flush a cycle, so coalescing
  works. A fixed cadence, for example a 120 per second cap, or output-driven
  with a debounce.
- Add a serializable snapshot for reattach and for on-disk state across a holder
  restart, carrying compressed scrollback.
- Keep a raw passthrough for graphics and for clients that want byte-exact
  output, since re-encoding can lose terminal quirks a program depends on.

## Adjacent features found in the same binary

Two capabilities ride on this model but solve different problems.

- Revision-stamped view. The control API carries a `Revision uint64` on the
  session view, described in the schema as unchanged when a call changes nothing
  the view shows. Clients sync to a revision instead of a byte offset, which is
  the structural sync layer above the per-terminal grid.
- Program status protocol. `OSC 7501` lets a program report a state of `idle`,
  `working`, `done`, `blocked`, or `error` with a 0 to 100 progress value. The
  terminal keeps one record per id, child ids under a parent, and the whole
  sequence caps at 4096 bytes. This is a side channel for agent and job status,
  independent of rendering.

## Open questions

- Fidelity. A re-encoding emulator must reproduce every sequence a program
  relies on, including obscure modes. Any gap is a visible rendering bug that
  raw forwarding never has.
- Where the emulator lives. A C library is proven but adds a non-Rust
  dependency and an FFI surface. A Rust grid is more work and must reach the
  same fidelity.
- Whether the win is worth it on quicsh's paths. On a LAN at 40 Gbit/s loopback
  the raw stream is already CPU bound, not bandwidth bound, so coalescing helps
  most on a slow or lossy link. Measure on the 12 ms VPS path before committing.
