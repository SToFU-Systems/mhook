# disasm-lib

Vendored instruction decoder used by the hook engine to measure the length of
the instructions in a target's prologue.

- Upstream: Matt Conover's disassembler, distributed inside the original Mhook
  by Marton Anka at https://github.com/martona/mhook
- Taken from: Mhook v2.4 (last upstream commit e58a58ca31, 2014-03-06)

This is a private component. It is not installed, not exported, and its headers
are not part of the public interface, so it carries no version of its own.

Formatting and build integration follow this repository's conventions; the
decoding logic is kept as close to upstream as possible so that fixes can still
be compared against the original.
