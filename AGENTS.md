# AGENTS.md

## Zig Development

Use `zigdoc` to discover current APIs for the Zig standard library and any third-party dependencies before coding.
Run `mise run lint` before finishing changes.

Examples:
```bash
zigdoc std.fs
zigdoc std.posix.getuid
zigdoc vaxis.Window
```

## Zig Style

- preferred file order: `//!` module doc comment, `const Self = @This()`, imports, `const log = std.log.scoped(...)`
- Alias `std.debug.assert` with `const assert = std.debug.assert` and use `assert(...)`.
- pass allocators explicitly and use `errdefer` for cleanup on error
- For borrowed arena-backed storage, use `arena: std.mem.Allocator` for parameters and fields. Pass the allocator by value, not `*std.heap.ArenaAllocator`. Use the concrete arena type only when managing its lifecycle, such as `reset` or `deinit`.
- keep tests inline with the code they cover and include them from the module test entry point
- Use a single blank line between logical steps within functions: setup, validation, loops, state updates, and final results.
- No tests that merely restate the code, check a mock's canned return, or test the framework. Regression tests only when asked or required by project conventions.

## Safety

- Add assertions at API boundaries and state transitions and avoid trivial assertions.
- Keep functions small and push pure computation into helpers.
- Comments should explain why, not what.
