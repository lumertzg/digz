# digz

A DNS lookup tool written in Zig, powered by [ldns](https://github.com/NLnetLabs/ldns).
Colored tables and traces in the terminal. Plain text when redirected.

## Usage

```sh
digz example.org
```

![A lookup for example.org](docs/images/query.png)

```sh
digz example.org --trace
```

![Delegation trace for example.org](docs/images/trace.png)

Run `digz --help` for all options.

## Build

Requires Zig 0.17.0.
Supports Linux and macOS on x86_64 and aarch64.

```sh
zig build -Doptimize=ReleaseFast
```

Binary: `zig-out/bin/digz`.

## Development

`mise install` · `mise run lint` · `zig build fmt` · `zig build test`
