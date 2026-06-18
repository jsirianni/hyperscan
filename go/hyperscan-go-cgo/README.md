# hyperscan-go-cgo

Go CGO binding for [Intel Hyperscan](https://github.com/intel/hyperscan) 5.4.2 —
block-mode, multi-pattern scanning with start/end match offsets.

The motivating use case is evaluating Hyperscan as a drop-in replacement for
`regexp` in an OpenTelemetry redaction processor that masks PII (email
addresses, SSNs, credit-card numbers, etc.) in short attribute-value strings.
The package ships a head-to-head benchmark (`bench_test.go`) so you can
measure whether Hyperscan is actually faster than `regexp` for your patterns
and input sizes — do not assume a win.

## Constraints

### x86-64 only

Hyperscan requires x86-64 with at least SSSE3. It uses `x86intrin.h` and
CMake will `FATAL_ERROR` on any other architecture. This package therefore
carries the build tag `//go:build cgo && amd64` on every file that imports
`"C"`. On `darwin/arm64` or any non-amd64 platform `go build ./...` "succeeds"
by compiling zero files — **no real validation happens locally on Apple Silicon**.

### CGO required

`CGO_ENABLED=0` builds are not supported. Using this package in a downstream
project (e.g., the OTel collector) makes that project x86-64-only with CGO,
breaking its pure-Go cross-platform build. This is acceptable for a benchmark
or spike; it is a hard constraint for production.

### C++ runtime and libcrypto

Hyperscan is internally written in C++, so linking requires `-lstdc++`.
The library also uses OpenSSL HMAC-SHA256 for database integrity checks, so
`-lcrypto` is a hard link dependency. Both are pulled automatically because the binding's cgo directive uses
`#cgo pkg-config: --static libhs` (no environment variable required).

### Static library only

The Dockerfile and CI build `libhs.a` (`-DBUILD_SHARED_LIBS=OFF`) with a
fixed `-march=x86-64-v2` baseline for reproducibility. The upstream default is
`-march=native`, which produces non-portable code.

## Redaction caveats

Before using this package for PII redaction, understand the semantic
differences from `regexp`:

- **Detect, not replace.** Hyperscan reports `(id, from, to)` offsets;
  the caller is responsible for masking the input string at those spans.
  The `MergeSpans` helper merges overlapping/adjacent spans before you apply
  replacements (always apply right-to-left so earlier offsets stay valid).

- **All matches, not leftmost-longest.** Hyperscan reports every match event,
  not the leftmost-longest match as RE2/`regexp` does. For example, `a+` over
  `"aaa"` fires three times (ends at 1, 2, 3). `MergeSpans` collapses these
  into a single `{0, 3}` span, which is the correct behavior for redaction.

- **`SOMLeftmost` required for `From`.** The `From` field of a `Match` is only
  valid when the pattern is compiled with `HS_FLAG_SOM_LEFTMOST`. Without this
  flag `From` is always 0. The `CompileMulti` call in the redaction example
  uses `FlagSOMLeftmost` on every pattern.

- **No capture groups, backreferences, or lookaround.** Hyperscan does not
  support these PCRE features. Patterns that use them will fail at `Compile`
  or `CompileMulti` time with a `*CompileError`. Such patterns must fall back
  to `regexp`.

## Building and testing

### Via Docker (recommended; works on Apple Silicon)

```sh
# From the go/hyperscan-go-cgo/ directory:
make docker-build   # builds the linux/amd64 image (compiles libhs from source)
make docker-test    # runs go test -v ./... inside the container
make docker-bench   # runs the benchmark suite inside the container
make docker-shell   # interactive shell for debugging
```

**Apple Silicon note:** `docker-test` is correct but `docker-bench` runs under
QEMU emulation. Benchmark `ns/op` values under emulation are **not meaningful**
and must be ignored. Use CI for authoritative benchmark numbers.

### Via CI (authoritative; native x86-64)

The GitHub Actions workflow (`.github/workflows/go-cgo.yml`) runs on
`ubuntu-24.04` (native amd64). It:

1. Installs build dependencies.
2. Compiles and installs `libhs` from source (only the `hs` and `hs_runtime`
   targets) with `-march=x86-64-v2`.
3. Runs `go test -race -v ./...` (unit tests + race detector).
4. Runs `go test -bench=. -benchmem ./...` (benchmark suite).

The benchmark output from CI is the authoritative Hyperscan-vs-`regexp`
comparison for the redaction workload.

Triggers: any push or pull-request that touches `go/hyperscan-go-cgo/**`,
`src/**`, `CMakeLists.txt`, or `cmake/**`.

### Manual (linux/amd64 only)

If you have Hyperscan 5.4.2 installed natively (e.g., in `/usr/local`):

```sh
export CGO_ENABLED=1
cd go/hyperscan-go-cgo
go test -race -v ./...
go test -run='^$' -bench=. -benchmem ./...
```

If `pkg-config` is not available you can set cgo flags directly:

```sh
export CGO_CFLAGS="-I/usr/local/include/hs"
export CGO_LDFLAGS="-L/usr/local/lib -lhs -lcrypto -lstdc++ -lm"
```

## Quick usage example

```go
package main

import (
    "fmt"
    "github.com/intel/hyperscan/go/hyperscan-go-cgo"
)

func main() {
    patterns := []hyperscan.Pattern{
        {Expr: `\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`, ID: 1, Flags: hyperscan.FlagSOMLeftmost | hyperscan.FlagCaseless},
        {Expr: `\b\d{3}-\d{2}-\d{4}\b`, ID: 2, Flags: hyperscan.FlagSOMLeftmost},
    }

    db, err := hyperscan.CompileMulti(patterns)
    if err != nil {
        panic(err)
    }
    defer db.Close()

    scratch, err := db.AllocScratch()
    if err != nil {
        panic(err)
    }
    defer scratch.Close()

    input := []byte("Contact user@example.com or SSN 123-45-6789 for details.")

    matches, err := db.Matches(input, scratch)
    if err != nil {
        panic(err)
    }

    spans := hyperscan.MergeSpans(matches)

    // Apply replacements right-to-left so earlier offsets stay valid.
    result := make([]byte, len(input))
    copy(result, input)
    for i := len(spans) - 1; i >= 0; i-- {
        s := spans[i]
        redacted := append(result[:s.Start], "****"...)
        result = append(redacted, result[s.End:]...)
    }

    fmt.Println(string(result))
    // Output: Contact **** or SSN **** for details.
}
```

## CMake targets built

The Dockerfile and CI harness build **only** the `hs` and `hs_runtime` CMake
targets:

- `hs` — the main static library (`libhs.a`), used for compile + scan.
- `hs_runtime` — the runtime-only static library (`libhs_runtime.a`), used
  when loading a serialised database at runtime.

The `hsdump` tool, Hyperscan's own unit tests, and the chimera library are
**not** built, keeping build time short.
