//go:build cgo && amd64

package hyperscan

// bench_test.go — head-to-head benchmarks: Hyperscan (CGO) vs Go's stdlib
// regexp for the OpenTelemetry redaction workload.
//
// IMPORTANT — reading the numbers:
//
//   - Only benchmark numbers produced on a NATIVE x86-64 CPU (the x86-64 CI
//     job) are authoritative. Hyperscan is x86-64-only; the local dev machine
//     is darwin/arm64 and can only run these under QEMU emulation, where the
//     reported ns/op are meaningless (emulation distorts both the CGO boundary
//     cost and the SIMD-heavy scan engine relative to pure-Go regexp). Never
//     draw a faster/slower conclusion from emulated runs.
//
//   - The make-or-break comparison for the redaction use case is the
//     "short/nomatch" row: Hyperscan vs RegexpCombined on a ~32B clean
//     attribute value. That is the dominant shape of OTel attribute values
//     (short, usually no PII). On such tiny inputs the fixed CGO call boundary
//     and per-match C->Go callback crossing can easily dominate the actual
//     scan, so a single combined-regexp may win despite Hyperscan's faster
//     core. If Hyperscan does not beat RegexpCombined here, it is not a win for
//     redaction regardless of how it does on long/dense inputs.
//
// Every benchmark runs the SAME end-to-end work per iteration so the engines
// are compared fairly: find match spans -> MergeSpans -> replace each span
// right-to-left with "****". Inputs are generated deterministically (no
// math/rand reseeding surprises; a fixed local seed where variety is wanted)
// so every engine sees byte-identical inputs.

import (
	"bytes"
	"math/rand"
	"regexp"
	"strings"
	"testing"
)

// redactMask is the fixed replacement written over each redacted span.
var redactMask = []byte("****")

// replaceSpans rewrites data, overwriting each span in spans with redactMask.
// spans must be sorted and non-overlapping (as produced by MergeSpans). The
// replacement is applied right-to-left so earlier span offsets remain valid as
// the buffer length changes. The input slice is never mutated; a fresh slice
// is returned.
func replaceSpans(data []byte, spans []Span) []byte {
	if len(spans) == 0 {
		// Return a copy so callers can treat the result uniformly.
		out := make([]byte, len(data))
		copy(out, data)
		return out
	}
	out := make([]byte, len(data))
	copy(out, data)
	for i := len(spans) - 1; i >= 0; i-- {
		s := spans[i]
		if s.End > uint64(len(out)) || s.Start > s.End {
			continue
		}
		out = append(out[:s.Start], append(append([]byte{}, redactMask...), out[s.End:]...)...)
	}
	return out
}

// regexpSpans collects all match spans found by a slice of separate regexps.
// The returned spans are unsorted/overlapping; callers feed them through
// MergeSpans exactly as the Hyperscan path does, keeping the pipelines aligned.
func regexpSpans(res []*regexp.Regexp, data []byte) []Match {
	var ms []Match
	for _, re := range res {
		for _, loc := range re.FindAllIndex(data, -1) {
			ms = append(ms, Match{From: uint64(loc[0]), To: uint64(loc[1])})
		}
	}
	return ms
}

// regexpCombinedSpans collects all (possibly overlapping) match spans from a
// single combined alternation regexp.
func regexpCombinedSpans(re *regexp.Regexp, data []byte) []Match {
	locs := re.FindAllIndex(data, -1)
	ms := make([]Match, 0, len(locs))
	for _, loc := range locs {
		ms = append(ms, Match{From: uint64(loc[0]), To: uint64(loc[1])})
	}
	return ms
}

// combinedRegexpSource builds a single alternation "(?:p1)|(?:p2)|..." from the
// shared PII pattern strings, the RegexpCombined baseline.
func combinedRegexpSource() string {
	parts := make([]string, len(redactionRegexStrings))
	for i, p := range redactionRegexStrings {
		parts[i] = "(?:" + p + ")"
	}
	return strings.Join(parts, "|")
}

// piiSnippets are short, byte-identical PII fragments used to seed inputs at a
// controlled density. They each match at least one redactionPatterns entry.
var piiSnippets = []string{
	"support@example.com",
	"123-45-6789",
	"4111-1111-1111-1111",
	"192.168.1.100",
	"550e8400-e29b-41d4-a716-446655440000",
	"AKIAIOSFODNN7EXAMPLE",
	"00:1A:2B:3C:4D:5E",
}

// filler is deterministic clean text with no PII, used to pad inputs to a
// target size for the "nomatch" density and between matches otherwise.
const filler = "the quick brown fox jumps over the lazy dog and then rests a while "

// buildInput generates a deterministic input of approximately size bytes at the
// requested density:
//
//   - "nomatch": pure filler text, no PII at all.
//   - "sparse":  a single PII snippet embedded in filler.
//   - "dense":   PII snippets packed back-to-back separated by short filler,
//     so the scan reports many matches (exercising the callback crossing).
//
// Generation is fully deterministic (fixed local rand seed) so every engine in
// the matrix scans byte-identical inputs.
func buildInput(size int, density string) []byte {
	r := rand.New(rand.NewSource(int64(size) * 1009))
	var buf bytes.Buffer

	switch density {
	case "nomatch":
		for buf.Len() < size {
			buf.WriteString(filler)
		}

	case "sparse":
		// Roughly one PII match somewhere in the middle of clean filler.
		half := size / 2
		for buf.Len() < half {
			buf.WriteString(filler)
		}
		buf.WriteByte(' ')
		buf.WriteString(piiSnippets[r.Intn(len(piiSnippets))])
		buf.WriteByte(' ')
		for buf.Len() < size {
			buf.WriteString(filler)
		}

	case "dense":
		// Pack many PII snippets separated by a few filler words so matches are
		// frequent throughout the buffer.
		for buf.Len() < size {
			buf.WriteString(piiSnippets[r.Intn(len(piiSnippets))])
			buf.WriteByte(' ')
			words := strings.Fields(filler)
			buf.WriteString(words[r.Intn(len(words))])
			buf.WriteByte(' ')
		}

	default:
		panic("unknown density: " + density)
	}

	out := buf.Bytes()
	if len(out) > size {
		out = out[:size]
	}
	return out
}

// benchSizes maps the named size dimension to an approximate byte length.
var benchSizes = []struct {
	name string
	size int
}{
	{"short", 32},   // primary OTel attribute-value case
	{"medium", 256}, // a longer field
	{"long", 4096},  // a log line / blob
}

// benchDensities is the density dimension of the matrix.
var benchDensities = []string{"nomatch", "sparse", "dense"}

// BenchmarkRedaction is the full-pipeline head-to-head benchmark. For each
// size/density it runs the identical end-to-end redaction work
// (find spans -> MergeSpans -> replace right-to-left) under three engines:
//
//	Hyperscan      — CompileMulti(...SOMLeftmost) + a per-iteration ScratchPool
//	                 Get/Put, the way a concurrent redaction processor would use it.
//	RegexpSeparate — 14 separate *regexp.Regexp, each scanned with FindAllIndex.
//	RegexpCombined — one "(?:p1)|(?:p2)|..." alternation regexp.
//
// Sub-benchmarks are named "<size>/<density>/<engine>". Each reports allocs and
// sets bytes to len(input) so MB/s is comparable across rows.
func BenchmarkRedaction(b *testing.B) {
	// Compile the engines once; they are immutable and shared across rows.
	db, err := CompileMulti(redactionPatterns)
	if err != nil {
		b.Fatalf("CompileMulti: %v", err)
	}
	defer db.Close()

	pool, err := db.NewScratchPool()
	if err != nil {
		b.Fatalf("NewScratchPool: %v", err)
	}
	defer pool.Close()

	separate := make([]*regexp.Regexp, len(redactionRegexStrings))
	for i, p := range redactionRegexStrings {
		separate[i] = regexp.MustCompile(p)
	}
	combined := regexp.MustCompile(combinedRegexpSource())

	for _, sz := range benchSizes {
		for _, density := range benchDensities {
			input := buildInput(sz.size, density)

			b.Run(sz.name+"/"+density+"/Hyperscan", func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(len(input)))
				for i := 0; i < b.N; i++ {
					sc, err := pool.Get()
					if err != nil {
						b.Fatalf("pool.Get: %v", err)
					}
					matches, err := db.Matches(input, sc)
					if err != nil {
						b.Fatalf("Matches: %v", err)
					}
					pool.Put(sc)
					spans := MergeSpans(matches)
					_ = replaceSpans(input, spans)
				}
			})

			b.Run(sz.name+"/"+density+"/RegexpSeparate", func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(len(input)))
				for i := 0; i < b.N; i++ {
					matches := regexpSpans(separate, input)
					spans := MergeSpans(matches)
					_ = replaceSpans(input, spans)
				}
			})

			b.Run(sz.name+"/"+density+"/RegexpCombined", func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(len(input)))
				for i := 0; i < b.N; i++ {
					matches := regexpCombinedSpans(combined, input)
					spans := MergeSpans(matches)
					_ = replaceSpans(input, spans)
				}
			})
		}
	}
}

// BenchmarkScanOnly isolates the fixed CGO call boundary cost. It scans a
// short, clean (no-match) input with a no-op handler, so essentially nothing
// happens inside Hyperscan and no callback crossings occur — the measured time
// is dominated by the per-Scan cgo.Handle setup/teardown and the C entry/exit.
// This is the floor that the redaction "short/nomatch" row pays on every call.
func BenchmarkScanOnly(b *testing.B) {
	db, err := CompileMulti(redactionPatterns)
	if err != nil {
		b.Fatalf("CompileMulti: %v", err)
	}
	defer db.Close()
	sc, err := db.AllocScratch()
	if err != nil {
		b.Fatalf("AllocScratch: %v", err)
	}
	defer sc.Close()

	input := buildInput(32, "nomatch")
	noop := func(Match) error { return nil }

	b.ReportAllocs()
	b.SetBytes(int64(len(input)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := db.Scan(input, sc, noop); err != nil {
			b.Fatalf("Scan: %v", err)
		}
	}
}

// BenchmarkCallbackCrossing isolates the per-match C->Go crossing cost. It
// scans a dense input (many matches) with a handler that only counts, so the
// per-iteration time over the same buffer is dominated by the number of
// callback invocations rather than by span merging or replacement. Compare
// against BenchmarkScanOnly to estimate the marginal cost of each reported
// match.
func BenchmarkCallbackCrossing(b *testing.B) {
	db, err := CompileMulti(redactionPatterns)
	if err != nil {
		b.Fatalf("CompileMulti: %v", err)
	}
	defer db.Close()
	sc, err := db.AllocScratch()
	if err != nil {
		b.Fatalf("AllocScratch: %v", err)
	}
	defer sc.Close()

	input := buildInput(4096, "dense")

	b.ReportAllocs()
	b.SetBytes(int64(len(input)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var count int
		err := db.Scan(input, sc, func(Match) error {
			count++
			return nil
		})
		if err != nil {
			b.Fatalf("Scan: %v", err)
		}
		_ = count
	}
}

// BenchmarkCompileMulti measures the one-time startup cost of building the PII
// database from the shared pattern set. This is paid once at processor
// initialization, not per scan, so it is reported separately and must not be
// folded into the per-attribute redaction cost.
func BenchmarkCompileMulti(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		db, err := CompileMulti(redactionPatterns)
		if err != nil {
			b.Fatalf("CompileMulti: %v", err)
		}
		db.Close()
	}
}

// BenchmarkRedactionParallel measures concurrent throughput of the Hyperscan
// redaction pipeline using a ScratchPool, the way a multi-goroutine OTel
// processor would run it: the immutable Database is shared across all
// goroutines, while each goroutine borrows its own Scratch from the pool for
// the duration of a scan. Run with -cpu to vary parallelism. This is the
// scenario where Hyperscan's shareable database is expected to shine relative
// to per-goroutine regexp usage.
func BenchmarkRedactionParallel(b *testing.B) {
	db, err := CompileMulti(redactionPatterns)
	if err != nil {
		b.Fatalf("CompileMulti: %v", err)
	}
	defer db.Close()

	pool, err := db.NewScratchPool()
	if err != nil {
		b.Fatalf("NewScratchPool: %v", err)
	}
	defer pool.Close()

	// Use the primary short/sparse attribute-value shape for the parallel run.
	input := buildInput(32, "sparse")

	b.ReportAllocs()
	b.SetBytes(int64(len(input)))
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			sc, err := pool.Get()
			if err != nil {
				b.Fatalf("pool.Get: %v", err)
			}
			matches, err := db.Matches(input, sc)
			if err != nil {
				b.Fatalf("Matches: %v", err)
			}
			pool.Put(sc)
			spans := MergeSpans(matches)
			_ = replaceSpans(input, spans)
		}
	})
}
