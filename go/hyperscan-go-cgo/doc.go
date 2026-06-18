//go:build cgo && amd64

// Package hyperscan is a CGO binding for Intel Hyperscan 5.4.2, scoped to
// block-mode, multi-pattern scanning. It is built for evaluating Hyperscan as
// a replacement for Go's regexp in an OpenTelemetry redaction processor that
// scans short attribute-value strings against many PII patterns and replaces
// the matched spans.
//
// # Scope
//
// This binding covers block mode (hs_compile / hs_compile_multi with
// HS_MODE_BLOCK) only; streaming and vectored modes are intentionally omitted.
// Hyperscan is x86-64 only, so every source file carries the build constraint
// "cgo && amd64"; on other platforms the package compiles to nothing.
//
// # Start-of-match offsets
//
// Hyperscan reports only a match end offset by default. To obtain a valid
// Match.From (the start offset), patterns MUST be compiled with the
// SOMLeftmost flag (HS_FLAG_SOM_LEFTMOST). This is mandatory for redaction,
// where the caller needs the full [From, To) span to replace the matched text.
// Without SOMLeftmost, Match.From is zero and only Match.To is meaningful.
//
// # Match semantics and MergeSpans
//
// Unlike RE2 / regexp, Hyperscan reports every match end (and every SOM start),
// not the single leftmost-longest match. A pattern such as "a+" over "aaa"
// reports several events rather than one. Before replacing text, collect the
// matches (see Database.Matches) and pass them to MergeSpans, which sorts and
// coalesces overlapping and adjacent ranges into a minimal set of spans. Apply
// replacements right-to-left so earlier offsets remain valid as the string
// shrinks.
//
// Hyperscan has no capture groups, backreferences, or lookaround. Whole-match
// replacement is supported; PCRE-only patterns fail at compile time and must
// fall back to regexp.
//
// # Thread-safety
//
// A Database is immutable once compiled and may be shared freely across
// goroutines. A Scratch is NOT safe for concurrent use: each goroutine
// scanning concurrently needs its own Scratch. Use a ScratchPool to manage
// per-goroutine scratch instances over a shared Database. Never call Scan
// inside a MatchHandler using the same Scratch (Hyperscan reports
// HS_SCRATCH_IN_USE).
//
// # Memory ownership
//
// Database and Scratch own C memory. Call Close to release it; both Close
// methods are idempotent and nil-safe. Finalizers are registered as a leak
// backstop but are not a substitute for explicit Close.
//
// # Redaction example
//
//	db, err := hyperscan.CompileMulti([]hyperscan.Pattern{
//	    {Expr: `[\w.]+@[\w.]+`, ID: 0, Flags: hyperscan.SOMLeftmost},
//	    {Expr: `\d{3}-\d{2}-\d{4}`, ID: 1, Flags: hyperscan.SOMLeftmost},
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer db.Close()
//
//	scratch, err := db.AllocScratch()
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer scratch.Close()
//
//	data := []byte("contact alice@example.com ssn 123-45-6789")
//	matches, err := db.Matches(data, scratch)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	spans := hyperscan.MergeSpans(matches)
//	// Replace each span right-to-left so offsets stay valid.
//	for i := len(spans) - 1; i >= 0; i-- {
//	    s := spans[i]
//	    data = append(data[:s.Start], append([]byte("****"), data[s.End:]...)...)
//	}
package hyperscan
