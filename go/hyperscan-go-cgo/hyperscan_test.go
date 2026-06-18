//go:build cgo && amd64

package hyperscan

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
)

// mustCompile compiles a single expression or fails the test.
func mustCompile(t *testing.T, expr string, flags CompileFlag) *Database {
	t.Helper()
	db, err := Compile(expr, flags)
	if err != nil {
		t.Fatalf("Compile(%q, %v) failed: %v", expr, flags, err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// mustCompileMulti compiles a Pattern slice or fails the test.
func mustCompileMulti(t *testing.T, patterns []Pattern) *Database {
	t.Helper()
	db, err := CompileMulti(patterns)
	if err != nil {
		t.Fatalf("CompileMulti(%d patterns) failed: %v", len(patterns), err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// mustScratch allocates a scratch for the database or fails the test.
func mustScratch(t *testing.T, db *Database) *Scratch {
	t.Helper()
	s, err := db.AllocScratch()
	if err != nil {
		t.Fatalf("AllocScratch failed: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// collectMatches scans data and returns all match events.
func collectMatches(t *testing.T, db *Database, s *Scratch, data []byte) []Match {
	t.Helper()
	ms, err := db.Matches(data, s)
	if err != nil {
		t.Fatalf("Matches(%q) failed: %v", string(data), err)
	}
	return ms
}

func TestVersion(t *testing.T) {
	v := Version()
	if v == "" {
		t.Fatal("Version() returned empty string")
	}
	if !strings.Contains(v, "5.4.2") {
		t.Errorf("Version() = %q, want it to contain %q", v, "5.4.2")
	}
}

func TestValidPlatform(t *testing.T) {
	if err := ValidPlatform(); err != nil {
		t.Errorf("ValidPlatform() = %v, want nil on an x86-64 host", err)
	}
}

func TestCompileSingle(t *testing.T) {
	db := mustCompile(t, "foobar", 0)

	sz, err := db.Size()
	if err != nil {
		t.Fatalf("Size() failed: %v", err)
	}
	if sz == 0 {
		t.Error("Size() = 0, want > 0")
	}

	info, err := db.Info()
	if err != nil {
		t.Fatalf("Info() failed: %v", err)
	}
	if info == "" {
		t.Error("Info() returned empty string")
	}
}

func TestCompileMulti(t *testing.T) {
	db := mustCompileMulti(t, redactionPatterns)

	sz, err := db.Size()
	if err != nil {
		t.Fatalf("Size() failed: %v", err)
	}
	if sz == 0 {
		t.Error("Size() = 0, want > 0")
	}

	info, err := db.Info()
	if err != nil {
		t.Fatalf("Info() failed: %v", err)
	}
	if info == "" {
		t.Error("Info() returned empty string")
	}
}

func TestCompileError_Single(t *testing.T) {
	db, err := Compile("(", 0)
	if db != nil {
		db.Close()
		t.Fatal("Compile of an invalid pattern returned a non-nil Database")
	}
	if err == nil {
		t.Fatal("Compile of an invalid pattern returned nil error")
	}
	var ce *CompileError
	if !errors.As(err, &ce) {
		t.Fatalf("error %v is not a *CompileError", err)
	}
	if ce.Message == "" {
		t.Error("CompileError.Message is empty")
	}
}

func TestCompileError_MultiIndex(t *testing.T) {
	patterns := []Pattern{
		{Expr: "abc", ID: 1, Flags: 0},
		{Expr: "def", ID: 2, Flags: 0},
		{Expr: "(", ID: 3, Flags: 0}, // bad pattern at index 2
		{Expr: "ghi", ID: 4, Flags: 0},
	}
	db, err := CompileMulti(patterns)
	if db != nil {
		db.Close()
		t.Fatal("CompileMulti with an invalid pattern returned a non-nil Database")
	}
	if err == nil {
		t.Fatal("CompileMulti with an invalid pattern returned nil error")
	}
	var ce *CompileError
	if !errors.As(err, &ce) {
		t.Fatalf("error %v is not a *CompileError", err)
	}
	if ce.Expression != 2 {
		t.Errorf("CompileError.Expression = %d, want 2", ce.Expression)
	}
	if ce.Message == "" {
		t.Error("CompileError.Message is empty")
	}
}

func TestMatchOffsets_SOM(t *testing.T) {
	db := mustCompile(t, "bar", SOMLeftmost)
	s := mustScratch(t, db)

	ms := collectMatches(t, db, s, []byte("foobarbaz"))
	if len(ms) == 0 {
		t.Fatal("expected at least one match for \"bar\" in \"foobarbaz\"")
	}
	found := false
	for _, m := range ms {
		if m.From == 3 && m.To == 6 {
			found = true
		}
	}
	if !found {
		t.Errorf("matches = %+v, want one with {From:3, To:6}", ms)
	}
}

func TestMatchOffsets_NoSOM(t *testing.T) {
	db := mustCompile(t, "bar", 0)
	s := mustScratch(t, db)

	ms := collectMatches(t, db, s, []byte("foobarbaz"))
	if len(ms) == 0 {
		t.Fatal("expected at least one match for \"bar\" in \"foobarbaz\"")
	}
	// Without SOMLeftmost, From is not reported (stays 0) and only To is valid.
	found := false
	for _, m := range ms {
		if m.To == 6 {
			found = true
			if m.From != 0 {
				t.Errorf("without SOMLeftmost, From = %d, want 0 (From is not reported)", m.From)
			}
		}
	}
	if !found {
		t.Errorf("matches = %+v, want one with To:6", ms)
	}
}

func TestAllMatchesSemantics(t *testing.T) {
	// "a+" over "aaa" reports an end at every position Hyperscan can terminate
	// the match (ends 1, 2, 3) rather than a single leftmost-longest match.
	db := mustCompile(t, "a+", SOMLeftmost)
	s := mustScratch(t, db)

	ms := collectMatches(t, db, s, []byte("aaa"))
	if len(ms) < 2 {
		t.Fatalf("expected multiple match events for \"a+\" over \"aaa\", got %d: %+v", len(ms), ms)
	}

	// MergeSpans collapses all the overlapping events into a single span.
	spans := MergeSpans(ms)
	want := []Span{{Start: 0, End: 3}}
	if !reflect.DeepEqual(spans, want) {
		t.Errorf("MergeSpans(%+v) = %+v, want %+v", ms, spans, want)
	}
}

func TestNoMatch(t *testing.T) {
	db := mustCompile(t, "zzz", SOMLeftmost)
	s := mustScratch(t, db)

	ms := collectMatches(t, db, s, []byte("the quick brown fox"))
	if len(ms) != 0 {
		t.Errorf("expected no matches, got %+v", ms)
	}
}

func TestEmptyInput(t *testing.T) {
	db := mustCompile(t, "abc", SOMLeftmost)
	s := mustScratch(t, db)

	cases := []struct {
		name string
		data []byte
	}{
		{"empty-slice", []byte{}},
		{"nil-slice", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ms, err := db.Matches(tc.data, s)
			if err != nil {
				t.Fatalf("Matches(%v) failed: %v", tc.data, err)
			}
			if len(ms) != 0 {
				t.Errorf("expected no matches for empty input, got %+v", ms)
			}
		})
	}
}

func TestFlag_AllowEmpty(t *testing.T) {
	// A pattern that can match the empty string requires HS_FLAG_ALLOWEMPTY to
	// compile at all; without it hs_compile rejects the pattern.
	if _, err := Compile("a*", 0); err == nil {
		t.Error("Compile(\"a*\") without AllowEmpty unexpectedly succeeded")
	}

	db, err := Compile("a*", AllowEmpty)
	if err != nil {
		t.Fatalf("Compile(\"a*\", AllowEmpty) failed: %v", err)
	}
	defer db.Close()
	s, err := db.AllocScratch()
	if err != nil {
		t.Fatalf("AllocScratch failed: %v", err)
	}
	defer s.Close()

	ms, err := db.Matches([]byte("baab"), s)
	if err != nil {
		t.Fatalf("Matches failed: %v", err)
	}
	if len(ms) == 0 {
		t.Error("expected match events for \"a*\" with AllowEmpty over \"baab\"")
	}
}

func TestMultiPatternIDs(t *testing.T) {
	patterns := []Pattern{
		{Expr: "foo", ID: 100, Flags: SOMLeftmost},
		{Expr: "bar", ID: 200, Flags: SOMLeftmost},
		{Expr: "baz", ID: 300, Flags: SOMLeftmost},
	}
	db := mustCompileMulti(t, patterns)
	s := mustScratch(t, db)

	ms := collectMatches(t, db, s, []byte("foo bar baz"))
	gotIDs := map[uint]bool{}
	for _, m := range ms {
		gotIDs[m.ID] = true
	}
	for _, want := range []uint{100, 200, 300} {
		if !gotIDs[want] {
			t.Errorf("expected a match carrying ID %d, got matches %+v", want, ms)
		}
	}
}

func TestFlag_Caseless(t *testing.T) {
	// Without Caseless, an upper-case input should not match a lower-case pattern.
	db0 := mustCompile(t, "foo", SOMLeftmost)
	s0 := mustScratch(t, db0)
	if ms := collectMatches(t, db0, s0, []byte("FOO")); len(ms) != 0 {
		t.Errorf("expected no case-sensitive match, got %+v", ms)
	}

	db := mustCompile(t, "foo", SOMLeftmost|Caseless)
	s := mustScratch(t, db)
	if ms := collectMatches(t, db, s, []byte("FOO")); len(ms) == 0 {
		t.Error("expected a caseless match for \"foo\" over \"FOO\"")
	}
}

func TestFlag_DotAll(t *testing.T) {
	// Without DotAll, "." does not cross a newline.
	db0 := mustCompile(t, "a.b", SOMLeftmost)
	s0 := mustScratch(t, db0)
	if ms := collectMatches(t, db0, s0, []byte("a\nb")); len(ms) != 0 {
		t.Errorf("expected no match for \"a.b\" over \"a\\nb\" without DotAll, got %+v", ms)
	}

	db := mustCompile(t, "a.b", SOMLeftmost|DotAll)
	s := mustScratch(t, db)
	if ms := collectMatches(t, db, s, []byte("a\nb")); len(ms) == 0 {
		t.Error("expected a match for \"a.b\" over \"a\\nb\" with DotAll")
	}
}

func TestFlag_MultiLine(t *testing.T) {
	// With MultiLine, "^" anchors at embedded newlines too.
	db := mustCompile(t, "^bar", SOMLeftmost|MultiLine)
	s := mustScratch(t, db)
	ms := collectMatches(t, db, s, []byte("foo\nbar"))
	found := false
	for _, m := range ms {
		if m.From == 4 {
			found = true
		}
	}
	if !found {
		t.Errorf("expected \"^bar\" to match at offset 4 with MultiLine, got %+v", ms)
	}

	// Without MultiLine, "^bar" only anchors at the very start.
	db0 := mustCompile(t, "^bar", SOMLeftmost)
	s0 := mustScratch(t, db0)
	if ms := collectMatches(t, db0, s0, []byte("foo\nbar")); len(ms) != 0 {
		t.Errorf("expected no match for \"^bar\" over \"foo\\nbar\" without MultiLine, got %+v", ms)
	}
}

func TestFlag_SingleMatch(t *testing.T) {
	// With SingleMatch, at most one match per pattern ID is reported.
	db := mustCompile(t, "a+", SingleMatch)
	s := mustScratch(t, db)
	ms := collectMatches(t, db, s, []byte("aaa"))
	if len(ms) != 1 {
		t.Errorf("with SingleMatch, expected exactly 1 match for \"a+\" over \"aaa\", got %d: %+v", len(ms), ms)
	}
}

func TestCallbackHalt(t *testing.T) {
	db := mustCompile(t, "a", SOMLeftmost)
	s := mustScratch(t, db)

	// A custom (non-ErrStop) handler error is returned verbatim by Scan.
	sentinel := errors.New("halt now")
	count := 0
	err := db.Scan([]byte("aaaa"), s, func(m Match) error {
		count++
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Errorf("Scan returned %v, want the handler's sentinel error", err)
	}
	if errors.Is(err, ErrScanTerminated) {
		t.Error("Scan returned ErrScanTerminated, want the handler error instead")
	}
	if count != 1 {
		t.Errorf("handler invoked %d times, want 1 (scan should halt on first error)", count)
	}

	// ErrStop is a clean stop: Scan returns nil.
	count = 0
	err = db.Scan([]byte("aaaa"), s, func(m Match) error {
		count++
		return ErrStop
	})
	if err != nil {
		t.Errorf("Scan returned %v, want nil for ErrStop", err)
	}
	if count != 1 {
		t.Errorf("handler invoked %d times after ErrStop, want 1", count)
	}
}

func TestHandlerPanic(t *testing.T) {
	db := mustCompile(t, "a", SOMLeftmost)
	s := mustScratch(t, db)

	const msg = "boom from handler"
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected Scan to re-raise the handler panic, but it did not panic")
		}
		got, ok := r.(string)
		if !ok || got != msg {
			t.Errorf("recovered panic = %v, want %q", r, msg)
		}
	}()

	_ = db.Scan([]byte("aaaa"), s, func(m Match) error {
		panic(msg)
	})
	t.Fatal("Scan returned normally; expected a re-raised panic")
}

func TestSerializeDeserializeRoundtrip(t *testing.T) {
	db := mustCompileMulti(t, redactionPatterns)
	s := mustScratch(t, db)

	input := []byte(sampleInputs()["multi"])
	want := collectMatches(t, db, s, input)

	blob, err := db.Serialize()
	if err != nil {
		t.Fatalf("Serialize failed: %v", err)
	}
	if len(blob) == 0 {
		t.Fatal("Serialize returned empty bytes")
	}

	db2, err := Deserialize(blob)
	if err != nil {
		t.Fatalf("Deserialize failed: %v", err)
	}
	defer db2.Close()
	s2, err := db2.AllocScratch()
	if err != nil {
		t.Fatalf("AllocScratch on deserialized DB failed: %v", err)
	}
	defer s2.Close()

	got := collectMatches(t, db2, s2, input)
	if !reflect.DeepEqual(MergeSpans(got), MergeSpans(want)) {
		t.Errorf("deserialized DB produced different spans:\n got %+v\nwant %+v",
			MergeSpans(got), MergeSpans(want))
	}
}

func TestScratchClone(t *testing.T) {
	db := mustCompile(t, "bar", SOMLeftmost)
	s := mustScratch(t, db)

	clone, err := s.Clone()
	if err != nil {
		t.Fatalf("Clone failed: %v", err)
	}
	defer clone.Close()

	sz, err := clone.Size()
	if err != nil {
		t.Fatalf("clone Size failed: %v", err)
	}
	if sz == 0 {
		t.Error("clone Size() = 0, want > 0")
	}

	// The clone must independently drive a scan.
	ms := collectMatches(t, db, clone, []byte("foobarbaz"))
	if len(ms) == 0 {
		t.Error("expected a match using the cloned scratch")
	}
}

func TestConcurrentScans_Race(t *testing.T) {
	db := mustCompileMulti(t, redactionPatterns)

	pool, err := db.NewScratchPool()
	if err != nil {
		t.Fatalf("NewScratchPool failed: %v", err)
	}
	defer pool.Close()

	inputs := sampleInputs()
	values := make([]string, 0, len(inputs))
	for _, v := range inputs {
		values = append(values, v)
	}

	const goroutines = 16
	const iters = 50
	var wg sync.WaitGroup
	errCh := make(chan error, goroutines)
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				s, err := pool.Get()
				if err != nil {
					errCh <- fmt.Errorf("pool.Get: %w", err)
					return
				}
				data := []byte(values[(g+i)%len(values)])
				if _, err := db.Matches(data, s); err != nil {
					pool.Put(s)
					errCh <- fmt.Errorf("Matches: %w", err)
					return
				}
				pool.Put(s)
			}
		}(g)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}
}

func TestMergeSpans(t *testing.T) {
	cases := []struct {
		name string
		in   []Match
		want []Span
	}{
		{
			name: "empty",
			in:   nil,
			want: nil,
		},
		{
			name: "single",
			in:   []Match{{From: 2, To: 5}},
			want: []Span{{Start: 2, End: 5}},
		},
		{
			name: "overlap",
			in:   []Match{{From: 0, To: 5}, {From: 3, To: 8}},
			want: []Span{{Start: 0, End: 8}},
		},
		{
			name: "adjacency",
			in:   []Match{{From: 0, To: 3}, {From: 3, To: 6}},
			want: []Span{{Start: 0, End: 6}},
		},
		{
			name: "disjoint",
			in:   []Match{{From: 0, To: 2}, {From: 5, To: 7}},
			want: []Span{{Start: 0, End: 2}, {Start: 5, End: 7}},
		},
		{
			name: "unsorted",
			in:   []Match{{From: 5, To: 7}, {From: 0, To: 2}, {From: 3, To: 4}},
			want: []Span{{Start: 0, End: 2}, {Start: 3, End: 4}, {Start: 5, End: 7}},
		},
		{
			name: "nested",
			in:   []Match{{From: 0, To: 10}, {From: 3, To: 6}},
			want: []Span{{Start: 0, End: 10}},
		},
		{
			name: "all-matches-of-a-plus",
			in:   []Match{{From: 0, To: 1}, {From: 0, To: 2}, {From: 0, To: 3}},
			want: []Span{{Start: 0, End: 3}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Snapshot the input to assert it is not mutated. Use append so a nil
			// input snapshots to nil (make([]Match, 0) is non-nil and would spuriously
			// differ from a nil input under reflect.DeepEqual).
			snapshot := append([]Match(nil), tc.in...)

			got := MergeSpans(tc.in)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("MergeSpans(%+v) = %+v, want %+v", tc.in, got, tc.want)
			}
			if !reflect.DeepEqual(tc.in, snapshot) {
				t.Errorf("MergeSpans mutated its input: got %+v, want %+v", tc.in, snapshot)
			}
		})
	}
}

func TestClose_Idempotent(t *testing.T) {
	db, err := Compile("abc", SOMLeftmost)
	if err != nil {
		t.Fatalf("Compile failed: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Errorf("first Close() = %v, want nil", err)
	}
	if err := db.Close(); err != nil {
		t.Errorf("second Close() = %v, want nil (idempotent)", err)
	}

	// Scratch Close is likewise idempotent.
	db2 := mustCompile(t, "abc", SOMLeftmost)
	s, err := db2.AllocScratch()
	if err != nil {
		t.Fatalf("AllocScratch failed: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Errorf("first Scratch.Close() = %v, want nil", err)
	}
	if err := s.Close(); err != nil {
		t.Errorf("second Scratch.Close() = %v, want nil (idempotent)", err)
	}

	// Close on a nil Database is safe.
	var nilDB *Database
	if err := nilDB.Close(); err != nil {
		t.Errorf("nil Database Close() = %v, want nil", err)
	}
}

func TestScanAfterClose(t *testing.T) {
	db := mustCompile(t, "abc", SOMLeftmost)
	s := mustScratch(t, db)

	if err := db.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	// Scanning a closed database must error cleanly, not segfault.
	_, err := db.Matches([]byte("abc"), s)
	if !errors.Is(err, ErrClosed) {
		t.Errorf("Matches after Close = %v, want ErrClosed", err)
	}

	// Other accessors should also report ErrClosed.
	if _, err := db.Size(); !errors.Is(err, ErrClosed) {
		t.Errorf("Size after Close = %v, want ErrClosed", err)
	}
	if _, err := db.Info(); !errors.Is(err, ErrClosed) {
		t.Errorf("Info after Close = %v, want ErrClosed", err)
	}
}

func TestRedactionEndToEnd(t *testing.T) {
	db := mustCompileMulti(t, redactionPatterns)
	s := mustScratch(t, db)

	// Surrounding non-PII text with an email, an SSN, and a credit card embedded.
	prefix := "User "
	email := "alice@corp.io"
	mid := " with SSN "
	ssn := "987-65-4320"
	mid2 := " paid via card "
	card := "5500-0000-0000-0004"
	suffix := " today."
	input := prefix + email + mid + ssn + mid2 + card + suffix

	matches := collectMatches(t, db, s, []byte(input))
	if len(matches) == 0 {
		t.Fatal("expected PII matches, got none")
	}
	spans := MergeSpans(matches)

	// Expected PII regions, located in the assembled input.
	emailStart := len(prefix)
	emailEnd := emailStart + len(email)
	ssnStart := emailEnd + len(mid)
	ssnEnd := ssnStart + len(ssn)
	cardStart := ssnEnd + len(mid2)
	cardEnd := cardStart + len(card)

	wantSpans := []Span{
		{Start: uint64(emailStart), End: uint64(emailEnd)},
		{Start: uint64(ssnStart), End: uint64(ssnEnd)},
		{Start: uint64(cardStart), End: uint64(cardEnd)},
	}
	if !reflect.DeepEqual(spans, wantSpans) {
		t.Fatalf("MergeSpans = %+v, want exactly the 3 PII regions %+v", spans, wantSpans)
	}

	// Mask variant: replace each span with "****", applying spans RIGHT-TO-LEFT
	// so earlier offsets remain valid as later regions are rewritten.
	maskStars := func(in string, sp []Span) string {
		b := []byte(in)
		for i := len(sp) - 1; i >= 0; i-- {
			b = append(b[:sp[i].Start], append([]byte("****"), b[sp[i].End:]...)...)
		}
		return string(b)
	}
	gotStars := maskStars(input, spans)
	wantStars := prefix + "****" + mid + "****" + mid2 + "****" + suffix
	if gotStars != wantStars {
		t.Errorf("star-masked output =\n  %q\nwant\n  %q", gotStars, wantStars)
	}
	// Non-PII text must be untouched and no PII may survive.
	for _, leak := range []string{email, ssn, card} {
		if strings.Contains(gotStars, leak) {
			t.Errorf("star-masked output still contains PII %q", leak)
		}
	}
	for _, keep := range []string{prefix, mid, mid2, suffix} {
		if !strings.Contains(gotStars, keep) {
			t.Errorf("star-masked output dropped non-PII text %q", keep)
		}
	}
	// No double-masking: exactly three replacements.
	if n := strings.Count(gotStars, "****"); n != 3 {
		t.Errorf("expected exactly 3 masked regions, found %d in %q", n, gotStars)
	}

	// Hash variant: replace each span with a fixed-length hash, also RIGHT-TO-LEFT.
	const hashLen = 8
	hashOf := func(b []byte) string {
		sum := sha256.Sum256(b)
		return hex.EncodeToString(sum[:])[:hashLen]
	}
	maskHash := func(in string, sp []Span) string {
		b := []byte(in)
		for i := len(sp) - 1; i >= 0; i-- {
			h := []byte(hashOf(b[sp[i].Start:sp[i].End]))
			b = append(b[:sp[i].Start], append(h, b[sp[i].End:]...)...)
		}
		return string(b)
	}
	gotHash := maskHash(input, spans)
	wantHash := prefix + hashOf([]byte(email)) + mid + hashOf([]byte(ssn)) + mid2 + hashOf([]byte(card)) + suffix
	if gotHash != wantHash {
		t.Errorf("hash-masked output =\n  %q\nwant\n  %q", gotHash, wantHash)
	}
	for _, leak := range []string{email, ssn, card} {
		if strings.Contains(gotHash, leak) {
			t.Errorf("hash-masked output still contains PII %q", leak)
		}
	}
	for _, keep := range []string{prefix, mid, mid2, suffix} {
		if !strings.Contains(gotHash, keep) {
			t.Errorf("hash-masked output dropped non-PII text %q", keep)
		}
	}
}
