//go:build cgo && amd64

package hyperscan

import "sort"

// MatchHandler is invoked for every match event during a Scan. Returning a
// non-nil error halts scanning: ErrStop halts cleanly (Scan returns nil), any
// other error is propagated out of Scan.
type MatchHandler func(Match) error

// Match describes a single match event reported by Hyperscan. From is the
// start offset and is only valid when the pattern was compiled with
// SOMLeftmost; To is the end offset (exclusive). ID is the pattern identifier
// and Flags carries any event flags.
type Match struct {
	ID    uint
	From  uint64
	To    uint64
	Flags uint
}

// Len returns the length of the matched region (To - From). It is only
// meaningful when the pattern was compiled with SOMLeftmost.
func (m Match) Len() uint64 {
	if m.To < m.From {
		return 0
	}
	return m.To - m.From
}

// Span is a half-open byte range [Start, End) in the scanned input, suitable
// for substring replacement during redaction.
type Span struct {
	Start uint64
	End   uint64
}

// Matches scans data and collects every match event into a slice. It is a
// convenience wrapper over Scan for redaction-style callers that want all
// matches up front. Patterns should be compiled with SOMLeftmost so the
// resulting From offsets are valid.
func (d *Database) Matches(data []byte, s *Scratch) ([]Match, error) {
	var out []Match
	err := d.Scan(data, s, func(m Match) error {
		out = append(out, m)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// MergeSpans converts match events into a minimal set of non-overlapping
// spans suitable for replacement. Matches are interpreted as [From, To)
// ranges, sorted by Start then End, and coalesced when they overlap or are
// adjacent (cur.End >= next.Start). The input slice is never mutated; a fresh
// slice is always returned (nil for empty input).
func MergeSpans(matches []Match) []Span {
	if len(matches) == 0 {
		return nil
	}

	// Copy into a local slice so the caller's input is never reordered.
	spans := make([]Span, len(matches))
	for i, m := range matches {
		spans[i] = Span{Start: m.From, End: m.To}
	}
	sort.Slice(spans, func(i, j int) bool {
		if spans[i].Start != spans[j].Start {
			return spans[i].Start < spans[j].Start
		}
		return spans[i].End < spans[j].End
	})

	merged := make([]Span, 0, len(spans))
	cur := spans[0]
	for _, s := range spans[1:] {
		if s.Start <= cur.End { // overlapping or adjacent
			if s.End > cur.End {
				cur.End = s.End
			}
			continue
		}
		merged = append(merged, cur)
		cur = s
	}
	merged = append(merged, cur)
	return merged
}
