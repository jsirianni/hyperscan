//go:build cgo && amd64

package hyperscan

/*
#include <hs.h>
*/
import "C"

import "strings"

// CompileFlag is a bitmask of HS_FLAG_* pattern-compilation flags. Multiple
// flags may be combined with the bitwise OR operator.
type CompileFlag uint

// Pattern compilation flags, mirroring the HS_FLAG_* macros in hs_compile.h.
const (
	// Caseless makes the pattern match case-insensitively (HS_FLAG_CASELESS).
	Caseless CompileFlag = C.HS_FLAG_CASELESS
	// DotAll makes "." match newlines (HS_FLAG_DOTALL).
	DotAll CompileFlag = C.HS_FLAG_DOTALL
	// MultiLine makes "^" and "$" match at embedded newlines (HS_FLAG_MULTILINE).
	MultiLine CompileFlag = C.HS_FLAG_MULTILINE
	// SingleMatch reports at most one match per pattern ID (HS_FLAG_SINGLEMATCH).
	SingleMatch CompileFlag = C.HS_FLAG_SINGLEMATCH
	// AllowEmpty permits patterns that can match an empty string (HS_FLAG_ALLOWEMPTY).
	AllowEmpty CompileFlag = C.HS_FLAG_ALLOWEMPTY
	// UTF8 interprets the pattern and data as UTF-8 (HS_FLAG_UTF8).
	UTF8 CompileFlag = C.HS_FLAG_UTF8
	// UCP enables Unicode property support, requires UTF8 (HS_FLAG_UCP).
	UCP CompileFlag = C.HS_FLAG_UCP
	// Prefilter compiles the pattern in prefiltering mode (HS_FLAG_PREFILTER).
	Prefilter CompileFlag = C.HS_FLAG_PREFILTER
	// SOMLeftmost enables start-of-match reporting, required for valid Match.From
	// offsets (HS_FLAG_SOM_LEFTMOST). Mandatory for redaction use.
	SOMLeftmost CompileFlag = C.HS_FLAG_SOM_LEFTMOST
	// Combination marks the pattern as a logical combination of others (HS_FLAG_COMBINATION).
	Combination CompileFlag = C.HS_FLAG_COMBINATION
	// Quiet suppresses match reporting for the pattern (HS_FLAG_QUIET).
	Quiet CompileFlag = C.HS_FLAG_QUIET
)

// compileFlagNames pairs each flag with its short name for String().
var compileFlagNames = []struct {
	flag CompileFlag
	name string
}{
	{Caseless, "CASELESS"},
	{DotAll, "DOTALL"},
	{MultiLine, "MULTILINE"},
	{SingleMatch, "SINGLEMATCH"},
	{AllowEmpty, "ALLOWEMPTY"},
	{UTF8, "UTF8"},
	{UCP, "UCP"},
	{Prefilter, "PREFILTER"},
	{SOMLeftmost, "SOM_LEFTMOST"},
	{Combination, "COMBINATION"},
	{Quiet, "QUIET"},
}

// String renders the set flags joined by "|", for example
// "CASELESS|SOM_LEFTMOST". The empty set renders as "0".
func (f CompileFlag) String() string {
	if f == 0 {
		return "0"
	}
	var parts []string
	remaining := f
	for _, e := range compileFlagNames {
		if f&e.flag != 0 {
			parts = append(parts, e.name)
			remaining &^= e.flag
		}
	}
	if remaining != 0 {
		parts = append(parts, "0x"+strings.ToUpper(uintToHex(uint(remaining))))
	}
	return strings.Join(parts, "|")
}

// ModeFlag is a bitmask of HS_MODE_* database mode flags. This binding only
// uses block mode.
type ModeFlag uint

// Database mode flags, mirroring the HS_MODE_* macros in hs_compile.h.
const (
	// ModeBlock selects block (non-streaming) scanning (HS_MODE_BLOCK).
	ModeBlock ModeFlag = C.HS_MODE_BLOCK
)

// String renders the mode flag name.
func (m ModeFlag) String() string {
	switch m {
	case ModeBlock:
		return "BLOCK"
	default:
		return "0x" + strings.ToUpper(uintToHex(uint(m)))
	}
}

// uintToHex formats v as a lowercase hexadecimal string without a prefix.
func uintToHex(v uint) string {
	if v == 0 {
		return "0"
	}
	const digits = "0123456789abcdef"
	var buf [16]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = digits[v&0xf]
		v >>= 4
	}
	return string(buf[i:])
}
