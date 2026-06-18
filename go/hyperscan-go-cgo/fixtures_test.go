//go:build cgo && amd64

package hyperscan

// fixtures_test.go — shared PII pattern set for unit tests and benchmarks.
//
// All patterns are Hyperscan-compatible: no backreferences, lookaround, or
// capture-group-based replacement. Each pattern is also exported as a raw
// string in redactionRegexStrings so the benchmark can compile equivalent
// *regexp.Regexp baselines from the identical source strings.

// redactionRegexStrings holds the raw Go string representations of each PII
// pattern, in the same order as redactionPatterns. Benchmarks use these to
// build stdlib regexp.Regexp baselines that are driven by the exact same
// pattern text.
var redactionRegexStrings = []string{
	// 1. Email address
	`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`,
	// 2. US Social Security Number (ddd-dd-dddd)
	`\d{3}-\d{2}-\d{4}`,
	// 3. Credit card number — 16 digits with optional separators
	`\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}`,
	// 4. US phone number — (ddd) ddd-dddd or ddd-ddd-dddd or ddd.ddd.dddd
	`(\+1[-.\s]?)?(\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4})`,
	// 5. IPv4 address
	`\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`,
	// 6. IPv6 address (full 8-group form)
	`[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){7}`,
	// 7. UUID (canonical 8-4-4-4-12 hex form)
	`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`,
	// 8. AWS access key ID (AKIA + 16 uppercase alphanum)
	`AKIA[0-9A-Z]{16}`,
	// 9. JWT-like token (three base64url segments separated by dots)
	`[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}`,
	// 10. MAC address (six colon- or hyphen-separated hex pairs)
	`[0-9a-fA-F]{2}(?:[:\-][0-9a-fA-F]{2}){5}`,
	// 11. US ZIP code (5 digits, optionally +4)
	`\b\d{5}(?:-\d{4})?\b`,
	// 12. HTTP Bearer token header value
	`[Bb]earer\s+[A-Za-z0-9\-._~+/]+=*`,
	// 13. Generic 16-or-more consecutive digit run (catches PANs and other numeric secrets)
	`\d{16,}`,
	// 14. Basic-auth-style credential (scheme://user:secret@host)
	`[a-zA-Z][a-zA-Z0-9+\-.]*://[^:@/\s]+:[^@/\s]+@[^\s/]+`,
}

// redactionPatterns is the compiled-ready Pattern slice for CompileMulti.
// Every pattern is assigned a sequential 1-based ID and compiled with
// SOMLeftmost so Match.From offsets are valid for substring replacement.
// The slice index matches the corresponding entry in redactionRegexStrings.
var redactionPatterns = []Pattern{
	{Expr: redactionRegexStrings[0], ID: 1, Flags: SOMLeftmost},   // email
	{Expr: redactionRegexStrings[1], ID: 2, Flags: SOMLeftmost},   // US SSN
	{Expr: redactionRegexStrings[2], ID: 3, Flags: SOMLeftmost},   // credit card
	{Expr: redactionRegexStrings[3], ID: 4, Flags: SOMLeftmost},   // US phone
	{Expr: redactionRegexStrings[4], ID: 5, Flags: SOMLeftmost},   // IPv4
	{Expr: redactionRegexStrings[5], ID: 6, Flags: SOMLeftmost},   // IPv6
	{Expr: redactionRegexStrings[6], ID: 7, Flags: SOMLeftmost},   // UUID
	{Expr: redactionRegexStrings[7], ID: 8, Flags: SOMLeftmost},   // AWS key
	{Expr: redactionRegexStrings[8], ID: 9, Flags: SOMLeftmost},   // JWT-like
	{Expr: redactionRegexStrings[9], ID: 10, Flags: SOMLeftmost},  // MAC address
	{Expr: redactionRegexStrings[10], ID: 11, Flags: SOMLeftmost}, // US ZIP
	{Expr: redactionRegexStrings[11], ID: 12, Flags: SOMLeftmost}, // Bearer token
	{Expr: redactionRegexStrings[12], ID: 13, Flags: SOMLeftmost}, // 16+ digit run
	{Expr: redactionRegexStrings[13], ID: 14, Flags: SOMLeftmost}, // basic-auth URL
}

// sampleInputs returns a map of named test strings useful for unit tests and
// benchmarks. Each value exercises at least one PII pattern in redactionPatterns.
// The keys indicate the dominant PII type embedded in the string; callers may
// combine values to build multi-match inputs.
func sampleInputs() map[string]string {
	return map[string]string{
		"email":      "Please contact support@example.com for help.",
		"ssn":        "SSN on file: 123-45-6789.",
		"creditcard": "Charged card 4111-1111-1111-1111 successfully.",
		"phone":      "Call us at (800) 555-1234 any time.",
		"ipv4":       "Origin: 192.168.1.100 flagged.",
		"ipv6":       "Address 2001:0db8:85a3:0000:0000:8a2e:0370:7334 assigned.",
		"uuid":       "Request ID: 550e8400-e29b-41d4-a716-446655440000.",
		"awskey":     "Key=AKIAIOSFODNN7EXAMPLE leaked in log.",
		"jwt":        "Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
		"mac":        "Device 00:1A:2B:3C:4D:5E registered.",
		"zip":        "Shipped to ZIP 94103-1234.",
		"bearer":     "Header: Bearer eyJhbGciOiJSUzI1NiJ9.payload.sig",
		"digits16":   "PAN: 4111111111111111 stored.",
		"basicauth":  "Fetched https://admin:s3cr3t@internal.example.com/api.",
		// multi-PII: email + SSN together, used by the flagship redaction test
		"multi": "User alice@corp.io (SSN 987-65-4320) paid with 5500-0000-0000-0004.",
		// clean: no PII, used for nomatch benchmark dimension
		"clean": "The quick brown fox jumps over the lazy dog. No secrets here.",
	}
}
