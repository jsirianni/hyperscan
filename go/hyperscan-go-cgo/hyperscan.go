//go:build cgo && amd64

package hyperscan

/*
#include <hs.h>
*/
import "C"

import (
	"errors"
	"fmt"
)

// Version returns the Hyperscan library version string (for example
// "5.4.2 ..."). The underlying C string is statically allocated and must not
// be freed.
func Version() string {
	return C.GoString(C.hs_version())
}

// ValidPlatform reports whether the host CPU supports the instruction set
// required by the Hyperscan runtime. It returns nil if the platform is
// supported, otherwise an Error (HS_ARCH_ERROR).
func ValidPlatform() error {
	return errFrom(C.hs_valid_platform())
}

// Error is a Hyperscan runtime error code (an hs_error_t value). The zero
// value is not used; HS_SUCCESS (0) is mapped to a nil error by errFrom.
type Error int

// Hyperscan error-code sentinels, mirroring the HS_* macros in hs_common.h.
const (
	ErrInvalid           Error = -1  // HS_INVALID: a parameter was invalid
	ErrNoMem             Error = -2  // HS_NOMEM: memory allocation failed
	ErrScanTerminated    Error = -3  // HS_SCAN_TERMINATED: scan halted by callback
	ErrCompilerError     Error = -4  // HS_COMPILER_ERROR: pattern compilation failed
	ErrDBVersionError    Error = -5  // HS_DB_VERSION_ERROR: database version mismatch
	ErrDBPlatformError   Error = -6  // HS_DB_PLATFORM_ERROR: database built for another platform
	ErrDBModeError       Error = -7  // HS_DB_MODE_ERROR: database built for another mode
	ErrBadAlign          Error = -8  // HS_BAD_ALIGN: a parameter was not correctly aligned
	ErrBadAlloc          Error = -9  // HS_BAD_ALLOC: an allocator returned misaligned memory
	ErrScratchInUse      Error = -10 // HS_SCRATCH_IN_USE: scratch already in use
	ErrArchError         Error = -11 // HS_ARCH_ERROR: unsupported CPU architecture
	ErrInsufficientSpace Error = -12 // HS_INSUFFICIENT_SPACE: provided buffer too small
	ErrUnknownError      Error = -13 // HS_UNKNOWN_ERROR: unexpected internal error
)

// Error implements the error interface, returning a human-readable
// description of the Hyperscan error code.
func (e Error) Error() string {
	switch e {
	case ErrInvalid:
		return "hyperscan: invalid parameter (HS_INVALID)"
	case ErrNoMem:
		return "hyperscan: out of memory (HS_NOMEM)"
	case ErrScanTerminated:
		return "hyperscan: scan terminated by callback (HS_SCAN_TERMINATED)"
	case ErrCompilerError:
		return "hyperscan: compiler error (HS_COMPILER_ERROR)"
	case ErrDBVersionError:
		return "hyperscan: database version mismatch (HS_DB_VERSION_ERROR)"
	case ErrDBPlatformError:
		return "hyperscan: database platform mismatch (HS_DB_PLATFORM_ERROR)"
	case ErrDBModeError:
		return "hyperscan: database mode mismatch (HS_DB_MODE_ERROR)"
	case ErrBadAlign:
		return "hyperscan: bad alignment (HS_BAD_ALIGN)"
	case ErrBadAlloc:
		return "hyperscan: bad allocation (HS_BAD_ALLOC)"
	case ErrScratchInUse:
		return "hyperscan: scratch in use (HS_SCRATCH_IN_USE)"
	case ErrArchError:
		return "hyperscan: unsupported architecture (HS_ARCH_ERROR)"
	case ErrInsufficientSpace:
		return "hyperscan: insufficient space (HS_INSUFFICIENT_SPACE)"
	case ErrUnknownError:
		return "hyperscan: unknown error (HS_UNKNOWN_ERROR)"
	default:
		return fmt.Sprintf("hyperscan: error code %d", int(e))
	}
}

// errFrom converts an hs_error_t return value into a Go error. HS_SUCCESS
// yields nil; any other code yields an Error.
func errFrom(rc C.hs_error_t) error {
	if rc == C.HS_SUCCESS {
		return nil
	}
	return Error(int(rc))
}

// CompileError describes a pattern compilation failure reported by Hyperscan
// (an hs_compile_error_t). Expression is the zero-based index of the offending
// pattern, or -1 when the failure is not specific to a single expression.
type CompileError struct {
	Message    string
	Expression int
}

// Error implements the error interface.
func (e *CompileError) Error() string {
	if e.Expression >= 0 {
		return fmt.Sprintf("hyperscan: compile error at expression %d: %s", e.Expression, e.Message)
	}
	return fmt.Sprintf("hyperscan: compile error: %s", e.Message)
}

// ErrClosed is returned by methods called on a Database (or via Scan) after it
// has been closed or on a nil Database.
var ErrClosed = errors.New("hyperscan: database is closed")

// ErrNilScratch is returned by Scan when the supplied Scratch is nil or has
// been closed.
var ErrNilScratch = errors.New("hyperscan: scratch is nil or closed")
