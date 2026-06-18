//go:build cgo && amd64

package hyperscan

/*
#include <stdlib.h>
#include <hs.h>
*/
import "C"

import (
	"runtime"
	"unsafe"
)

// Database is a compiled Hyperscan pattern database. It is immutable once
// compiled and may be shared across goroutines. Memory must be released with
// Close; a finalizer is registered as a leak backstop but is not a substitute
// for calling Close explicitly.
type Database struct {
	ptr *C.hs_database_t
}

// Pattern describes one expression for multi-pattern compilation. Expr is the
// raw pattern (no delimiters or inline flags), ID is the identifier reported
// on matches, and Flags are the per-pattern compile flags.
type Pattern struct {
	Expr  string
	ID    uint
	Flags CompileFlag
}

// newDatabase wraps a freshly compiled C database pointer and attaches the
// Close finalizer.
func newDatabase(ptr *C.hs_database_t) *Database {
	d := &Database{ptr: ptr}
	runtime.SetFinalizer(d, (*Database).Close)
	return d
}

// compileErrorFrom builds a *CompileError from a C hs_compile_error_t and frees
// it with hs_free_compile_error. cerr may be nil.
func compileErrorFrom(cerr *C.hs_compile_error_t) *CompileError {
	if cerr == nil {
		return &CompileError{Message: "unknown compile error", Expression: -1}
	}
	ce := &CompileError{
		Message:    C.GoString(cerr.message),
		Expression: int(cerr.expression),
	}
	C.hs_free_compile_error(cerr)
	return ce
}

// Compile compiles a single expression into a block-mode database. flags is a
// bitmask of CompileFlag values; redaction callers should include SOMLeftmost
// so match start offsets are valid. A pattern failure yields a *CompileError.
func Compile(expr string, flags CompileFlag) (*Database, error) {
	cexpr := C.CString(expr)
	defer C.free(unsafe.Pointer(cexpr))

	var db *C.hs_database_t
	var cerr *C.hs_compile_error_t
	rc := C.hs_compile(cexpr, C.uint(flags), C.HS_MODE_BLOCK, nil, &db, &cerr)
	if rc != C.HS_SUCCESS {
		if rc == C.HS_COMPILER_ERROR {
			return nil, compileErrorFrom(cerr)
		}
		return nil, errFrom(rc)
	}
	return newDatabase(db), nil
}

// CompileMulti compiles multiple patterns into a single block-mode database.
// Each Pattern carries its own flags and ID. A pattern failure yields a
// *CompileError whose Expression is the offending index.
func CompileMulti(patterns []Pattern) (*Database, error) {
	n := len(patterns)
	if n == 0 {
		return nil, &CompileError{Message: "no patterns supplied", Expression: -1}
	}

	// Build the parallel C arrays. The expressions array holds C strings that
	// must each be freed; the flags/ids arrays are malloc'd C-typed arrays.
	exprsRaw := C.malloc(C.size_t(n) * C.size_t(unsafe.Sizeof((*C.char)(nil))))
	cflagsRaw := C.malloc(C.size_t(n) * C.size_t(unsafe.Sizeof(C.uint(0))))
	cidsRaw := C.malloc(C.size_t(n) * C.size_t(unsafe.Sizeof(C.uint(0))))
	// Free the three backing allocations on every return path. C.free(nil) is a
	// no-op, so this is safe even if one of the mallocs above returned nil.
	defer C.free(exprsRaw)
	defer C.free(cflagsRaw)
	defer C.free(cidsRaw)
	if exprsRaw == nil || cflagsRaw == nil || cidsRaw == nil {
		return nil, ErrNoMem
	}
	exprs := (*[1 << 28]*C.char)(exprsRaw)
	cflags := (*[1 << 28]C.uint)(cflagsRaw)
	cids := (*[1 << 28]C.uint)(cidsRaw)
	// Free every C string in the expressions array on return. Entries left as
	// nil (e.g. if a later CString failed) are skipped by C.free's nil no-op.
	defer func() {
		for i := 0; i < n; i++ {
			C.free(unsafe.Pointer(exprs[i]))
		}
	}()

	for i, p := range patterns {
		exprs[i] = C.CString(p.Expr)
		cflags[i] = C.uint(p.Flags)
		cids[i] = C.uint(p.ID)
	}

	var db *C.hs_database_t
	var cerr *C.hs_compile_error_t
	rc := C.hs_compile_multi(
		(**C.char)(unsafe.Pointer(&exprs[0])),
		(*C.uint)(unsafe.Pointer(&cflags[0])),
		(*C.uint)(unsafe.Pointer(&cids[0])),
		C.uint(n), C.HS_MODE_BLOCK, nil, &db, &cerr)
	if rc != C.HS_SUCCESS {
		if rc == C.HS_COMPILER_ERROR {
			return nil, compileErrorFrom(cerr)
		}
		return nil, errFrom(rc)
	}
	return newDatabase(db), nil
}

// Close frees the underlying database. It is idempotent and safe to call on a
// nil Database; after Close the database can no longer be used to Scan.
func (d *Database) Close() error {
	if d == nil || d.ptr == nil {
		return nil
	}
	rc := C.hs_free_database(d.ptr)
	d.ptr = nil
	runtime.SetFinalizer(d, nil)
	return errFrom(rc)
}

// Size returns the size in bytes of the compiled database.
func (d *Database) Size() (uint64, error) {
	if d == nil || d.ptr == nil {
		return 0, ErrClosed
	}
	var sz C.size_t
	rc := C.hs_database_size(d.ptr, &sz)
	runtime.KeepAlive(d)
	if rc != C.HS_SUCCESS {
		return 0, errFrom(rc)
	}
	return uint64(sz), nil
}

// Info returns a human-readable string describing the database (version,
// mode, and feature information).
func (d *Database) Info() (string, error) {
	if d == nil || d.ptr == nil {
		return "", ErrClosed
	}
	var cinfo *C.char
	rc := C.hs_database_info(d.ptr, &cinfo)
	runtime.KeepAlive(d)
	if rc != C.HS_SUCCESS {
		return "", errFrom(rc)
	}
	info := C.GoString(cinfo)
	C.free(unsafe.Pointer(cinfo))
	return info, nil
}

// AllocScratch allocates a Scratch sized for this database. A Scratch is not
// safe for concurrent use; see ScratchPool for the multi-goroutine pattern.
func (d *Database) AllocScratch() (*Scratch, error) {
	if d == nil || d.ptr == nil {
		return nil, ErrClosed
	}
	var sc *C.hs_scratch_t
	rc := C.hs_alloc_scratch(d.ptr, &sc)
	runtime.KeepAlive(d)
	if rc != C.HS_SUCCESS {
		return nil, errFrom(rc)
	}
	return newScratch(sc), nil
}

// Serialize returns a portable byte representation of the database that can be
// reconstructed with Deserialize.
func (d *Database) Serialize() ([]byte, error) {
	if d == nil || d.ptr == nil {
		return nil, ErrClosed
	}
	var cbytes *C.char
	var length C.size_t
	rc := C.hs_serialize_database(d.ptr, &cbytes, &length)
	runtime.KeepAlive(d)
	if rc != C.HS_SUCCESS {
		return nil, errFrom(rc)
	}
	out := C.GoBytes(unsafe.Pointer(cbytes), C.int(length))
	C.free(unsafe.Pointer(cbytes))
	return out, nil
}

// Deserialize reconstructs a Database from bytes produced by Serialize.
func Deserialize(b []byte) (*Database, error) {
	if len(b) == 0 {
		return nil, ErrInvalid
	}
	var db *C.hs_database_t
	rc := C.hs_deserialize_database(
		(*C.char)(unsafe.Pointer(&b[0])), C.size_t(len(b)), &db)
	runtime.KeepAlive(b)
	if rc != C.HS_SUCCESS {
		return nil, errFrom(rc)
	}
	return newDatabase(db), nil
}
