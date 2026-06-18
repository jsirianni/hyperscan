//go:build cgo && amd64

package hyperscan

/*
// libhs.a is internally C++ and uses OpenSSL, so the static link needs its
// private deps (-lstdc++ -lm -lcrypto) in addition to -lhs. --static makes
// pkg-config emit those private libs in the correct order after -lhs. It must
// go here, NOT via PKG_CONFIG="pkg-config --static", because cgo keeps only
// the first word of $PKG_CONFIG and silently drops --static.
#cgo pkg-config: --static libhs
#include <stdint.h>
#include <stdlib.h>
#include <hs.h>

extern int goMatchBridge(unsigned int id, unsigned long long from,
                         unsigned long long to, unsigned int flags, uintptr_t ctx);

// matchTrampoline has the exact match_event_handler signature and forwards to
// the //export-ed Go function. cgo cannot hand a Go func directly to C as a
// function pointer, so this static C shim bridges the two.
static int matchTrampoline(unsigned int id, unsigned long long from,
                           unsigned long long to, unsigned int flags, void *ctx) {
    return goMatchBridge(id, from, to, flags, (uintptr_t)ctx);
}

// hs_scan_cgo wires hs_scan to the trampoline. ctx is a cgo.Handle token,
// round-tripped through void* so the Go side never forms an
// unsafe.Pointer(uintptr) (which go vet flags).
static hs_error_t hs_scan_cgo(const hs_database_t *db, const char *data,
                              unsigned int length, hs_scratch_t *scratch, uintptr_t ctx) {
    return hs_scan(db, data, length, 0, scratch, matchTrampoline, (void *)ctx);
}
*/
import "C"

import (
	"errors"
	"math"
	"runtime"
	"runtime/cgo"
	"unsafe"
)

// scanContext carries per-scan Go state across the C boundary. It is never
// handed to C as a pointer; instead a cgo.Handle token references it, so the
// Go pointers it holds do not violate the cgo pointer-passing rule.
type scanContext struct {
	handler MatchHandler // user callback; a non-nil return halts scanning
	err     error        // first handler error (clean stop)
	panicV  any          // recovered panic, re-raised after hs_scan returns
}

// ErrStop halts scanning without being treated as a failure. A MatchHandler
// may return ErrStop to stop early; Scan then returns nil.
var ErrStop = errors.New("hyperscan: scan stopped by handler")

// ErrTooLarge is returned by Scan when the input exceeds the maximum length
// (math.MaxUint32) accepted by Hyperscan's unsigned length argument.
var ErrTooLarge = errors.New("hyperscan: input exceeds maximum scan length")

// hsEmptyData backs the non-nil pointer handed to hs_scan for zero-length
// input (hs_scan rejects a NULL data pointer with HS_INVALID). It is never
// read because the scan length is 0.
var hsEmptyData [1]byte

//export goMatchBridge
func goMatchBridge(id C.uint, from, to C.ulonglong, flags C.uint, ctx C.uintptr_t) (ret C.int) {
	sc := cgo.Handle(uintptr(ctx)).Value().(*scanContext)
	if sc.err != nil || sc.panicV != nil {
		return 1 // already stopping
	}
	// A panic must never unwind through the C stack frame; recover it here and
	// re-raise it on the caller's goroutine once hs_scan returns.
	defer func() {
		if r := recover(); r != nil {
			sc.panicV = r
			ret = 1
		}
	}()
	if err := sc.handler(Match{ID: uint(id), From: uint64(from), To: uint64(to), Flags: uint(flags)}); err != nil {
		sc.err = err
		return 1
	}
	return 0
}

// Scan runs the compiled database over data in block mode, invoking handler
// for every match event. Returning a non-nil error from handler halts the
// scan; ErrStop halts cleanly (Scan returns nil), any other error is returned
// by Scan. The Scratch must not be shared with a concurrent Scan and must not
// be reused inside handler.
func (d *Database) Scan(data []byte, s *Scratch, handler MatchHandler) error {
	if d == nil || d.ptr == nil {
		return ErrClosed
	}
	if s == nil || s.ptr == nil {
		return ErrNilScratch
	}
	if uint64(len(data)) > math.MaxUint32 {
		return ErrTooLarge
	}

	sc := &scanContext{handler: handler}
	h := cgo.NewHandle(sc) // NewHandle, not Handle(sc)
	defer h.Delete()

	var ptr *C.char
	if len(data) > 0 {
		ptr = (*C.char)(unsafe.Pointer(&data[0]))
	} else {
		// hs_scan rejects a NULL data pointer with HS_INVALID even when the
		// length is 0, so hand it a valid throwaway pointer. With length 0 the
		// byte is never read; patterns compiled with AllowEmpty still fire.
		ptr = (*C.char)(unsafe.Pointer(&hsEmptyData[0]))
	}
	rc := C.hs_scan_cgo(d.ptr, ptr, C.uint(len(data)), s.ptr, C.uintptr_t(h))
	runtime.KeepAlive(data)
	runtime.KeepAlive(d)
	runtime.KeepAlive(s)

	if sc.panicV != nil {
		panic(sc.panicV) // re-raise on the caller's goroutine
	}
	switch rc {
	case C.HS_SUCCESS:
		return nil
	case C.HS_SCAN_TERMINATED: // only set by our nonzero callback return
		if sc.err != nil && !errors.Is(sc.err, ErrStop) {
			return sc.err
		}
		return nil
	default:
		return errFrom(rc)
	}
}
