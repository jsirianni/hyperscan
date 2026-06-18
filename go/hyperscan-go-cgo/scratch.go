//go:build cgo && amd64

package hyperscan

/*
#include <hs.h>
*/
import "C"

import (
	"runtime"
	"sync"
)

// Scratch is per-scan working memory required by Scan. A Scratch is sized for
// a particular Database and is NOT safe for concurrent use: each goroutine
// scanning at the same time needs its own Scratch (see ScratchPool). Release
// it with Close; a finalizer is registered as a leak backstop.
type Scratch struct {
	ptr *C.hs_scratch_t
}

// newScratch wraps a freshly allocated C scratch pointer and attaches the
// Close finalizer.
func newScratch(ptr *C.hs_scratch_t) *Scratch {
	s := &Scratch{ptr: ptr}
	runtime.SetFinalizer(s, (*Scratch).Close)
	return s
}

// Clone returns an independent copy of the scratch, usable by another
// goroutine concurrently with the original.
func (s *Scratch) Clone() (*Scratch, error) {
	if s == nil || s.ptr == nil {
		return nil, ErrNilScratch
	}
	var dst *C.hs_scratch_t
	rc := C.hs_clone_scratch(s.ptr, &dst)
	runtime.KeepAlive(s)
	if rc != C.HS_SUCCESS {
		return nil, errFrom(rc)
	}
	return newScratch(dst), nil
}

// Close frees the underlying scratch. It is idempotent and safe to call on a
// nil Scratch.
func (s *Scratch) Close() error {
	if s == nil || s.ptr == nil {
		return nil
	}
	rc := C.hs_free_scratch(s.ptr)
	s.ptr = nil
	runtime.SetFinalizer(s, nil)
	return errFrom(rc)
}

// Size returns the size in bytes of the scratch region.
func (s *Scratch) Size() (uint64, error) {
	if s == nil || s.ptr == nil {
		return 0, ErrNilScratch
	}
	var sz C.size_t
	rc := C.hs_scratch_size(s.ptr, &sz)
	runtime.KeepAlive(s)
	if rc != C.HS_SUCCESS {
		return 0, errFrom(rc)
	}
	return uint64(sz), nil
}

// ScratchPool hands out per-goroutine Scratch instances for a single Database.
// It is backed by a sync.Pool whose New clones a template scratch allocated
// once from the database. Obtain a scratch with Get, return it with Put, and
// release the pool (and its template) with Close.
type ScratchPool struct {
	template *Scratch
	pool     *sync.Pool
	newErr   error // first clone error encountered by pool.New, surfaced via Get
	mu       sync.Mutex
}

// NewScratchPool allocates a template scratch from the database and returns a
// pool that clones it on demand. The template is freed by Close.
func (d *Database) NewScratchPool() (*ScratchPool, error) {
	if d == nil || d.ptr == nil {
		return nil, ErrClosed
	}
	template, err := d.AllocScratch()
	if err != nil {
		return nil, err
	}
	p := &ScratchPool{template: template}
	p.pool = &sync.Pool{
		New: func() any {
			clone, err := template.Clone()
			if err != nil {
				p.mu.Lock()
				if p.newErr == nil {
					p.newErr = err
				}
				p.mu.Unlock()
				return nil
			}
			return clone
		},
	}
	return p, nil
}

// Get returns a Scratch for the current goroutine. The caller must return it
// with Put when finished. Get reports the first clone error if pool growth
// failed.
func (p *ScratchPool) Get() (*Scratch, error) {
	v := p.pool.Get()
	if v == nil {
		p.mu.Lock()
		err := p.newErr
		p.newErr = nil
		p.mu.Unlock()
		if err != nil {
			return nil, err
		}
		return nil, ErrNilScratch
	}
	return v.(*Scratch), nil
}

// Put returns a Scratch to the pool for reuse. A nil or already-closed Scratch
// is ignored.
func (p *ScratchPool) Put(s *Scratch) {
	if s == nil || s.ptr == nil {
		return
	}
	p.pool.Put(s)
}

// Close frees the template scratch. Scratch instances still checked out of the
// pool are reclaimed by their finalizers; callers should drain outstanding
// Get/Put pairs before Close.
func (p *ScratchPool) Close() error {
	if p == nil || p.template == nil {
		return nil
	}
	err := p.template.Close()
	p.template = nil
	return err
}
