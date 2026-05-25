// Package main is the CGO entry point for pytrivydb's Python binding.
//
// It exposes a small set of //export functions over `pkg/reader`,
// using runtime/cgo.Handle for typed handle values. Per the plan:
//
//   - 11 //exports total (database/iterator/query handles).
//   - Variable-length string args use **C.char + int, never
//     comma-joined strings.
//   - Returned strings are allocated with C.CString; the Python layer
//     wraps each with ffi.gc(ptr, libc free) so the buffer is freed
//     when the wrapper is GC'd.
//   - Errors flow via the `err` field of pytrivyResponse; the JSON
//     field is nil on error and vice versa.
//   - Iterator Close is synchronous + idempotent (per-handle mutex
//     lives in pkg/reader's iterator state).
package main

/*
#include <stdint.h>  // for uintptr_t — Linux headers don't transitively pull this in via stdlib.h
#include <stdlib.h>

typedef struct {
    char *json;
    char *err;
} pytrivyResponse;
*/
import "C"

import (
	"encoding/json"
	"errors"
	"runtime/cgo"
	"sync"
	"unsafe"

	"github.com/drape-io/pytrivydb/go-src/pkg/reader"
)

// lastErr stores the most recent error string produced by an Open*
// call (those return uintptr_t with 0 meaning failure; Python reads
// LastError() to retrieve the message).
var (
	lastErrMu sync.Mutex
	lastErr   string
)

func setLastError(err error) {
	lastErrMu.Lock()
	// Prefix with kind so the Python layer's from_go_error can route
	// to the correct exception class. Same format errResponse uses
	// for per-call responses.
	lastErr = errKind(err) + ": " + err.Error()
	lastErrMu.Unlock()
}

// getLastError returns and clears the stored error message
// (consume-once semantics). Clearing prevents a stale message from
// surfacing on a later unrelated call that checks LastError without
// first observing a handle==0 failure.
func getLastError() string {
	lastErrMu.Lock()
	defer lastErrMu.Unlock()
	msg := lastErr
	lastErr = ""
	return msg
}

// errKind translates a reader sentinel error into a short code the
// Python layer routes to specific exception classes.
func errKind(err error) string {
	switch {
	case errors.Is(err, reader.ErrUnsupportedSchema):
		return "unsupported_schema"
	case errors.Is(err, reader.ErrNotFound), errors.Is(err, reader.ErrMetadataNotFound):
		return "not_found"
	case errors.Is(err, reader.ErrCorrupt):
		return "corrupt"
	default:
		return "error"
	}
}

// errResponse builds a pytrivyResponse with the error payload set.
// Format is `<kind>: <message>` so the Python layer can split on the
// first colon.
func errResponse(err error) C.pytrivyResponse {
	msg := errKind(err) + ": " + err.Error()
	return C.pytrivyResponse{json: nil, err: C.CString(msg)}
}

// okResponse marshals v and returns a pytrivyResponse with the JSON
// payload set.
func okResponse(v any) C.pytrivyResponse {
	data, err := json.Marshal(v)
	if err != nil {
		return errResponse(err)
	}
	return C.pytrivyResponse{json: C.CString(string(data)), err: nil}
}

// safeValue wraps cgo.Handle.Value() with a recover so an invalid /
// already-deleted handle returns (nil, false) instead of panicking
// the Go runtime through the CGO boundary (which would abort Python).
func safeValue(h C.uintptr_t) (v any, ok bool) {
	defer func() {
		if r := recover(); r != nil {
			v = nil
			ok = false
		}
	}()
	return cgo.Handle(h).Value(), true
}

// goStrings copies a C **char + length into a Go []string.
func goStrings(arr **C.char, n C.int) []string {
	if n <= 0 || arr == nil {
		return nil
	}
	// Mirror tfparse's pattern: `unsafe.Slice` on the C array.
	slice := unsafe.Slice(arr, n)
	out := make([]string, 0, len(slice))
	for _, p := range slice {
		if p == nil {
			continue
		}
		out = append(out, C.GoString(p))
	}
	return out
}

// --- Database handles ---

//export OpenDatabase
func OpenDatabase(dbDir *C.char) C.uintptr_t {
	dir := C.GoString(dbDir)
	db, err := reader.Open(dir)
	if err != nil {
		setLastError(err)
		return 0
	}
	return C.uintptr_t(cgo.NewHandle(db))
}

//export CloseDatabase
func CloseDatabase(handle C.uintptr_t) {
	if handle == 0 {
		return
	}
	v, ok := safeValue(handle)
	if !ok {
		return
	}
	// Only Delete the cgo.Handle slot after confirming this handle
	// belongs to a Database — guards against a caller passing the
	// wrong-kind handle and us nuking an unrelated slot.
	db, ok := v.(*reader.Database)
	if !ok {
		return
	}
	_ = db.Close()
	cgo.Handle(handle).Delete()
}

func dbFromHandle(handle C.uintptr_t) (*reader.Database, error) {
	if handle == 0 {
		return nil, errors.New("nil database handle")
	}
	v, ok := safeValue(handle)
	if !ok {
		return nil, errors.New("stale or invalid database handle")
	}
	db, ok := v.(*reader.Database)
	if !ok {
		return nil, errors.New("invalid database handle")
	}
	return db, nil
}

// --- Iterators ---

//export OpenAdvisoryIterator
func OpenAdvisoryIterator(dbHandle C.uintptr_t) C.uintptr_t {
	db, err := dbFromHandle(dbHandle)
	if err != nil {
		setLastError(err)
		return 0
	}
	it, err := db.OpenAdvisoryIterator()
	if err != nil {
		setLastError(err)
		return 0
	}
	return C.uintptr_t(cgo.NewHandle(it))
}

//export OpenMetaIterator
func OpenMetaIterator(dbHandle C.uintptr_t) C.uintptr_t {
	db, err := dbFromHandle(dbHandle)
	if err != nil {
		setLastError(err)
		return 0
	}
	it, err := db.OpenMetaIterator()
	if err != nil {
		setLastError(err)
		return 0
	}
	return C.uintptr_t(cgo.NewHandle(it))
}

//export IterNext
func IterNext(iterHandle C.uintptr_t, batchSize C.int) C.pytrivyResponse {
	if iterHandle == 0 {
		return errResponse(errors.New("nil iterator handle"))
	}
	v, ok := safeValue(iterHandle)
	if !ok {
		return errResponse(errors.New("stale or invalid iterator handle"))
	}
	switch it := v.(type) {
	case *reader.AdvisoryIterator:
		batch, err := it.Next(int(batchSize))
		if err != nil {
			return errResponse(err)
		}
		if batch == nil {
			return okResponse([]reader.AdvisoryRow{})
		}
		return okResponse(batch)
	case *reader.MetaIterator:
		batch, err := it.Next(int(batchSize))
		if err != nil {
			return errResponse(err)
		}
		if batch == nil {
			return okResponse([]reader.MetaRow{})
		}
		return okResponse(batch)
	default:
		return errResponse(errors.New("invalid iterator handle"))
	}
}

//export IterClose
func IterClose(iterHandle C.uintptr_t) {
	if iterHandle == 0 {
		return
	}
	v, ok := safeValue(iterHandle)
	if !ok {
		// Already-deleted handle. Idempotent: just return.
		return
	}
	// Only Delete after confirming this handle belongs to an iterator
	// — defensively avoids deleting a wrong-kind slot if a caller
	// passes (e.g.) a Database handle by mistake.
	matched := false
	switch it := v.(type) {
	case *reader.AdvisoryIterator:
		_ = it.Close()
		matched = true
	case *reader.MetaIterator:
		_ = it.Close()
		matched = true
	}
	if matched {
		cgo.Handle(iterHandle).Delete()
	}
}

// --- Queries ---

//export FindAdvisories
func FindAdvisories(
	dbHandle C.uintptr_t,
	cve, pkg, packageType *C.char,
	sources **C.char, numSources C.int,
	repositories **C.char, numRepos C.int,
	nvrs **C.char, numNvrs C.int,
) C.pytrivyResponse {
	db, err := dbFromHandle(dbHandle)
	if err != nil {
		return errResponse(err)
	}
	opts := reader.FindOpts{
		PackageType:  C.GoString(packageType),
		Sources:      goStrings(sources, numSources),
		Repositories: goStrings(repositories, numRepos),
		NVRs:         goStrings(nvrs, numNvrs),
	}
	rows, err := db.FindAdvisories(C.GoString(cve), C.GoString(pkg), opts)
	if err != nil {
		return errResponse(err)
	}
	if rows == nil {
		rows = []reader.AdvisoryRow{}
	}
	return okResponse(rows)
}

//export GetAdvisory
func GetAdvisory(dbHandle C.uintptr_t, source, pkg, cve *C.char) C.pytrivyResponse {
	db, err := dbFromHandle(dbHandle)
	if err != nil {
		return errResponse(err)
	}
	row, ok, err := db.GetAdvisory(C.GoString(source), C.GoString(pkg), C.GoString(cve))
	if err != nil {
		return errResponse(err)
	}
	if !ok {
		// Returning JSON "null" lets the Python layer distinguish
		// "not found" from "empty advisory".
		return C.pytrivyResponse{json: C.CString("null"), err: nil}
	}
	return okResponse(row)
}

//export ListSources
func ListSources(dbHandle C.uintptr_t) C.pytrivyResponse {
	db, err := dbFromHandle(dbHandle)
	if err != nil {
		return errResponse(err)
	}
	sources, err := db.ListSources()
	if err != nil {
		return errResponse(err)
	}
	if sources == nil {
		sources = []string{}
	}
	return okResponse(sources)
}

//export SourcesForPackageType
func SourcesForPackageType(dbHandle C.uintptr_t, packageType *C.char) C.pytrivyResponse {
	db, err := dbFromHandle(dbHandle)
	if err != nil {
		return errResponse(err)
	}
	sources, err := db.SourcesForPackageType(C.GoString(packageType))
	if err != nil {
		return errResponse(err)
	}
	if sources == nil {
		sources = []string{}
	}
	return okResponse(sources)
}

//export LastError
func LastError() *C.char {
	msg := getLastError()
	if msg == "" {
		return nil
	}
	return C.CString(msg)
}

func main() {}
