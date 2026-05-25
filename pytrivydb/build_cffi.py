"""CFFI binding declaration for pytrivydb's Go-built shared library.

Mirrors the CGO //export surface in `go-src/cmd/pytrivydb/main.go`.
Uses CFFI in hybrid mode (set_source declares the cdef compile target;
`ffi.dlopen` at runtime in `_ffi.py` loads the Go-built .so).
"""

from cffi import FFI

ffi = FFI()

ffi.set_source(
    "pytrivydb._pytrivydb_cffi",
    None,
    include_dirs=[],
    libraries=[],
    # NO -march=native: would bake CI-runner CPU features into the wheel
    # and SIGILL on older user machines. See plan §15 / anti-criteria.
)

ffi.cdef(
    """
    typedef struct {
        char *json;
        char *err;
    } pytrivyResponse;

    /* Database handles */
    uintptr_t OpenDatabase(char *dbDir);
    void      CloseDatabase(uintptr_t handle);

    /* Iterators */
    uintptr_t OpenAdvisoryIterator(uintptr_t dbHandle);
    uintptr_t OpenMetaIterator(uintptr_t dbHandle);
    pytrivyResponse IterNext(uintptr_t iterHandle, int batchSize);
    void      IterClose(uintptr_t iterHandle);

    /* Queries */
    pytrivyResponse FindAdvisories(
        uintptr_t dbHandle,
        char *cve, char *pkg, char *packageType,
        char **sources,      int numSources,
        char **repositories, int numRepos,
        char **nvrs,         int numNvrs
    );
    pytrivyResponse GetAdvisory(
        uintptr_t dbHandle, char *source, char *pkg, char *cve
    );
    pytrivyResponse ListSources(uintptr_t dbHandle);
    pytrivyResponse SourcesForPackageType(
        uintptr_t dbHandle, char *packageType
    );

    /* Error reporting (used when Open* returns 0) */
    char *LastError(void);

    /* libc free for ffi.gc registration on returned strings */
    void free(void *ptr);
    """
)

if __name__ == "__main__":
    ffi.compile()
