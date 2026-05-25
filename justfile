# pytrivydb dev commands.

# Install / sync deps and (re)build the Go-built .so.
install:
    uv sync --frozen
    uv pip install -e .

# Run the Python + Go test suites.
test:
    cd go-src && go test ./...
    uv run pytest pytrivydb/tests

# Run just the Python tests.
test-py:
    uv run pytest pytrivydb/tests

# Run just the Go tests.
test-go:
    cd go-src && go test ./...

# Format Python and Go source.
fmt:
    uv run ruff format pytrivydb/
    cd go-src && gofmt -w .

# Lint Python source.
lint:
    uv run ruff check pytrivydb/
    uv run ruff format --check pytrivydb/

# Type-check Python source.
typecheck:
    uv run ty check pytrivydb/

# Rebuild the synthetic test fixture from scratch.
regen-fixture:
    rm -f pytrivydb/tests/fixtures/trivy.db pytrivydb/tests/fixtures/metadata.json
    cd go-src && go run ./cmd/build_synthetic ../pytrivydb/tests/fixtures

# Smoke-test an installed wheel against a real trivy.db directory.
# Usage: just smoke-test /path/to/trivydb
smoke-test path:
    uv run python -c "from pathlib import Path; from pytrivydb import Database; \
        db = Database(Path('{{path}}')); \
        print('sources:', len(db.list_sources())); \
        print('first 5:', [(a.source, a.package_name, a.cve_id) for a in __import__('itertools').islice(db.iter_advisories(), 5)]); \
        db.close()"

# Measure per-call latency on a real trivy.db.
# Usage: just bench /path/to/trivydb
bench path:
    uv run python -c "import time, statistics; from pathlib import Path; from pytrivydb import Database; \
        db = Database(Path('{{path}}')); \
        samples = []; \
        [samples.append((lambda t0: time.perf_counter()-t0)(time.perf_counter())) \
            for _ in range(100) \
            if db.find_advisories('CVE-2024-XXXX', 'glibc', package_type='rpm') is not None]; \
        samples.sort(); \
        print(f'p50={samples[50]*1000:.2f}ms p95={samples[94]*1000:.2f}ms p99={samples[98]*1000:.2f}ms')"

# Run all anti-criteria grep tests.
anti-criteria:
    uv run pytest pytrivydb/tests/test_anti_criteria.py -v
