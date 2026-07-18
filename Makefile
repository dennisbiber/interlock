# Convenience wrappers around the canonical commands. No dependency on make;
# everything here is runnable by hand.

.PHONY: test test-py test-js test-e2e lint deps all

test: test-py test-js       ## unit tests, both languages

test-py:                    ## Python PDP + unit tests
	python -m unittest discover -v

test-js:                    ## JS PEP adapter tests (needs Node 20+)
	cd interlock/adapters/openclaw && node --test

test-e2e:                   ## cross-language e2e over a real unix socket
	python -m unittest tests.test_e2e_openclaw -v

lint:                       ## ruff + mypy (needs: pip install -e ".[dev]")
	ruff check .
	ruff format --check .
	mypy interlock

deps:                       ## enforce zero runtime dependencies
	python scripts/check_no_runtime_deps.py

all: deps test test-e2e lint
