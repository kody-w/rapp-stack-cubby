PYTHON ?= python3.11

.PHONY: check test verify census refresh-census audit graph context pages-build pages-check command-manifest

check:
	PYTHON="$(PYTHON)" ./scripts/check.sh

test:
	PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src "$(PYTHON)" -m unittest discover -s tests -t . -v

verify:
	PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src "$(PYTHON)" -m rapp_stack_cubby verify

census:
	PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src "$(PYTHON)" -m rapp_stack_cubby census

refresh-census:
	CENSUS_CUTOFF="$(CENSUS_CUTOFF)" PYTHON="$(PYTHON)" ./scripts/refresh-census.sh

audit:
	PYTHON="$(PYTHON)" ./scripts/audit-build.sh

graph:
	PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src "$(PYTHON)" -m rapp_stack_cubby.graph --root .

context:
	PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src "$(PYTHON)" -m rapp_stack_cubby context

pages-build:
	PYTHON="$(PYTHON)" ./scripts/pages-build.sh

pages-check:
	PYTHON="$(PYTHON)" ./scripts/pages-check.sh

command-manifest:
	PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src "$(PYTHON)" -m rapp_stack_cubby command-manifest --root .
