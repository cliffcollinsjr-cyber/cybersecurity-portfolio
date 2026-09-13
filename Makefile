.PHONY: help test-python build-go lint check-structure summary

help:
	@echo "Cybersecurity Portfolio — Cliff Collins Jr"
	@echo ""
	@echo "  make test-python     Run Python alert-enrichment unit tests"
	@echo "  make build-go        Build Go notifier CLI"
	@echo "  make lint            Run lightweight lint/structure checks"
	@echo "  make check-structure Verify required domain folders exist"
	@echo "  make summary         Print BUILD_SUMMARY.md head"

check-structure:
	@bash scripts/check_structure.sh

test-python: check-structure
	@bash scripts/test_python.sh

build-go: check-structure
	@bash scripts/build_go.sh

lint: check-structure
	@bash scripts/lint.sh

summary:
	@head -n 80 BUILD_SUMMARY.md
