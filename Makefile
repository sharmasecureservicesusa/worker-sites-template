.PHONY: test run install

install:
	python3 -m venv .venv
	.venv/bin/pip install -r backend/requirements-dev.txt

test:
	.venv/bin/pytest

run:
	chmod +x scripts/dev.sh
	./scripts/dev.sh
