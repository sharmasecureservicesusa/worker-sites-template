.PHONY: test run install prod

install:
	python3 -m venv .venv
	.venv/bin/pip install -r backend/requirements-dev.txt

test:
	.venv/bin/pytest

run:
	chmod +x scripts/dev.sh
	./scripts/dev.sh

prod:
	chmod +x scripts/prod.sh
	./scripts/prod.sh
