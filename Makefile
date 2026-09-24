.PHONY: all format lint check test black ruff checkblack checkruff mypy dev serve install build run static precommit precommit-install

# 8111, not 8000: this is meant to run alongside a full lnurl_server
# instance on the same host, which already claims 8000
IMAGE_NAME = lnurl-mint
CONTAINER_NAME = lnurl-mint
PORT = 8111

all: format lint
format: black ruff
lint: checkruff mypy
check: checkblack checkruff

black:
	uv run black lnurl_mint tests

ruff:
	uv run ruff check lnurl_mint tests --fix

checkruff:
	uv run ruff check lnurl_mint tests

checkblack:
	uv run black --check lnurl_mint tests

mypy:
	uv run mypy lnurl_mint

test: static
	uv run pytest

install:
	uv sync

precommit-install:
	uv run pre-commit install

precommit:
	uv run pre-commit run --all-files

# the /docs assets are gitignored and fetched at build time (pinned version
# + sha256, see scripts/fetch_swagger_ui.py); a no-op once they're present
static:
	uv run python scripts/fetch_swagger_ui.py

dev: static
	FORWARDED_ALLOW_IPS=* \
	uv run uvicorn lnurl_mint.server:app --reload --host 0.0.0.0 --port $(PORT)

serve: static
	FORWARDED_ALLOW_IPS=* \
	uv run uvicorn lnurl_mint.server:app --host 0.0.0.0 --port $(PORT)

build:
	docker build --pull -t $(IMAGE_NAME) .

ENV_FILE := $(wildcard .env)

run:
	@echo "Restarting container..."
	docker stop $(CONTAINER_NAME) 2>/dev/null || true
	docker rm $(CONTAINER_NAME) 2>/dev/null || true
	mkdir -p data
	touch data/mint.db
	# the whole data/ dir is bind-mounted, not just mint.db - sqlite needs
	# to create its rollback-journal/WAL companion files in the *same
	# directory* as the db file, and --user (below) only guarantees this
	# host dir is writable by that UID, not /app itself (owned by the
	# image's own baked-in non-root user, whichever UID that happens to
	# be - see Dockerfile). DATABASE_PATH tells the app to look for its db
	# there instead of the image's default ./mint.db.
	docker run --restart always -d --name $(CONTAINER_NAME) \
		--network host \
		--user $(shell id -u):$(shell id -g) \
		-e PORT=$(PORT) \
		-e DATABASE_PATH=/app/data/mint.db \
		$(if $(ENV_FILE),--env-file $(ENV_FILE),) \
		-v $(PWD)/data:/app/data \
		$(IMAGE_NAME)
	@echo "Container $(CONTAINER_NAME) is running at http://localhost:$(PORT)"
