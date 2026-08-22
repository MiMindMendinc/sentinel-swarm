.PHONY: install test audit lint run lock docker-up docker-down

install:
	python -m pip install --upgrade pip==26.2.1
	python -m pip install --require-hashes -r requirements-dev.lock

test:
	coverage erase
	coverage run -m pytest -q
	coverage report -m

audit:
	pip-audit -r requirements.lock
	pip-audit -r requirements-dev.lock

lint:
	ruff check app tests scripts
	bandit -q -r app scripts

run:
	uvicorn app.main:app --reload --host 127.0.0.1 --port 7777 --no-server-header --no-proxy-headers --ws-max-size 4096

lock:
	python -m pip install pip-tools==7.6.1
	pip-compile --generate-hashes --strip-extras --output-file=requirements.lock requirements.txt
	pip-compile --allow-unsafe --generate-hashes --strip-extras --output-file=requirements-dev.lock requirements-dev.txt

docker-up:
	docker compose up --build

docker-down:
	docker compose down
