.PHONY: install test run docker-up docker-down

install:
	python -m pip install -r requirements-dev.txt

test:
	pytest -q

run:
	uvicorn app.main:app --reload --port 7777

docker-up:
	docker compose up --build

docker-down:
	docker compose down
