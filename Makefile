.PHONY: tidy vet test build up down logs migrate seed

tidy:
	go mod tidy

vet:
	go vet ./...

test:
	go test -race -count=1 ./...

build:
	go build ./...

up:
	docker compose up --build

down:
	docker compose down -v

migrate:
	go run ./cmd/migrate up

seed:
	go run ./cmd/migrate seed
