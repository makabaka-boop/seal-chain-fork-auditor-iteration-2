.PHONY: build test cover vet fmt run docker-build docker-up docker-down tidy

ADDR ?= :8080

build:
	go build -trimpath -o bin/sealaudit ./cmd/sealaudit

test:
	go test -race ./...

cover:
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

vet:
	go vet ./...

fmt:
	gofmt -w .

run:
	go run ./cmd/sealaudit -addr=$(ADDR)

docker-build:
	docker compose build

docker-up:
	docker compose up -d --build

docker-down:
	docker compose down --remove-orphans

tidy:
	go mod tidy
