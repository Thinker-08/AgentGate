.PHONY: build run test vet fmt tidy up up-x402 down logs e2e pay clean

build:
	go build ./...

run:
	go run ./cmd/agentgate

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w internal cmd

tidy:
	go mod tidy

up:
	docker compose up -d --build

up-x402:
	AGENTGATE_VERIFIER=x402 docker compose up -d --build

down:
	docker compose down -v

logs:
	docker compose logs -f agentgate

e2e:
	./test/e2e.sh

pay:
	cd client/agentpay && go run . $(PAY_ARGS)

clean:
	docker compose down -v || true
	go clean
