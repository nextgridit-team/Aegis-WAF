.PHONY: build dashboard test integration container-test browser-test fmt
build: dashboard
	mkdir -p bin
	go build -trimpath -o bin/aegis-waf ./cmd/aegis-waf
dashboard:
	cd web && npm ci && npm run build
test:
	go test -race ./...
integration:
	@test -n "$(TEST_DATABASE_URL)" || (echo 'TEST_DATABASE_URL is required' && exit 1)
	go test -race -count=1 ./...
container-test:
	docker build -t aegis-waf:verification .
	python3 tests/container-smoke.py
browser-test:
	docker build -t aegis-waf:ui-verification .
	python3 tests/acme-browser.py
fmt:
	gofmt -w cmd internal
	cd web && npx --no-install prettier --write src index.html package.json tsconfig.json ../compose.yaml ../docs/*.md ../README.md
