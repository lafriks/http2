.PHONY: test race fmt lint

test:
	go test ./...

race:
	go test -race ./...

fmt:
	goimports -w .
	gofmt -w -s .

lint:
	golangci-lint run
