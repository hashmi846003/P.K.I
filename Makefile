.PHONY: all clean run

all: run

run:
    go run cmd/main.go

clean:
    rm -f cert.pem key.pem
