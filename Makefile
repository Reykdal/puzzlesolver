# Builds the Rust puzzlesolver and places the binary at ./puzzlesolver
# so it can be run as: ./puzzlesolver <IP> <port1> <port2> <port3> <port4>

all: puzzlesolver

puzzlesolver:
	cargo build --release
	cp target/release/puzzlesolver ./puzzlesolver

clean:
	cargo clean
	rm -f puzzlesolver

.PHONY: all clean
