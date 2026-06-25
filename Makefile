.PHONY: build install run clean

build:
	cargo build --release

install: build
	mkdir -p ~/.local/bin
	install -m 755 ../target/release/cce-authenticator ~/.local/bin/cce-authenticator

run:
	cargo run

clean:
	cargo clean
