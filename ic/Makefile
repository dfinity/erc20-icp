MINTER_WASM=target/wasm32-unknown-unknown/release/ckicp-minter.wasm
MINTER_SRCS=$(wildcard rs/minter/src/*.rs)

rs/minter/minter.did: $(MINTER_WASM)
	candid-extractor $< > $@

$(MINTER_WASM): $(MINTER_SRCS)
	cargo build --target wasm32-unknown-unknown --release -p ckicp-minter
