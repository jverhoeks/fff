# fff: build, test and run. `make help` lists the targets.

BIN    := target/release/fff
PREFIX ?= $(HOME)/.cargo
ARGS   ?=

.DEFAULT_GOAL := build
.PHONY: help build test lint install uninstall run scan stats treemap serve mcp-test skill clean

help: ## list targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  make %-10s %s\n", $$1, $$2}'
	@echo "  e.g. make run ARGS='find invoice'   make scan ARGS=~/src   FFF_HOME=/tmp/ff make scan"

build: ## release build -> target/release/fff
	cargo build --release

test: ## unit tests (the git tests need the git binary)
	cargo test --release

lint: ## clippy, warnings are errors
	cargo clippy --release -- -D warnings

install: ## install fff into $(PREFIX)/bin (default ~/.cargo/bin)
	cargo install --path . --root $(PREFIX)

uninstall: ## remove the installed binary (the index in ~/.local/share/fff stays)
	cargo uninstall fff --root $(PREFIX)

run: build ## run any command: make run ARGS='find budget 2026'
	$(BIN) $(ARGS)

scan: build ## index $HOME (or ARGS='~/src ~/Downloads'), ~1.5-5 min
	$(BIN) scan $(ARGS)

stats: build ## what is indexed, and when
	$(BIN) stats

treemap: build ## open the treemap (ARGS='-u ~/src' for one subtree)
	$(BIN) treemap $(ARGS)

serve: build ## treemap with Reveal / Open / Move to Trash
	$(BIN) treemap --serve $(ARGS)

mcp-test: build ## smoke-test the MCP server without a client
	@printf '%s\n' \
	  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}' \
	  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"find","arguments":{"terms":["readme"],"limit":3}}}' \
	  | $(BIN) mcp

skill: build ## install the agent skill into ~/.claude/skills/fff
	$(BIN) skill --install

clean: ## remove build output (not the index)
	cargo clean
