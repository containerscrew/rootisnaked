SHELL:=/bin/sh
.PHONY: all

app_name="rootisnaked"

help: ## this help
	@awk 'BEGIN {FS = ":.*?## ";  printf "Usage:\n  make \033[36m<target> \033[0m\n\nTargets:\n"} /^[a-zA-Z0-9_-]+:.*?## / {gsub("\\\\n",sprintf("\n%22c",""), $$2);printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

update-deps: ## Update dependencies
	go get -u ;\
	go mod tidy

mtoc: ## Create table of contents with mtoc
	mtoc

# pre-commit-install: ## Install pre-commit
# 	pre-commit install

# pre-commit-uninstall: ## Uninstall pre-commit
# 	pre-commit uninstall

# run-pre-commit: ## Run pre-commit locally
# 	pre-commit run -a

# generate-changelog: ## Generate changelog
# 	git cliff -o CHANGELOG.md

go-generate: ## Run go generate
	go generate ./...

run: go-generate update-deps ## Run the application
	CGO_ENABLED=0 GOARCH=amd64 sudo go run main.go

build-run: go-generate update-deps ## Run the application
	CGO_ENABLED=0 GOARCH=amd64 go build && sudo ./rootisnaked

gen-vmlinux: ## Generate vmlinux.h headers
	sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > headers/vmlinux.h

remote-sync: ## Sync this repository to remote machine using rsync.
	rsync -avzh --exclude='.git/' --exclude='target/' --exclude='.idea/' $(shell pwd)/ $(USER)@$(IP):/home/$(USER)/rootisnaked
