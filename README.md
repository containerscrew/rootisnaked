# rootisnaked

`Rootisnaked` is a simple tool to monitor owner id (uid) changes in Linux processes. It can be used, for example, to detect possible Linux privilege escalation.

> The ebpf program (kernel space) its written in C and compiled using [cilium-ebpf library](https://github.com/cilium/ebpf). The code in user space is entirely written in Go.

# Running `rootisnaked`

## Install system dependencies

> Tested in `debian12` with kernel version `6.1.0-30-amd64`

```bash
sudo apt install -y linux-headers-$(uname -r) gcc git make clang llvm libbpf-dev libbpf-tools bpftool bpftrace
```

* Install Golang: https://go.dev/doc/install (do not install Golang from apt repository if using debian, sinde it not has the latest versions)

This page can be helpful https://ebpf-go.dev/guides/getting-started/#ebpf-c-program

## Compile and run

```bash
make build-run #if using arm64, change GOARCH in Makefile
```

# LICENSE

[`license`](./LICENSE)