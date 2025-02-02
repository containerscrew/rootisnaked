<p align="center" >
    <img src="logo.png" alt="logo" width="250"/>
<h3 align="center">rootisnaked</h3>
<p align="center">Simple root privilege escalation detection using eBPF</p>
</p>

<p align="center" >
    <img alt="Go report card" src="https://goreportcard.com/badge/github.com/containerscrew/rootisnaked">
    <img alt="GitHub code size in bytes" src="https://img.shields.io/github/languages/code-size/containerscrew/rootisnaked">
    <img alt="GitHub go.mod Go version" src="https://img.shields.io/github/go-mod/go-version/containerscrew/rootisnaked">
</p>

# rootisnaked

<!-- START OF TOC !DO NOT EDIT THIS CONTENT MANUALLY-->
**Table of Contents**  *generated with [mtoc](https://github.com/containerscrew/mtoc)*
- [rootisnaked](#rootisnaked)
- [Running `rootisnaked`](#running-rootisnaked)
  - [Install system dependencies](#install-system-dependencies)
  - [Compile and run](#compile-and-run)
  - [Using docker](#using-docker)
- [Simulate](#simulate)
- [What's next?](#whats-next)
- [License](#license)
<!-- END OF TOC -->

![example](example.png)

```markdown
[2025-02-01 19:16:16] INFO uid changed or capabilities changed for process new_caps=[CAP_NET_RAW CAP_SYS_MODULE ......] pid=206493 exe_path=/usr/bin/sudo cmd_line=sudo su -  user=dcr old_uid=1000 new_uid=0 old_caps=[CAP_NET_RAW CAP_SYS_MODULE .....]
```

`Rootisnaked` is a simple [eBPF](https://ebpf.io/) program designed to monitor changes in user credentials (specifically, the UID) on a Linux system. It hooks into the `commit_creds` kernel function, which is called when a process's credentials are updated. The program detects when a process's UID changes to 0 (root) and logs this event to a ring buffer for further analysis in user space.
It can be used, for example, to detect possible Linux privilege escalation.

> The eBPF program (kernel space) is written in C and compiled using [cilium-ebpf library](https://github.com/cilium/ebpf). The code in user space is entirely written in Go.

> [!CAUTION]
> This is an introduction of eBPF. This tool probably does not cover all possible attack vectors for escalating privileges.

To extend this tool, you probably need to detect:

- Gaining capabilities (CAP_SYS_ADMIN...): Right now it shows when the capabilities of a process change
- Changing group IDS (gid): no timplemented
- Manipulating file permissions (`chmod`, `setuid`...): not implemented
- Track parent process ID (ppid) and process hierarchy: not implemented
- Others

# Running `rootisnaked`

## Install system dependencies

> Tested on `debian12` with kernel version `6.1.0-30-amd64`

* Dependencies:

```bash
sudo apt install -y linux-headers-$(uname -r) gcc git make clang llvm libbpf-dev libbpf-tools bpftool bpftrace
```

* Install Golang: https://go.dev/doc/install (Do not install Golang from the APT repository if using Debian, since it does not have the latest versions)

*This page can be helpful https://ebpf-go.dev/guides/getting-started/#ebpf-c-program*

## Compile and run

```bash
make build-run GOARCH=amd64 # if using arm, GOARCH=arm64
```

## Using docker

```bash
docker build -t rootisnaked/rootisnaked:latest .
```

**eBPF code needs to be run under a privileged user.**

```bash
docker run -it --rm --name rootisnaked --privileged rootisnaked/rootisnaked:latest
```

# Simulate

```bash
sudo su -
sudo capsh --caps="cap_sys_admin+eip" -- -c "/path/to/some_process"
```

# What's next?

- Implement more features
- Log too much verbose when capabilities changes
- Send notifications to systray (notify-send)
- Implement testing
- Others

# License

**`rootisnaked`** is distributed under the terms of the [AGPL3](./LICENSE) license.
