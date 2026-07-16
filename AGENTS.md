# AGENTS.md

Canonical guide for the `rootisnaked` repository, shared across all AI agents
(Claude Code, Cursor, OpenCode, etc.). It is the **single source of truth** for what the
project is, how it's built, what it covers, and what it still needs to be production-ready.

---

## 1. What rootisnaked is

A C + eBPF (libbpf, CO-RE) PoC to **detect Linux privilege escalation**. Core idea: hook
the kernel `commit_creds` function, which is invoked whenever a process updates its
credentials, and alert when a process transitions to `euid == 0` (root) or changes its
capabilities while being root.

It is explicitly an **educational eBPF introduction** (as the README states) and **not** a
complete detection tool. This document assumes that starting point and describes what it
would take to move it toward something "professional".

### Architecture

```
src/kernel/rootisnaked.bpf.c   BPF programs: fentry/commit_creds + chmod/fchmod/fchmodat tracepoints
src/main.c                     Loads/attaches programs, polls the ring buffer
src/handle_events.c            Ring buffer callbacks: format log + build alert JSON
src/utils.c                    /proc lookups (exe, cmdline), capability decode, hostname
src/alerting.c                 POST to Alertmanager via libcurl
src/log.c                      Vendored logging library (rxi/log.c)
include/common.h               Event structs shared between kernel<->user space
include/vmlinux.h              BTF dump (COMMITTED — this is a problem, see §5)
```

Flow: BPF detects transition → `bpf_ringbuf` → `ring_buffer__poll` in `main.c` →
`handle_event()` dispatches by **event size** → log + (optional) HTTP alert.

### Build / run

```bash
make                                   # builds BPF (.bpf.o) + user-space binary
DEBUG=false ALERTS=true sudo -E ./bin/rootisnaked
make format   # clang-format
make lint     # clang-tidy
```

The binary looks for `build/rootisnaked.bpf.o`, falling back to
`/usr/local/share/rootisnaked/`. Requires root (`geteuid() == 0`). Config is currently via
the `DEBUG` and `ALERTS` env vars.

### Developing on macOS (Lima + Zed)

eBPF is **Linux-only** — it cannot build or run natively on macOS (`libbpf` doesn't exist
there and the `.bpf.o` needs the Linux kernel's BTF). Develop in a lightweight Linux VM:

```bash
limactl start --name=rootisnaked ./ubuntu.yml   # first boot: downloads image + provisions toolchain
limactl shell rootisnaked                        # shell inside the VM
# inside: cd to the repo (mounted at the SAME path) and `make`
```

`ubuntu.yml` is a Lima 2.x template (Ubuntu 24.04 LTS, `vmType: vz` + virtiofs) that
provisions the full toolchain (clang, libbpf-dev, bpftool, clang-format/tidy…). The repo is
virtiofs-mounted at the **same absolute path** inside the guest.

**Zed integration (SSH remote):** Zed's remote projects work over SSH, so clangd, build and
run all execute inside Linux.
1. Expose the VM's SSH host: add `Include ~/.lima/rootisnaked/ssh.config` to `~/.ssh/config`
   (Lima writes a `lima-rootisnaked` host alias there).
2. In Zed: open the remote project on host `lima-rootisnaked` at the repo path (same as on
   the host), or `zed ssh://lima-rootisnaked/<repo-path>`.

Editing on macOS directly is fine too, but formatting/linting/build require the VM (the
`Makefile` uses `nproc` and `pkg-config libbpf`, both Linux-only).

---

## 2. Which privilege escalations it covers

| Vector | Covered | How |
|---|---|---|
| `setuid`/`su`/`sudo` → root (euid 0) | ✅ | `fentry/commit_creds`, `new_euid==0 && old_euid!=0` |
| SUID binaries calling `setresuid(0,...)` | ✅ | same (they go through `commit_creds`) |
| Kernel exploits calling `commit_creds()` with root creds | ✅ | same |
| Capability change **while already root** | ✅ (partial) | `new_caps != old_caps && new_euid==0` |
| `chmod`/`fchmodat` on files (post-exploitation signal) | ⚠️ noisy | tracepoints, no filter or dedup |

The `commit_creds` detection is a solid baseline: it covers the "canonical" path by which
most legitimate escalations and many exploits obtain root.

## 3. What it does NOT cover (detection gaps)

Ordered from most to least relevant:

1. **Exploits overwriting `task->cred` directly.** Many real kernel LPEs never call
   `commit_creds`: they gain an arbitrary write and clobber the `cred` struct (or patch
   `uid`/`caps` in-place). Since the hook is never invoked, **they are invisible**.
   Mitigation: periodically sample process creds, or hook additional points.
2. **Capability escalation WITHOUT uid 0.** The code requires `new_euid==0` before looking
   at caps. A process gaining `CAP_SYS_ADMIN`/`CAP_BPF`/`CAP_DAC_READ_SEARCH` via *file
   capabilities* or *ambient caps* while keeping a non-zero uid is a real escalation and is
   **missed**. Dangerous caps should be alerted regardless of uid.
3. **User namespaces / rootless.** `CLONE_NEWUSER` grants namespaced "root" (uid 0 mapped).
   There's no namespace context (`user_ns`, `pid_ns`), so real root can't be told apart
   from namespaced root, and container escapes aren't detected.
4. **Group-based escalation (`setgid`/`setresgid`, gid 0 / privileged groups).** Only UIDs
   (euid) are inspected. No gid/egid nor membership in groups like `docker`, `disk`, `sudo`.
5. **Persistence / post-exploitation via file writes:** modifying `/etc/passwd`,
   `/etc/shadow`, `/etc/sudoers(.d)`, `authorized_keys`, cron, systemd units. Only `chmod`
   is traced (no `chown`, no `write`/`openat` to sensitive paths).
6. **`fchmodat2`** (new syscall, kernel ≥6.6) is not hooked; chmod monitoring can be
   evaded by using it.
7. **No process/exec context.** No `execve` nor ancestry (parent/child), which is key to
   telling a legitimate `sudo` apart from an unexpected shell obtaining root.
8. **Other classic vectors:** kernel module loading, `ptrace` injection, `io_uring` abuse,
   mounts, `CAP_NET_ADMIN`+scripts, etc.

## 4. Detected bugs and quality issues

Prioritize these when working in the repo. **Items marked 🔴 are correctness/security.**

### 🔴 4.1 — Inverted alert logic (`handle_events.c`)
In `handle_commit_creds_event` and `handle_file_perm_event`:
```c
if (!ALERTS_ENABLED) {   // <-- inverted
    ... send_alert(...) ...
}
```
`init_alerts_enabled_flag()` sets `ALERTS_ENABLED = true` when `ALERTS=true`. With the
negated condition, **alerts are only sent when `ALERTS=false`**, the opposite of what the
README documents (`ALERTS=true` to enable them). It should be `if (ALERTS_ENABLED)`. Also,
in `handle_file_perm_event` `send_alert` is never even called (the JSON is only built and
logged) — the file_perm alert is unimplemented.

### 🔴 4.2 — JSON injection in the alert payload
`cmdline`, `executable_path`, and `filename` are interpolated raw with `snprintf` into the
JSON. These values are **attacker-controlled** (their own `argv`, binary name, path). A `"`
or `\` breaks the JSON; worse, it allows injecting arbitrary fields into the Alertmanager
alert (spoof `severity`, `alertname`, etc.). Strings must be **escaped** or the JSON built
with a library (e.g. `json-c`/`jansson`).

### 🔴 4.3 — Uninitialized link pointers in `main.c` cleanup
`commit_creds_link`, `file_permission_*_link` are declared uninitialized. If a
`goto cleanup` jumps before they're assigned (e.g. `bpf_object__load` fails), the `cleanup`
block runs `if (commit_creds_link) bpf_link__destroy(...)` on garbage memory → UB / crash.
Initialize all to `NULL`. Also, `file_permission_fchmod_link` and
`file_permission_fchmodat_link` are **never destroyed** in cleanup (resource leak).

### 4.4 — Dead work and confusing memory ownership
In `handle_commit_creds_event`, `old_caps_str`/`new_caps_str` are `malloc`'d and freed but
**never used** (neither in log nor JSON). `GetExecutablePath`/`GetCommandLine` return
**`static` buffers**, yet the code does `if (!executable_path) executable_path = strdup(...)`,
mixing semantics: if that branch ran, it would leak (no `free`). Since they return static
buffers, they are also **non-reentrant** (would break under multithreading). Unify to a
single ownership model (return a caller-freed buffer, or pass a buffer by parameter).

### 4.5 — Events dispatched by size, not type
`handle_event` does `switch (size)` instead of using the `event_type` field that already
exists in both structs. This is fragile: if two events share a size, they're mis-dispatched.
Use `event_type` (read the common leading `u32`).

### 4.6 — `send_alert` blocks the event loop
`send_alert` does a **synchronous `curl_easy_perform` with a 10s timeout inside the ring
buffer callback**. If Alertmanager is slow or down, the poll blocks up to 10s per event,
events pile up, and the ring buffer (16MB) can fill and **drop detections**. It should be
async (queue + worker thread) or aggressive-timeout fire-and-forget.

### 4.7 — TLS hardcoded off
`alerting.c` sets `CURLOPT_SSL_VERIFYPEER=0` and `CURLOPT_SSL_VERIFYHOST=0`. Acceptable for
`http://localhost`, but if the URL ever becomes remote/HTTPS, all transport guarantees are
void. Gate it on the scheme or make it configurable.

### 4.8 — Weak whitelist, applied only to alerts
`commit_creds_whitelist` includes `/usr/bin/sudo`, `/usr/bin/pkexec`… → **sudo/pkexec
escalations (the most common and most abused vectors, e.g. the pkexec/PwnKit CVE) are
silenced** in alerts (though still logged). Also, the comparison is by exact path read from
`/proc/<tgid>/exe` **after** the event: there's a TOCTOU (the process may have re-exec'd)
and an attacker can name their binary `/usr/bin/sudo`. The whitelist should rely on more
signals (ancestry, signature) and be applied consistently.

### 🔴 4.10 — Fatal on arm64: `sys_enter_chmod` tracepoint doesn't exist
Verified by running in the Lima VM (aarch64, kernel 6.8): **arm64 has no `chmod` syscall**
(glibc `chmod` wraps `fchmodat`), so the `syscalls/sys_enter_chmod` tracepoint is absent —
only `fchmod`, `fchmodat` and `fchmodat2` exist. `main.c` treats an attach failure as fatal
(`goto cleanup`), so **the whole tool dies on startup on arm64** even though `commit_creds`
(the actual privesc detector) attached fine:
```
libbpf: failed to determine tracepoint 'syscalls/sys_enter_chmod' perf event ID: No such file or directory
Failed to attach BPF program to tracepoint
```
Fixes: (a) make optional-tracepoint attach **non-fatal** (warn + continue), and (b) hook
`fchmodat2` (present on ≥6.6) — see §3.6. This also confirms the §3.6 gap is exploitable.

### 4.9 — Others
- **Inherent TOCTOU:** `GetExecutablePath/CommandLine` read `/proc/<tgid>` in user space
  after the event; the process may have exited or changed (reused PID). Capturing
  `comm`/exe on the BPF side too narrows the window.
- **`file_perm` has no filter or dedup:** every `chmod` by any user generates an event →
  huge noise. No filtering by sensitive paths or by uid.
- `bpf_get_current_pid_tgid()` stored as `pid` takes the TID, not the TGID (minor).
- The signal handler uses `log_warn` (printf), not async-signal-safe. Use `write()` or just
  set the flag.
- The endianness fallback in `read_caps` assumes little-endian when recombining hi/lo.

---

## 5. Improvements to make it "production-grade"

Suggested roadmap, grouped.

### Detection (close the §3 gaps)
- Alert on dangerous caps **regardless of uid** (drop the `new_euid==0` from that branch).
- Add **namespace** context (user_ns/pid_ns id) to the event to distinguish real root.
- Monitor **gid/egid** in addition to uid.
- Add an **`execve`** hook (`tracepoint/sched/sched_process_exec` or LSM) for ancestry.
- Hook **`fchmodat2`**; and extend to `chown`/writes to sensitive paths
  (`/etc/passwd`, `/etc/shadow`, `/etc/sudoers.d/*`, `authorized_keys`).
- Consider **BPF LSM** (`lsm/bprm_creds_from_file`, `lsm/task_fix_setuid`) for hooks that
  are more robust and harder to evade than fentry.
- Periodically sample creds to catch changes that don't go through `commit_creds`.

### Engineering / robustness
- **Embedded BPF skeleton** (`bpftool gen skeleton`) instead of loading `.bpf.o` from the
  filesystem: removes the path dependency and makes the binary self-contained.
- **Don't commit `vmlinux.h`**: generate it at build time or rely on system BTF
  (`/sys/kernel/btf/vmlinux`) via CO-RE. The committed file ties you to one kernel version.
- **Real config:** CLI flags (`getopt`) + config file (Alertmanager URL, whitelist, dedup
  window, verbosity). Today everything is hardcoded, including the URL.
- **Async alerting** with retries/backoff and a queue (see 4.6); consider backends beyond
  Alertmanager (structured syslog/journald, JSON to stdout for SIEM).
- **Structured output** (JSON logs) optional for SIEM/Loki ingestion.
- **JSON escaping** (4.2) and validation of all user-space inputs.
- **Robust error handling** on load/attach with actionable messages.

### Quality / process
- **Re-enable CI** (`.github/workflows/build.yml` and `release.yml` are 100% commented out).
  Matrix build amd64/arm64, `clang-tidy`, and a BPF load test.
- **Tests** (`tests/.keep` is empty): at least a smoke test that loads the BPF object and
  fires a synthetic event (namespace + `unshare`/`setuid` in a test binary).
- **Harden the systemd service:** today it runs as root with no sandboxing. Add
  `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, minimal `CapabilityBoundingSet`
  (`CAP_BPF`/`CAP_PERFMON`/`CAP_SYS_ADMIN` depending on kernel) instead of full root.
- Packaging (.deb/.rpm) and versioning of the event structs (`version` field).

---

## 6. Repo conventions

- **Formatting:** `clang-format` (`.clang-format`), `clang-tidy` (`.clang-tidy`). Run
  `make format` before committing (there's a `.pre-commit-config.yaml`).
- **Commits:** Conventional Commits (`cog.toml` / cocogitto), kept **short and terse**:
  `feat:`, `fix:`, `docs:`, `refactor:`… One concise line; no fluff.
- **License:** dual GPL3 + MIT. The BPF program declares `"Dual BSD/GPL"`.
- **C style:** a mix of `snake_case` (mostly) and `PascalCase` (`GetExecutablePath`,
  `GetCommandLine`, `GetHostname`) inherited from the Go version; worth unifying to snake_case.
- When adding a new event: define the struct in `include/common.h`, emit it in the `.bpf.c`,
  and add its handler in `handle_events.c`, dispatching by `event_type` (not by size).
