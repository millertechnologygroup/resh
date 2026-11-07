# Resource Shell (resh) – Message Queue Handle Documentation

## 1. Overview

Resource Shell (resh) is a command-line tool that runs operations on resources named by URLs.

The `mq://` handle is a local, file-based FIFO queue. Each message is one file in a per-queue directory, so messages put by one `resh` command can be taken by a later one on the same host. Producers and consumers may run at the same time: messages come out in the order the `put` commands finished, and no two running `get` commands ever take the same message. Delivery is at-least-once: a message whose `get` was killed before it finished is delivered again (see 5). It is meant for local hand-offs between scripts, not as a message broker; there is no network backend.

```text
resh mq://<queue>.<verb> [key=value ...]
```

Verbs: `create`, `put`, `get`, `peek`, `len`, `purge`.

---

## 2. Design Notes

* `get` and `peek` print the message bytes exactly as stored, with no JSON envelope and no trailing newline added.
* `len` prints a bare number.
* `create`, `put` and `purge` print nothing on success.
* An empty queue makes `get` and `peek` fail with exit code 1 and the error code `mq.empty`.
* `get` fails at once on an empty queue; with `wait=true` it waits for a message instead (see 4.2).
* There is no dry-run mode; `dry_run=true` is refused (exit 2) before anything runs, and `dry_run=false` changes nothing.
* Every verb refuses arguments it does not take (exit 2, `mq.invalid_argument`, with a "did you mean" hint).

---

## 3. Command Syntax and Execution Model

### 3.1 Queue names and storage

The queue name is the URL host: 1 to 120 letters, digits, `.`, `-` and `_`, not starting with `.`. Names are case-sensitive (`mq://Jobs` and `mq://jobs` are different queues). A URL with anything else (a path such as `mq://team/a`, a port, a user, a query, a fragment, or percent-encoded characters) is refused with exit 2 and `mq.invalid_target`; names are never rewritten, so two different URLs never share a queue.

Queues are stored in the resh state directory:

```text
$XDG_STATE_HOME/resh/mq/<queue>/        (default ~/.local/state/resh/mq/<queue>/), mode 0700
  00000000000000000001.msg               one file per message (mode 0600), numbered in queue order
  .seq                                   queue lock and the next message number (0600)
  .tmp/                                  messages being written by put (0700)
  _inflight/                             messages being taken by get (0700), named
    <number>.<pid>.<start time>.claim    after the claiming process
```

If the state directory cannot be determined (no absolute `XDG_STATE_HOME` and no home directory), every verb fails with exit 1 and `mq.no_state_dir`; there is no fallback to a shared directory such as `/tmp`. Directories resh creates are owner-only, and existing queue directories are tightened to 0700 when a verb uses them. A symlink in place of the mq directory, a queue directory or `.seq` is refused (`mq.unsafe_path`); a symlink named like a message is not treated as one.

Queues made by earlier resh versions (whose messages are numbered by put time in nanoseconds) keep working: new messages are numbered after the existing ones.

### 3.2 Example commands

Create a queue (optional; `put` creates the directories if needed):

```bash
resh mq://tasks.create
```

Put a message from an argument or from stdin:

```bash
resh mq://tasks.put data=hello
echo "process file1.txt" | resh mq://tasks.put
```

Take, inspect and count messages:

```bash
resh mq://tasks.get
resh mq://tasks.peek
resh mq://tasks.len
```

Delete all messages:

```bash
resh mq://tasks.purge
```

### 3.3 FIFO behaviour

```bash
resh mq://demo.put data=one
resh mq://demo.put data=two
resh mq://demo.get
resh mq://demo.get
```

The two `get` commands print `one` and then `two`. Messages are numbered from a counter kept in the queue, not from the clock, so the order is the order in which `put` commands finished, even across clock changes.

### 3.4 Exit codes

| Code | Meaning                                                                 |
| ---- | ----------------------------------------------------------------------- |
| 0    | Success                                                                 |
| 1    | Failed: the queue is empty (`get`, `peek`), or a filesystem error       |
| 2    | Invalid usage (unknown verb or argument, bad value, invalid queue name); nothing was done |
| 124  | `timeout_ms` passed (see 4.2)                                           |

Errors are printed on stderr as `Error: [<code>] <message>`:

| Code                  | Exit | Meaning |
| --------------------- | ---- | ------- |
| `mq.invalid_argument` | 2    | Unknown verb or argument, `timeout_ms` on a verb that does not take it, a non-numeric `timeout_ms`, a `wait` value other than true/false (1/0, yes/no, on/off), or `dry_run=true` |
| `mq.invalid_target`   | 2    | The URL is not `mq://<queue>` with a valid queue name |
| `mq.empty`            | 1    | `get` (without `wait=true`) or `peek` found no message (a queue that does not exist is empty) |
| `mq.timeout`          | 124  | `timeout_ms` passed while waiting for the queue lock (nothing was done), while `get wait=true` waited for a message (nothing was taken), or during `purge` (the rest is still queued) |
| `mq.no_state_dir`     | 1    | The state directory cannot be determined |
| `mq.unsafe_path`      | 1    | A queue path is a symlink or not a directory |
| `mq.io_error`         | 1    | A filesystem error, failure to read stdin, or failure to write the message to stdout |

Script example that tells "empty" apart from errors:

```bash
err=$(mktemp)
if msg=$(resh mq://tasks.get 2>"$err"); then
  echo "got: $msg"
elif grep -q '^Error: \[mq\.empty\]' "$err"; then
  echo "queue empty"
else
  cat "$err" >&2
fi
rm -f "$err"
```

---

## 4. Verbs

| Verb     | Arguments                    | Description |
| -------- | ---------------------------- | ----------- |
| `create` | none                         | Creates the queue directory, `.tmp` and `_inflight` (idempotent) |
| `put`    | `[data=]` `[timeout_ms=]`    | Stores `data=<message>`, or all of stdin when `data` is absent |
| `get`    | `[wait=]` `[timeout_ms=]`    | Takes the oldest message, prints it and deletes it; `wait=true` waits for one |
| `peek`   | none                         | Prints the oldest message without removing it |
| `len`    | none                         | Prints the number of queued messages (0 for a queue that does not exist) |
| `purge`  | `[timeout_ms=]`              | Deletes every queued message and every message left in `_inflight` (idempotent) |

`len`, `peek`, `get` and `purge` do not create a queue that does not exist (`get wait=true` creates it, to watch it).

### 4.1 Message content

* `put` from stdin is binary-safe; the bytes are stored unchanged. stdin is streamed to disk, so a large message is not held in memory.
* `data=` stores the argument's text exactly (quote it in the shell if it contains spaces). With `data=`, nothing is read from stdin.
* An empty `data=` or empty stdin stores an empty message.
* There is no size limit other than the filesystem's.

```bash
printf '\x00\x01\x02\xff' | resh mq://binary.put
resh mq://binary.get | od -An -tx1
```

### 4.2 wait and timeout_ms

`get wait=true` waits for a message when the queue is empty, and takes the first one that arrives. Several waiting consumers never get the same message. It wakes as soon as the queue directory changes (inotify), and also checks every 500 ms. `wait=false` (the default) fails at once with `mq.empty`.

`put`, `get` and `purge` take `timeout_ms=<ms>`, a whole number of milliseconds; `0` means no limit. It limits the wait for the queue lock, which another `put`, `get` or `purge` holds only while it numbers, claims or deletes messages, and for `get wait=true` the whole wait for a message. When the limit passes the command exits 124 with `mq.timeout` and nothing was done (nothing was queued or taken). For `purge` it also limits the deletion: messages not yet deleted stay queued.

Defaults: no limit, except `get wait=true`, which waits at most 30000 ms unless `timeout_ms` says otherwise.

```bash
resh mq://jobs.get wait=true timeout_ms=60000
```

The time `put` spends reading stdin is not limited. `len`, `peek` and `create` never wait for the lock and refuse `timeout_ms` (exit 2).

---

## 5. Concurrency and Limitations

* `put` writes the message to a private file in `.tmp` and syncs it, then, holding the queue lock, gives it the next number and renames it into the queue. A consumer never sees a partly written message, and two producers never get the same number.
* `get` holds the queue lock while it picks the oldest message and moves it into `_inflight`, so two consumers never take the same message. The message is then printed and deleted. If it cannot be written to stdout (for example the reader closed the pipe), it is moved back to the head of the queue and `get` fails with `mq.io_error`; part of it may already have been written.
* `peek` and `len` take no lock and never wait.
* The lock is an `flock` on `.seq`; the kernel releases it if the process dies, so a killed command never leaves the queue locked. A process that is stopped (for example with Ctrl-Z) while holding the lock makes other `put`, `get` and `purge` commands wait; use `timeout_ms` to bound that wait.
* `get` moves the message it claims into `_inflight` under a name that records its PID and the process start time. If that process no longer exists (it was killed, or the PID now belongs to a different process), the next `get` moves the message back to the queue under its original number, so it is delivered next, before newer messages. `len` and `peek` do the same when the lock is free; when it is busy, `len` counts such messages and `peek` shows the queue as it is. Delivery is therefore **at-least-once**: a consumer killed after printing a message but before deleting its in-flight copy causes that message to be delivered again. Make consumers idempotent if that matters.
* Messages left in `_inflight` by earlier resh versions (`<number>.msg`, no claimer recorded) are treated as abandoned and delivered again.
* There is no acknowledgement step, retry limit or dead-letter queue.
* `purge` deletes temporary files in `.tmp` left by `put` commands whose process no longer exists.
* `purge` runs under the lock; a `get` that claimed a message just before the purge still prints it.
* The queue lives on one host. Sharing it through a network filesystem is not tested (`flock` semantics vary).

---

## 6. Platform Support

Linux is the only supported and tested platform.

---

## 7. Usage Guidance

* Use separate queues for separate workflows.
* Test for exit code 1 with `mq.empty` to detect an empty queue; exit 2 means the command itself is wrong.
* Use `get wait=true` instead of polling `get` in a loop.
* Expect a message to be delivered again after a consumer is killed (at-least-once).
* Message files are owner-only, but they are plain files on disk; use the `secret` handle for credentials.

---

## 8. Implementation Notes

* Written in Rust using standard filesystem calls, `flock(2)`, `/proc/<pid>/stat` (claimer liveness) and inotify through the `notify` crate (`get wait=true`). All verbs run in the calling process; there is no background service.
