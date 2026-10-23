# Resource Shell (resh) – Message Queue Handle Documentation

## 1. Overview

Resource Shell (resh) is a command-line tool that runs operations on resources named by URLs.

The `mq://` handle is a local, file-based FIFO queue. Each message is one file in a per-queue directory, so messages put by one `resh` command can be taken by a later one on the same host. It is meant for simple local hand-offs between scripts, not as a message broker.

```text
resh mq://<queue>.<verb> [key=value ...]
```

Verbs: `create`, `put`, `get`, `peek`, `len`, `purge`.

---

## 2. Design Notes

* `get` and `peek` print the message bytes exactly as stored, with no JSON envelope and no trailing newline added.
* `len` prints a bare number.
* `create`, `put` and `purge` print nothing on success.
* An empty queue makes `get` and `peek` exit with code 2 (resh prints `Error: empty` to stderr).
* There is no dry-run mode; `get` and `purge` delete messages immediately.

---

## 3. Command Syntax and Execution Model

### 3.1 Queue names and storage

The queue name is the URL host plus path. Any character other than letters, digits, `.`, `-` and `_` is replaced with `_`, and the name is cut to 120 characters; for example `mq://team/a` uses the directory `team_a`.

Queues are stored in the resh state directory:

```text
$XDG_STATE_HOME/resh/mq/<queue>/                (default ~/.local/state/resh/mq/<queue>/)
  01792761003306294654.msg                       one file per message, named by put time in nanoseconds
  _inflight/                                     messages being taken by get
```

If no state directory can be determined, the handle falls back to `/tmp/resh/mq/`, which is shared with other users. On Linux the state directory is always resolved, so this does not normally happen. Directories and files are created with the default umask, so other local users can usually read messages; do not queue secrets.

### 3.2 Example commands

Create a queue (optional; every verb creates the directories if needed):

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

The two `get` commands print `one` and then `two`. Order is by the nanosecond timestamp in the file name.

### 3.4 Exit codes

These codes are set by the handle (verified in the source):

| Code | Meaning                             |
| ---- | ----------------------------------- |
| 0    | Success                             |
| 1    | Filesystem error, or unknown verb   |
| 2    | Queue empty (`get`, `peek`)         |

Script example that tells "empty" apart from errors:

```bash
msg=$(resh mq://tasks.get)
case $? in
  0) echo "got: $msg" ;;
  2) echo "queue empty" ;;
  *) echo "error" >&2 ;;
esac
```

---

## 4. Verbs

| Verb     | Description                                                                 |
| -------- | --------------------------------------------------------------------------- |
| `create` | Creates the queue directory and its `_inflight` directory (idempotent)      |
| `put`    | Stores `data=<message>`, or all of stdin when `data` is absent              |
| `get`    | Moves the oldest message to `_inflight`, prints it, then deletes it         |
| `peek`   | Prints the oldest message without removing it                               |
| `len`    | Prints the number of `.msg` files in the queue directory                    |
| `purge`  | Deletes every `.msg` file in the queue and in `_inflight` (idempotent)      |

### 4.1 Message content

* `put` from stdin is binary-safe; the bytes are stored unchanged.
* `data=` stores the argument's text (quote it in the shell if it contains spaces). With `data=`, nothing is read from stdin.
* There is no size limit other than the filesystem's; `put` from stdin reads the whole input into memory first.

```bash
printf '\x00\x01\x02\xff' | resh mq://binary.put
resh mq://binary.get | od -An -tx1
```

### 4.2 timeout_ms

No mq verb reads `timeout_ms`; it is ignored if given. No verb waits: `get` on an empty queue returns at once with exit code 2.

---

## 5. Concurrency and Limitations

* `put` writes the message to a temporary file and renames it into place. **The temporary file name (`tmp-<ns>.msg`) also ends in `.msg`**, so a `get`, `peek` or `len` that runs while a `put` is still writing can see it: `len` counts it, and when it is the only file, `get` or `peek` can read a partial message. Avoid running consumers while a large message is being written, or check message integrity in your own format.
* `get` claims a message by renaming it into `_inflight`. If two `get` commands pick the same file at once, one wins and the other fails with a filesystem error (exit 1) instead of moving on to the next message.
* A message whose `get` was interrupted after the rename stays in `_inflight` and is not returned again; `purge` deletes it. There is no acknowledgement, retry or dead-letter mechanism.
* Ordering relies on the system clock. Messages put on hosts or containers with different clocks, or across a clock step, can be out of order.
* `len` and `peek` create the queue directories if they do not exist.
* The queue lives on one host. Sharing it through a network filesystem is not tested.

---

## 6. Platform Support

Linux is the only supported and tested platform.

---

## 7. Usage Guidance

* Use separate queues for separate workflows.
* Test for exit code 2 to detect an empty queue.
* Have one consumer per queue if you need each message to be processed exactly once.
* Check `_inflight` for messages left by interrupted consumers.

---

## 8. Implementation Notes

* Written in Rust using standard filesystem calls. All verbs run in the calling process; there is no background service.
