# Handle and Verb Help (`resh <handle> --help`)

> **Status:** approved format, populated for all 28 handles and every
> registered verb.

Resource Shell answers two help requests without running any resource
operation:

```text
resh <handle> --help          handle-level help
resh <handle> <verb> --help   verb-level help
```

`-h` and `help` work in place of `--help`, and the word `help` can also come
first:

```bash
resh svc --help          # same as: resh svc -h, resh svc help, resh help svc
resh svc status --help   # same as: resh svc status -h, resh svc status help,
                         #          resh help svc status
```

`resh help` on its own, like `resh --help`, prints the global help.

Help is printed on stdout with exit code 0. A request that names an unknown
handle or verb is an error: a message on stderr and exit code 2. It suggests
the closest name when the input looks like a typo, and lists the handle's
verbs for an unknown verb:

```text
$ resh file reed --help
Error: unknown verb 'reed' for handle 'file'. Did you mean 'read'?
Available verbs: read, exists, stat, ...
Run `resh file --help` for details.
```

A bare handle name used as a stage (`resh file`, `resh file read`) is also
refused with exit code 2 and a hint showing the stage syntax
(`file://<target>.<verb>`) and the help command.

## Handle-level format

```text
Handle: <handle>

Description:
  <two or three sentences, wrapped at 80 columns>

Available Verbs:
  <verb>   <one-sentence definition>
  ...

Usage:
  <handle usage syntax>

For help with a specific verb:
  resh <handle> <verb> --help
```

## Verb-level format

```text
Handle: <handle>
Verb: <verb>
Definition: <one sentence, continuation lines indented two spaces>

Usage:
  <exact stage syntax>

Example:
  <valid example command>

Example Output:
  <sample output of the example, indented two spaces>

  <optional note on how the sample was produced>
```

`Example Output:` is optional and shown only when `VerbDetail.example_output`
is set.

The output is plain ASCII with no ANSI escape codes, and lines are at most 80
columns.

## How it works

- **The verb list comes from the handle itself.** `Handle::verbs()` decides
  which verbs appear. The help aliases `help`, `--help` and `-h` are left out.
  If metadata describes a verb the handle doesn't register, that verb isn't
  shown.
- **The metadata lives in the handle.** A handle opts in by overriding
  `Handle::help()` and returning a `static HandleHelp` (see
  `src/core/help.rs`). Verb-level help is shown only for verbs whose
  `VerbHelp.detail` is set, because that field holds the usage line and the
  example.
- **Help doesn't touch the resource.** `Registry::instantiate()` builds the
  handle from the placeholder URL `<scheme>://resh-help-probe` so its metadata
  can be read. `call()` is never invoked. If a constructor rejects that URL,
  the handle's `register()` supplies a valid one with `Registry::set_probe_url`
  (cache, db, log, proc and secret do this). The constructor must not do any
  I/O for its probe URL.

## Conventions for verb help

- **Usage** lists required arguments as `key=<value>` and optional ones as
  `[key=<value>]`, written as trailing `key=value` words. Long usage continues
  on lines that start with two spaces.
- **Example** is one shell-safe line whose stage parses to the documented
  handle and verb.
- **Example Output** for JSON is the `--json-pretty` form (keys sorted, two-space
  indent), followed by a one-line note that says so and names the case shown
  when output varies by backend. It is omitted for streaming verbs and for
  verbs that print nothing on success.
- A verb the stage parser cannot reach (currently only `cert csr.sign`) says
  so in its definition, and its example points to the working alternative.
  It is listed in `UNREACHABLE` in `tests/help_coverage.rs`.

## Adding help for a handle

1. In the handle's module, define a `static <NAME>_HELP: HandleHelp` with a
   `VerbHelp` entry for each registered verb.
2. Override `fn help(&self) -> Option<&'static HandleHelp>` in its `Handle`
   impl.
3. Run `HELP_COVERAGE_ONLY=<scheme> cargo test --test help_coverage`. It
   fails until every registered verb is documented and the output follows
   the rules above.
