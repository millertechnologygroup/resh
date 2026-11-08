# Resource Shell (resh) – Automation Utilities Overview

## 1. Overview

Resource Shell (resh) is a command-line tool that runs operations on resources named by URLs and prints the results as JSON.

Every operation is one stage: a handle (URL scheme), a target, a verb after the last dot, and `key=value` arguments:

```text
resh <handle>://<target>.<verb> key=value ...
resh '<handle>://<target>.<verb>(key=value,...)'      alternative form; quote it for the shell
```

This page covers the **Automation Utilities** handles:

| Handle        | Purpose | Verbs |
| ------------- | ------- | ----- |
| `backup://`   | Run restic, borg, rsync or tar to create, list, restore, verify and prune snapshots | `create`, `list`, `restore`, `verify`, `prune`, `schedule` (installs a systemd timer or crontab line through `cron://`) |
| `plugin://`   | Manage the local resh plugin store and read plugin catalogs | `install`, `update`, `rollback`, `remove`, `enable`, `disable`, `installed.list`, `available.list`, `available.search`, `available.info`, `keys.add`, `keys.list`, `keys.delete` |
| `template://` | Render, validate and test Tera templates | `render`, `validate`, `test` |

Detailed pages: [backup](backup.md), [plugin](plugin.md), [template](template.md). Built-in help: `resh <handle> --help` and `resh <handle> <verb> --help`.

---

## 2. Common Behavior

* **JSON output.** Each verb prints one JSON object on stdout. The shape is specific to each handle (and, for `plugin`, to each verb group); there is no shared envelope across handles. See each page for real field names.
* **Failure reporting.** On failure resh exits non-zero and prints `Error: <reason>` on stderr (unless the handle already wrote to stderr). Check `ok` in the JSON or the exit status.
* **Independent invocations.** Each `resh` command is a separate process. Nothing is kept between commands except what a handle writes to disk: backup repositories, the plugin store and state files (under the XDG data/state directories), and nothing at all for `template`.
* **`--json-pretty`** before the stage pretty-prints the output.
* **Platform.** Only Linux is supported and verified.

### Dry run

| Handle   | `dry_run` |
| -------- | --------- |
| backup   | Honored by `create`, `restore` (lists what would be restored), `prune` and `schedule` (cron add's dry run). `list` and `verify` refuse `dry_run` in any spelling (exit 2, `backup.invalid_argument`). An unrecognised value (such as `dry_run=maybe`) is refused |
| plugin   | Honored by `install`, `update`, `rollback`, `remove`, `enable`, `disable`. Values other than true/false/1/0/yes/no/on/off are errors |
| template | Not read (no verb writes anything) |

### timeout_ms

| Handle   | Enforced | Accepted but not used | Notes |
| -------- | -------- | --------------------- | ----- |
| backup   | every verb, as a deadline for the whole verb (backend runs and in-process tar/rsync work; `schedule` passes it to the cron handle) | none | At the deadline the backend's whole process tree is stopped and the verb fails with `backup.timeout`, exit 124. Malformed values are refused (exit 2) |
| plugin   | `install`, `update`, `rollback`, `remove`, `available.search`, `available.info` (a deadline for the whole verb; exit 124) | none: `enable`, `disable`, `available.list`, `installed.list` and `keys.*` refuse it (exit 2) | 1 ms to 24 hours; any other value is an error (exit 2) |
| template | none | all verbs ignore it | |

---

## 3. Examples

Backup (restic and borg also need a password source: `password_file=`, `password=`, or their usual environment variables; otherwise they fail with `backup.missing_password`, exit 2):

```bash
resh backup://mydata.create src=/srv/app/data backend=tar repo_url=/srv/backups dry_run=true
resh backup://mydata.create src=/srv/app/data backend=tar repo_url=/srv/backups
resh backup://mydata.list backend=tar repo_url=/srv/backups
resh backup://mydata.verify backend=restic repo_url=/srv/restic password_file=/root/.restic-pass
resh backup://mydata.prune backend=tar repo_url=/srv/backups keep_daily=7 keep_weekly=4 dry_run=true
resh backup://mydata.restore snapshot_id=backup_20261016_091244 dest=/srv/restore backend=tar repo_url=/srv/backups
resh backup://mydata.schedule 'when=0 2 * * *' src=/srv/app/data backend=tar
```

`schedule` only reports a definition; it installs no cron job or timer. Run the `create` command from cron or a systemd timer yourself.

Plugins:

```bash
resh plugin://installed.list format=names
resh plugin://available.search q=monitoring offline=true
resh plugin://aws.install version=1.2.3 dry_run=true
resh plugin://demo.install source=file path=/home/alice/demo.tar.gz
resh plugin://aws.enable
resh plugin://aws.update dry_run=true
resh plugin://aws.remove dry_run=true
```

Templates:

```bash
resh template://inline.render 'template=Service: {{ name }}' 'context={"name":"api"}'
resh template://nginx.conf.render context_file=/srv/vars/prod.json
resh template://email.html.validate 'context={"user":"alice"}'
resh template://newsletter.html.test
```

---

## 4. Handle Summaries

### 4.1 backup://

* The profile comes from the URL host (`backup://mydata` is profile `mydata`). It names the reported schedule path; nothing else.
* Backend: `backend=restic|borg|rsync|tar`, or the first of these found on `PATH`.
* tar, rsync and borg require `repo_url` (there is no default repository; the former `/tmp` defaults were removed in v1.0.3-beta). restic without `repo_url` uses `RESTIC_REPOSITORY`.
* Encryption, deduplication and remote repositories are whatever the chosen backend provides (restic and borg encrypt; tar and rsync do not).

### 4.2 plugin://

* Sources: a registry over HTTPS (default), a direct HTTPS URL, or a local file.
* Registry installs require a well-formed SHA-256 from the registry, checked before extraction (`verify=sha256`, the default), and an Ed25519 publisher signature over it by a trusted key (`keys.add`, `trust_key=`; no official key is built in yet). Unsigned or untrusted artifacts are refused unless `allow_unsigned=true`.
* install and update keep one previous version; `rollback` switches back to it. `progress=true` streams JSON progress lines.
* `source=url` cannot be verified and needs an explicit `verify=none`, which installs the artifact **unverified** (only HTTPS protects it).
* Plain `http://` registries and artifact URLs are refused, as are HTTPS-to-HTTP redirects.
* Artifacts may contain only regular files and directories; links, devices, FIFOs, absolute and `..` paths fail the install with nothing installed.
* `enable`/`disable` write a state file for `scope=user` (default) or `scope=system` (`/var/lib/resh/plugins/state.json`); `installed.list` reads the same files.
* `ca_file=<pem>` adds a private CA for registry, index and artifact downloads; certificates are always verified.
* Plugin verbs refuse directories that are symbolic links, belong to another user or are writable by others, so running them as root with another user's `HOME` (`sudo -E`) fails with `plugin.unsafe_path`.

See [plugin.md](plugin.md) for the full security rules and known limitations.

### 4.3 template://

* Tera engine: variables, conditionals, loops, filters, comments. Templates are compiled one at a time, so `extends`/`include` of other files does not work.
* Context: a JSON string (`context`) or a JSON file (`context_file`, `render` only).
* Output formats for `render`: `text`, `html`, `json`, `bytes` (base64).
* `validate` reads the template text from `from=`, not `template=`.
* Tera's `get_env` function can read the environment of the `resh` process; do not render untrusted templates.

---

## 5. Operational Notes

* Use `dry_run=true` before `backup prune` and plugin changes; remember that `backup restore` has no dry run (it refuses `dry_run=true`).
* Verify backups (`backup verify`) and test restores regularly.
* Install plugins only from registries you trust, and pin versions with `version=`.
* Validate templates (`template validate`) before rendering them in pipelines.
* Gate automation on `ok` or the exit status, not on text output.
