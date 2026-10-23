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
| `backup://`   | Run restic, borg, rsync or tar to create, list, restore, verify and prune snapshots | `create`, `list`, `restore`, `verify`, `prune`, `schedule` (reports only) |
| `plugin://`   | Manage the local resh plugin store and read plugin catalogs | `install`, `update`, `remove`, `enable`, `disable`, `installed.list`, `available.list`, `available.search`, `available.info` |
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
| backup   | Honored by `create` and `prune`. `restore` has no dry run and refuses `dry_run=true`; `list`, `verify` and `schedule` have no dry-run mode either, so `dry_run=true` is refused for them too. An unrecognised value (such as `dry_run=maybe`) is an error for `create`, `prune` and `restore` |
| plugin   | Honored by `install`, `update`, `remove`, `enable`, `disable`. Values other than true/false/1/0/yes/no/on/off are errors |
| template | Not read (no verb writes anything) |

### timeout_ms

| Handle   | Enforced | Accepted but not used | Notes |
| -------- | -------- | --------------------- | ----- |
| backup   | `create`, `restore`; `list`, `verify`, `prune` when they run a backend (restic, borg; tar `verify` per archive) | `schedule`; tar/rsync `list` and `prune`; rsync `verify` | At the deadline the backend process is killed and the verb fails with `TIMEOUT`. Only the direct child is killed. Malformed values silently fall back to the default |
| plugin   | `install`, `update` (per HTTPS request, not a total deadline); `available.search`; `available.info` | `remove`, `enable`, `disable`; not read by `available.list`, `installed.list` | `available.search` rejects values outside 100-60000; `available.info` rejects non-integers and clamps to 100-30000; the other verbs silently use their default for a malformed value |
| template | none | all verbs ignore it | |

---

## 3. Examples

Backup (restic and borg also need a password source: `password_file=`, `password=`, or their usual environment variables; otherwise they fail with `MISSING_PASSWORD`):

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

* The profile comes from the URL host (`backup://mydata` is profile `mydata`). It names the default tar repository `/tmp/resh_backup_<profile>` and the reported schedule path; nothing else.
* Backend: `backend=restic|borg|rsync|tar`, or the first of these found on `PATH`.
* Pass `repo_url` explicitly. The defaults (`/tmp/resh_backup_<profile>`, `/tmp/rsync_backup`, `/tmp/borg_repo`) are in world-writable `/tmp`; restic has no default and uses `RESTIC_REPOSITORY`.
* Encryption, deduplication and remote repositories are whatever the chosen backend provides (restic and borg encrypt; tar and rsync do not).

### 4.2 plugin://

* Sources: a registry over HTTPS (default), a direct HTTPS URL, or a local file.
* Registry installs require a well-formed SHA-256 from the registry, checked before extraction (`verify=sha256`, the default). The checksum comes from the same registry, so it proves integrity in transit, not who published the plugin.
* `source=url` cannot be verified and needs an explicit `verify=none`, which installs the artifact **unverified** (only HTTPS protects it).
* Plain `http://` registries and artifact URLs are refused, as are HTTPS-to-HTTP redirects.
* Artifacts may contain only regular files and directories; links, devices, FIFOs, absolute and `..` paths fail the install with nothing installed.
* `enable`/`disable` write a state file for `scope=user` (default) or `scope=system` (`/var/lib/resh/plugins/state.json`).

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
