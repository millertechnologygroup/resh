# Security Policy

## Supported Versions

resh is beta software. Security fixes are made only for the latest published release and are delivered as a new release; earlier releases are not patched.

| Version | Supported |
| ------- | --------- |
| v1.0.6-beta (latest release) | ✅ |
| v1.0.5-beta and earlier | ❌ Upgrade to the latest release |

Only Linux x86_64 is supported (see the [README](README.md#installation)). Fixes are verified on that platform only.

## Reporting a Vulnerability

**Do not report security vulnerabilities in public GitHub issues, discussions or pull requests.**

Report them privately through GitHub:

1. Go to the [Security tab](https://github.com/millertechnologygroup/resh/security) of this repository.
2. Select **Report a vulnerability**.
3. Fill in the form. The report is visible only to you and the maintainers.

GitHub's guide to this form: [Privately reporting a security vulnerability](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability).

### What to include

- The resh version (`resh --version`) and how you installed it (release archive or built from source, and from which commit)
- Linux distribution and version, and the backend tool and version involved (for example `nft`, `systemctl`, `restic`)
- The handle and verb, and the exact command or arguments that trigger the issue
- What happens, what you expected, and what an attacker gains (for example command injection, file access outside an intended path, a wrong result reported as success)
- Whether the attacker needs local access, control of an argument value, control of a remote server, or a particular configuration
- A minimal reproduction, ideally one that runs in a disposable container or virtual machine
- Whether you have shared the issue with anyone else, and any disclosure date you have in mind

## What Happens Next

There is no bug bounty and no guaranteed response time. Reports are handled as follows:

1. The report is acknowledged in the private advisory.
2. The issue is reproduced and its impact assessed. You may be asked for more details.
3. A fix is developed and reviewed privately, with regression tests.
4. The fix is published in a new release. The release notes and [CHANGELOG.md](CHANGELOG.md) describe the issue and which versions are affected, and a GitHub security advisory may be published.
5. You are credited in the release notes unless you prefer not to be.

If a report is not accepted as a vulnerability, you will be told why.

## Disclosure

Please give the maintainers a reasonable chance to release a fix before you disclose an issue publicly, and coordinate the timing in the private advisory. Do not publish exploit details or proof-of-concept code for an issue that has no released fix.

When testing, use only systems you own or are authorized to test. Many resh handles change system state (firewall rules, services, packages, users), so run tests in disposable environments.

## Scope

In scope:

- The resh source code in this repository
- The release archives published on [GitHub Releases](https://github.com/millertechnologygroup/resh/releases) and the installation instructions in the README

Report these elsewhere:

- Vulnerabilities in a dependency (a Rust crate, OpenSSL, or a tool resh runs such as `nft` or `systemctl`) go to that project. If resh exposes the vulnerability in a way the dependency alone does not, report that part here.
- Each advisory listed in `.cargo/audit.toml` has a written assessment there: most are not reachable from resh, and some are accepted risks. If you find that one is reachable, or has more impact than its assessment says, report it here.

Behavior that is already documented as a limitation (see [docs/known_issues.md](docs/known_issues.md) and each handle's page) is not treated as a new vulnerability unless you show an impact the documentation does not describe.

## Security Fixes in Past Releases

Security fixes are listed in the "Security" sections of [CHANGELOG.md](CHANGELOG.md), and remaining limitations in [docs/known_issues.md](docs/known_issues.md). A security release fixes the issues it lists; it does not mean resh is free of vulnerabilities.
