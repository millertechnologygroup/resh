# Contributing to resh

Thank you for your interest in contributing to resh! We're building the future of AI-native infrastructure automation together.

---

## 🎉 v1.0 Beta is Available - We Need Your Help!

**resh v1.0-beta is now available for testing!** With 28 production-ready handles, we're ready for community feedback, bug reports, and real-world testing.

### How You Can Contribute Right Now

While we're not accepting code pull requests yet, there are many valuable ways to contribute:

**1. 🐛 Test and Report Bugs**
- Try resh in your environment
- Report issues with detailed reproduction steps
- Test on different Linux distributions
- Find edge cases and corner cases

**2. 💡 Provide Feedback**
- Share your automation use cases
- Suggest missing features or improvements
- Tell us which handles you use most
- Describe your AI agent integration ideas

**3. 📝 Improve Documentation**
- Report unclear or missing documentation
- Suggest examples for specific use cases
- Request tutorials for common workflows
- Share your own usage examples

**4. 🧪 Real-World Testing**
- Test in production-like environments
- Try complex multi-server scenarios
- Validate database operations at scale
- Test SSH remote execution across fleets

**5. ⭐ Spread the Word**
- Star the repository
- Share with your network
- Write blog posts about your experience
- Present at local meetups

---

## Contribution Timeline

### ✅ Now: v1.0 Beta (January-March 2026)
**Currently accepting:**
- Bug reports and issue submissions
- Feature requests and suggestions
- Documentation feedback and improvements
- Testing and validation feedback
- Use case sharing and examples
- Community discussions

**What's available:**
- All 28 handles ready for testing
- Complete documentation
- Multiple output formats (JSON, table, log)
- Comprehensive automation utilities

### v1.1 Feature Complete (March 2026)
**Continued focus:**
- Bug fix validation
- Performance testing
- Edge case discovery
- Real-world workflow testing
- Documentation refinement

### v1.0 Stable (Q2 2026)
**We will begin accepting:**
- Bug fix pull requests
- Documentation improvements
- Example scripts and use cases
- Test contributions
- Handle enhancement suggestions

**Community infrastructure:**
- GitHub Discussions activated
- Discord server launched
- Community calls initiated
- Contribution guidelines finalized

### v1.2+ Enhanced (Q3 2026+)
**Expanded contribution opportunities:**
- Feature development contributions
- Performance optimization PRs
- Plugin development
- Translation and internationalization
- Comprehensive testing
- Full open source contribution workflow

---

## How to Report Bugs (v1.0 Beta)

We welcome and encourage bug reports! Good bug reports help us improve resh quickly.

### Before Reporting

1. **Check existing issues** - Your bug may already be reported
2. **Update to latest** - Ensure you're running the latest v1.0-beta release
3. **Verify it's a bug** - Not a documentation or usage issue

### Bug Report Template

When reporting bugs, please include:

**Environment:**
- OS and version (e.g., Ubuntu 22.04, Debian 12, RHEL 9, Alpine 3.18)
- resh version: `resh --version`
- Installation method (built from source, script, etc.)

**Command:**
```bash
# Exact command you ran
resh svc://nginx.status --json-pretty
```

**Expected Behavior:**
What you expected to happen.

**Actual Behavior:**
What actually happened. Include full error output.

**Additional Context:**
- Does it happen consistently?
- Does it work with a different handle/format?
- Any relevant logs or system state?

### Example Good Bug Report

```markdown
**Title:** svc:// handle fails on OpenRC systems

**Environment:**
- Alpine Linux 3.18
- resh v1.0.1-beta
- Built from source

**Command:**
resh svc://nginx.status --format json

**Expected:**
JSON output with service status

**Actual:**
Error: "systemd not found"

**Context:**
Alpine uses OpenRC, not systemd. The handle should detect
and use OpenRC but appears to only check for systemd.
```

### Where to Report

- **GitHub Issues:** https://github.com/millertechnologygroup/resh/issues
- Use issue labels: `bug`, `v1.0-beta`, `handle:<name>`
- Be respectful and constructive

---

## How to Request Features

Have an idea for resh? We'd love to hear it!

### Feature Request Template

**Title:** Clear, descriptive title

**Problem:**
What problem does this solve? What pain point does it address?

**Proposed Solution:**
How would this feature work? What would the API look like?

**Example Usage:**
```bash
# Show what commands would look like
resh newhandle://resource.action --json-pretty
```

**Alternatives Considered:**
What other approaches did you consider?

**Additional Context:**
Why is this important? What use cases does it enable?

### Example Good Feature Request

```markdown
**Title:** Add k8s:// handle for Kubernetes operations

**Problem:**
Managing Kubernetes resources requires kubectl with
unstructured text output, making it difficult for AI agents
to operate reliably.

**Proposed Solution:**
Add k8s:// handle for Kubernetes operations:

resh k8s://mycluster/pod/nginx-123.status --format json
resh k8s://mycluster/deployment/web.scale --replicas 5

**Alternatives:**
Could use kubectl with jq, but that's fragile and requires
external dependencies.

**Context:**
Many teams are moving to Kubernetes. An AI-native k8s://
handle would enable autonomous Kubernetes operations.
```

---

## Testing v1.0 Beta

### What to Test

**High Priority:**
- Different Linux distributions (Ubuntu, Debian, RHEL, Arch, Alpine)
- SSH remote execution across multiple servers
- Database operations (PostgreSQL, MySQL, SQLite)
- Service management (systemd vs OpenRC)
- Template rendering with complex variables
- Certificate operations and validation
- Backup operations with different backends

**Medium Priority:**
- Firewall rule management
- Archive operations (tar, zip, 7z)
- Git operations on real repositories
- Plugin installation and management
- Cache operations with Redis/Memcached
- HTTP client operations with real APIs
- Secret management with different backends

**Also Valuable:**
- Edge cases and error handling
- Performance with large files/data
- Concurrent operations
- Long-running operations
- Resource cleanup and memory usage
- AI agent integration workflows

### How to Share Results

**Successful Tests:**
- Comment on GitHub Issues with "✅ Tested on [OS] - Working"
- Share your use case and example commands
- Note any performance observations

**Failed Tests:**
- Open a new GitHub Issue with the bug report template
- Include full reproduction steps
- Attach relevant logs if available

### Testing Environments

**Safe Environments:**
- Virtual machines or containers
- Development/test servers
- Home lab setups
- Non-production environments

**Approach with Caution:**
- Production servers (v1.0-beta is stable but still beta)
- Critical infrastructure (test thoroughly first)
- Systems without backups
- Customer-facing services

### Structured Testing

If you want to be thorough, try testing:

1. **Each handle individually** - Does it work as documented?
2. **Output formats** - Do JSON, table, and log all work?
3. **Error handling** - Do errors return useful messages?
4. **Edge cases** - What happens with invalid input?
5. **Remote operations** - Does SSH work across your network?
6. **Integration** - Can you build real workflows?
7. **AI automation** - Can AI agents reliably use the structured output?

### Sharing Your Experience

Beyond bug reports, we'd love to hear:
- What workflows did you automate?
- How does it compare to your current tools (Ansible, Terraform, scripts)?
- What documentation is missing or unclear?
- What features would unlock new use cases?
- How's the developer experience?
- How well does it work with AI agents?

---

## Future Contribution Guidelines (v1.0 Stable+)

When code contributions open with v1.0 stable in Q2 2026, here's what the development workflow will look like:

### Development Setup (Future)

**Prerequisites:**
```bash
# Rust 1.70 or later
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Git
sudo apt install git  # Debian/Ubuntu
sudo yum install git  # RHEL/CentOS
```

**Fork and Clone:**
```bash
# Fork the repository on GitHub, then:
git clone https://github.com/yourusername/resh.git
cd resh

# Add upstream remote
git remote add upstream https://github.com/millertechnologygroup/resh.git
```

**Build and Test:**
```bash
# Build
cargo build

# Run tests
cargo test

# Run a specific handle's tests
cargo test --package resh --lib handles::file::tests

# Run resh locally
cargo run -- svc://nginx.status --json-pretty
```

**Development Workflow:**
```bash
# Create a feature branch
git checkout -b feature/add-new-handle

# Make your changes
# ... edit code ...

# Format code
cargo fmt

# Run linter
cargo clippy

# Run tests
cargo test

# Commit changes
git add .
git commit -m "Add new handle for XYZ"

# Push to your fork
git push origin feature/add-new-handle

# Open a pull request on GitHub
```

---

## Code of Conduct

resh is committed to providing a welcoming and inclusive environment for all contributors.

### Our Pledge

We pledge to make participation in our project a harassment-free experience for everyone, regardless of age, body size, disability, ethnicity, gender identity and expression, level of experience, nationality, personal appearance, race, religion, or sexual identity and orientation.

### Our Standards

**Examples of behavior that contributes to a positive environment:**
- Using welcoming and inclusive language
- Being respectful of differing viewpoints and experiences
- Gracefully accepting constructive criticism
- Focusing on what is best for the community
- Showing empathy towards other community members

**Examples of unacceptable behavior:**
- Trolling, insulting/derogatory comments, and personal or political attacks
- Public or private harassment
- Publishing others' private information without explicit permission
- Other conduct which could reasonably be considered inappropriate

### Enforcement

Instances of abusive, harassing, or otherwise unacceptable behavior may be reported by contacting the project team via GitHub Issues. All complaints will be reviewed and investigated and will result in a response that is deemed necessary and appropriate to the circumstances.

---

## Pull Request Process (Future - v1.0 Stable+)

When we begin accepting PRs with v1.0 stable (Q2 2026), this will be the process:

### Before Submitting

1. **Check existing issues** - Is this already being worked on?
2. **Open an issue first** - Discuss the change before coding (for features)
3. **Write tests** - All new code needs test coverage
4. **Update documentation** - Document new features/changes
5. **Follow code style** - Run `cargo fmt` and `cargo clippy`

### PR Requirements

**All PRs must:**
- Include tests that cover the changes
- Update relevant documentation
- Pass all CI checks (tests, linting, formatting)
- Include a clear description of the changes
- Reference any related issues

**PR Description Should Include:**
- What problem does this solve?
- How does it solve it?
- Are there any breaking changes?
- Screenshots/examples (if applicable)
- Testing instructions

### Review Process

1. **Automated checks** run (tests, linting, formatting)
2. **Maintainer review** - Code quality and design
3. **Community feedback** - Others can comment
4. **Address feedback** - Make requested changes
5. **Approval and merge** - Once everything looks good

---

## Coding Standards (Future)

When contributing code, please follow these standards:

### Rust Code Style

**Use cargo fmt:**
```bash
cargo fmt
```

**Use cargo clippy:**
```bash
cargo clippy -- -D warnings
```

**Follow Rust idioms:**
- Use `Result<T, E>` for error handling
- Prefer `impl Trait` for return types when appropriate
- Use descriptive variable names
- Write comprehensive doc comments

### Handle Implementation Standards

**All handles must:**
- Return structured data (no free-form text)
- Implement all three output formats (JSON, table, log)
- Include comprehensive error handling
- Provide helpful error messages
- Include examples in documentation
- Have test coverage >80%

**Example handle structure:**
```rust
pub struct FileHandle {
    // Handle state
}

impl Handle for FileHandle {
    fn execute(&self, verb: &str, args: &Args) -> Result<Output, Error> {
        match verb {
            "read" => self.read(args),
            "write" => self.write(args),
            // ... other verbs
            _ => Err(Error::UnknownVerb(verb.to_string()))
        }
    }
}
```

### Documentation Standards

**All public APIs must have doc comments:**
```rust
/// Reads the contents of a file
///
/// # Arguments
/// * `path` - The path to the file to read
///
/// # Returns
/// * `Ok(String)` - The file contents
/// * `Err(Error)` - If the file cannot be read
///
/// # Examples
/// ```
/// let contents = handle.read("/etc/hosts")?;
/// ```
pub fn read(&self, path: &str) -> Result<String, Error> {
    // Implementation
}
```

### Testing Standards

**Write comprehensive tests:**
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_read_success() {
        // Test successful file read
    }

    #[test]
    fn test_file_read_not_found() {
        // Test error handling
    }

    #[test]
    fn test_file_read_permissions() {
        // Test permission errors
    }
}
```

---

## Plugin Development (Future - v1.2+)

Plugins will allow you to extend resh with custom handles (coming in v1.2+).

### Plugin Structure
```
my-plugin/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   └── handles/
│       └── my_handle.rs
├── tests/
│   └── integration_tests.rs
└── README.md
```

### Plugin API
```rust
use resh_plugin_api::{Handle, Plugin, Output, Error};

#[derive(Plugin)]
pub struct MyPlugin;

impl Plugin for MyPlugin {
    fn name(&self) -> &str {
        "my-plugin"
    }
    
    fn handles(&self) -> Vec<Box<dyn Handle>> {
        vec![Box::new(MyHandle::new())]
    }
}
```

More details will be available in the Plugin Development Guide when the plugin system is ready (v1.2+).

---

## Recognition

We believe in recognizing contributors!

### How We'll Recognize Contributors

**Contributors.md**
- All contributors listed with their contributions

**GitHub Profile**
- Your contributions show on your GitHub profile
- Contributor badge on the repository

**Release Notes**
- Contributors mentioned in release notes
- Special callouts for significant contributions

**Community Spotlight**
- Featured contributors on website/blog
- Social media recognition
- Conference talk acknowledgments

**Swag and Rewards**
- Contributors receive resh swag (post-v1.0 stable)
- Top contributors get special recognition
- Plugin developers featured in marketplace

**Early Tester Recognition**
- v1.0 beta testers will be acknowledged
- "Founding Contributors" list for pre-v1.0 stable contributors
- Special recognition in v1.0 stable release notes

---

## Communication Channels

### Active Now (v1.0 Beta)
- **GitHub Issues** - Bug reports and feature requests
- **GitHub Discussions** - Coming with v1.0 stable for questions and community
- **LinkedIn** - Development updates and announcements
- **Twitter/X** - Daily progress and quick updates

### Coming Soon (v1.0 Stable - Q2 2026)
- **Discord Server** - Real-time community chat
- **Community Calls** - Quarterly roadmap reviews
- **Office Hours** - Weekly Q&A with maintainers
- **Email Newsletter** - Major updates and releases

### Stay Informed
- **Watch the GitHub repo** for releases and updates
- **Star the repo** to show support and track progress
- **Follow on social media** for daily progress
- **Check the roadmap** for upcoming features

---

## License

By contributing to resh, you agree that your contributions will be licensed under the Apache License 2.0.

All contributions must be your original work, or properly attributed if derived from other sources. You must have the right to submit the work under the Apache 2.0 license.

---

## Questions?

### About v1.0 Beta
- **Installation issues?** Open a GitHub Issue
- **Usage questions?** Check the [README](README.md) and [docs/](docs/)
- **Found a bug?** Report it via GitHub Issues
- **Have a feature idea?** Submit a feature request

### About Contributing
- **When can I submit PRs?** Code contributions open with v1.0 stable (Q2 2026)
- **How can I help now?** Test, report bugs, provide feedback, spread the word
- **Where to discuss?** GitHub Issues for specific bugs/features; Discussions coming with v1.0 stable

### General Questions
- Review the [README](README.md) for current status
- Check the [ROADMAP](ROADMAP.md) for detailed timeline
- Read [docs/](docs/) for comprehensive usage guides
- Contact the maintainers via GitHub Issues

---

## Thank You!

**Thank you for testing resh v1.0 beta and being part of this journey!**

Your bug reports, feedback, and real-world testing are invaluable. Every issue you report, every suggestion you make, and every test you run helps shape resh into a better tool.

We're building resh in public, and you're helping us build it right.

**Your early involvement matters:**
- You're shaping the future of AI-native automation
- Your feedback directly influences v1.0 stable and v1.1 priorities
- You'll be recognized as an early contributor and founding tester
- You're helping solve real infrastructure problems

**Together, we're building the automation platform for the AI era.** 🚀

---

**Last Updated:** January 2026 (v1.0 Beta)  
**Next Review:** Q2 2026 (when code contributions open with v1.0 stable)

For questions about contributing, please open a [GitHub Issue](https://github.com/millertechnologygroup/resh/issues) or check back as we set up GitHub Discussions with v1.0 stable.

**Star the repo • Test the beta • Report bugs • Help us build the future**