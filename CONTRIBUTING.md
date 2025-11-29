# Contributing to resh

Thank you for your interest in contributing to resh! We're excited to build the future of AI-native infrastructure automation together.

---

## 🚧 Current Status: Early Development

**resh is currently in early development** and we're not accepting pull requests yet. We're working toward a v0.8 feature-complete release in Q1 2026, at which point we'll open the project for contributions.

### How You Can Help Right Now

While we're not ready for code contributions yet, you can help in these ways:

**1. ⭐ Star the Repository**
- Shows your interest and helps us gauge community support
- You'll be notified when we're ready for contributions

**2. 👀 Watch the Repository**
- Follow development progress
- See when features are implemented
- Get notified of major milestones

**3. 💡 Share Ideas**
- Once GitHub Discussions are enabled, share your use cases
- Describe your automation pain points
- Suggest features or improvements

**4. 📢 Spread the Word**
- Share resh with your network
- Star and share on social media
- Write about your interest in AI-native automation

**5. 📝 Document Your Use Cases**
- Tell us what automation problems you're trying to solve
- Share your current tooling challenges
- Describe how you'd use resh in your environment

---

## When Will Contributions Open?

### v0.8 Alpha (Q1 2026)
**We will begin accepting contributions** including:
- Bug reports and fixes
- Documentation improvements
- Example scripts and use cases
- Plugin development
- Testing and feedback

### v0.9 Beta (Q2 2026)
**Expanded contribution opportunities:**
- Feature development
- Handle improvements
- Performance optimization
- Translation and internationalization
- Community plugins

### v1.0 Production (Q3 2026)
**Full contribution model:**
- Complete contribution guidelines
- Contributor recognition program
- Plugin marketplace
- Community governance

---

## Future Contribution Guidelines

When contributions open, we'll welcome the following types of contributions:

### Code Contributions

**Bug Fixes**
- Fix issues in existing handles
- Improve error handling
- Address edge cases
- Performance improvements

**New Features**
- Implement new handles
- Add new verbs to existing handles
- Enhance output formats
- Improve CLI experience

**Performance**
- Optimize handle operations
- Reduce memory usage
- Improve startup time
- Enhance concurrency

### Documentation Contributions

**Guides and Tutorials**
- Getting started guides
- Handle-specific documentation
- Migration guides (from Ansible, Terraform, etc.)
- Best practices and patterns

**Examples**
- Real-world use cases
- Integration examples
- Template examples
- Script examples

**API Documentation**
- Handle reference documentation
- Verb documentation
- Error code documentation
- Schema documentation

### Plugin Development

**Community Plugins**
- Custom handles for specific use cases
- Integration plugins (cloud providers, monitoring tools)
- Utility plugins
- Domain-specific plugins

### Testing

**Test Coverage**
- Unit tests for handles
- Integration tests
- Performance tests
- Edge case tests

**Quality Assurance**
- Beta testing
- Bug reporting
- Security testing
- Usability testing

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

Instances of abusive, harassing, or otherwise unacceptable behavior may be reported by contacting the project team. All complaints will be reviewed and investigated and will result in a response that is deemed necessary and appropriate to the circumstances.

---

## Development Setup (Future)

When contributions open, here's what the development setup will look like:

### Prerequisites
```bash
# Rust 1.70 or later
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Git
sudo apt install git  # Debian/Ubuntu
sudo yum install git  # RHEL/CentOS
```

### Fork and Clone
```bash
# Fork the repository on GitHub, then:
git clone https://github.com/YOUR-USERNAME/resh.git
cd resh

# Add upstream remote
git remote add upstream https://github.com/millertg/resh.git
```

### Build and Test
```bash
# Build
cargo build

# Run tests
cargo test

# Run a specific handle's tests
cargo test --package resh --lib handles::file::tests

# Run resh locally
cargo run -- svc://nginx status --format json
```

### Development Workflow
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

## Pull Request Process (Future)

When we begin accepting PRs, this will be the process:

### Before Submitting

1. **Check existing issues** - Is this already being worked on?
2. **Open an issue first** - Discuss the change before coding
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

## Plugin Development (Future)

Plugins will allow you to extend resh with custom handles.

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

More details will be available in the Plugin Development Guide when the plugin system is ready.

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
- Contributors receive resh swag (post-v1.0)
- Top contributors get special recognition
- Plugin developers featured in marketplace

---

## Communication Channels

### Current (Limited)
- **GitHub Issues** - For bug reports (when open)
- **GitHub Discussions** - For questions and ideas (when enabled)

### Future (Post-v0.8)
- **Discord Server** - Real-time community chat
- **Community Calls** - Monthly video calls
- **Office Hours** - Weekly Q&A with maintainers
- **Twitter/LinkedIn** - Updates and announcements
- **Blog** - Technical deep-dives and tutorials

---

## License

By contributing to resh, you agree that your contributions will be licensed under the Apache License 2.0.

All contributions must be your original work, or properly attributed if derived from other sources. You must have the right to submit the work under the Apache 2.0 license.

---

## Questions?

### Before v0.8
- Watch this repository for updates
- Check the [README](README.md) for current status
- Review the [ROADMAP](ROADMAP.md) for timeline

### After v0.8
- Open a GitHub Discussion
- Join the Discord server
- Attend community calls
- Contact the maintainers

---

## Thank You!

Even though we're not accepting contributions yet, **your interest means everything**. 

Building an open source project takes a community, and we're excited to have you be part of resh's journey from the beginning.

**Star the repo, watch for updates, and we'll see you in Q1 2026 when contributions open!** 🚀

---

**Last Updated:** November 2025  
**Next Review:** Q1 2026 (when contributions open)

For questions about contributing, please open a GitHub Discussion (when available) or contact the maintainers.