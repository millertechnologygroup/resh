# Changelog

All notable changes to resh will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Comprehensive documentation for all handle categories
- Individual documentation files for each of the 25 implemented handles
- Organized documentation structure with category overviews
- Examples and usage patterns for core functionality
- Complete resh overview documentation

### Coming in v0.9
- webhook:// handle - Webhook receiver
- lock:// handle - Distributed locking

### Coming in v0.8
- lock:// handle - Distributed locking
- plugin:// handle - Plugin receiver

## [0.7.0] - 2025-11-30

### Added
- 25 of 30 production handles implemented
- Filesystem handles: file://, fs://, snapshot://, archive://
- Process handles: proc://, svc://, cron://
- Network handles: ssh://, http://, net://, dns://, mail://
- Security handles: secret://, cert://, firewall://, user://
- Data handles: db://, cache://, config://, mq://, log://, event://
- System handles: system://, pkg://, git://
- JSON, table, and log output formatters
- URI-based resource addressing
- Basic CLI with clap
- Initial documentation

### Known Issues
- Documentation incomplete for some handles
- Limited test coverage (expanding in v0.9)
- Performance not yet optimized
- Error messages need improvement

## [0.1.0] - 2025-09-12

### Added
- Initial project structure
- Core URI parsing
- Handle framework
- Basic output formatting