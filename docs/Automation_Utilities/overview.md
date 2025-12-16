# Automation Utilities Overview

Resource Shell provides three powerful automation utilities that help you manage data, extend functionality, and generate content. These utilities work together to automate common tasks in your development and operations workflows.

## The Three Automation Handles

Resource Shell includes three specialized handles for automation:

1. **backup://** - Data protection and backup management
2. **plugin://** - Extension and plugin management  
3. **template://** - Content generation and templating

Each handle follows a simple URL-like pattern that makes automation commands easy to read and write.

## backup:// - Protect Your Data

The backup handle helps you create, manage, and restore backups of your important data. Think of it as your data protection assistant that works with multiple backup tools.

### What Can You Do?

- **Create backups** of files and folders
- **List existing backups** to see what you've saved
- **Restore files** from any backup snapshot
- **Verify backups** to make sure they're not corrupted
- **Clean up old backups** with automatic retention policies
- **Schedule regular backups** to run automatically

### Backup Tools Supported

The backup handle works with four different backup programs:

- **restic** - Modern tool with encryption and deduplication (recommended)
- **borg** - Popular deduplication backup tool
- **rsync** - Simple file synchronization  
- **tar** - Basic archive creation

The system automatically picks the best tool available on your computer.

### Quick Examples

Create a backup:
```sh
backup://mydata.create(src="/home/user/documents")
```

List all your backups:
```sh
backup://mydata.list()
```

Restore files:
```sh
backup://mydata.restore(snapshot_id="abc123", dest="/restore")
```

Set up daily backups:
```sh
backup://mydata.schedule(when="0 2 * * *", src="/important/files")
```

### Key Features

- **Multiple backends** - Works with different backup tools
- **Smart selection** - Automatically chooses the best available tool
- **Encryption support** - Keeps your data secure
- **Deduplication** - Saves storage space by removing duplicates
- **Cloud storage** - Can backup to AWS S3, Azure, Google Cloud
- **Retention policies** - Automatically removes old backups
- **Verification** - Checks that backups are valid and complete

## plugin:// - Extend Your System

The plugin handle manages extensions that add new capabilities to Resource Shell. It's like an app store for command-line tools and utilities.

### What Can You Do?

- **Install plugins** from registries, URLs, or local files
- **Update plugins** to get the latest features and fixes
- **Remove plugins** you no longer need
- **Enable/disable plugins** without uninstalling them
- **Search for plugins** to find new tools
- **Get plugin information** before installing
- **List installed plugins** to see what you have

### Plugin Sources

You can install plugins from three types of sources:

- **Registry** - Official plugin catalog (default and recommended)
- **URL** - Direct download from any web address
- **File** - Local plugin files on your computer

### Quick Examples

Search for plugins:
```sh
plugin://available.search(q="aws")
```

Install a plugin:
```sh
plugin://aws.install()
```

List installed plugins:
```sh
plugin://installed.list()
```

Update a plugin:
```sh
plugin://aws.update()
```

Remove a plugin:
```sh
plugin://aws.remove()
```

### Special Plugin Targets

Some plugin operations use special targets instead of specific plugin names:

- `plugin://available.list()` - Browse all available plugins
- `plugin://available.search()` - Search the plugin catalog
- `plugin://available.info()` - Get details about a plugin
- `plugin://installed.list()` - See what's installed

### Key Features

- **Registry support** - Access to official plugin catalog
- **Version management** - Install specific versions or get latest
- **Security verification** - SHA256 checksums ensure safe downloads
- **User/system scope** - Install plugins for just you or everyone
- **Dry run mode** - Test operations without making changes
- **Source flexibility** - Install from registries, URLs, or local files
- **Plugin discovery** - Search and browse available extensions

## template:// - Generate Content

The template handle helps you create dynamic content by combining templates with data. It's perfect for generating configuration files, documents, or any text-based content.

### What Can You Do?

- **Render templates** with your data to create final content
- **Validate templates** to check for syntax errors
- **Test templates** with automated test cases
- **Use inline templates** for quick content generation
- **Load data from files** in JSON format
- **Output in multiple formats** (text, HTML, JSON, binary)

### Template Engine

All templates use the **Tera template engine** which supports:

- **Variables**: `{{ username }}` - Insert dynamic values
- **Conditions**: `{% if admin %}` - Show content conditionally  
- **Loops**: `{% for item in items %}` - Repeat content
- **Filters**: `{{ name | upper }}` - Transform values
- **Inheritance**: Reuse common template parts

### Quick Examples

Render an inline template:
```sh
template://inline.render(template="Hello {{ name }}", context="{\"name\":\"Alice\"}")
```

Render a file template:
```sh
template://config.yaml.render(context_file="/data/vars.json")
```

Validate template syntax:
```sh
template://email.html.validate()
```

Run template tests:
```sh
template://newsletter.html.test()
```

### Data Sources

Templates can get data from multiple sources:

1. **Inline JSON** - Small amounts of data in the command
2. **JSON files** - Larger datasets stored in files  
3. **URL parameters** - Individual values from the command

### Output Formats

Templates can generate content in different formats:

- **text** - Plain text output (default)
- **html** - HTML content for web pages
- **json** - Structured JSON data
- **bytes** - Binary content encoded as base64

### Key Features

- **File and inline templates** - Use template files or write templates directly in commands
- **Rich template syntax** - Variables, conditions, loops, filters, and inheritance
- **Data validation** - Check that templates have all required data
- **Automated testing** - Run test cases to ensure templates work correctly
- **Multiple output formats** - Generate text, HTML, JSON, or binary content
- **Error reporting** - Clear messages when templates or data have problems

## How They Work Together

These three automation utilities complement each other perfectly:

### Development Workflow
1. Use **templates** to generate configuration files for your project
2. Use **plugins** to add tools for building, testing, or deploying
3. Use **backups** to protect your source code and important files

### Operations Workflow  
1. Use **templates** to create deployment configurations
2. Use **plugins** to install monitoring and management tools
3. Use **backups** to protect production data and configurations

### Content Management Workflow
1. Use **templates** to generate documents, reports, or web content
2. Use **plugins** to add content processing tools
3. Use **backups** to protect your content and templates

## Common Patterns

### Safe Operations with Dry Run
All three handles support `dry_run` mode to test operations safely:

```sh
backup://data.create(src="/important", dry_run="true")
plugin://aws.install(dry_run="true")  
template://config.render(template="test", dry_run="true")
```

### JSON Output for Automation
All handles return structured JSON that scripts can process:

```sh
backup://data.list() | jq '.result.snapshots'
plugin://installed.list() | jq '.result.items[].name'  
template://config.render() | jq '.body.value'
```

### Error Handling
All handles provide detailed error information:

```sh
# Backup error example
{
  "op": "backup.create",
  "status": "error", 
  "error": {
    "kind": "BACKEND_FAILED",
    "message": "Source directory not found"
  }
}
```

### Timeout Control
All long-running operations support timeout settings:

```sh
backup://data.create(timeout_ms="600000")  # 10 minutes
plugin://aws.install(timeout_ms="300000")  # 5 minutes
template://big.render(timeout_ms="30000")  # 30 seconds
```

## Best Practices

### Planning Your Automation

1. **Start small** - Test commands with dry run before automating
2. **Use specific versions** - Pin plugin versions for reproducible environments
3. **Validate first** - Check templates before rendering important content
4. **Set up monitoring** - Use backup verification and plugin health checks
5. **Document your workflows** - Keep notes about your automation patterns

### Error Prevention

1. **Check prerequisites** - Ensure required tools are installed
2. **Validate inputs** - Use template validation before rendering
3. **Test with safe data** - Don't test backups with production data
4. **Use timeouts** - Prevent operations from running forever
5. **Monitor results** - Check that operations completed successfully

### Security Considerations

1. **Verify plugin sources** - Only install plugins from trusted sources
2. **Use encryption** - Enable backup encryption for sensitive data  
3. **Protect templates** - Don't put secrets directly in template files
4. **Check permissions** - Ensure backup destinations are secure
5. **Regular updates** - Keep plugins updated for security fixes

## Getting Help

Each handle provides comprehensive documentation and examples:

- **backup.md** - Complete backup handle reference
- **plugin.md** - Full plugin management guide
- **template.md** - Detailed template engine documentation

All handles support the same basic patterns, so once you learn one, the others become easier to use. Start with simple examples and gradually build more complex automation workflows.