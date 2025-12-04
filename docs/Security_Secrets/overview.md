# Security & Secrets

This section covers tools for protecting your system and managing sensitive information in Resource Shell. These tools help you control access, secure data, and manage certificates and passwords safely.

## What This Section Covers

Security and secrets management includes:
- **User Management**: Creating and managing user accounts and groups
- **Secret Storage**: Safely storing and retrieving passwords and sensitive data
- **Digital Certificates**: Working with certificates and cryptographic keys
- **Firewall Protection**: Controlling network access and blocking unwanted connections

## Available Tools

### user - Manage User Accounts and Groups
The `user` handle lets you create, modify, and manage user accounts and groups on your system. You can add new users, change passwords, and control who has access to what.

**What it does:**
- Create and delete user accounts
- Add users to groups for different permissions
- Change user passwords securely
- Lock and unlock user accounts
- Check if users exist on the system

**Common workflows:**
- Set up new user accounts for team members
- Organize users into groups with specific permissions
- Reset forgotten passwords safely
- Disable accounts when people leave
- Check user permissions and group memberships

[Learn more about user management →](user.md)

### secret - Store and Retrieve Sensitive Data
The `secret` handle provides secure storage for passwords, API keys, and other sensitive information. It keeps your secrets encrypted and safe from unauthorized access.

**What it does:**
- Store passwords and API keys securely
- Retrieve secrets when you need them
- Access environment variables as secrets
- Remove old or unused secrets
- Keep sensitive data encrypted on disk

**Common workflows:**
- Store database passwords safely
- Manage API keys for different services
- Share secrets securely between applications
- Keep configuration files free of sensitive data
- Access secrets in scripts without exposing them

[Learn more about secret management →](secret.md)

### cert - Manage Digital Certificates and Keys
The `cert` handle works with digital certificates and cryptographic keys. These are like digital ID cards that prove identity and enable secure communication over networks.

**What it does:**
- View information about certificates
- Create new certificates and private keys
- Generate certificate signing requests (CSRs)
- Sign certificates with your own certificate authority
- Verify certificate chains and validity

**Common workflows:**
- Set up SSL certificates for websites
- Create certificates for secure communication
- Check when certificates will expire
- Generate keys for encryption and signing
- Build your own certificate authority

[Learn more about certificate management →](cert.md)

### firewall - Control Network Access
The `firewall` handle manages your system's firewall to control what network connections are allowed. It works with different firewall systems like iptables, UFW, and firewalld.

**What it does:**
- List current firewall rules
- Add rules to allow or block connections
- Remove rules you don't need anymore
- Enable and disable firewall protection
- Check firewall status and configuration

**Common workflows:**
- Allow specific programs to connect to the internet
- Block unwanted incoming connections
- Set up rules for web servers and databases
- Protect your system from network attacks
- Manage different firewall systems consistently

[Learn more about firewall management →](firewall.md)

## How These Tools Work Together

These security tools are designed to work together for complete system protection:

1. **Use user** to control who can access your system and what they can do
2. **Use secret** to store passwords and sensitive data that users and applications need
3. **Use cert** to set up secure communication and verify identities
4. **Use firewall** to control what network connections are allowed

For example, you might:
- Use `user` to create accounts for your team members
- Use `secret` to store the database password safely
- Use `cert` to create SSL certificates for your web server
- Use `firewall` to only allow web traffic and SSH connections

## Getting Started

Each tool uses a simple URL-style syntax:
- `user://alice.add` - Create a new user named alice
- `secret://local/api_key.get` - Get a stored API key
- `cert:///path/to/cert.pem.info` - View certificate information
- `firewall://.status` - Check firewall status

All tools return results in JSON format that's easy to read and use in scripts. Most operations include helpful error messages and safety checks to prevent mistakes.

## Security Best Practices

When using these tools:
- Always use strong passwords and change them regularly
- Store secrets in the secret handle instead of plain text files
- Check certificate expiration dates regularly
- Keep firewall rules simple and well-documented
- Test changes carefully before applying them to production systems
- Use dry-run modes when available to preview changes

## Platform Support

- **Linux**: Full support for all tools
- **Unix/macOS**: Most features work (some firewall features may be limited)
- **Windows**: Limited support - user and secret tools work, others may not

Each tool documentation includes specific platform compatibility information and any limitations you should know about.